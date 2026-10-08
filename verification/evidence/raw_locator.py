#!/usr/bin/env python3
"""Standalone real-validator tamper case, using disposable local PostgreSQL.

Reuses RC test fixture setup only; production validators and signature verification
are not patched. Nothing is written to the backend checkout.
"""
import argparse
import asyncio
import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
from contextlib import asynccontextmanager
sys.dont_write_bytecode = True

BACKEND_SHA = '0f7b61ff58463a1bd1fe40f89d824059d1bb2bc3'

@asynccontextmanager
async def fixture(fn, *args):
    gen = inspect.unwrap(fn)(*args)
    try:
        yield await anext(gen)
    finally:
        await gen.aclose()

async def run(backend, out):
    import pytest
    import s1791_aws_support as support
    import test_s1791_checkpoint_receipts as receipts
    import test_s1791_gateway_verification as gwfixtures
    import test_s1791_aws_verification as awsfixtures
    from app.services import gateway_verification_service as gateway
    from app.services import aws_verification_service as aws
    from app.services.data_verification_service import (
        DataVerificationRefused, _successful_receipt_signature_binding, parse_verification_report)
    from app.schemas.verification_runner import unb64
    from services.gateway_signer.verification_contract import runner_payload, canonical_json_bytes
    results = []

    async def cases(name, validate, f, epoch, report, private, hashes=None):
        payload = runner_payload(epoch.signed_spec_payload, 'scan')
        kwargs = {} if hashes is None else dict(member_sha256s=hashes)
        binding = _successful_receipt_signature_binding(report)
        assert 'artifact_locator_commitment' in binding and 'raw_locator' not in binding
        await validate(f.db, report, epoch, payload, **kwargs)
        control = canonical_json_bytes(report.model_dump(mode='json'))
        (out/(name+'-control.json')).write_bytes(control)
        wrong = dict(binding)
        wrong.pop('artifact_locator_commitment')
        wrong['raw_locator'] = '/private/customer/data.csv'
        sig = base64.b64encode(private.sign(canonical_json_bytes(wrong))).decode()
        tampered = report.model_copy(update={'receipt_signature': sig})
        raw = canonical_json_bytes(tampered.model_dump(mode='json'))
        (out/(name+'-tampered.json')).write_bytes(raw)
        (out/(name+'-signed-binding.json')).write_bytes(canonical_json_bytes(wrong))
        try:
            await validate(f.db, tampered, epoch, payload, **kwargs)
            rejected, reason = False, None
        except DataVerificationRefused as exc:
            rejected, reason = True, str(exc)
        results.append(dict(validator=name, valid_control_accepted=True,
                            raw_locator_binding_rejected=rejected, rejection=reason,
                            control_sha256=hashlib.sha256(control).hexdigest(),
                            tampered_sha256=hashlib.sha256(raw).hexdigest(),
                            binding_sha256=hashlib.sha256(canonical_json_bytes(wrong)).hexdigest()))
        assert rejected, name
        # Also exclude a literal raw path field at the strict document boundary.
        extra = {**report.model_dump(mode='json'), 'raw_locator': wrong['raw_locator']}
        try:
            parse_verification_report(canonical_json_bytes(extra))
        except (DataVerificationRefused, ValueError):
            results[-1]['raw_locator_document_field_rejected'] = True
        else:
            raise AssertionError('raw_locator extra field accepted')

    for kind in ['gateway', 'aws']:
        database = inspect.unwrap(support.s1791_database_url)()
        # Unavailable PostgreSQL is a failed run, never a silently skipped case.
        url = next(database)
        try:
            with pytest.MonkeyPatch.context() as patch:
                if kind == 'gateway':
                    async with fixture(receipts.gateway_local, url, patch):
                        async with fixture(gwfixtures.runner_db, patch) as f:
                            epoch, _, _, _ = await gwfixtures.quote_and_start(f)
                            report = parse_verification_report(await gwfixtures.matching_report(f, epoch))
                            await cases('gateway', gateway.validate_runner_receipt, f, epoch, report, f.private)
                else:
                    async with fixture(awsfixtures.aws_db, url, patch) as setup:
                        async with fixture(awsfixtures.aws_source, setup, patch) as f:
                            epoch, work, _, _ = await awsfixtures.aws_paid(f)
                            from datetime import timedelta
                            await aws.poll_work(f.db, f.runner, now=awsfixtures.NOW+timedelta(minutes=31))
                            body = await awsfixtures.aws_scan_body(f, epoch, work)
                            report = parse_verification_report(unb64(body['document_b64'], aws.MAX_DOCUMENT))
                            for name, validator in [('shared', gateway.validate_runner_receipt), ('aws', aws.validate_receipt)]:
                                await cases(name, validator, f, epoch, report, awsfixtures.PRIVATE, body['member_sha256s'])
        finally:
            database.close()
    (out/'results.json').write_text(json.dumps(dict(backend_sha=BACKEND_SHA, results=results,
        scope='Real receipt validators and Ed25519 verification with disposable PostgreSQL; test-only signer/KMS/payment fixture setup, no backend edits.'), indent=2)+'\n')
    print(json.dumps(results, indent=2))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('backend')
    parser.add_argument('output')
    args = parser.parse_args()
    backend = Path(args.backend).resolve()
    sha = subprocess.check_output(['rtk', 'proxy', 'git', '-C', str(backend), 'rev-parse', 'HEAD'], text=True).strip()
    assert sha == BACKEND_SHA, sha
    sys.path[:0] = [str(backend), str(backend/'tests')]
    os.environ.setdefault('DATABASE_URL', 'postgresql://test:test@localhost:5432/test')
    os.environ.setdefault('ENVIRONMENT', 'test')
    os.environ.setdefault('TESTING', '1')
    os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-pytest-only-32chars!')
    os.chdir(backend)
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    assert not any(output.iterdir()), 'refusing to overwrite raw-locator artifacts'
    asyncio.run(run(backend, output))
