#!/usr/bin/env python3
"""Read-only backend model conformance runner. No backend files are written.

Usage: python run_python.py BACKEND_CHECKOUT [--generate]
Run --generate before the Go test, then run again to compare results.
"""
import argparse
import base64
import copy
import hashlib
import json
import pathlib
import subprocess
import sys
sys.dont_write_bytecode = True

OUT = pathlib.Path('/Users/max/koskadeux-state/s1791/cp81/conformance')
def canon(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
def digest(value):
    return hashlib.sha256(canon(value)).hexdigest()
def save(name, value):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT/name).write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')

def main():
    p = argparse.ArgumentParser()
    p.add_argument('backend')
    p.add_argument('--generate', action='store_true')
    p.add_argument('--directional', action='store_true')
    args = p.parse_args()
    sys.path.insert(0, str(pathlib.Path(args.backend).resolve()))
    from app.schemas.data_verification import SuccessfulVerificationReport, TerminalVerificationReport, QuoteProbeRequest, SignedScanSpec
    from app.schemas.verification_runner import RunnerRegistration, ProbeReceipt
    from services.gateway_signer.verification_contract import GatewayScanPayload, canonical_json_bytes
    models = dict(scan_spec=GatewayScanPayload, scan_report=SuccessfulVerificationReport,
                  terminal_report=TerminalVerificationReport, probe_report=ProbeReceipt,
                  quote_probe=QuoteProbeRequest, registration=RunnerRegistration)
    if args.directional:
        directional(args.backend, models, canonical_json_bytes)
        return
    schemas = {k: m.model_json_schema() for k, m in models.items()}
    # SignedScanSpec is the retired RSA wrapper, not the S1791 Ed25519 envelope.
    save('schema-digests.json', {**{k: {'model': models[k].__module__+'.'+models[k].__name__, 'sha256': digest(s)} for k,s in schemas.items()},
                               'legacy_signed_scan_spec': {'model': 'SignedScanSpec', 'sha256': digest(SignedScanSpec.model_json_schema())}})
    sha = subprocess.check_output(['rtk','proxy','git','-C',args.backend,'rev-parse','HEAD'], text=True).strip()
    if args.generate:
        root = pathlib.Path(__file__).resolve().parents[2]/'contract/vectors/verification'
        if not root.exists():
            root = pathlib.Path.cwd()/'contract/vectors/verification'
        vectors = {k: json.loads((root/(k+'.json')).read_text())['input'] for k in ['scan_spec','scan_report','terminal_report','probe_report','registration']}
        vectors['scan_spec'] = json.loads(base64.urlsafe_b64decode(vectors['scan_spec']['payload_b64']+'=='))
        vectors['quote_probe'] = vectors['probe_report']['probe']
        cases = []
        coverage = []
        for cls, baseline in vectors.items():
            schema = schemas[cls]
            cases.append(dict(id=cls+'/baseline', cls=cls, input=baseline, dimension='baseline'))
            def resolve(s):
                if '$ref' in s: return schema['$defs'][s['$ref'].split('/')[-1]]
                return s
            def visit(value, s, path):
                s=resolve(s)
                if isinstance(value, dict):
                    for field, child in value.items():
                        cs=resolve(s.get('properties',{}).get(field,{}))
                        cp=path+[field]
                        variants=[('positive',child),('requiredness', '__DELETE__'),('null',None)]
                        for name, val in [('string','invalid'),('integer',-1),('float',1.0),('boolean',True),('false',False),('array',[]),('object',{})]:
                            variants.append(('type_'+name,val))
                        for lit in cs.get('enum', [cs['const']] if 'const' in cs else []):
                            variants.append(('literal_'+str(lit),lit))
                        for bound in ['minimum','maximum','exclusiveMinimum','exclusiveMaximum']:
                            if bound in cs:
                                b=cs[bound]
                                variants.extend([(bound+'_at',b),(bound+'_below',b-1),(bound+'_above',b+1)])
                        for bound in ['minLength','maxLength']:
                            if bound in cs:
                                b=cs[bound]
                                for n in sorted(set([max(0,b-1),b,b+1])):
                                    variants.append((bound+'_'+str(n),'x'*n))
                        if isinstance(child,list):
                            item_schema=resolve(cs.get('items',{}))
                            literals=item_schema.get('enum',[item_schema['const']] if 'const' in item_schema else [])
                            for lit in literals:
                                variants.append(('item_literal_'+str(lit),[lit]))
                            variants.append(('item_literal_invalid',['invalid']))
                            for bound in ['minItems','maxItems']:
                                if bound in cs:
                                    b=cs[bound]
                                    for n in sorted(set([max(0,b-1),b,b+1])):
                                        variants.append((bound+'_'+str(n),[child[0] if child else 'invalid']*n))
                        coverage.append(dict(cls=cls,path=cp,schema=cs,dimensions=['positive','requiredness','null','type','literal/bounds when declared']))
                        for name, replacement in variants:
                            v=copy.deepcopy(baseline); dest=v
                            for part in path: dest=dest[part]
                            if replacement == '__DELETE__': dest.pop(field)
                            else: dest[field]=replacement
                            cases.append(dict(id=cls+'/'+'/'.join(map(str,cp))+'/'+name,cls=cls,input=v,dimension=name))
                        visit(child,cs,cp)
                elif isinstance(value,list):
                    for i, child in enumerate(value): visit(child,s.get('items',{}),path+[i])
            visit(baseline,schema,[])
        save('corpus.json',dict(authority='5d8267dc',gateway_base='7fcbd770c7ffb7e21284e28767eeafedfe878c23',backend_actual=sha,cases=cases,coverage=coverage))
    corpus=json.loads((OUT/'corpus.json').read_text())
    results=[]
    for case in corpus['cases']:
        r=dict(id=case['id'],accept=False)
        try:
            model=models[case['cls']].model_validate(case['input'])
            output=canonical_json_bytes(model.model_dump(mode='json'))
            r.update(accept=True,sha256=hashlib.sha256(output).hexdigest())
        except Exception as e:
            r['error']=str(e)
        results.append(r)
    save('python-results.json',dict(backend_actual=sha,backend_requested='4d6875de',authority='5d8267dc',results=results))
    if (OUT/'go-results.json').exists() and not args.generate:
        go={r['id']:r for r in json.loads((OUT/'go-results.json').read_text())['results']}
        if set(go) != {r['id'] for r in results}:
            raise RuntimeError('Go results do not cover exactly this corpus; rerun Go after generation')
        differences=[]
        for r in results:
            g=go.get(r['id'])
            if g is None or g['accept'] != r['accept'] or (r['accept'] and g.get('sha256') != r.get('sha256')):
                differences.append(dict(id=r['id'],go=g,python=r))
        save('diff.json',dict(authority='5d8267dc',backend_actual=sha,backend_requested='4d6875de',cases=len(results),differences=differences,zero_diff=not differences))
        print(f'{len(results)} cases; {len(differences)} divergences; backend {sha}')
    else: print(f'{len(results)} Python cases; backend {sha}; run Go then rerun Python')

def directional(backend, models, canonical_json_bytes):
    """Keep symmetric artifacts immutable; audit actual emissions at the exact RC."""
    from collections import Counter
    from app.schemas.verification_runner import AWSRunnerRegistration, CloudflareRunnerRegistration
    from services.gateway_signer.verification_contract import require_canonical_json
    sha = subprocess.check_output(['rtk', 'proxy', 'git', '-C', backend, 'rev-parse', 'HEAD'], text=True).strip()
    assert sha == '4d6875dec49e3ca877e39258ffad11ec8714bfdb', sha
    original = {n: hashlib.sha256((OUT/n).read_bytes()).hexdigest()
                for n in ['diff.json', 'corpus.json', 'python-results.json', 'go-results.json']}
    frames, validations = [], []
    registrations = dict(aim_gateway=models['registration'], aws_s3_verifier=AWSRunnerRegistration,
                         r2_verifier=CloudflareRunnerRegistration)
    def validate(frame, cls, raw, model):
        result = dict(frame=frame, cls=cls, model=model.__module__+'.'+model.__name__,
                      received_sha256=hashlib.sha256(raw).hexdigest(), accept=False)
        try:
            value = model.model_validate(require_canonical_json(raw))
            result.update(accept=True, dump_sha256=hashlib.sha256(canonical_json_bytes(value.model_dump(mode='json'))).hexdigest())
        except Exception as exc:
            result['error'] = str(exc)
        validations.append(result)
    captures = OUT.parent/'captures'
    for path in sorted(captures.rglob('*')):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        name = str(path.relative_to(captures))
        frame = dict(path=name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
        frames.append(frame)
        if path.suffix != '.frame':
            frame['role'] = 'capture metadata'
            continue
        if path.name.endswith('_claims.frame'):
            frame['role'] = 'customer request JWS claims, not report/schema document'
            frame['decoded_claims'] = json.loads(base64.urlsafe_b64decode(raw.split(b'.')[1]+b'=='))
            continue
        if path.name.endswith('_http_request.frame'):
            frame['role'] = 'HTTP transport duplicate; validate decoded body document independently'
            raw = raw.split(b'\r\n\r\n', 1)[1]
        else:
            frame['role'] = 'JSON frame'
        body = json.loads(raw)
        if 'document_b64' in body:
            doc = base64.urlsafe_b64decode(body['document_b64']+'==')
            cls = dict(scan='scan_report', terminal='terminal_report', probe='probe_report')[body['variant']]
            validate(name, cls, doc, models[cls])
            if cls == 'probe_report':
                validate(name+'#probe', 'quote_probe', canonical_json_bytes(json.loads(doc)['probe']), models['quote_probe'])
        elif path.name == 'registration.frame':
            validate(name, 'registration', raw, registrations[path.parent.name])
        else:
            frame['role'] = 'local audit/log record, not sent to backend report receiver'
    corpus = {c['id']: c for c in json.loads((OUT/'corpus.json').read_text())['cases']}
    differences = json.loads((OUT/'diff.json').read_text())['differences']
    classified, counts = [], {}
    for diff in differences:
        case = corpus[diff['id']]
        cls = case['cls']
        # Scan flows backend -> Go. All other classes flow Go -> backend.
        # Equal-accept normalization cases are compared to actual emitter field
        # representations (RFC3339 strings / boolean), not a nonexistent parser.
        if cls == 'scan_spec':
            category, reason = 'b', 'Go receiver rejects a backend-model-accepted input; fail-closed (includes fixed signing-key admission context)'
        elif not diff['python']['accept']:
            category, reason = 'a', 'Go only emits this class; canonical transport is not a field parser; backend receiver rejects mutation'
        else:
            category, reason = 'c', 'backend model accepts numeric timestamp/boolean representation never emitted by real Go serializers; receiver coercion/normalization risk'
        rc = dict(id=case['id'], cls=cls, category=category, reason=reason,
                  original_go=diff['go'], original_python=diff['python'], input=case['input'])
        try:
            parsed = models[cls].model_validate(case['input'])
            rc['rc_accept'] = True
            rc['rc_dump_sha256'] = hashlib.sha256(canonical_json_bytes(parsed.model_dump(mode='json'))).hexdigest()
        except Exception as exc:
            rc.update(rc_accept=False, rc_error=str(exc))
        classified.append(rc)
        counts.setdefault(cls, Counter())[category] += 1
        if category == 'c':
            if cls in {'scan_report', 'terminal_report'}:
                rc['admission_impact'] = 'Model is looser; runner full-dump equality guard rejects these bytes before signature verification (data_verification_service.py:1364-1368). No end-to-end acceptance claimed.'
                rc['emitter_evidence'] = 'internal/verification/runner.go:474-483; internal/awsverification/report.go:19-28; internal/cloudflareverification/report.go:19-28; accepted_at_utc comes from wire.VerifyScan RFC3339-parsed payload (internal/wire/verification.go:192).'
            elif cls == 'registration':
                rc['admission_impact'] = 'Receiver model accepts numeric datetime; proof input preserves original dict, not normalized model. Correct proof still required; no signature bypass demonstrated.'
                rc['emitter_evidence'] = 'internal/verification/keys.go:163; internal/awsverification/bootstrap.go:106; internal/cloudflareverification/bootstrap.go:92 emit timestamp strings.'
            else:
                rc['admission_impact'] = 'Receiver model coerces 1.0 to true; ProbeReceipt signature uses original decoded dict, so numeric value must itself be signed (gateway_verification_service.py:605-609). Standalone request has no receipt signature.'
                rc['emitter_evidence'] = 'internal/verification/runner.go:388; internal/awsverification/handler.go:290; internal/cloudflareverification/scan.go:118 emit owner_consent=true.'
    assert len(classified) == 1126 and len({c['id'] for c in classified}) == 1126
    sites = []
    def site(file, start, end, yes, description):
        source = pathlib.Path(backend)/file
        lines = source.read_text().splitlines()
        sites.append(dict(file=file, start=start, end=end, model_dump_reserialization=yes,
                          explanation=description, source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                          excerpt='\n'.join(f'{i+1}: {lines[i]}' for i in range(start-1, end))))
    gw = 'app/services/gateway_verification_service.py'
    aws = 'app/services/aws_verification_service.py'
    cf = 'app/services/cloudflare_verification_service.py'
    dv = 'app/services/data_verification_service.py'
    site(gw, 587, 609, False, 'Probe signature canonicalizes received decoded dict excluding signature, not ProbeReceipt.model_dump; numeric owner_consent stays numeric in signature input.')
    site(gw, 614, 623, False, 'Snapshot hash uses stored exact payload_bytes.')
    site(gw, 748, 754, True, 'Spec hash is over canonical payload.model_dump.')
    site(gw, 781, 792, False, 'Content hash uses binary snapshot member preimage, not a report model dump.')
    site(gw, 795, 795, True, 'Receipt signature delegates to shared model-dump binding below.')
    site(dv, 1214, 1267, True, 'Success and terminal receipt bindings come from report.model_dump; signature verifies canonical selected binding. Success accepted_at_utc is not signed; terminal completed_at_utc is signed.')
    site(dv, 1364, 1368, True, 'Runner reports first require full model dump equal to raw_body: all four report timestamp normalization mutations fail closed before signature verification.')
    site(aws, 379, 387, True, 'Poll admission compares canonical spec model dump hash to work.spec_hash.')
    site(dv, 1418, 1424, True, 'Fingerprint hash canonicalizes report.canonical_fingerprint(), a projected validated model representation; none of the six changed fields belongs to the fingerprint.')
    site(aws, 515, 522, True, 'Receipt path hashes spec model dump.')
    site(aws, 529, 531, False, 'Snapshot hash uses exact payload_bytes.')
    site(aws, 537, 542, True, 'Receipt signature delegates to shared model-dump binding; content_hash comparison on line 538 uses binary preimage documented separately.')
    site(aws, 441, 452, False, 'Cloud content hash uses ordered length-prefixed identities, sizes and member digests, not JSON model dump.')
    site(aws, 791, 802, False, 'Registration key proof uses decoded original dict excluding proof; request hash uses exact raw bytes. Numeric registration timestamps remain numeric in proof.')
    site(aws, 840, 859, False, 'Request JWS body digest binds exact raw bytes.')
    site(aws, 907, 934, False, 'Stored snapshot and spec checks hash exact stored/decoded bytes and verify JWS signing input.')
    site(cf, 37, 49, True, 'Cloudflare delegates receipt, content, intake, work and stored snapshot to AWS shared functions; this is delegation evidence, with per-verification YES/NO outcomes in the referenced shared sites.')
    site(cf, 229, 247, False, 'Cloudflare registration proof uses original decoded dict; request hash uses raw bytes.')
    site(cf, 282, 297, False, 'Cloudflare request JWS body digest binds exact raw bytes.')
    site('app/services/data_verification_signing.py', 110, 135, False, 'All verify_gateway_jws call sites verify original encoded header.payload signing input, not any decoded model dump.')
    for file in [gw, aws]:
        lines = (pathlib.Path(backend)/file).read_text().splitlines()
        for i, line in enumerate(lines):
            if ' = verify_gateway_jws(' in line:
                site(file, i+1, min(i+3, len(lines)), False, 'JWS signature verification delegates to exact encoded signing input; model-dump hash checks, where present, are separate sites above.')
    result = dict(backend_requested=sha, backend_actual=sha, backend_checkout=backend,
                  gateway_head='13167d197f8544a41caa8f19a74823c1f7f584c5', symmetric_artifact_sha256=original,
                  frames=frames, real_documents=validations,
                  real_document_counts=dict(Counter((v['cls']) for v in validations)),
                  unique_document_validations_total=sum('_http_request.frame' not in v['frame'] for v in validations),
                  unique_document_validations_accepted=sum(v['accept'] and '_http_request.frame' not in v['frame'] for v in validations),
                  real_documents_accepted=sum(v['accept'] for v in validations), real_documents_total=len(validations),
                  classification=classified, counts_by_class={k: {c: v[c] for c in 'abc'} for k,v in counts.items()},
                  category_c=[v for v in classified if v['category']=='c'], verification_sites=sites,
                  rc_verdict_changes=[v['id'] for v in classified if v['rc_accept'] != v['original_python']['accept']],
                  signed_specs=json.loads((OUT/'directional-go.json').read_text()),
                  limits=['Model conformance is not full database-backed receipt/admission acceptance.',
                          'Category c uses real emitter representations for the six equal-accept normalization differences; they cannot be classified by accept bits alone.',
                          'No demonstrated signature bypass: report dump-equality guard rejects normalized timestamps; probe/registration proofs retain original values.'])
    save('directional.json', result)
    assert original == {n: hashlib.sha256((OUT/n).read_bytes()).hexdigest() for n in original}
    print(f'Backend {sha}: real documents {result["real_documents_accepted"]}/{len(validations)} accepted; classifications {dict(Counter(v["category"] for v in classified))}')
    assert all(v['accept'] for v in validations), 'real frame rejection recorded in directional.json'

if __name__ == '__main__': main()
