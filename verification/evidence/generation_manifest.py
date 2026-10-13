#!/usr/bin/env python3
"""Check frame identity independently, then inventory immutable evidence files."""
import argparse
import hashlib
import json
from pathlib import Path

GATEWAY = '25779953b1c27e0dec5f39ba871422a6b81f8cff'
BACKEND = '0f7b61ff58463a1bd1fe40f89d824059d1bb2bc3'

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load(root, name):
    return json.loads((root/name).read_text())

def check(root):
    rows = load(root, 'captures/summary.json')['captures']
    expected = {r['file']: r['bytes_sha256'] for r in rows}
    assert len(rows) == len(expected) == 36
    actual = {str(p.relative_to(root/'captures')): digest(p) for p in (root/'captures').rglob('*.frame')}
    assert actual == expected, 'capture inventory mismatch'
    absence = load(root, 'keyflow/absence.json')['frames']
    keyhashes = {r['kind']+'/'+r['class']+'.frame': r['sha256'] for r in absence}
    assert len(absence) == 36 and keyhashes == actual, 'keyflow frame mismatch'
    assert all(r['key_hits'] == 0 for r in absence)
    assert all(all(n == 0 for n in r['marker_hits'].values()) for r in rows)
    reconstruction = load(root, 'reconstruction/results.json')
    assert reconstruction['capture_frame_sha256'] == actual, 'reconstruction capture mismatch'
    for row in reconstruction['capture_results']:
        assert row['report_sha256'] == actual[row['fixture'].removeprefix('captures/')]
        assert row['expectations_matched']
    assert len(reconstruction['capture_results']) == 3
    assert len(reconstruction['results']) == 216
    for row in reconstruction['results']:
        name = row['fixture']
        frame = 'repeated_first' if name == 'repeated_content' else name
        assert row['report_sha256'] == digest(root/'reconstruction'/row['runner']/(frame+'.frame')), 'fixture hash mismatch'
        assert row['expectations_matched']
    directional = load(root, 'conformance/directional.json')
    assert directional['capture_frame_sha256'] == actual, 'conformance capture mismatch'
    assert directional['backend_actual'] == BACKEND and directional['gateway_head'] == GATEWAY
    assert all(r['accept'] for r in directional['real_documents'])
    assert all(r['accept'] for r in directional['signed_specs']['results'])
    assert len(load(root, 'conformance/corpus.json')['cases']) == 2130
    negative = load(root, 'conformance/negative-receive.json')
    assert negative['total'] == negative['rejected'] and negative['total'] > 0
    assert len(directional['classification']) == len(load(root, 'conformance/diff.json')['differences'])
    assert all(r['closure_citation'] for r in directional['classification'])
    tamper = load(root, 'tamper/raw_locator/results.json')
    assert len(tamper['results']) == 3
    assert all(r['valid_control_accepted'] and r['raw_locator_binding_rejected'] and r['raw_locator_document_field_rejected'] for r in tamper['results'])
    return actual

def directional_criterion(root):
    result = load(root, 'conformance/directional.json')
    rows = result['real_documents']
    failures = [r for r in rows if not r['accept'] or not r['canonical_bytes_equal_received']]
    return dict(passed=not failures, documents_total=len(rows), documents_accepted=sum(r['accept'] for r in rows), canonical_full_dump_equal=sum(r['canonical_bytes_equal_received'] for r in rows), failures=failures)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    frames = check(args.root)
    if args.write:
        commands = load(args.root, 'commands.json')
        failed_commands = [c for c in commands if c['exit_code'] != 0]
        inventory = {str(p.relative_to(args.root)): dict(sha256=digest(p), bytes=p.stat().st_size)
                     for p in sorted(args.root.rglob('*')) if p.is_file() and p.name not in {'manifest.json', 'manifest.sha256'}}
        manifest = dict(gateway_sha=GATEWAY, gateway_evidence_commit=load(args.root, 'provenance.json')['evidence_commit'],
                        backend_sha=BACKEND, backend_worktree='/var/tmp/cp81-backend-0f7b61ff',
                        artifacts=inventory, frame_sha256=frames, commands=commands,
                        generation_passed=not failed_commands, failed_commands=failed_commands,
                        directional_criterion=directional_criterion(args.root),
                        self_check=dict(passed=True, capture_frames=36, sources=['captures', 'keyflow/absence.json', 'reconstruction/results.json', 'conformance/directional.json']),
                        checksum_policy='manifest.json is hashed separately by manifest.sha256; neither lists its own recursive digest.')
        path = args.root/'manifest.json'
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True)+'\n')
        (args.root/'manifest.sha256').write_text(digest(path)+'  manifest.json\n')
    print('PASS: 36 identical capture hashes across capture, keyflow, reconstruction and conformance; all inventory, acceptance, reconstruction and tamper assertions passed; directional full-dump criterion recorded separately')
