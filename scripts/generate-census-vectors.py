#!/usr/bin/env python3
"""Independent stdlib reference for the C1/Python backend contract. No source data."""
import hashlib
import hmac
import io
import json
from pathlib import Path
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_FORMATS = json.loads((ROOT / "internal/inventory/archive_formats.json").read_text())

def u64(n):
    return struct.pack('>Q', n)

def field(b):
    return u64(len(b)) + b

def metadata(m):
    return u64(m['size']) + field(m['etag'].strip('"').encode()) + field(m['version_id'].encode())

def planned(seed, members, literals):
    remaining = literals['planned_processed_bytes']
    result = []
    census = [m for m in members if m['format'] not in ('csv', 'tsv', 'jsonl', 'parquet')]
    for m in sorted(census, key=lambda m: (hmac.digest(seed, m['identity'].encode(), 'sha256'), m['identity'].encode())):
        cost = literals['archive_allowance_bytes'] if m['format'].removeprefix('.').lower() in ARCHIVE_FORMATS else m['size']
        if cost <= remaining:
            result.append(m['identity'])
            remaining -= cost
    return result

def main():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_STORED) as z:
        for name, body in [('a.txt', b'generated first\n'), ('b.txt', b'generated second\n')]:
            zi = zipfile.ZipInfo(name, (2026, 11, 5, 0, 0, 0))
            z.writestr(zi, body)
    zip_bytes = buffer.getvalue()
    zip_extent = 30 + len('a.txt') + len(b'generated first\n')
    decoded = b'generated decoded prefix\x00' * 30
    bodies = {'a-table': b'n\n1\n2\n', 'b-full': b'plain\x00\xff\n', 'c-zip': zip_bytes, 'd-tar': decoded}
    members = []
    for identity, fmt in [('a-table', 'csv'), ('b-full', 'txt'), ('c-zip', 'zip'), ('d-tar', 'tar.gz'), ('e-unread', 'txt'), ('f-gzip', 'gz'), ('g-tgz', 'tgz'), ('é-未読', 'txt')]:
        members.append({'identity': identity, 'size': len(bodies[identity]) if identity in bodies else (57 if fmt in ('gz', 'tgz') else 1_000_000_000),
                        'etag': 'é-tag' if identity.startswith('é') else 'tag-' + identity,
                        'version_id': '版本-2' if identity.startswith('é') else '', 'format': fmt})
    seed = bytes(range(32))
    cases = []
    for budget in [0, 4, 8, 64 << 20, (128 << 20) + 8, 3_000_000_000]:
        literals = {'archive_allowance_bytes': 64 << 20, 'planned_processed_bytes': budget}
        selection = planned(seed, members, literals)
        unread = b''.join(field(m['identity'].encode()) + metadata(m) for m in members
                          if m['format'] != 'csv' and m['identity'] not in selection)
        cases.append({'seed_hex': seed.hex(), 'literals': literals, 'members': members,
                      'planned': selection, 'unread_binding_sha256': hashlib.sha256(unread).hexdigest()})
    forms = [
        {'tag': 'full', 'bytes_hex': bodies['b-full'].hex(), 'sha256': hashlib.sha256(bodies['b-full']).hexdigest()},
        {'tag': 'zip_entries', 'bytes_hex': zip_bytes.hex(), 'extents': [{'offset': 0, 'length': zip_extent}],
         'sha256': hashlib.sha256(u64(0) + u64(zip_extent) + zip_bytes[:zip_extent]).hexdigest()},
        {'tag': 'decoded_prefix', 'bytes_hex': decoded.hex(), 'length': 513,
         'sha256': hashlib.sha256(u64(513) + b'decoded_prefix' + decoded[:513]).hexdigest()},
    ]
    commitments = {}
    for m in members:
        identity = m['identity']
        if identity == 'a-table':
            commitments[identity] = {'tag': 'full', 'sha256': hashlib.sha256(bodies[identity]).hexdigest()}
        elif identity in ('b-full', 'c-zip', 'd-tar'):
            f = forms[('b-full', 'c-zip', 'd-tar').index(identity)]
            commitments[identity] = {'tag': f['tag'], 'sha256': f['sha256']}
        else:
            commitments[identity] = {'tag': 'unread', 'sha256': hashlib.sha256(metadata(m)).hexdigest()}
    framed = b''
    for m in members:
        c = commitments[m['identity']]
        framed += field(m['identity'].encode()) + u64(m['size'])
        if m['format'] == 'csv':
            framed += bytes.fromhex(c['sha256'])
        else:
            framed += field(c['tag'].encode()) + field(bytes.fromhex(c['sha256']))
    vector = {'contract': 'content_census_v1/planned_read_commitment_v2',
              'framing': 'u64be byte lengths; table identity,size,digest; census identity,size,field(tag),field(digest); unread digest=sha256(size,field(etag),field(version_id))',
              'plans': cases, 'commitment_forms': forms,
              'content_binding': {'members': members, 'commitments': commitments,
                                  'preimage_hex': framed.hex(), 'content_sha256': hashlib.sha256(framed).hexdigest()}}
    path = ROOT / 'contract/census_plan_vectors.json'
    path.write_text(json.dumps(vector, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    manifest = ROOT / 'contract/VECTORS.sha256'
    lines = [line for line in manifest.read_text().splitlines() if not line.endswith('  contract/census_plan_vectors.json')]
    lines.append(hashlib.sha256(path.read_bytes()).hexdigest() + '  contract/census_plan_vectors.json')
    manifest.write_text('\n'.join(sorted(lines, key=lambda line: line.split('  ', 1)[1])) + '\n')

if __name__ == '__main__':
    main()
