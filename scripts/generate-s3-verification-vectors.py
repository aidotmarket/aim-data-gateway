#!/usr/bin/env python3
"""Freeze S3 vectors using Python oracle facts; requires cryptography for test keys."""
import base64
import copy
import hashlib
import hmac
import json
import struct
import unicodedata
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "contract/vectors/verification/s3_listing"
OUT.mkdir(exist_ok=True)
KEY, SEED, RECEIPT_SEED = bytes([99])*32, bytes([66])*32, bytes([2])*32
canon = lambda v: json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
sha = lambda b: hashlib.sha256(b).hexdigest()
nfc = lambda s: unicodedata.normalize("NFC", s)
mac = lambda s: hmac.new(KEY, nfc(s).encode(), hashlib.sha256).hexdigest()
manifest = json.loads((ROOT / "verification/testdata/oracle/manifest.json").read_text())
files = {v["name"]: v for v in manifest["files"]}

def member(name, key, version=None):
    v = files[name]
    data = (ROOT / "verification/testdata/oracle" / v["input"]).read_bytes()
    raw = (ROOT / "verification/testdata/oracle" / v["expected"]).read_bytes()
    assert sha(data) == v["input_sha256"] and sha(raw) == v["expected_sha256"]
    return {"key": key, "etag": "test-etag", "size_bytes": len(data), "format": v["format"], "provider": "aws", **({"version_id": version} if version else {})}, data, json.loads(raw)

csv = member("quoted_null_csv", "a.csv", "v1")
tsv = member("multiline_tsv", "b.tsv")
jsonl = member("json_order_missing", "c.jsonl", "v2")
parquet = member("all_approved_types", "d.parquet")
cases = [("csv_version", [csv]), ("tsv_etag", [tsv]), ("jsonl_version", [jsonl]), ("parquet_etag", [parquet]), ("mixed_formats", [csv, tsv, jsonl, parquet]), ("unicode_order", [member("quoted_null_csv", "e\u0301.csv", "ve\u0301"), member("multiline_tsv", "é.tsv"), member("json_order_missing", "\U00010000.jsonl"), member("quoted_null_csv", "\ue000.csv")])]
for field, value in [("key", "changed.csv"), ("version_id", "v3")]:
    m, data, facts = copy.deepcopy(csv)
    m[field] = value
    cases.append(("changed_" + field, [(m, data, facts)]))
m, data, facts = copy.deepcopy(csv)
data = data.replace(b"\n", b"\r\n")
m["size_bytes"] = len(data)
cases += [("changed_bytes", [(m, data, facts)]), ("changed_bucket", [csv])]
m, data, facts = copy.deepcopy(tsv)
m["etag"] = "changed-etag"
cases.append(("changed_etag", [(m, data, facts)]))
cases.append(("unicode_normalized", [member("quoted_null_csv", "é.csv", "vé")]))
s1590 = json.loads((ROOT / "verification/testdata/s1590/report.json").read_text())["objects"][0]
data = ("problem_id,difficulty,accepted_count\n" + "".join(f"{i},level_{i},{i*10}\n" for i in range(1, 13))).encode()
cases.append(("s1590_csv", [({"provider": "aws", "key": "s1590.csv", "etag": "test-etag", "size_bytes": len(data), "format": "csv"}, data, s1590)]))

for name, members in cases:
    members = copy.deepcopy(members)
    members.sort(key=lambda v: (nfc(v[0]["key"]) + "\0" + nfc(v[0].get("version_id", v[0]["etag"]))).encode())
    bucket = "changed-fixture" if name == "changed_bucket" else "fixture"
    payload = {"snapshot_version": "verification-source-snapshot-v1", "source_kind": "s3_listing", "connection_id": "22222222-2222-4222-8222-222222222222", "bucket": bucket, "listing_id": "33333333-3333-4333-8333-333333333333", "listing_version_id": "44444444-4444-4444-8444-444444444444", "source_handle_id": "55555555-5555-4555-8555-555555555555", "members": [m for m, _, _ in members]}
    snapshot = canon(payload)
    snapshot_hash = sha(snapshot)
    claims = {"aud": "66666666-6666-4666-8666-666666666666", "runner_id": "66666666-6666-4666-8666-666666666666", "manifest_hash": snapshot_hash, "payload_b64": b64(snapshot)}
    header = {"alg": "EdDSA", "kid": "test-only-scan-key", "typ": "aim-scan-snapshot+jwt"}
    signing = b64(canon(header)) + "." + b64(canon(claims))
    token = signing + "." + b64(Ed25519PrivateKey.from_private_bytes(SEED).sign(signing.encode()))
    objects, preimages, inputs, content = [], [], [], b""
    for m, data, fact in members:
        identity = nfc(m["key"]) + "\0" + nfc(m.get("version_id", m["etag"]))
        digest = sha(data)
        preimage = nfc("object\0s3_listing\0" + bucket + "\0" + identity + "\0" + digest).encode()
        content += struct.pack(">Q", len(identity.encode())) + identity.encode() + struct.pack(">Q", len(data)) + bytes.fromhex(digest)
        fact["object_id"] = mac(preimage.decode())
        objects.append(fact)
        preimages.append(preimage.hex())
        inputs.append({"identity": identity, "ordering_key_hex": identity.encode().hex(), "source_hex": data.hex(), "sha256": digest})
    objects.sort(key=lambda o: o["object_id"])
    coverage = {"objects_discovered": len(members), "objects_scanned": len(members), "objects_skipped_by_reason": {}, "skipped": []}
    fp = {"coverage": coverage, "objects": objects, "depth_class": "complete_standard_v1", "row_count_algorithm_version": "exact-v1", "distinct_algorithm_version": "hll-sha256-v1", "histogram_version": "fixed-buckets-v1", "numeric_bucket_version": "fixed-buckets-v1", "canonicalization_version": "python-json-sort-compact-v1"}
    locator_preimage = nfc("s3_listing\0" + bucket + "\0" + snapshot_hash).encode()
    facts = {"coverage": coverage, "objects": objects, "fingerprint_hash": sha(canon(fp)), "content_sha256": sha(content), "artifact_locator_commitment": mac(locator_preimage.decode())}
    receipt = {"spec_hash": "a" * 64, "nonce_echo": b64(bytes([1]) * 32), "install_key_id": "77777777-7777-4777-8777-777777777777", "artifact_locator_commitment": facts["artifact_locator_commitment"], "content_sha256": facts["content_sha256"], "started_at_utc": "2026-08-21T10:05:00Z", "completed_at_utc": "2026-08-21T10:05:01Z", "duration_ms": 1000, "coverage": coverage, "fingerprint_hash": facts["fingerprint_hash"]}
    v = {"label": "TEST ONLY - S1791 Chunk 2a S3 vector", "oracle_source_pin": manifest["source_pin"], "test_only_commitment_key_hex": KEY.hex(), "test_only_scan_seed_hex": SEED.hex(), "test_only_receipt_seed_hex": RECEIPT_SEED.hex(), "snapshot": payload, "snapshot_canonical": snapshot.decode(), "snapshot_sha256": snapshot_hash, "snapshot_claims": claims, "snapshot_jws": token, "members": inputs, "object_preimages_hex": preimages, "locator_preimage_hex": locator_preimage.hex(), "content_preimage_hex": content.hex(), "facts": facts, "facts_canonical": canon(facts).decode(), "receipt_canonical": canon(receipt).decode(), "receipt_signature": base64.b64encode(Ed25519PrivateKey.from_private_bytes(RECEIPT_SEED).sign(canon(receipt))).decode(), "digest_modes": ["absent", "present"], "expected_verdict": "valid"}
    if name == "s1590_csv":
        spec = json.loads((ROOT / "verification/testdata/s1590/scan_spec.json").read_text())
        v["seed_hex"] = spec["payload"]["deterministic_seed"]
    (OUT / (name + ".json")).write_bytes(canon(v) + b"\n")

refusals = [
    {"name": "empty_members", "members": []},
    {"name": "empty_key", "members": [{"key": "", "etag": "pin"}]},
    {"name": "empty_pin", "members": [{"key": "a.csv", "etag": ""}]},
    {"name": "nul_key", "members": [{"key": "a\0.csv", "etag": "pin"}]},
    {"name": "nul_pin", "members": [{"key": "a.csv", "etag": "p\0in"}]},
    {"name": "duplicate", "members": [{"key": "a.csv", "etag": "pin"}] * 2},
    {"name": "nfc_collision", "members": [{"key": "é.csv", "etag": "pin"}, {"key": "e\u0301.csv", "etag": "pin"}]},
    {"name": "pin_nfc_collision", "members": [{"key": "a.csv", "version_id": "é"}, {"key": "a.csv", "version_id": "e\u0301"}]},
    {"name": "wrong_order", "members": [{"key": "z.csv", "etag": "pin"}, {"key": "a.csv", "etag": "pin"}]},
]
(OUT / "refusals.json").write_bytes(canon({"label": "TEST ONLY", "cases": refusals, "expected_verdict": "artifact_changed_before_open"}) + b"\n")
