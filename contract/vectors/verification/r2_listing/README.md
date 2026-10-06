# R2 listing vectors (S1791 Chunk 3a)

Authority: runbooks commit `4e07cee955f2227a884ac5ca77fd0a814c414f08`,
`specs/BQ-DATA-VERIFICATION-EVERYWHERE-S1791-GATE2-CHUNK3-CLOUDFLARE.md` §4.3.
All keys, bytes, IDs and signing seeds here are synthetic test fixtures.

Generate with `python3 scripts/generate-r2-verification-vectors.py` (Python
`cryptography` required), then `python3 scripts/check-vector-digest.py --update`.
The local `VECTORS.sha256` covers every JSON file; the repository manifest also
covers these files while retaining the gateway/AWS vector hashes unchanged.

Source vectors reuse the pinned Python aggregate oracle and S1590 facts.
Commitments and content framing are computed independently in Python. Both
digest-present and first-pass digest modes must produce the same canonical facts.
`bridge_cases.json` supplies executable missing/precondition/metadata/range/retry
and same-ETag mutation scenarios. `control.json` freezes linked signed work,
HTTP authentication, probe/report/terminal documents and digest companions for
3b/3c; it does not implement their transport or admission state machine.

The injected Go `Bridge` is private to the invocation. 3b binds its capability to
the durably admitted snapshot and connection/spec, verifies the member index and
raw names, and performs only HEAD/conditional GET. Request `IfMatch` is the raw
unquoted ETag. GET metadata contains total object size and raw ETag; range
metadata contains the exact returned offset/length. Missing metadata or a missing
body refuses. Every transport retry preserves the pin and range. The bridge must
honor context cancellation and make body Close interrupt concurrent Read.

No Worker, deployment, backend copy, network client or release is part of 3a.
