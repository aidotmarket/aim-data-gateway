# Local findings — 2026-10-04

Base gateway: `b447e13c7f47ab728d7d9c88cb2f309a748cd34c`.
Go 1.27.1, macOS arm64 host (T6031), Docker Desktop Linux arm64 VM.
These are single-run local file-backed S3 fake measurements in fresh,
network-disabled Lambda-base containers, with synthetic fixtures generated
before measurement. No cloud data, credentials, deployment or APIs were used.
System build activity was present; these are exploratory numbers, not a controlled
benchmark or a cloud performance promise. RSS is measured before parity-oracle
allocation. Scanner budgets are the gateway defaults (128 MiB scanner budget,
16 MiB record/scalar, 1000 columns, 32768-byte facts, 30-minute scanner deadline).

| Fixture | File bytes | Rows | SHA pre-pass seconds | Scan seconds | Scan physical MB/s | VmHWM MB | Scan bytes read | Range GETs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| csv | 50,000,000 | 965,720 | 0.042980 | 1.707791 | 58.56 | 19.88 | 100,000,000 | 0 |
| parquet | 4,438,749 | 200,000 | 0.004207 | 0.558861 | 23.91 | 24.48 | 13,364,084 | 35 |

Both scans succeeded and full canonical facts were byte-identical to scanning
those same bytes through an in-memory Source with identical policy / commitments.
Exact measured JSON is in [csv.json](csv.json) and [parquet.json](parquet.json).
The reported invocation digest uses a random HMAC key; it is not a stable fixture
checksum. Go Sys / HeapInuse samples and repeat-scan timings are in those JSON files.
Physical MB/s divides all phase response-body bytes by wall time. Logical input
MB/s differs (50 / CSV scan seconds; 4.438749 / Parquet scan seconds).

CSV: pre-pass + two scanner traversals = 150,000,000 bytes total. Parquet:
4,438,749 pre-pass + 13,364,084 scanner bytes = 17,802,833 bytes, about 4.01x
file size due to verified random reads / 256 KiB read-ahead overlap. Scanner needs
member SHA-256 up front: the cloud pre-pass is additional to its own two-pass work.

## WASM build findings

Both targets compiled unmodified scanner + Arrow dependencies successfully:

| Target | Raw bytes | gzip -n bytes |
| --- | ---: | ---: |
| GOOS=js GOARCH=wasm | 39,340,479 | 6,538,771 |
| GOOS=wasip1 GOARCH=wasm | 39,272,996 | 6,535,225 |

Commands: `rtk proxy make js`, `rtk proxy make wasi` in `r2-wasm/` (default
Go build flags plus `-trimpath`; compression `gzip -n`). No compile errors.
Node js/wasm smoke scanned the generated 200k-row Parquet successfully; its
synthetic binding digest was `dac947752ac66dabc464307f40ac4e1af9c7ceb07f479aca35e36e28f3c599b4`.
This does not prove Workers memory / CPU / startup feasibility or WASI hosting.

## Offline validation

- `go build ./...`, `go vet ./...`, `go test ./...` inside the isolated module.
- Large file-backed / in-memory canonical fact parity, complete rows, retained
  ETag and VersionId across ranges, cache count, mutation failure and cancellation.
- Docker builds: Lambda linux/arm64, R2 container linux/amd64; both static Go builds
  (`CGO_ENABLED=0`). No image pushes. Docker build uses public registry pulls.
- Shell syntax checks on deploy / invoke / teardown / shared AWS helper.
- Generated Wrangler binding types and TypeScript noEmit check.
- Real local workerd + SQLite Ledger tests: signature, missing authorization,
  wrong version, expiry, replay, concurrent duplicate, tenth/eleventh daily cap,
  persistence after runtime restart.
- Both Wrangler **dry-run** bundles completed, without deployment. WASM bundle
  reported 38,443.67 KiB / gzip 6,391.89 KiB; container Worker 57.59 KiB / gzip
  14.54 KiB. Wrangler 4.147.0 warned `standard` is renamed `standard-1`; retained
  `standard` as requested. Dry-run is packaging validation, not a runtime proof.

## Open design findings for Vulcan

1. Scanner member IDs must be 32 hex chars. Cloud IDs are adapted to deterministic
   synthetic IDs; this changes `content_sha256` framing/order from Gate 1's cloud
   identity contract. Typed HMAC object/locator preimages use the real key/pin.
2. The SHA pre-pass adds a full object read. Parquet verified read-ahead can exceed
   three full reads in bytes and adds range request costs.
3. Probe runs a full Scan internally; it has similar traversal costs.
4. WASM bundles are large and whole-object buffering duplicates memory across JS
   and Go; real Workers startup, CPU / memory and largest supported size are open.
5. S-AWS 900-second budget, cloud CPU / memory / price, multi-invocation merge vs
   source-size refusal, strict network costs, marketplace TLS pinning and actual
   scheduled pull are not answered by offline tests. This branch implements no
   production cloud runner and must never merge.
