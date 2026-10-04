# S1791 cloud runner measurement spikes — NEVER MERGE

This branch is a disposable measurement harness for Gate 1 §12 S-AWS / S-R2.
Vulcan owns deployment and seller-account runs. No cloud APIs, pushes of images,
or deployments were performed during implementation. Public package downloads,
public base-image pulls, local Docker runs and Wrangler **dry runs** are build checks.
Every source change is under `spikes/`. This is a separate Go module with
`replace github.com/aidotmarket/aim-data-gateway => ../`; the gateway module,
scanner, dependencies, CI and `scripts/count-lines.py` are untouched.

Design read: `/Users/max/Projects/ai-market/runbooks/specs/BQ-DATA-VERIFICATION-EVERYWHERE-S1791-GATE1.md`
(R5), especially E6 and §§6.1–6.3 / 12. These instructions are the spike's runbook.
The native adapters call the public `verification.Scan` / `Probe` unchanged;
`harness.Policy` copies all constants from `internal/verification/runner.go:357`.
The deterministic aggregate seed is zero and fixed, shared across adapters.

## Build and fixtures (offline)

From `spikes/` (Go 1.27.1; RTK required):

```sh
rtk proxy go build ./...
rtk proxy go vet ./...
rtk proxy go test ./...
rtk proxy mkdir -p artifacts/fixtures
rtk proxy go run ./fixtures -format csv -bytes 50000000 -seed 1791 -out artifacts/fixtures/synthetic.csv
rtk proxy go run ./fixtures -format parquet -rows 200000 -seed 1791 -out artifacts/fixtures/synthetic.parquet
```

CSV is exactly the requested byte count (minimum 128 bytes), extending the final
string field to finish a valid row. Both formats contain integer, float, string,
date and boolean columns with deterministic seed 1791. Parquet uses Arrow Go v18,
Snappy, 64 KiB pages and up to 50,000 rows per row group (four groups at 200k).
Only generated synthetic data is used. Generated files/binaries are ignored.

## AWS Lambda harness

Event shape (same for R2 container):

```json
{"mode":"scan","bucket":"synthetic-bucket","objects":[{"key":"spike/synthetic.csv","etag":"\"provider-etag\"","format":"csv"}]}
```

Modes: `throughput` streams each object into SHA-256 exactly once; `scan` computes
member SHA-256 in a streamed pre-pass then calls Scan; `probe` makes the same
pre-pass then calls Probe. Today's Probe internally performs a full Scan.
Supported native formats are csv, tsv, jsonl and parquet; use exact format names.
Every key must be under `spike/`. Scope is the event's explicit objects; no List API
or prefix discovery. If `version_id` is present it is used on HEAD and every GET /
range; otherwise the event ETag is used for HEAD and every GET / range. If neither
pin is supplied, HEAD discovers an ETag that is retained for all following reads.
For mutation experiments supply the expected pin explicitly. HEAD size and returned
pin are checked; a mismatch ends without a facts digest. A single invocation is
sequential. `RandomAccess` has one 256 KiB read-ahead cache, counting range requests
and the bytes actually consumed from all response bodies. SDK retries are disabled
(one attempt), so the range-call counter also counts transport attempts. Repeated disjoint Parquet
reads may fetch more than a full pass. No cell values or facts are emitted.

Output: `prepass` and `execution` wall seconds, bytes read, range requests and
**decimal physical MB/s** (response-body bytes / elapsed seconds); process VmHWM
RSS bytes, RSS availability, end-of-invocation Go MemStats Sys / HeapInuse,
remaining context-deadline seconds (null for no deadline), error string, and
SHA-256 of canonical Facts or ProbeResult. Throughput returns member stream hashes
and has an empty execution phase. HEAD and pre-pass hashing are both in `prepass`.
Peak RSS is process lifetime, including earlier warm invocations; Go memory numbers
are final samples, not peaks. Error strings stay in the seller measurement logs;
this is not a marketplace report protocol. No raw facts are returned on failure.
Each native invocation generates a random HMAC-SHA256 key, never stored or emitted;
canonical facts digests therefore differ between invocations even with identical
bytes. Parity tests explicitly share one fixed synthetic key and compare full
canonical facts, including commitments and fingerprints.

Typed HMAC preimages are Gate 1 §6.2:
`kind\0bucket\0manifest_hash` and
`object\0kind\0bucket\0key\0(version_id or ETag)\0sha256_hex`.
Kinds are `s3_listing` and `r2_listing`. NUL-containing / non-NFC event bindings are
refused. The measurement manifest hashes canonical JSON of the sorted resolved
provider/bucket/key/pin/size entries, not a signed marketplace source snapshot.

**Scanner compatibility finding:** the scanner requires 32 lowercase hex identity
characters and known member SHA-256. The adapter uses the first 128 bits of
SHA-256(key + NUL + pin) as its internal member identity, detects duplicates and
sorts those IDs. Typed object commitments still use the real key/pin. Consequently
the scanner's `content_sha256` uses these synthetic IDs and their order, and is
**not** the cloud canonical-member content commitment specified in §6.2. This
harness must not become a production adapter without resolving that contract.
Cloud scan conceptually reads data three times: hash pre-pass, scanner prepare,
scanner aggregate traversal. The scanner package has not been patched.

Static binary check, from `spikes/`:

```sh
rtk proxy env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o artifacts/bootstrap ./aws-lambda
```

From repository root:

```sh
rtk proxy docker build --platform linux/arm64 --provenance=false -f spikes/aws-lambda/Dockerfile -t s1791-lambda-spike:local .
rtk proxy docker build --platform linux/amd64 -f spikes/r2-container/Dockerfile -t s1791-r2-container-spike:local .
```

### Operator-only AWS deployment / invocation / teardown

Do not execute these during an offline build. In a dedicated spike account,
Vulcan sets `AWS_PROFILE`, `REGION`, `BUCKET`, `MEMORY_MB`, `FUNCTION` (58 characters
maximum, to fit IAM role names). Then, from `spikes/`:

```sh
rtk proxy bash aws-lambda/deploy.sh
rtk proxy bash aws-lambda/invoke.sh aws-lambda/event.example.json
rtk proxy bash aws-lambda/teardown.sh
```

Replace the event's bucket, object and pin first. Upload only synthetic fixtures
under `spike/` using the operator's AWS CLI. Deploy creates/updates dedicated
`${FUNCTION}-spike` ECR / IAM resources and `/aws/lambda/$FUNCTION` log group,
builds/pushes a single arm64 image (provenance disabled for Lambda image
compatibility), and sets timeout 900 and requested memory. Re-running updates
rather than duplicates. Unexpected credential/permission errors do not masquerade
as missing resources. IAM role propagation gets a bounded retry. Teardown removes
the function, its inline policy and role, ECR repository including images, and log
group; it does **not** delete the bucket or fixtures. AWS provisioning uses only
the AWS CLI; no Terraform, CloudFormation or SDK provisioning calls.

Execution permissions are only `s3:GetObject` / `s3:GetObjectVersion` on
`arn:aws:s3:::$BUCKET/spike/*` (these also authorize HEAD), and
`logs:CreateLogStream` / `logs:PutLogEvents` on that function's log streams.
Log group creation is an operator action, not execution permission. No List,
write, Secrets Manager, KMS decrypt or DynamoDB access is added. Use SSE-S3 / no
customer KMS encryption for this measurement. IAM/ECR/Lambda/operator privileges
are separate from the execution role. Use unique dedicated resource names; these
scripts are not intended to reconcile unrelated roles or functions.

## Offline native measurement and parity

`cloud/source_test.go` uses a **local file-backed fake** implementing the same
S3 SDK HeadObject/GetObject interface used by Lambda, with ranged file reads.
It checks complete Scan and full byte equality with an independent in-memory
Source, both with the same scanner policy / commitment key. Other tests cover
version/ETag retention, read-ahead count, range mutation refusal, scope, throughput,
probe and cancellation. No credentials / HTTP client / cloud APIs are involved.

Small fixtures run by default. Large fixture test on macOS:

```sh
rtk proxy env SPIKE_LARGE=1 SPIKE_EXISTING=1 SPIKE_FIXTURE_DIR=artifacts/fixtures go test -v ./cloud -run TestLocalFixtures
```

macOS has no `/proc/self/status`; it honestly reports `rss_available:false`.
For Linux VmHWM, build a static test binary from `spikes/`:

```sh
rtk proxy mkdir -p artifacts/tmp
rtk proxy env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o artifacts/cloud.test ./cloud
```

Then, from repository root, substitute its absolute path for `/ABS/CHECKOUT`:

```sh
rtk proxy docker run --rm --network none --platform linux/arm64 --entrypoint /work/spikes/artifacts/cloud.test -v /ABS/CHECKOUT:/work -e TMPDIR=/work/spikes/artifacts/tmp -e SPIKE_LARGE=1 -e SPIKE_EXISTING=1 -e SPIKE_FIXTURE_DIR=/work/spikes/artifacts/fixtures -e SPIKE_RESULTS_DIR=/work/spikes/results s1791-lambda-spike:local -test.run '^TestLocalFixtures/csv$' -test.v
```

Repeat with `^TestLocalFixtures/parquet$` in a **fresh** container. Setting
`SPIKE_EXISTING=1` separates fixture generation from RSS measurement. Metrics are
sampled immediately after the first measured scan, before reading the fixture
into memory for the parity oracle; the repeat Scan and in-memory oracle occur
later. Results are JSON under `results/`. These are local file / Docker-VM results,
not S3/R2 network throughput, Lambda CPU allocation or cold-start measurements.

## R2 WASM candidate

From `spikes/r2-wasm/`:

```sh
rtk proxy make js
rtk proxy make wasi
```

Each prints raw / gzip sizes. `js` copies the exact Go toolchain's `wasm_exec.js`
into ignored `dist/`. The main package scans an in-memory Source without SDK cloud
imports; the js build exports `spikeScan(Uint8Array, format)` returning a digest or
error JSON. Native / WASI main reads a fixture from stdin and prints the same output.
The in-memory SHA-256 is computed up front, as the scanner requires. This simplified
WASM adapter uses a synthetic fixed commitment key and source binding; it is a
compilation / memory feasibility experiment, not a cloud commitment implementation.

Offline Node smoke test, from `spikes/`:

```sh
rtk proxy node r2-wasm/test-node.mjs artifacts/fixtures/synthetic.parquet parquet
```

`worker.mjs` instantiates the js/wasm module through `wasm_exec.js`, retains one Go
runtime per isolate, and calls that exported scan over a fetched R2 object body.
It illustrates a single pinned-ETag object per cron run, caps buffering at 50 MB,
and has a Ledger DO. It buffers the R2 object and copies it into Go memory, so
memory / CPU feasibility still needs a real account test. WASI has no Workers host
adapter here. Both targets compiled successfully; there is no compile error to
record. Detailed sizes and checks are in [results/README.md](results/README.md).

## R2 Container candidate

Go HTTP server listens on port 8080 and accepts the same event JSON at `POST /`.
It uses the same native harness with kind `r2_listing`, reading R2 via S3-compatible
API. `R2_ENDPOINT`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` are required env vars;
region is `auto`, path-style addressing enabled. Work is single-flight (busy = 429),
with a 15-minute context deadline and bounded event body. Docker binary is static
linux/amd64. For a local operator run, pass env vars via `docker run --env-file`
using a private ignored file. Such an R2 run is **not** an offline check.

`index.ts` uses `@cloudflare/containers` Container, one named instance, port 8080,
2-minute sleepAfter, `max_instances:1`, requested `instance_type:"standard"`.
Wrangler 4.147.0 warns that `standard` is deprecated / renamed `standard-1`; the
requested spelling is retained. Worker cron admits signed fixture work through
Ledger, then POSTs only the bound event to the container and logs its digest /
metrics. Both Workers return 404 for public HTTP requests; no external invoke
endpoint is provided. This is a measurement cron over a configured fixture;
production scheduled marketplace pull / key rotation / receipt signing is absent.

From `spikes/` for local type / bundle checks (no cloud writes):

```sh
rtk proxy npm ci --ignore-scripts
rtk proxy env WRANGLER_SEND_METRICS=false WRANGLER_LOG_PATH=./artifacts/types.log XDG_CONFIG_HOME=./artifacts/config ./node_modules/.bin/wrangler types --config r2-container/wrangler.jsonc r2-container/worker-configuration.d.ts --include-runtime false
rtk proxy ./node_modules/.bin/tsc --noEmit
rtk proxy node ledger/test.mjs
rtk proxy env WRANGLER_SEND_METRICS=false WRANGLER_LOG_PATH=./artifacts/wasm-dry.log XDG_CONFIG_HOME=./artifacts/config ./node_modules/.bin/wrangler deploy --dry-run --config r2-wasm/wrangler.jsonc --outdir artifacts/wasm-worker
rtk proxy env WRANGLER_SEND_METRICS=false WRANGLER_LOG_PATH=./artifacts/container-dry.log XDG_CONFIG_HOME=./artifacts/config ./node_modules/.bin/wrangler deploy --dry-run --config r2-container/wrangler.jsonc --outdir artifacts/container-worker
```

Only Vulcan may run the actual cloud secret / deploy commands, after replacing
placeholder bucket / endpoint and binding configuration. No secrets were set here:

```sh
rtk proxy ./node_modules/.bin/wrangler secret put R2_ACCESS_KEY_ID --config r2-container/wrangler.jsonc
rtk proxy ./node_modules/.bin/wrangler secret put R2_SECRET_ACCESS_KEY --config r2-container/wrangler.jsonc
rtk proxy ./node_modules/.bin/wrangler secret put SPIKE_SPEC_JSON --config r2-container/wrangler.jsonc
```

WASM uses its R2 binding and needs no S3 credentials. Set its `SPIKE_SPEC_JSON`
secret with the same CLI and its own config. Bucket access, secret storage,
container startup, cron execution and actual R2 throughput remain Vulcan's tests.

## Illustrative E6 Ledger (shared)

The cron's configured fixture envelope is `{payload_b64,signature_b64}`. Ed25519
verification uses a public key configured as `SPIKE_SPEC_PUBLIC_KEY_B64`; empty
configuration refuses work. Signed payload contains listing id/version, nonce,
owner authorization id, accepted / issued UTC timestamps, and bound harness event.
Both workers use the same DO name per runner. One SQLite storage transaction checks
and records nonce + authorization uniqueness and increments the per-listing UTC-day
counter, rejecting the eleventh spec. Freshness is 24 hours with up to 5 minutes
future skew; authorizations must be present and fresh. State is retained for 30 days
and lazily pruned. Storage errors refuse before any object reads. Log phases are
received / accepted / refused, without fixture data. This is an illustrative fixture
protocol, not the frozen marketplace token / source-snapshot implementation.

`ledger/test.mjs` runs real **local** workerd and SQLite storage, including signature,
missing authorization, wrong version, expiration, nonce/auth replay, two concurrent
requests, tenth/eleventh limits and persistence across a fresh runtime. Its signing
keys exist only in process memory. The test-only fetch entrypoint is not imported
by either deployed Worker. For an operator's fresh synthetic signed envelope:

```sh
rtk proxy node ledger/sign-fixture.mjs aws-lambda/event.example.json > artifacts/signed-fixture.json
```

The output contains `public_key_b64` to set in config and `envelope` to set as the
`SPIKE_SPEC_JSON` secret. It does not output the private key. A repeating cron
using the same fixture is correctly refused after the first acceptance; refresh
with a newly signed nonce/authorization for another measurement.

## Questions for Vulcan from Gate 1 §12

| Spike | Offline evidence | Still requires seller-account evidence |
| --- | --- | --- |
| S-AWS | One unchanged complete-or-refuse Scan per invocation; phase / bytes / ranges / memory instrumentation; 900-second deploy config | Lambda cold/warm start, memory/CPU matrix, S3 throughput and costs; deadline refusal under 15 minutes; supported source-size boundary or a separately designed deterministic multi-invocation merge; strict §5.4 network profile cost |
| S-R2 WASM | js and WASI compile and sizes; Node scan smoke; local Worker bundle; DO replay/atomicity checks | Worker startup, CPU/memory, largest completely traversable fixture, actual cron / R2 pin semantics / secrets; marketplace TLS pinning and egress restrictions |
| S-R2 Container | linux/amd64 image and Worker bundle; shared ranged harness; local Ledger tests | Cold start, container CPU/memory matrix, object-size boundary, R2 request amplification and cost, actual cron / secrets; TLS pinning and egress restrictions |

No production packaging choice, largest supported source size, cloud price,
15-minute Lambda completion guarantee or strict egress enforcement is claimed.
No multi-invocation traversal is implemented. Lambda has no production E6 ledger
or signed work exchange in this measurement-only harness. Fixture equality does
not establish the S1590 golden oracle or cross-provider production provenance.

References: [Cloudflare Wasm](https://developers.cloudflare.com/workers/runtime-apis/webassembly/),
[Container class](https://developers.cloudflare.com/containers/api/container-class/),
[instance types](https://developers.cloudflare.com/containers/platform/limits/),
[DO storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/).
