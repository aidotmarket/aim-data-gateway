# Cloudflare verifier (S1791 Chunk 3b)

This adapter runs optional complete probes and paid scans in the seller's
Cloudflare account. It uses the shared gateway scanner and the shipped 3a R2
reader. The marketplace receives control envelopes, aggregates, findings and
receipts, never cells or R2 access credentials. This subchunk supplies build
inputs and offline tests. It does not establish a published Cloudflare release,
website integration or real-account Gate 4 acceptance.

Authority: runbooks `4e07cee955f2227a884ac5ca77fd0a814c414f08`,
`specs/BQ-DATA-VERIFICATION-EVERYWHERE-S1791-GATE2-CHUNK3-CLOUDFLARE.md`
§1–§9 and §11. AWS registration, signed work, report encoding, scanner policy,
key rotation and ISRG transport are mirrored without importing AWS/Lambda SDKs.
The gateway dependency graph and shared scanner are unchanged.

## Seller deployment

Use the release-specific Deploy to Cloudflare button provided by the website.
It copies a frozen public repository into the seller's GitHub/GitLab account.
Workers Paid and a source-control account are required. Workers Builds builds
the committed static linux/amd64 binary with the scratch Dockerfile; it does
not compile Go. `worker.mjs` bundles Container SDK 0.3.7 and preserves the
`ContainerProxy` export. Wrangler uploads it with `no_bundle=true`.

The setup integration must substitute the seller's existing listed R2 bucket,
confirmed `default` jurisdiction, connection UUID, frozen exact keys/prefix,
and cataloged release identities into `wrangler.jsonc`. The configuration
contains a deliberately unusable placeholder bucket and empty connection;
deploying this unconfigured tree cannot register or read data. Do not accept
an automatically created empty bucket as setup. Scope is limited to 17,033
retained exact keys and 1 MiB canonical configuration. A newly published key
outside installed scope requires an explicit seller configuration update.
The button's existing-bucket selection/config injection is a 3c/3d integration
and Q1 real-account proof, not a capability established by this artifact alone.

Cloudflare's secret prompt installs `REGISTRATION_TOKEN` and `RUN_NOW_SECRET`.
The registration token is copied from the private setup page. The seller
generates a 32-byte random base64url run-now secret and keeps it privately;
ai.market never receives it. Secrets must not enter vars, source control,
URLs, logs or marketplace telemetry. An expired setup token is replaced through
the seller's setup page and Cloudflare secret prompt; the exact durable request
remains bound to its original token. Changed-request retries require fresh setup.

After deployment, open the seller-owned Worker at `/operator`, enter the
run-now secret and select **Run now**. The page retains no browser state.
Authenticated `POST /operator/run-now` accepts only the exact body `{}` and
returns 202 after scheduling. Both it and cron enqueue the same `schedule()`
task. No custom `alarm()` exists. Wakes coalesce and are limited to one/minute.
Cron defaults to every minute; `*/5 * * * *` or `*/15 * * * *` are alternatives.
Scheduled checks are a best-effort backstop: they have no delivery guarantee.
Ready requires registration and a successful poll, not a deployment click.

## Durable state and read boundary

One connection-named Container Durable Object owns SQLite state. The first
start transaction creates a 32-byte wrapping key and initialization marker.
The Container generates independent Ed25519 and commitment keys; the exact
registration request is AES-256-GCM encrypted before sending. Its signed ack
and scan-key pins are saved before work. Each encrypted save has a fresh nonce
and connection/state-version AAD. Ciphertext and wrapping key are co-resident,
not separate key-store isolation. Missing/corrupt custody state refuses; it
never silently generates replacement keys or resets replay history.

Signed work and snapshots are verified by Go before a transaction inserts the
spec, unique nonce/authorization, UTC acceptance-day listing counter, clock
high-water and audit event. Ten probes/scans per listing/day are allowed across
versions; the eleventh refuses. Backward clock movement exceeding 300 seconds
refuses. No source HEAD/GET precedes durable admission. Thirty-day replay/audit
retention never prunes unresolved admissions/outbox. Same signed work returns
saved status without incrementing quota or reopening source data.

The private HTTP host `r2-bridge.internal:80` is intercepted by `outboundByHost`.
Its signed HMAC capability binds connection, spec hash, DO/container identity,
invocation start, expiry and random nonce. Only a member index selects an object
in the admitted snapshot. HEAD checks size/ETag; every GET/range uses R2 `onlyIf`
and checks metadata/body/range. There are no list/write/delete routes. Streaming
keeps bytes inside the seller account; Parquet uses 4 MiB bounded read-ahead.
The binding itself is bucket-capable: restrictions are enforced by this code.

The Container has internet enabled, with no allowed-host override or HTTPS
interception. Its default marketplace client dials only `api.ai.market:443`,
rejects redirects and verifies chains against the embedded shipped AWS ISRG
roots/SPKI pins. The private bridge uses a separate HTTP client. Worker control
fetches use fixed HTTPS, reject redirects and normal platform TLS; **Worker
SPKI pinning is not implemented or claimed** (Q4). Seller-modified code can
reach other internet hosts; hashes/receipts are not external attestation.

The alarm awaits the private Container HTTP invocation. Go's deadline is
start+780 seconds, including bootstrap/poll elapsed time, reduced by the
remaining invocation budget with terminal persistence time reserved. The DO
lease coalesces retries until 900+120 seconds; interrupted consumed work is
never scanned again. Stale running or queued task markers become reclaimable
after that grace; an early SDK alarm retry schedules recovery just beyond lease
expiry before its one-shot schedule is deleted. Recovery precedes every new poll.
Signed snapshot tokens and expanded members are stored together in ASCII JSON
chunks of at most 512 KiB, in the admission transaction. A descriptor binds their
count, byte length and SHA-256; missing or corrupt chunks refuse reads. Settlement
deletes these chunks while retaining replay/consent metadata for thirty days;
retention pruning also removes orphan chunks. Existing v1 custody migrates to
v2 atomically without resetting keys, quota, leases or consent.
Complete signed report bytes are transactionally chunked
at 128 KiB before send. Every task resends committed outbox before polling,
with identical report bytes and fresh HTTP nonce. Exact backend ack settles
the row. First pickup+1,920 seconds is the terminal deadline, unchanged by
retries; late work cannot reopen consent. Interruptions without an outbox
become a terminal scanner failure (probe interruption settles locally).
Container SIGTERM cancels active requests; an uncommitted result relies on DO
and backend recovery. Tasks stop compute at the end; `sleepAfter=20m` is a
backstop. Empty polls use Worker/DO only, after first-start bootstrap.

## Build and release

Install exact lockfile dependencies in `deploy/cloudflare-verifier` with
`npm ci`, then run `npm run types`, `npm test` and `npm run build`.
Generate binding declarations with
`npx wrangler types --env-interface RuntimeEnv --include-runtime false`.
Go checks: `go test ./internal/cloudflareverification ./cmd/aim-cloudflare-verifier`,
focused race tests, gateway/AWS/shared scanner regressions, vector digests,
module/line budgets and `git diff --check`.

Run `python3 scripts/cloudflare-verifier-release.py --version 0.1.0`.
It compiles twice with separate caches, CGO disabled, linux/amd64, trimpath,
empty build ID and embedded release/version. It bundles twice with the locked
esbuild/SDK and compares bytes. Go build is offline (`GOPROXY=off`); fetch
dependencies beforehand. `--verify-committed` also compares the tracked binary
and bundle. After a source change, copy `dist/cloudflare-verifier/worker.mjs`
and `dist/cloudflare-verifier/aim-cloudflare-verifier` into
`deploy/cloudflare-verifier/`, then rerun the release command with
`--verify-committed` before committing those artifacts. The binary computes its executable SHA-256 at runtime. Worker
identity is deployment metadata, never embedded in its own hashed module.

The export includes a deterministic local release-template commit/tree,
canonical path-to-SHA-256 manifest, template tar/Git bundle, rebuild source archive, build record and exact §4.1
`default` catalog entry. URLs name a prospective public repository per release.
**The catalog is a candidate**; no external repository is created and no
backend catalog is enabled. `bundle` is the preferred artifact identity mode;
actual no-bundle upload equality remains unmeasured. If real Workers Builds
changes module bytes, explicitly amend/release `source_tree_lockfile` mode
with a documented canonical manifest/toolchain; never silently fall back.

The release workflow builds, tests, signs with GitHub OIDC Cosign, produces
binary/Worker SBOMs and publishes artifacts only. It emits the template tree/tar for a later
authorized immutable-repository export. It grants no seller account/provider
credentials. Run-now/operator secrets never enter the workflow. Tag signing
uses the exact Cloudflare workflow identity and verifies each bundle.

## Updates, removal and outstanding proof

Same-release configuration/schedule redeploys preserve DO identity/keys/ledger.
New versions use a new button and explicit replacement/fresh setup, then remove
the old deployment after evidence export. Mixed Worker/Container identity
refuses. Catalog withdrawal stops setup; allowlist retirement stops new work
while backend deadlines settle/void holds and retain historical evidence.
Never restore ledger PITR with active keys: revoke and create a fresh runner.

Remove verifier in the marketplace, export private audit evidence, then delete
seller Worker/Container/DO state to stop resource costs. R2 data and marketplace
delivery remain unchanged. Workers Paid has a base subscription, and Container,
Worker/DO/R2 reads can add costs; probes also traverse the complete source.

Outstanding spec questions/deviations for this subchunk:

- Q1: two-account full button setup, existing bucket/scope injection, copied
  release-byte comparison, deployed no-bundle equality, two seller-built OCI
  digest measurements, registration/poll/probe and update/retirement smoke.
  These are not inferred from the local artifact; OCI digest is nullable
  observed metadata and never an allowlist selector.
- Q3: actual 780-second alarm/Container/bridge lifetime, lifecycle coexistence,
  sleep/eviction/SIGTERM and 15-minute recovery; standard-2 text/20/400-group
  benchmarks, 256 KiB/4 MiB comparison, CPU/subrequests/backpressure and the
  near-17,033-member read-path limit. Local storage tests do not prove these.
- Q4: Worker-origin HTTPS has no SPKI pin API implemented. A normal-WebPKI
  amendment or supported pinning proof remains required. Q4b's settled internet
  policy is implemented; real internet-enabled private bridge proof is deferred.
- Q5/Q6: only default jurisdiction is admitted; residency and provider read
  attribution remain real-account evidence. No account IDs/secrets are shipped.
- Local test tooling pins Vitest 4.1.11/pool 0.22.0. Its workerd only supports
  compatibility dates through 2026-08-22, used by offline tests; production
  template retains 2026-10-06. Local tests exercise real SQLite/R2 bindings and
  SDK entrypoints via isolated storage plus mocked lifecycle/HTTP calls, without
  Docker, live TLS or external networking. They do not establish Container
  platform execution semantics. Runtime dependencies remain SDK 0.3.7 only;
  patched sharp/undici tooling overrides are pinned in the lockfile.
- The DO wrapping key is saved before Container-generated signing state. A
  crash during that initial generation is intentionally an unrecoverable
  partial first-start and requires explicit replacement, rather than rekeying.
- Unknown HTTP registration/ack field details in the yet-unshipped 3c backend
  are mirrored from AWS with the specified identity deltas. Contract integration
  must use the exact signed ack schema in this adapter, not weaken validation.

Real-account tests, external template-repository creation, deployment, backend
enablement and Gate 4 are outside this build's authority. Preserve candidate
artifacts and facts; do not advertise a ready Cloudflare release from unit tests.
