# Cloudflare verifier (S1791 Chunk 3b)

> **Scope of this document:** the technical notes and outstanding questions below record the original Chunk 3b build. Statements about an unshipped backend or unpublished release describe that build stage, not current availability. For published releases, catalog activation, current operator procedures and remaining real-account evidence, use the [gateway operations guide](https://github.com/aidotmarket/runbooks/blob/main/aim-data-gateway.md). A published artifact still does not prove a seller deployment upgraded or completed acceptance.

This adapter runs optional complete probes and paid scans in the seller's
Cloudflare account. It uses the shared gateway scanner and the shipped 3a R2
reader. The marketplace receives control envelopes, aggregates, findings and
receipts, never cells or R2 access credentials. This subchunk supplies build
inputs and offline tests. It does not establish a published Cloudflare release,
website integration or real-account Gate 4 acceptance.

Authority: runbooks Amendment A merged at `10f75e45`,
`specs/BQ-DATA-VERIFICATION-EVERYWHERE-S1791-GATE2-CHUNK3-CLOUDFLARE.md`
§3.1, §3.2, §4 and §12. AWS registration, signed work, report encoding, scanner policy,
key rotation and ISRG transport are mirrored without importing AWS/Lambda SDKs.
The gateway dependency graph and shared scanner are unchanged.

## OAuth distribution oauth-install-r1 (S1807 I3, S1810 Amendment A5)

This separately cataloged distribution adds one-use bootstrap and bounded polling.
Existing and new legacy button installs still get v0.1.1 until a separate legacy
follow-up; existing installations retain their manual controls.
The OAuth distribution has no `/operator` page; the frozen button instructions below do not apply to it.
The OAuth binary is `cloudflare-verifier-v0.1.2`, scanner `0.1.2`, SHA-256
`305f12ed690b29891398dd39ebf3aa84d7fcda8d4bcb58703fe30e1085c15488`.
The Container image is pinned to
`docker.io/aidotmarket/aim-cloudflare-verifier@sha256:194576cdeea50798511acebb0ebd294841ffb1a1553c91f7e134c38c8813f087`.
The new Worker hash selects a new binary/Worker allowlist pair; the old pair remains.
Use the unchanged strict catalog entry in `CLOUDFLARE_OAUTH_INSTALL_RELEASE_CATALOG`
(default `{}`, refusing new setup), selected internally only for installer intents.
Backend catalog selection/activation belongs to the installer backend chunks.

Installer metadata supplies `REGISTRATION_TOKEN` and `BOOTSTRAP_WAKE_SECRET` as
`secret_text`, plus `BOOTSTRAP_INSTALL` as a nonsecret canonical JSON string:
`{"expires_at":<Unix seconds>,"intent_id":"<intent UUID>","registration_expires_at":<Unix seconds>}`.
The spec leaves binding names/format open: this defines absolute UTC second deadlines;
registration expiry is the existing token's mint time + 30 minutes, never extended.
Wake expiry is the install work deadline. No reusable run-now binding or operator
page is exported. Upload with no cron; after exact module/config/image/DO readback,
enable minute cron and POST exact `{}` to `/bootstrap/install` with
`Authorization: Bearer <BOOTSTRAP_WAKE_SECRET>`. Only empty 202 is an acknowledgment.
The DO stores a fingerprint of the intent, deadlines and secret before scheduling.
Identical lost-ack retries return empty 202 even after wake expiry, recovering a missing
initial task without a second wake; changed or expired unused bindings refuse. Cron cannot start an unconsumed install.

One SDK next-poll row replaces the previous row; cron respects the next deadline.
Failures back off 1/2/4/8/15 minutes, capped at 15; success returns to minute polling.
Terminal bootstrap refusal or unused registration-token expiry stops scheduling;
signed work/report refusals after registration retain the outbox and retry with backoff.
Lease recovery resends committed outbox or produces a terminal failure; it never
repeats an admitted traversal. Pending `/create` may retry while no signing state
has been saved or registered (e.g. unavailable image); saved keys are never replaced.
Bootstrap/config/register/first empty poll open zero R2 objects. Ready still requires
backend observation and installer cleanup proof; 202 alone does not establish Ready.

Build locally with Go 1.27.2 and the locked npm dependencies:

```sh
# On this darwin/arm64 host, select the actual cached toolchain; the build uses GOTOOLCHAIN=local.
export PATH="$(rtk proxy go env GOMODCACHE)/golang.org/toolchain@v0.0.1-go1.27.2.darwin-arm64/bin:$PATH"
command -v go
rtk proxy env GOTOOLCHAIN=local go version
(cd deploy/cloudflare-verifier && rtk proxy npm ci)
COMMAND_PROXY="rtk proxy" rtk proxy python3 scripts/cloudflare-verifier-release.py \
  --version 0.1.2 --distribution oauth-install-r1 --verify-committed \
  --output /absolute/candidate/path
```

`BINARY_SOURCE=2b1e4692bda7516e27a55f5cc4219e3305f1929e` is the immutable
source for both compilation and the exported source archive. Each local/CI build
extracts a fresh `git archive BINARY_SOURCE`, then compiles with Go 1.27.2 and a
separate cache, using the script's exact environment and linker flags:
`-s -w -buildid= -X main.releaseID=cloudflare-verifier-v0.1.2 -X main.scannerVersion=0.1.2`.
Both independent clean builds must match the approved SHA-256 and the committed
template binary before signing. Investigate any mismatch and preserve the failed
run's evidence; never select a matching pair from repeated attempts.
`build.json.compiled_modules` records `go1.27.2`. The Worker is also bundled twice
and checked against the committed bundle. CI signs the bytes it compiled itself.
A frozen binary is re-pinned, never re-signed, when the toolchain moves; the
OAuth distribution name stays `oauth-install-r1` on this binary re-pin.

The image uses the three-line `FROM scratch` Dockerfile in the template.
`SOURCE_DATE_EPOCH=1792286324` is **BINARY_SOURCE's commit time**, not the later
template export commit time. After verifying the binary above, reproduce a local
OCI archive with this exact command (the context contains only that Dockerfile
and the verified executable, mode 0755). The image was built with BuildKit
v0.33.1 using the `s1807-repro` docker-container builder:

```sh
rtk proxy mkdir /absolute/image-context
rtk proxy cp deploy/cloudflare-verifier/Dockerfile /absolute/image-context/Dockerfile
rtk proxy cp /absolute/candidate/path/aim-cloudflare-verifier /absolute/image-context/aim-cloudflare-verifier
rtk proxy chmod 0755 /absolute/image-context/aim-cloudflare-verifier
rtk proxy docker buildx build --builder s1807-repro --no-cache --platform linux/amd64 \
  --provenance=false --sbom=false --build-arg SOURCE_DATE_EPOCH=1792286324 \
  --output type=oci,dest=/absolute/image.tar,name=docker.io/aidotmarket/aim-cloudflare-verifier:v0.1.2,rewrite-timestamp=true,oci-mediatypes=true \
  --metadata-file /absolute/image-metadata.json /absolute/image-context
```

Require two independent clean image builds to match the pinned manifest digest
above, and verify the image-extracted executable equals the approved binary.
Keep the interval between image publication and tag push short, and **run
govulncheck and Grype immediately before the tag push** (including the existing
`--only-fixed --fail-on high` Grype gates for binary and template SBOMs).
A newly disclosed fixed vulnerability blocks publication and requires a new pin.

The candidate uses immutable repository/tag `cloudflare-verifier-oauth-install-r1`,
its own bundle hash and Cosign workflow identity/signatures. Frozen v0.1.1 signing
is rejected; the original repository, tag and signatures are never replaced.
The tag workflow signs only the new distribution through the existing facilities;
local exports do not sign, publish, create repositories or deploy anything.
The exported template has the pinned image, no cron and no run-now prompt.
Live multipart secret binding/readback, fresh image pull/boot and provider accounting
remain T1/T5/T10 Gate 4 evidence; offline tests cannot establish them.

## Seller deployment (frozen button releases)

Use the release-specific Deploy to Cloudflare button provided by the website.
It copies a frozen public repository into the seller's GitHub/GitLab account.
Workers Paid and a source-control account are required. Workers Builds builds
the committed static linux/amd64 binary with the scratch Dockerfile; it does
not compile Go. `worker.mjs` bundles Container SDK 0.3.7 and preserves the
`ContainerProxy` export. Wrangler uploads it with `no_bundle=true`.

Start setup on ai.market and use its release-specific Deploy to Cloudflare
button. Enter exactly the listed bucket name shown on the setup page for the
`SOURCE` binding. If the deploy flow creates an empty bucket instead, open
Worker → Settings → Bindings, set `SOURCE` to your listed bucket, and delete
the empty bucket. Q1 must establish which click-only path Cloudflare supports
and prove that a later Workers Builds redeploy retains the binding.

Paste the registration token and the 43-character run-now secret generated
by your ai.market setup page into Cloudflare's two secret prompts. Save the
run-now secret privately. It is generated in your browser and never sent to
ai.market servers. Secrets must not enter vars, source control, URLs or logs.
No configuration is pasted or repository edited. The release template var
contains only release/version/binary/Worker identity and default jurisdiction.

Run now or cron bootstraps the fixed `aim-verifier` DO by pulling the frozen
config from the fixed marketplace deployment-config endpoint with the token.
Before generating keys, it verifies the canonical SHA-256, scope and shipped
identity, and atomically saves config/hash with first-start state. The token
also reveals the frozen key list until expiry or consumption; it grants no
scan consent. Scope is limited to 17,033 exact keys and 1 MiB canonical JSON.
A new published key outside that scope requires a new setup.

Every runtime scope load verifies the persisted config hash and connection.
After registration, restart, secret replacement and same-release redeploy
retain config without refetch. Lost acknowledgments resend the original stored
registration bytes. If an unconsumed token expires, obtain a new setup token
and replace the Cloudflare secret. After an explicit registration refusal,
the DO pulls config under that new token and durably saves a newly signed
request with the new hash before sending it. Missing or corrupt existing
state requires removal and fresh setup; it never silently resets keys.

Setup and registration perform no R2 HEAD/GET. The consented free probe checks
the binding. If it returns `source_unreachable`, check that `SOURCE` is your
listed bucket and retry. `artifact_changed` means the frozen files changed;
re-publish or run a new check. Readiness proves registration and a successful
poll; a successful probe proves the binding, before any quote or payment.

After deployment, open the seller-owned Worker at `/operator`, enter the
run-now secret and select **Run now**. The page retains no browser state.
Authenticated `POST /operator/run-now` accepts only the exact body `{}` and
returns 202 after scheduling. Both it and cron enqueue the same `schedule()`
task. No custom `alarm()` exists. Wakes coalesce and are limited to one/minute.
Cron defaults to every minute; `*/5 * * * *` or `*/15 * * * *` are alternatives.
Scheduled checks are a best-effort backstop: they have no delivery guarantee.
Ready requires registration and a successful poll, not a deployment click.

## Durable state and read boundary

One fixed-name `aim-verifier` Container Durable Object owns SQLite state. The first
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

The generic non-distribution binary release path is retired for now; a future binary release needs a script/workflow change.

Install exact lockfile dependencies in `deploy/cloudflare-verifier` with
`npm ci`, then run `npm run types`, `npm test` and `npm run build`.
Generate binding declarations with
`npx wrangler types --env-interface RuntimeEnv --include-runtime false`.
Go checks: `go test ./internal/cloudflareverification ./cmd/aim-cloudflare-verifier`,
focused race tests, gateway/AWS/shared scanner regressions, vector digests,
module/line budgets and `git diff --check`.

At the original release source tag, run `python3 scripts/cloudflare-verifier-release.py --version X.Y.Z`, replacing `X.Y.Z` with the intended build version. The script embeds that version in the binary and release identity; `0.1.0` was the first-release example, not a default for current source. To reproduce a published release, use that release's exact source tag and recorded toolchain rather than current main.
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

- Q1: two-account full button setup, existing bucket binding and config pull, copied
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
