# S1807: private Cloudflare OAuth install trial

Evidence-only harness, **not product code or proof that Option E is ready**. No
Cloudflare OAuth, management API, Worker, Container, R2, or production-backend calls
were made during author validation. Max has not created the OAuth client. Vulcan
runs the live trial after review; this PR neither creates that client nor runs it.

Authority: Max, Event Ledger `45702b9a`: PRIVATE client in ai.market's own account
`d5346d3e0f8f344c5f4915aaca689adf`, install only into that account. The supplied
account must match this compiled safety boundary. No seller account/data and no
production backend writes. The Worker receives neither `REGISTRATION_TOKEN` nor
`RUN_NOW_SECRET`; no cron, routes, Workers Builds, workers.dev activation, wake,
registration, probe, or scan is performed. No bucket is created or inspected.

## Sources and deviations

Read first: [runbooks PR #861](https://github.com/aidotmarket/runbooks/pull/861),
[spec at 3c64b9a9](https://github.com/aidotmarket/runbooks/blob/3c64b9a9/specs/BQ-DATA-VERIFICATION-EVERYWHERE-S1791-CLOUDFLARE-ONE-STEP-SETUP.md)
§3, §5, U1/U2/U4/U9, and
[release runbook](https://github.com/aidotmarket/runbooks/blob/main/aim-data-gateway.md).
The user's trial instructions take precedence over the product design:

| Area | This trial and its limit |
| --- | --- |
| U1 image | The pinned [catalog](https://github.com/aidotmarket/aim-data-gateway/releases/tag/cloudflare-verifier-v0.1.1), build metadata and [template Dockerfile](https://github.com/aidotmarket/cloudflare-verifier-v0.1.1/blob/f13e6d7a9052a3bff36d5e27d32212cfdf3305a2/Dockerfile) supply no public image digest. The template builds `./Dockerfile` from the released binary. A public image's existence/acceptance is **unproven**, not assumed. Without `--image`, Worker readback still runs, then U1 is refused, cleaned up and revoked; live exit is nonzero. No dummy image is submitted. |
| U1 template | Exact [worker.mjs](https://raw.githubusercontent.com/aidotmarket/cloudflare-verifier-v0.1.1/f13e6d7a9052a3bff36d5e27d32212cfdf3305a2/worker.mjs), compatibility date/flags, Container class, SQLite `v1` migration, `VERIFIER`, identity-only `DEPLOYMENT_CONFIG`. `ContainerProxy` remains exported in the unchanged bundle. Logs are disabled. Container scheduling is `default`, `standard-2`, max one, initially zero running deployments; no runtime is invoked. |
| U2 account | Exhaustively list visible accounts, record IDs only, require exactly the approved ID before writes. If `/accounts` requires another permission, refuse and record the HTTP status/codes; **do not add `account-settings.read`**. Visibility plus hardcoded endpoint confinement does not prove Cloudflare rejects all foreign-account actions. No foreign account is probed under this authorization. |
| U2 R2 | First run omits `SOURCE`. A separate run with a new run ID and `--r2-bucket` binds only an operator-confirmed existing test bucket. No data-plane request, list/create bucket, or permission escalation. Preserve refused upload's JSON `errors` verbatim if secret-free. Binding success alone does not close the full minimum-permission claim. |
| U4 order | Install → readback → delete own Container → delete own Worker including DO namespace → confirm absence → revoke access and refresh separately → retry a previously successful harmless account read. Refresh renewal must also fail with `invalid_grant`. |
| U9 client | PRIVATE visibility is distinct from public PKCE authentication. Use a private client with token authentication `none` and S256, or the optional confidential variant with `client_secret_post`. The env-only confidential-secret input is specifically allowed for this spike; it does **not** implement the spec's Infisical-only product delivery contract. |
| Dry-run | By default only the fixed GitHub artifact is fetched; redirects are refused. `--artifact-file` makes dry-run fully offline. No callback listener, OAuth exchange or Cloudflare request is made. This resolves “fetches artifact” versus “excluding network/offline” in the request. |

Official API references used to construct requests:
[OAuth endpoints](https://developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/),
[client authentication](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/),
[Worker multipart metadata](https://developers.cloudflare.com/workers/configuration/multipart-upload-metadata/),
[Container create](https://developers.cloudflare.com/api/resources/containers/subresources/applications/methods/create/),
[Worker delete including DO namespaces](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/methods/delete/).
Endpoint documentation is not live feasibility evidence.

## Review and offline validation

Python 3.9+ on macOS/Linux, standard library plus `httpx` (author used 0.28.1).
No Wrangler, Docker, git, subprocesses, or shell commands are invoked by `trial.py`.
Use an environment that already has `httpx`, or install it separately.

```sh
rtk proxy python3 -m py_compile spikes/s1807-cf-oauth-trial/trial.py
rtk proxy python3 spikes/s1807-cf-oauth-trial/trial.py --self-test
rtk proxy python3 spikes/s1807-cf-oauth-trial/trial.py --dry-run \
  --client-id reviewer-public-pkce-placeholder \
  --account-id d5346d3e0f8f344c5f4915aaca689adf \
  --run-id reviewer-dry-unique
```

The placeholder client ID is only for dry-run. For fully offline validation, append
`--artifact-file /absolute/path/to/worker.mjs`. A local artifact is accepted only
with the same pinned hash; never update the pin to make a failing run pass.
Every run ID is single-use, including dry runs and failed runs.

`--self-test` uses only `httpx.MockTransport`, opens no sockets, and checks PKCE's
RFC vector, callback state/host/duplicate rejection, canary detection, multipart
roundtrip, invalid inputs, artifact tampering/redirects, dry-run and foreign-path
guards, wrong-account/name collisions, lost upload responses, corrupt readback,
Container cleanup, revoke failure, refresh denial and unexpected renewal cleanup.
These are synthetic assertions, not provider findings.

## Vulcan's live procedure after review and client creation

1. Max creates the **PRIVATE** client in the approved account. Register exactly
   `http://127.0.0.1:8976/callback`; require only
   `workers-scripts.admin containers.write`. No refresh/offline-access scope is
   requested. Keep the client private. Public visibility/domain approval is a
   separate task. Confirm port 8976 is free and choose a fresh run ID.
2. Supply `CF_OAUTH_CLIENT_ID`, `CF_ACCOUNT_ID`, `CF_OAUTH_RUN_ID` through the
   environment or their flags. The redirect and scopes default to the fixed
   values; `CF_OAUTH_REDIRECT_URI`/`--redirect-uri` and `CF_OAUTH_SCOPES`/`--scopes`
   must equal them exactly. Optional `CF_OAUTH_CLIENT_SECRET` is **env only**,
   removed from the process environment on entry, and never accepted as an argv
   flag. Use an isolated local process with request/APM/terminal recording disabled;
   do not enable debug logging, tracing, packet-body capture or core dumps.
3. Run the command below **without `--dry-run` only after review**. Stdout contains
   exactly the authorization URL. Open it manually, select **only ai.market's
   approved account** and approve. The one-shot loopback server suppresses access
   and exception logs, verifies state/host/path, consumes one request, and clears
   the callback query from browser history. Invalid callbacks abort the attempt.

   ```sh
   rtk proxy python3 spikes/s1807-cf-oauth-trial/trial.py
   ```

4. Inspect the evidence and exit code. With no reviewed public digest supplied,
   expect `missing_public_image_U1` and nonzero after Worker readback, cleanup and
   revocation. If the account-list or a required API refuses the exact scopes,
   that earlier refusal is the finding; do not work around it with operator tokens.
5. Only after a release publisher supplies a **reviewed public Docker Hub image
   by digest containing binary SHA-256
   `45b5bf95b784bf6cc572fe84f8faba77bb09682a3d5cb1f25cae6eb4e6a1c8a6`**,
   a fresh run may supply `--image docker.io/OWNER/IMAGE@sha256:DIGEST` (replace
   all placeholders). No image is currently pinned in this harness. The operator
   must separately verify image provenance/executable bytes; this script measures
   API acceptance and readback of that reviewed reference, not image contents.
   Direct GHCR, mutable tags and registry-copy fallback are deliberately refused.
6. The optional second test uses another fresh run ID and
   `--r2-bucket EXISTING-TEST-BUCKET`, with the same scopes. The operator must
   confirm it is an existing test bucket in the approved account; the script
   never discovers buckets or reads objects. Retain the no-R2 and R2 evidence
   separately to identify the extra binding's permission effect.

## Evidence, refusal and recovery

Each run creates
`/Users/max/koskadeux-state/s1807/cf-oauth-trial/<runid>/evidence.json` and
`stdout.txt` with mode **0600**, inside a fresh **0700** directory. Reuse refuses
before network. Evidence contains timestamps, per-request status/error codes and
durations, account IDs, resource manifest, readback hashes/booleans, cleanup and
revocation results, failures, residual resources, and separate U1/U2/U4/U9 findings.
Only token type, lifetime, refresh-issued boolean, granted scopes and receipt
timestamp are retained from the token response. Error bodies and tokens are not
logged; the R2 exception stores only the secret-free `errors` array.

The canary first proves literal prefix detection with a synthetic value, then
greps candidate evidence and the in-process stdout capture for each actual token's
first 12 bytes (or its entire value if shorter). It also checks code, verifier and
client-secret prefixes, and rechecks the written files. Tokens stay in memory.
If a candidate leaks, secret-bearing evidence/capture is withheld and exit fails.
With dry-run there are zero issued tokens, so that result is only a synthetic
detector check, not a live token-handling proof. External terminal/APM capture is
outside this local check. Managed Python memory clearing is best effort.

The total session is bounded to ten minutes from process work start, stricter than
the spec's code-receipt start. Main work stops at seven minutes (callback wait at
most six), reserving three for independent cleanup and revoke attempts. Requests
use fixed API/OAuth hosts, no redirects or environment proxies, bounded timeouts,
no automatic retries, and no caller-supplied management URLs. SIGINT/SIGTERM during
main work enter `finally`; a second cancel during finalization stops further
network attempts. SIGKILL/process crash cannot execute `finally`, revoke provider
authority or recover a token. Use the recorded reserved name to inspect residual
resources and disconnect the app in Cloudflare; never claim revocation on crash.

Create-only means collision refusal before upload, a unique reserved run name,
an atomic local run-ID directory lock, and no write retries. Cloudflare's script
PUT is an upsert, so the preflight is not a provider-side atomic create primitive;
do not run another installer/operator against this reserved name concurrently.
Timed-out creates are reconciled by that fresh name for bounded cleanup. Only
that Worker/its DO namespace and matching Container applications can be deleted;
the bucket, shared images and other Workers are never deleted. DELETE uses
`force=true` to remove the fresh Worker's DO namespace, then lists namespaces to
confirm absence. Inspect `resource_manifest`, `residual_resources` and `failures`
even when a provider response was lost. Cleanup precedes revocation on every path.

A revoke 200 alone is insufficient: access must get 401/403 on the same account
read that worked before, and an issued refresh token must get `invalid_grant`
when renewal is attempted after its separate revocation. If renewal unexpectedly
succeeds, any newly issued access/refresh tokens are retained only in memory,
immediately submitted for revocation, and the trial fails. A baseline permission
denial, deleted-Worker 404, network error or missing scope is never denial proof.
Every refusal, ambiguous cleanup or revocation failure exits nonzero.

No single run closes U1/U2/U4/U9 in full: image provenance/execution, workers.dev
bootstrap, real R2 permission minima and removed-scope negative trials, foreign
account enforcement, public client/domain/consent UX, provider TTL/refresh refusal,
broader telemetry/crash lifecycle and single-use bootstrap require further
evidence. This harness verifies the specified bundle SHA-256, not release signatures
or the binary inside an image. The pinned v0.1.1 reusable wake endpoint cannot implement §5's proposed
single-use product bootstrap; this trial never invokes it.

## Author validation, 2026-10-17

Freshly fetched `origin/main` was `801b59fcea0ae2d8a48c9a7c5f5239dffb4bef81`.
`python3 -m py_compile` and all six in-file offline test groups passed.
Artifact-fetch dry-run `author-dry-20261017-final`
printed:

```json
{"U1": "blocked_missing_public_image", "bundle_bytes": 90561, "bundle_sha256": "69e62e36aee28c96521ca6e06d93b82532d3314db50a4ec09f18786d220b54d4", "cloudflare_calls": 0, "dry_run": "PASS", "multipart_bytes": 91657}
```

Multipart boundaries are random; body length is stable for these inputs. Dry-run
success establishes artifact integrity and request construction, not provider
behavior. Full private author logs and run evidence are retained under the
evidence root; no live credentials or live trial results belong in this PR.
