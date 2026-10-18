# S1807: private Cloudflare OAuth install trial

Evidence-only harness, **not product code or proof that Option E is ready**.
Validation of this revision is offline: no Cloudflare OAuth, management API,
Worker, Container, R2, or production-backend calls. Keep PR #30 draft; do not merge.

The PRIVATE OAuth client now exists on ai.market's own account
`d5346d3e0f8f344c5f4915aaca689adf`. It uses PKCE S256, token authentication
`none`, redirect `http://127.0.0.1:8976/callback`, and exactly Workers Admin
(`workers-scripts.admin`) plus Workers Containers Write (`containers.write`).
The public client ID appears as a default **only in the shell example below**;
the program still requires `CF_OAUTH_CLIENT_ID` or `--client-id`.

Only the compiled approved account is allowed. No seller account/data or
production registration: no `REGISTRATION_TOKEN`, `RUN_NOW_SECRET`, cron, routes,
Workers Builds, workers.dev activation, wake, probe, scan, or backend call.
No bucket is created or inspected. The default token authentication remains
`none`, with the existing `CF_OAUTH_CLIENT_SECRET` refusal guard. The S1810
confidential rehearsal below requires a separately registered PRIVATE client.

## S1810: private confidential T0 rehearsal (never production)

Authority: runbooks Chunk 3c §§4.2, 8.1, 9 T0 and 11 step 1. Use the client's
registered method explicitly; there is no retry with another auth method or
without PKCE. [Cloudflare's client documentation](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/)
supports `client_secret_basic` and `client_secret_post` for server-side clients.
S256 stays mandatory here in both modes. These commands are operator instructions;
the build and all self-tests make zero live Cloudflare calls.

`--exchange-only` does exchange → exact scope/lifetime checks → account scripts
GET baseline → access/refresh revoke → same GET denial (strictly 401/10000) →
refresh `invalid_grant` check if issued. It never fetches a bundle, installs a
Worker/DO/Container, or reads their settings. Both T0 and confidential modes reject
the old experimental missing-scope override. Issued tokens
are retained for finally revocation on failed checks; refresh is never persisted
or used to continue work. Cleanup/denial ambiguity exits nonzero.

Use the **same private confidential client ID** for both runs below and fresh
authorization codes/run IDs. Replace only the client ID placeholder. The existing
Infisical identity must already have access restricted to `/cloudflare-installer`;
this tool does not configure or prove vault isolation. With terminal/session/body
capture disabled, in zsh or bash:

```sh
unset CF_OAUTH_CLIENT_SECRET
T0_CLIENT_ID='REPLACE_WITH_PRIVATE_CONFIDENTIAL_CLIENT_ID'
T0_RUN_ID="s1810-t0-basic-$(rtk proxy date -u +%Y%m%d%H%M%S)"

rtk proxy python3 spikes/s1807-cf-oauth-trial/trial.py begin \
  --manual-callback --client-id "$T0_CLIENT_ID" \
  --account-id d5346d3e0f8f344c5f4915aaca689adf --run-id "$T0_RUN_ID" \
  --token-auth client_secret_basic --exchange-only

rtk proxy python3 spikes/s1807-cf-oauth-trial/trial.py finish \
  --manual-callback --client-id "$T0_CLIENT_ID" \
  --account-id d5346d3e0f8f344c5f4915aaca689adf --run-id "$T0_RUN_ID" \
  --token-auth client_secret_basic --exchange-only --client-secret-fd 3 \
  3< <(rtk proxy infisical secrets get CLOUDFLARE_INSTALLER_OAUTH_CLIENT_SECRET \
    --projectId bd272d48-c5a1-4b52-9d24-12066ae4403c --env prod \
    --path /cloudflare-installer --include-imports=false --expand=false --plain --silent)
```

After `begin`, open the printed URL and authorize only the approved account.
At `finish`, paste the full callback URL to stdin and press Enter; echo is disabled.
FD 3 carries only the secret, read once through EOF and closed, separately from
callback stdin. A trailing newline from `--plain` is removed; empty, multiline,
invalid UTF-8 or over-64-KiB input refuses. `begin` never reads the secret FD.
The secret and its reversible wire encodings stay in memory, covered by the
existing evidence canary; `CF_OAUTH_CLIENT_SECRET` is removed and never used.
For a client registered with `client_secret_post`, replace the method in **both**
commands; basic sends an Authorization header, post sends client_id/client_secret
form fields to both OAuth endpoints. Never change methods to bypass a refusal.

Optional negative, using the same client ID and fresh consent, **without** a secret:

```sh
T0_NEG_RUN_ID="s1810-t0-none-$(rtk proxy date -u +%Y%m%d%H%M%S)"
rtk proxy python3 spikes/s1807-cf-oauth-trial/trial.py begin \
  --manual-callback --client-id "$T0_CLIENT_ID" \
  --account-id d5346d3e0f8f344c5f4915aaca689adf --run-id "$T0_NEG_RUN_ID" \
  --token-auth none --exchange-only

rtk proxy python3 spikes/s1807-cf-oauth-trial/trial.py finish \
  --manual-callback --client-id "$T0_CLIENT_ID" \
  --account-id d5346d3e0f8f344c5f4915aaca689adf --run-id "$T0_NEG_RUN_ID" \
  --token-auth none --exchange-only
```

Paste this run's callback at finish. Expected refusal exits 1; do not treat a
generic failure as proof of confidential auth enforcement. In private evidence,
inspect `exchange_without_secret_refused` alongside `code_exchange.http_status`,
numeric `cf_error_codes` and allowlisted `oauth_error` (e.g. `invalid_client`).
`invalid_grant` could instead mean an invalid code/PKCE; repeat with fresh consent
before concluding that the secret was required. A successful none exchange records
false and still revokes any issued tokens; it never claims `secret_accepted`.

Evidence remains under the existing private root/run ID. It records `token_auth`,
`secret_accepted` (exchange succeeded with the supplied secret; not proof the server
requires it), scope set equality, expires_in, refresh issuance, each exchange/revoke/
denial HTTP status and numeric code, and `refresh_invalid_grant` (null when absent).
No secret, code, access or refresh token is written. Vault isolation and whether
the app authorization remains in connected-apps after revoke require separate
operator observations; offline tooling does not close T0 or authorize production.

## Two-phase procedure: browser on Max's laptop, script on Koskadeux

The laptop's `127.0.0.1` cannot reach Koskadeux. Manual mode uses two processes;
it does not start a callback listener. Run these commands on Koskadeux in the
same environment, with a fresh run ID. Finish main work within seven minutes of
begin; the ten-minute total includes the cleanup/revocation reserve.

```sh
export CF_OAUTH_CLIENT_ID="${CF_OAUTH_CLIENT_ID:-1395f6ac7f7bb21095c59488d864b8f4}"
export CF_ACCOUNT_ID=d5346d3e0f8f344c5f4915aaca689adf
export CF_OAUTH_RUN_ID=max-trial-20261017-01

rtk proxy python3 spikes/s1807-cf-oauth-trial/trial.py begin \
  --manual-callback --run-id "$CF_OAUTH_RUN_ID"
```

`begin` makes no network calls. It writes **only** `state`, `verifier`, and
`run_id` to
`/Users/max/koskadeux-state/s1807/cf-oauth-trial/<runid>/pkce.json` (0600, directory
0700) and prints the authorization URL. State and verifier are single-use,
short-lived handoff material, not provider credentials. The verifier is never
printed. The file's creation mtime supplies the expiry without extra JSON fields.
`--manual-callback` on the default `run` command also selects `begin`.

Open the printed URL on Max's laptop, select only the approved ai.market account,
and approve. The browser will fail to connect to the laptop's loopback redirect.
Copy the **full callback URL** from its address bar. On Koskadeux, run:

```sh
rtk proxy python3 spikes/s1807-cf-oauth-trial/trial.py finish \
  --manual-callback --run-id "$CF_OAUTH_RUN_ID" \
  --reuse-existing-container-image a030d580-f639-48c8-9627-f10c1f3ce6e4
```

Paste the full URL into that process's **stdin**, then press Enter. Terminal echo
is disabled while reading; no prompt or callback URL is logged. Do not put the
URL/code in argv, environment variables, a file, shell history, or a recorded
terminal/session. Disable external APM/debug/body/terminal capture. The script
validates the exact scheme, host, port and path, rejects fragments, duplicate
state/code, errors and state mismatch, then exchanges the code using the stored
verifier. `pkce.json` is deleted immediately when exchange returns or raises,
before response validation, and on every handled finish failure. A finish lock
prevents replay or concurrent finish. Abandoned begin files expire after ten
minutes and must be discarded; use a new run ID. Process termination by SIGKILL
cannot execute deletion or cleanup.

Finish continues install → readback → cleanup → revoke → verify denial in the
same process. Codes and tokens stay in memory; evidence records only the
`code_received` boolean about the code. A wrong callback consumes the attempt.
Inspect the exit code, `failures`, `residual_resources`, and `resource_manifest`.
All ambiguous results exit nonzero.

For same-machine browser use, omit `--manual-callback` and use `trial.py run`
with the same image option. The existing one-shot listener binds only
`127.0.0.1:8976`, suppresses access/error logs, validates state/host/path and
consumes one request. It is unsuitable for the two-machine procedure above.

## Image discovery and the U1 limit

```sh
rtk proxy python3 spikes/s1807-cf-oauth-trial/trial.py find-image
```

This helper accepts no credential options and only prints instructions; it makes
no requests. Discovery happens in `finish`, using the trial OAuth token:
`--reuse-existing-container-image` without an argument defaults to
`a030d580-f639-48c8-9627-f10c1f3ce6e4`, the existing
`aim-cloudflare-verifier-cloudflareverifier` application. The command above uses
that ID explicitly. Only
`GET /accounts/<approved-account>/containers/applications/<id>` is made for it.
Its `configuration.image` must be digest-pinned. The source app is never modified,
scaled, or deleted. An explicit write guard rejects non-GET requests targeting
any application ID the trial did not create, including this source ID.

Alternatively, replace the reuse option with
`--image-ref REGISTRY/OWNER/IMAGE@sha256:<64hex>` after verifying provenance.
Tags, including tag-plus-digest spellings, are refused. The old `--image` spelling
remains an alias. Image options are mutually exclusive; a missing image source or
mutable discovered reference refuses before creation. No image is uploaded or
copied by this harness. The pinned catalog/template does not supply a reviewed
public digest; operators must verify any supplied image contains binary SHA-256
`45b5bf95b784bf6cc572fe84f8faba77bb09682a3d5cb1f25cae6eb4e6a1c8a6`.

Evidence labels reuse as **account-local registry path only**, and leaves public
image distribution **unproven: U1 stays open for sellers**. Acceptance/readback
of a reference does not prove its executable contents or run a container.

## Scope, account and creation gates

After exchange, evidence retains the granted scope string and whether the field
was present. Before any management write, the scope set must be exactly
`{workers-scripts.admin, containers.write}`. Missing `scope` fails closed unless
`--accept-missing-scope-field` is explicitly supplied (default off); that override
and omission are recorded. It never accepts an explicit wrong/empty scope set.
Issued tokens are retained before PKCE deletion and for finally revocation even when
scope validation fails. PKCE deletion is attempted on every path; failure sets the
non-secret `pkce_delete_failed` evidence flag without discarding issued tokens.

Account verification is the harmless, paginated
`GET /accounts/<approved-account>/workers/scripts`. A 403/404 or other refusal
stops before writes. The script **never enumerates accounts** and never probes a
foreign account. Revocation denial uses the same previously successful read,
requiring 401/403; a deleted-resource 404 is insufficient.

Create-only preflight refuses any Worker or Container app whose name starts with
`aim-oauth-trial-<runid>`, checks Worker settings for confirmed absence, and checks
DO namespace collisions. Every management mutation passes scope/account/collision
and ownership gates plus the hard denylist: `aim-cloudflare-verifier*`,
`allai-dead-man-switch`, `get-ai-market`, `vectoraiz-installer`. Only the freshly
reserved Worker and newly created app IDs may be changed/deleted. Existing app
IDs are tracked and cannot become cleanup targets, even if returned by a create
or reconciliation response. The atomic local run directory and finish lock
prevent local reuse. Worker PUT remains a provider upsert: do not concurrently
install anything at this reserved name. There are no write retries; lost create
responses are reconciled by the fresh name for cleanup.

The Worker is the exact pinned
[worker.mjs](https://raw.githubusercontent.com/aidotmarket/cloudflare-verifier-v0.1.1/f13e6d7a9052a3bff36d5e27d32212cfdf3305a2/worker.mjs),
SHA-256 `69e62e36aee28c96521ca6e06d93b82532d3314db50a4ec09f18786d220b54d4`.
Readback checks the bundle hash, compatibility flags/date, SQLite migration
namespace, `VERIFIER` and identity-only `DEPLOYMENT_CONFIG`; logs are disabled.
Container scheduling is `default`, `standard-2`, initially zero instances, max one.
Optional `--r2-bucket EXISTING-TEST-BUCKET` binds only an operator-confirmed test
bucket as `SOURCE`; use a fresh run ID and retain separate evidence. No R2 API
or data-plane read occurs; a secret-free refused upload's `errors` are recorded.

## Offline validation

Python 3.9+ on macOS/Linux, standard library plus `httpx`. No Wrangler, Docker or
subprocesses are invoked by `trial.py`. Dry-run requires a local artifact and
checks the **same immutable bundle hash**, with zero network. Never change the
pin to make validation pass.

```sh
rtk proxy python3 -m py_compile spikes/s1807-cf-oauth-trial/trial.py
rtk proxy python3 spikes/s1807-cf-oauth-trial/trial.py --self-test
rtk proxy python3 spikes/s1807-cf-oauth-trial/trial.py begin \
  --manual-callback --run-id offline-validation-unique --dry-run
rtk proxy python3 spikes/s1807-cf-oauth-trial/trial.py finish \
  --manual-callback --run-id offline-validation-unique --dry-run \
  --artifact-file /absolute/path/to/worker.mjs
```

For the last command, supply a fabricated callback on stdin with a deliberately
wrong state: expect exit 1, `callback_state_or_code_refused` in evidence, zero HTTP
steps, and deleted `pkce.json`. A correctly fabricated callback using the begin
state validates offline and skips exchange; it is never live trial evidence.
Run IDs are single-use even for dry runs and failures. `--self-test` uses only
`httpx.MockTransport`, with no network sockets, including all OAuth tests.

## Evidence, cleanup and limits

Each completed/failed trial saves `evidence.json` and `stdout.txt` as 0600 files in
the 0700 run directory. Evidence contains timestamps, statuses, integer API error
codes, durations, hashes/booleans, created resource manifests, findings and
cleanup/revocation results. Token metadata includes type, lifetime, refresh-issued
boolean and scopes; codes, tokens and token responses are never saved. A token
canary checks synthetic detection plus code/verifier/token prefixes against
candidate evidence/stdout and the actual disk bytes. Secret-bearing evidence is
withheld and the run fails. No issued tokens in dry-run means no live canary proof.
Managed memory clearing is best effort; external recording is outside this check.

Main work is bounded to seven minutes, reserving three of the ten-minute total
for independent finally attempts: delete created Container apps → delete the
created Worker including its DO namespace (`force=true`) → confirm absence →
revoke access/refresh separately → verify access denial and refresh `invalid_grant`.
Unexpectedly renewed tokens are immediately revoked and the trial fails.
Cleanup requests stop at the hard deadline minus 90 seconds; unfinished resources
are recorded as residual. The last 90 seconds are reserved exclusively for
access/refresh revocation and denial checks, using the hard revocation deadline.
Cleanup failure cannot skip revocation. Only fixed API/OAuth/artifact hosts are
used, without redirects or environment proxies, with bounded request timeouts.
Every HTTP response, including the artifact download, is streamed with a 2 MiB
body cap and monotonic phase-deadline checks between chunks. Connect, read, write
and pool waits each have a five-second timeout. A separate cleanup alarm interrupts
an in-flight read at the cleanup cutoff without disabling revocation; the final
alarm is armed only when revocation starts, two seconds before its hard deadline.
SIGINT/SIGTERM enter finalization; a second cancellation stops further calls.
Crashes/SIGKILL cannot revoke in-memory tokens: inspect the fresh reserved name,
residual manifest and Cloudflare connected-app controls before claiming recovery.

No run closes U1/U2/U4/U9 fully. Public image provenance/execution, workers.dev,
R2 permission minima, foreign-account enforcement, public consent UX, provider
TTL/refresh behavior and crash lifecycle require further evidence. The pinned
bundle's reusable wake endpoint does not implement single-use product bootstrap;
this trial never invokes it. Background design:
[runbooks PR #861](https://github.com/aidotmarket/runbooks/pull/861) and
[spec at 3c64b9a9](https://github.com/aidotmarket/runbooks/blob/3c64b9a9/specs/BQ-DATA-VERIFICATION-EVERYWHERE-S1791-CLOUDFLARE-ONE-STEP-SETUP.md).

Author validation (2026-10-17): `py_compile`, eleven offline self-test groups,
and two-phase dry-run checks, including deliberately wrong callback state.
Private full command logs are retained under
`/Users/max/koskadeux-state/s1807/cf-oauth-trial/fold-validation-20261017/`.
These results establish local validation and request construction, not provider
behavior. No live credentials or live trial results belong in this PR.
