# Opaque files: gateway chunk A release preparation

Candidate gateway release: **v0.2.3**, subject to the operator checking the next
unused version at release time. This document prepares a later release; chunk A
only opens a draft PR. No tag, image, release, allowlist, installer pin or Railway
setting is changed by this build.

## Release notes

- Describe now returns only SHA-256, zero rows and `columns: []` for opaque files.
  PDF, zip, binary and pretty-printed JSON objects are examples. A minified JSON
  array, CSV quote error, NDJSON syntax/type error, oversized NDJSON line or
  excessive NDJSON columns also falls back, after the entire file reads cleanly.
  I/O errors and timeouts remain failures. Broken Parquet remains a read error.
- Verification chooses the parser from the same content prefix as inventory,
  including files with misleading extensions or aliases. Drop/rename safeguards
  apply in eligibility and every scanner open. Detection failures refuse scans.
- Detection is deliberately unchanged: prose with a comma in its first line can
  look like CSV. If it describes as a table but fails strict scanning, its probe
  reports `source_reachable: false` (backend `source_unreachable`); no scan receipt
  is issued. The seller needs a **new listing without that file**, because an
  existing gateway version has fixed members. Single-column text without a
  delimiter is unsupported by inventory, regardless of its filename.
- AWS and Cloudflare verifier releases remain unchanged. Chunk A changes no core
  scanner source. Both verifier binaries must compare byte for byte with the
  parent using the release Go toolchain, target architectures and linker flags.
- The three new signed description vectors include source bytes and their
  detected media types; `contract/VECTORS.sha256` pins the gateway copy. The
  backend copies under `tests/contract/gateway/` are **not yet added** (chunk B,
  ai-market-backend `ab7e7ec3`, deferred them). Add byte-identical copies, the
  manifest update and a passing backend contract check before this release.

## Later operator procedure (not executed)

After chunk B and the website chunk deploy, follow [the release runbook](release-runbook.md)
and the [operations guide](https://github.com/aidotmarket/runbooks/blob/main/aim-data-gateway.md).
Existing release scripts and workflows supply the required version, reproducible
image build, digest validation, scanning, signing and provenance.

1. Re-run the release checks, including the race test and binary comparisons.
   Select the approved merged commit and next unused gateway version. Create the
   gateway release only under later operator authorization; record the version
   and verified image digest from the release workflow.
2. Re-read and preserve every existing entry in `VERIFICATION_SCANNER_ALLOWLIST`.
   Add only the new **gateway** version/digest pair. Add the version to the JSON
   list `VERIFICATION_CONTENT_DETECTING_SCANNERS`. Never change the Cloudflare or
   AWS entries, `CLOUDFLARE_OAUTH_INSTALL_RELEASE_CATALOG` or installer pins.
3. Set `VERIFICATION_CONTENT_DETECTING_SCANNERS` on `ai-market-backend` and its
   `${{ai-market-backend.VERIFICATION_CONTENT_DETECTING_SCANNERS}}` reference on
   `ai-market-celery-worker` in the same window, before chunk B code reading it
   deploys. Initially that list can remain `[]`; add the gateway version after
   the release is verified. Coordinate that prerequisite with chunk B rollout.
4. After updating the allowlist and capability list, **redeploy both
   `ai-market-backend` and `ai-market-celery-worker`**. Confirm effective values
   in each service contain the new entries. Railway references resolve on deploy.
5. Only after those checks and chunk B deployment, move `GATEWAY_IMAGE` and the
   matching `GATEWAY_VERSION` to the verified gateway release. Retain old approvals
   while older paired gateways remain in use.

## Amendment B update for the operations guide

The gateway measures **9,325 non-test Go lines** with
`python3 scripts/count-lines.py`, above the previous 9,275 cap. The approved cap
is 9,325 (Max, Event Ledger `89cefcdb`, 2026-10-23); both the gateway cap and
`over_budget` default change in this PR. Counting rules and all other budgets are
unchanged. The matching note in `aim-data-gateway.md` (aidotmarket/runbooks) is
updated in its own reviewed runbooks PR when this change merges.
