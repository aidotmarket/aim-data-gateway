# Gateway image release

## Technical details for your IT team

The `Release` workflow builds the existing `v<semver>` tag. A tag push publishes
the image and release assets; a manual workflow dispatch is a dry run and does
not push an image or create a release.

From this change, the next AWS verifier release (built with `go-version-file: go.mod`) carries new binary hashes because of Go 1.27.3; the Cloudflare reproducible rebuild of v0.1.2 stays on Go 1.27.2; coordinate any verifier catalog or allowlist change with Vulcan first.

Releases from this change build with Go 1.27.4 and therefore carry new binary hashes.

Before a release, dispatch `release.yml` from the intended workflow ref with
`tag` set to an existing tag. The workflow file comes from the dispatch ref;
checkout and the build source come from the tag. Wait for the image job to
complete. Its two OCI image digests must match, and the Grype scan must pass.

The workflow sets up a `docker-container` Buildx builder and pins its BuildKit
image. `scripts/release-image.sh` uses the default builder for both OCI builds;
`scripts/push-release-image.sh` uses that same default builder for the registry
build. All three builds use `linux/amd64`, the tag commit's `SOURCE_DATE_EPOCH`,
`VERSION` set to the tag without `v`, and `rewrite-timestamp=true`. The push script checks that the registry build
digest matches the reproducible OCI digest. Keep these inputs aligned when
changing either script or the workflow.

After a release, verify the published digest from outside the workflow with
cosign v3.1.3 or newer and GitHub CLI, then run the image to check its version:
The attestation command below is a lighter check; use `SECURITY.md` for tag-pinned provenance and SPDX checks.

```sh
image=ghcr.io/aidotmarket/aim-gateway@sha256:<digest>
cosign verify "$image" \
  --certificate-identity-regexp '^https://github\.com/aidotmarket/aim-data-gateway/\.github/workflows/release\.yml@refs/tags/v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify "oci://$image" -R aidotmarket/aim-data-gateway \
  --signer-workflow aidotmarket/aim-data-gateway/.github/workflows/release.yml
docker run --rm "$image" version # prints the tag version without v
```

If `OCI exporter is not supported for the docker driver` appears, check that
the Buildx setup step ran before the build and that its builder is selected.

## S1791 gateway verification release

Before publishing a scanner-capable image, run `go vet ./...`, `gofmt -l .`, `go test ./...`, and `go test -race -timeout 30m ./internal/ledger ./internal/verification ./internal/channel ./internal/audit ./verification` (allow up to fifteen minutes). Run reproducibility, line/module budgets, vector digest, generated outbound documentation and Compose/license self-checks, plus the existing SBOM/vulnerability, Cosign and attestation workflow. Use the current caps and counting rules in `scripts/count-lines.py`: the gateway cap is inclusive 9,325 non-test Go lines (opaque-files Amendment B update, Max decision 89cefcdb, 2026-10-23; supersedes 9,275). AWS and Cloudflare source are counted separately by that script; report the actual counts without changing its exclusions or limits.

The release Compose renderer supplies `AIM_GATEWAY_IMAGE_DIGEST` from the same verified pinned image digest used for the service. The hardening check requires an exact match; local builds cannot claim a released digest. This is automatic release provenance, not a seller-entered trust key. Backend registration still enforces version/digest allowlists. A source-built development gateway without release provenance does not register for paid work.

Pair responses add `scan_spec_keys`. Upgrade an existing state volume without re-pairing: accept the listing-key-signed one-time bootstrap only while scan pins are absent. Local receipt and commitment secrets are generated independently with atomic 0600 persistence and directory fsync. Receipt identity is the backend acknowledgment's opaque UUID, never a hash or gateway file ID. Registration is proof-of-possession under the identity-key channel audit. A binary upgrade re-registers the same retained receipt public key with the new version/digest and requires a new acknowledgment before accepting new work.

Default local `verification_enabled` is true for the ready scanner release; a seller may turn it off. For current backend deployment settings and rollout status, use the [gateway operations guide](https://github.com/aidotmarket/runbooks/blob/main/aim-data-gateway.md). Publishing an image does not configure backend keys or allowlists, issue paid work, settle money or establish live customer acceptance.

### Historical Chunk 1 integration and acceptance scope

The following records the original Chunk 1 scope, including its then-deferred AWS/R2 work; it is not a statement that those adapters remain unimplemented. Their release procedures now live in [AWS verifier](aws-verifier.md) and [Cloudflare verifier](cloudflare-verifier.md). Current deployment and unfinished acceptance evidence belong in the gateway operations guide linked above.

At Chunk 1 integration, backend gateway/verification service flags were to be enabled only when 1b/1c/1d integration was ready. No seller allowlist or second backend verification flag was introduced by that chunk.

Chunk 1 Gate 4 remains a separately authorized website/released-image journey: record exact backend/frontend/gateway SHAs, image/scanner version and spec revision; run free probe, quote, deliberate paid start/JIT card setup if needed, captured full findings, unedited publication and public badge. Compare epoch/spec/snapshot/member hashes, inner receipt, consent/audit and server received-message view. Prove actual provider usage and independent 2x cost bounded $1–25 with exactly one capture; use synthetic privacy markers rather than customer values. Demonstrate E7 before quote/no hold, mutation FAILED_VOIDED/no capture, restart/replay refusal, signed-binding tamper refusal, projection isolation and Remove verifier preserving delivery. AWS/R2 are deferred.

Rollback stops new verification with the backend service flag and/or local `verification_enabled=false`, settles/voids accepted work, and retains the volume, admissions, outbox, keys, epochs and audit history. Downgrade only after work is terminal. Do not restore legacy live install-addressed verification or delete Stripe objects. Published findings remain historical.

## C0 preparation status

### Technical details for your IT team

This section covers the S1964 C0 preparation scaffold, kit version `0.0.0-c0`.
It is not a signed kit release or a platform/profile certification. Authority:
[S1964 Gate 2](https://github.com/aidotmarket/runbooks/blob/main/specs/BQ-AIM-GATEWAY-ONBOARDING-S1964-GATE2.md)
sections 1, 2, 3.2–3.3, 8–13 and its Gate 1. Source baseline is the G pin.
The gateway image in the kit is exactly the released v0.2.4 pin in that authority.
It has no `synthetic_download_v1` capability. Do not count reachability, local
preparation or the negative probes as a synthetic download pass.
The source baseline measures 12,052 gateway Go lines against the existing
12,135 cap. C0 changes zero Go lines and neither cap constant.

Before install or connection choice, show the hosting/copies/metadata,
provider-traffic/plan and Windows availability/licence notices in the README.
Own HTTPS is the default. The seller confirms traffic disclosure separately
from any provider plan acknowledgement. A TLS-terminating provider in front of
own HTTPS needs both acknowledgements and a manual/provider origin certificate.
Do not infer legal entitlement from an installed program. Docker's published
free commercial category requires fewer than 250 employees AND annual revenue
below US $10 million. IT must verify the current terms, including boundaries.

The optional named Cloudflare profile is **UNADVERTISED / UNVERIFIED V2/V3**.
The corporate Squid upstream profile is **UNSUPPORTED / UNADVERTISED V4** and is
not shipped as an executable parent-proxy configuration. No tunnelling
transport, upstream-proxy support, plan entitlement or maximum file size is
claimed. Do not enable either path based on a source check.

1. Run the local preparation check from the repository. Native PowerShell
   checks Windows 11, virtualization, WSL2, Docker and Linux-container mode.
   Then run the Linux check inside the distribution that will serve files.
   Python 3.9+ is required there. No host settings or services are changed.
2. Review unknown results locally. The current scaffold leaves source UID
   read/traverse, state write, live hardening, verifier registration, public DNS,
   ingress, sleep/lid/startup and actual control-channel operation unverified.
   Inspect these separately in V1. Static checks do not turn them green.
3. Before running any container, obtain the signed release manifest and bundle.
   There are no approved C0 helper pins or kit signatures in this PR. Missing
   pins or signatures stop execution. Do not invent pins or bypass verification.
4. Check source read/traverse as UID 65532 and state write separately on the
   clean target. Grant narrowly scoped access only. Do not use world-writable
   permissions, root fallback or mount the whole company share. Preserve the
   existing named state volume and identity. C0 does not supply new pairing.
5. Compare all Docker networks and host routes against the kit subnet. The
   preflight checks host routes/listeners where tools are present and leaves
   subnet readiness unknown until Docker networks are inspected too. An
   existing kit also overlaps its own routes, so investigate a reported conflict
   rather than changing its persistent address automatically.

The three Compose documents use JSON syntax, a valid subset of YAML, for an
offline standard-library contract checker. The base creates an internal gateway
network and a separate outbound network for the allow-only Squid proxy. The
gateway has no host port, external network or recursive DNS. Set the local
gateway configuration's `egress.connect_proxy` to `172.30.196.3:3128` before use.
The source/config mounts stay read-only. No pairing variable is in these files.
Compose variable inputs are local paths, never secret values or credentials.
Use protected local configuration and no shell tracing or terminal recording.

The default own-HTTPS overlay uses manual certificates, only host TCP 443 and
no outbound network. The TLS private key is a separate protected read-only
mount used only by the reverse proxy. It never enters the gateway, reports or
source/state mounts. IT must prepare the directory with narrow UID 65532
read/traverse access. The proxy forwards the signed reachability route,
`/v1/files/` and the future `/v1/synthetic/` over the same route, preserving
Authorization, query and Range. No cache, encoding, access log, login, redirects
or challenge pages are configured. This routing does not create a synthetic
handler in v0.2.4. Public DNS must be DNS-only and stable. Do not expose 8080.

`Caddyfile.acme` is an **UNADVERTISED preparation template**, not a runnable
certified overlay. It disables HTTP-01, leaving TLS-ALPN-01. No DNS-01 plugin is
shipped. Initial issuance and renewal have **NOT been demonstrated in C0**.
This is an unmet section 8 evidence requirement: stop ACME profile promotion.
Before promotion, supply verified helper pins and a release-specific CA/DNS
allowlist, enforce it from the reverse-proxy namespace and demonstrate initial
issuance, renewal and denied non-CA/DNS outbound. Do not attach unrestricted
outbound to the gateway or replace this requirement with a self-signed cert.
Use a manual/provider certificate behind a TLS-terminating provider.

The read-only certificate option uses OpenSSL to flag expiry within 14 days.
It does not prove the public hostname, chain or routing. A public certificate
failure requires renewal/correction and the separate outside check. No private
key is read by this check.

The named tunnel template mounts only its non-secret route configuration and
protected credential file. The seller owns the tunnel and DNS zone in the same
account. Keep its named hostname across restarts, disable auto-update and never
use a `trycloudflare.com` address. Credentials never pass through ai.market,
argv or a report. Before V2/V3 acceptance, replace no example with a real
credential in this repository and do not advertise the profile. V2 must test
each candidate transport and a mandatory HTTP upstream from the actual
connector namespace. V3 must re-read current official terms and record dated
content hashes, plan scope and seller acknowledgements. Historical quotations
are insufficient. V5 separately proves large-file behavior.

### Verification inputs and explicit diagnostic action

Release preparation verifies a Cosign Sigstore bundle offline, with exact
GitHub release-workflow identity and OIDC issuer. No new signer type or signing
key is introduced. C8 owns manifest generation/signing/publication. For the
C0 verifier, the signed JSON object is closed: `schema_version:1`,
`kit_version:"0.0.0-c0"`, `gateway_version:"0.2.4"`, `images` and `files`.
`images` has exactly `gateway`, `squid`, `tls_proxy`, `probe`, `cloudflared`,
each an immutable image reference. `gateway` must equal the authority pin.
`files` contains SHA-256 for exactly `FILES` in `scripts/check-install-kit.py`,
binding all scripts, profiles and guidance. Duplicate fields, missing entries,
bad checksums, symlinks and unpinned helpers fail. Fake signatures and example
helper pins are never accepted as release inputs. Verify gateway image
signature, SBOM/provenance and the version/digest allowlist on each relevant
worker separately before promotion, preserving previous registrations.

The following commands are local and explicit. The diagnostic action starts
one temporary helper only after release verification and container inspection.
It never pulls an image, pairs a gateway or starts the gateway service. Run it
only on a separately authorized isolated acceptance host, never production.

```sh
python3 scripts/check-install-kit.py
python3 -m unittest discover -s scripts -p test_install_kit.py
sh install-kit/preflight.sh --report --certificate /local/public-certificate.pem
sh install-kit/preflight.sh --report --start-probes \
  --manifest /local/manifest.json --bundle /local/manifest.sigstore.json \
  --release-tag v0.0.0-c0 --gateway-container isolated-test-gateway
```

The probe shares `--network container:<actual-gateway>` and keeps UID 65532,
read-only root, dropped capabilities and no-new-privileges. It mounts only its
own diagnostic script. It requires AIM CONNECT plus normal TLS hostname/chain
verification, then denies public DNS, direct TCP, arbitrary CONNECT, wrong-port
CONNECT, DNS recursion and forward-proxy attempts through the door helpers.
Fixed results contain no addresses, paths, secrets or logs. Missing helper
images fail without a pull. Cleanup attempts removal even on timeout. This is
finite negative coverage, not proof of all routing, live pinned control,
server canary correlation or helper-namespace isolation. Capture those separate
receipts, including proxy ACME/DNS-only outbound, in check 8.

No diagnostic was run against a real host, Cloudflare or production in this
source change. V1–V4 and Gate 1 checks 2, 3 and 8 remain pending external
acceptance. V1 must record exact Linux server, Linux cloud VM and Windows 11
Home x64 versions, Docker/Compose/WSL versions, virtualization initially off,
UID access, digest/verifier registration and restart/sign-in/sign-out/sleep/
power-loss retention. Do not freeze minima or claim ARM64 without full runs.
Inspect Windows mains/battery/lid policy locally, enable Docker start at sign-in
only by explicit IT action, and demonstrate recovery. Never enable automatic
Windows login. Remote silence cannot distinguish sleep, power or Docker loss.

For corporate inspection, obtain an AIM TLS-inspection exemption. Never disable
TLS verification, widen the exact AIM allow rule or install a corporate root as
a workaround for gateway pins. V4 must require a corporate upstream, deny
direct Squid outbound and test its loss without fallback before that profile
can be supported. If a provider connection is refused, use own HTTPS under IT
policy. Save only sanitized receipts outside the repository. Reports are
seller-supplied acknowledgement, not host attestation or a publication gate.

Upgrade is an explicit seller action using verified release artifacts. Rerun
the tests, preserve state/identity/settings/hostname and verify worker allowlists
before selecting a new image. Rollback changes only the kit release pointer
to a compatible signed release. Stop containers for uninstall, retain volumes
unless the seller deliberately deletes their identity after understanding the
consequence. Never use `down -v` as a repair. There is no agent, remote shell,
background updater, desktop app, per-seller secret artifact or signer chunk.
