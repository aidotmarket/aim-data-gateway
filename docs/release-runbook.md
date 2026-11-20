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
2. Review unknown results locally. Source read/traverse and state write have
   separate explicit diagnostic actions below. Default preparation leaves them,
   live hardening, verifier registration, public DNS,
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

The Compose templates use JSON syntax, a valid subset of YAML, for an
offline standard-library contract checker. Their `x-kit-services` extension
contains no executable Compose services. Direct `docker compose up` on a raw
template cannot start a service. Only the verified entry point below constructs
`services`, with literal image references returned by signature verification.
Helper image environment overrides must match the signed references exactly;
tags and different digests fail before any Compose invocation. The optional
named tunnel has no executable entry point and remains unavailable.

Select `--state-volume` using the exact existing Docker volume name from the
old installation (for example its legacy project's prefixed name). The entry
point inspects that name before invoking Compose, and supplies `external:true`
with the same exact name. The new project name does not change its selection.
An absent name fails without creating storage. Never use an empty replacement.
Inspect the original gateway's volume mount and identity before switching, then
stop the old gateway and disable its automatic restart before cutover. Keep it
stopped throughout migration and subsequent kit operation: recovery must never
open a ledger still served by the old process. Before `up`, the entry point
inspects containers mounting the selected volume and refuses any other running
writer. A stopped legacy container is permitted; repeating `up` permits the
kit's own single gateway. Inspection failure stops startup. This is a snapshot,
not a cross-project lock: IT must prevent concurrent starts of the old gateway
or other writers during and after cutover. Compose cannot attest which existing
volume contains the intended identity. The base creates an internal gateway
network and a separate outbound network for the allow-only Squid proxy. The
gateway has no host port, external network or recursive DNS. Set the local
gateway configuration's `egress.connect_proxy` to `172.30.196.3:3128` before use.
The source/config mounts stay read-only. No pairing variable is in these files.
Compose variable inputs are local paths, never secret values or credentials.
Use protected local configuration and no shell tracing or terminal recording.

The default own-HTTPS overlay uses manual certificates, only host TCP 443 and
an ingress bridge with IP masquerading disabled. The TLS private key is a separate protected read-only
mount used only by the reverse proxy. It never enters the gateway, reports or
source/state mounts. IT must prepare the directory with narrow UID 65532
read/traverse access. The proxy forwards the signed reachability route,
`/v1/files/` and the future `/v1/synthetic/` over the same route, preserving
Authorization, query and Range. No cache, encoding, access log, login, redirects
or challenge pages are configured. This routing does not create a synthetic
handler in v0.2.4. Public DNS must be DNS-only and stable. Do not expose 8080.

Before starting either door profile, IT must deny new outbound flows from its
ingress bridge while allowing established replies to inbound 443. On a Linux
Docker host using the iptables backend, identify the actual ingress bridge and
install persistent REJECT rules equivalent to the following. Insert the general
rule first so the TCP-specific rule ends up ahead of it in each chain:

```sh
iptables -I DOCKER-USER -i <ingress-bridge> -m conntrack --ctstate NEW -j REJECT --reject-with icmp-port-unreachable
iptables -I DOCKER-USER -i <ingress-bridge> -p tcp -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset
iptables -I INPUT -i <ingress-bridge> -m conntrack --ctstate NEW -j REJECT --reject-with icmp-port-unreachable
iptables -I INPUT -i <ingress-bridge> -p tcp -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset
# If IPv6 is enabled, apply the same policy there too:
ip6tables -I DOCKER-USER -i <ingress-bridge> -m conntrack --ctstate NEW -j REJECT --reject-with icmp6-adm-prohibited
ip6tables -I DOCKER-USER -i <ingress-bridge> -p tcp -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset
ip6tables -I INPUT -i <ingress-bridge> -m conntrack --ctstate NEW -j REJECT --reject-with icmp6-adm-prohibited
ip6tables -I INPUT -i <ingress-bridge> -p tcp -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset
```

`DOCKER-USER` covers forwarded traffic; `INPUT` covers connections to the Docker
host itself, including bridge gateway addresses and host services. Install both
before broader accept rules and retain established replies to inbound 443.
For an nftables backend, use equivalent bridge-scoped input/forward rules with
`reject with tcp reset` for TCP and `reject with icmp type port-unreachable` /
`reject with icmpv6 type admin-prohibited` for other IPv4/IPv6 traffic.
These spellings are documented in the [upstream nftables manual](https://www.netfilter.org/projects/nftables/manpage.html);
the exact nftables version and rule load/reboot receipts still belong in V1.
REJECT supplies positive, attributable evidence: TCP connection refusal or an
ICMP unreachable received by the connected UDP probe. A silent DROP cannot
satisfy these diagnostics; an uncorrelated timeout remains inconclusive and
blocks setup. Gate 2 §8 restricts destinations but does not require silent DROP:
“Reverse-proxy outbound is only the configured ACME directory/service endpoints
and required DNS resolver, explicitly pinned/configured per release”.
Do not substitute a public interface for the bridge. The gateway remains single-homed on its internal
network; the door can reach it there. This host rule is an explicit IT action,
not performed by preflight. No-masquerade alone does not deny routed private
networks. On Windows 11 Home/WSL2 with Docker Desktop Linux containers, the same
bridge-scoped forwarding and host-input REJECT policy belongs in the Linux VM
that owns Docker's bridges. `DOCKER-USER`/`INPUT` (or the nftables equivalents)
there enforce the policy; Windows Defender Firewall or rules in an unrelated
serving WSL distribution do not establish this container boundary. IT must apply
and persist the policy explicitly, without a host agent. **UNVERIFIED on Windows:**
this change has no clean Windows host receipt for locating/configuring that
Docker Desktop VM boundary, supported persistent rule installation, ICMP delivery,
or policy survival across Docker Desktop/WSL2/host restart. V1 must establish
those steps and minimum versions before release approval. Do not start service
until enforcement is in place.

Both profiles set the gateway and door's sole DNS upstream to `127.0.0.1`.
On user-defined Docker networks, `/etc/resolv.conf` can name Docker's embedded
resolver, `127.0.0.11`, which returns SERVFAIL when that upstream is closed.
The launcher inspects **each namespace owner's** `HostConfig.Dns`, requires exactly
`["127.0.0.1"]`, and passes that inspected upstream into its namespace probe.
A complete matching SERVFAIL from `127.0.0.11` counts only when a separate
connected-UDP query from that same namespace to the configured upstream on port
53 receives kernel ECONNREFUSED (ICMP port unreachable) or EACCES (administrative
prohibition) after attempting to send the query. A connect-time refusal, a DNS
answer from the upstream, silent loss, bare send permission error, or host/network
routing failure cannot corroborate it. The loopback refusal establishes closure
in the probed container namespace only. It does not establish which namespace
Docker uses to forward to a loopback upstream, or host forwarding enforcement.
No per-container namespace root step, firewall mutation or restart watcher is
required.

The evidence path is the same on Linux Engine and Docker Desktop/WSL2: an
unprivileged helper joins the inspected gateway or door network namespace,
queries the embedded resolver, and queries that namespace's loopback upstream.
Closure of loopback port 53 normally supplies its own kernel refusal; the host
REJECT rules above supply refusal/prohibition for probes that cross the ingress
bridge. Gateway AIM DNS resolution stays in the allow-only CONNECT proxy;
ACME resolution stays in its separate CA proxy. Neither namespace needs direct
UDP DNS. Every public/helper UDP target is still probed independently, so the
embedded-resolver fallback does not replace host-boundary UDP coverage.
V1 must demonstrate both pass markers on a clean Linux host with only the host
rules, repeat after gateway/door recreation, and repeat on Windows Docker Desktop.
Use the delivered launcher with `--start-probes`, exercising its inspected
`--dns-upstream`, `--door-hostname` and `DOOR_HOSTNAME` binding, and capture both
printed markers. Also test Linux with a host resolver listening on `127.0.0.1:53`
and the door attached to its real gateway and non-internal `door-ingress`
networks. Record whether Docker forwards from the host namespace; require the
door marker to stay absent when that resolver can answer the query, including
when it returns SERVFAIL. A Caddy-only internal-network harness does not cover
these cases. Those full-kit/restart and host-resolver receipts remain
**UNVERIFIED**; offline fixtures do not certify them. Keep helpers at UID 65532
with zero capabilities and no host sockets.

Both profiles need external `curl` reachability on host 443 and negative direct
TCP/DNS tests from the actual door namespace. `--start-probes` requires
`--gateway-container`, `--door-container` and `--door-hostname <stable-hostname>`
in both manual and ACME modes. For the manual profile, use a hostname present
in the certificate's names for `--door-hostname` and `DOOR_HOSTNAME`.
The launcher checks that the signed door is
running on the gateway network, then joins each namespace separately. Reports
record the door as running and the unavailable tunnel as unselected. An absent
helper is never a denial receipt. On the already-inspected door, refusal of a
closed listener on 3128/8080 proves that listener unavailable. Port 8443 must
complete a TLS handshake and present a server certificate (certificate trust is not required
for this protocol check). It connects to `172.30.196.4:8443` while sending the
configured door hostname as TLS SNI; an IP literal would omit SNI and can prevent
Caddy from selecting the hostname-only certificate. The launcher requires the
inspected door's `DOOR_HOSTNAME` to match the selected hostname. Attribution assumes that `172.30.196.4` remains the
address of the door inspected at preflight and that traffic is not redirected
between inspection and the probe. The 8443 check proves denial only for that
inspected address under this assumption; it does not authenticate the door's
identity. Certificate pinning is not part of this protocol check. CONNECT is then
sent inside TLS: a final non-2xx HTTP response or a clean TLS close before any
response bytes proves denial. The ACME listener has an explicit 403 fallback
for unmatched authorities; otherwise Caddy can return an empty default 200 for
a forbidden CONNECT host without opening a tunnel, blocking the diagnostic.
Every response must have a strict HTTP/1.0 or HTTP/1.1 status line and a complete
CRLF-terminated header section with valid token field names and field values,
limited to 64 fields and 4096 header bytes per response. Framing must also be
valid: Content-Length values must be non-negative decimal integers with all
repetitions (including comma lists) identical in value. Conflicting/invalid
lengths, Content-Length with Transfer-Encoding, and unsupported transfer codings
are inconclusive. Only a single `chunked` transfer coding on HTTP/1.1 is supported;
framing fields on 1xx/204 responses are rejected. This validation applies
to informational and final responses on both plaintext and TLS CONNECT paths,
including the allowed route. Informational 1xx responses are read through to a
final status under the same read deadline, with at most five informational
responses accepted. Protocol switching (101) is inconclusive. A close or timeout
after a 1xx without a final status, or exceeding that limit, is inconclusive.
EOF/reset before the handshake, missing certificates, timeouts, unclean TLS
closes, and malformed or incomplete replies remain inconclusive; every CONNECT
2xx on any forbidden path fails the negative check. All negative probes use
`True` for denied, `False` for reached, and `None` for inconclusive; every required
probe must return exactly `True` before either namespace prints a pass marker.
Direct TCP probes in both namespaces require an explicit connection refusal.
The gateway's internal network has no default internet route, so direct TCP
and DNS can instead produce kernel ENETUNREACH: this counts only when the
same namespace's read-only `/proc/net/route` also confirms no IPv4 route to
that exact target. A matching route, unreadable/malformed route table, other
routing error, timeout, reset or other transport failure remains inconclusive.
DNS probes require a complete, matching standard response from the queried peer,
with the expected transaction ID and question. NXDOMAIN or REFUSED without
answers, or NOERROR/NODATA with an IN SOA in the authority section whose owner
equals the query name or an ancestor at a DNS label boundary (including root),
proves DNS denial. An unrelated zone's SOA is inconclusive. A referral (NS authority without SOA) or an empty NOERROR reply is
inconclusive. A matching positive A answer
(including a CNAME chain) fails the negative check. Malformed, truncated, unrelated
or unsupported DNS replies are inconclusive. An explicit connected-UDP refusal
or administrative prohibition received after sending the query also proves denial.
Post-send EHOSTUNREACH/ENETUNREACH are inconclusive: a router with a dead uplink
can produce them without an isolation rule.
Corroborated kernel no-route evidence as above also proves denial. Timeouts
and other transport failures remain inconclusive. Every nameserver
entry in resolv.conf is tested, including IPv6 and scoped IPv6 addresses, using
its address family. An invalid or unprobeable entry blocks the namespace pass.
The allow-only Squid proxy requires a complete, valid final 403/405/407 for
denial; 3xx, 5xx and other non-2xx responses are inconclusive because they can
reflect attempted forwarding. Inspected door plaintext listeners retain their
reviewed semantics: an explicit connection refusal or a complete valid final
non-2xx response proves denial. All CONNECT 2xx responses fail the negative check.
V2 must add explicit connector presence and its own namespace tests before enabling that optional profile. Denial probes
are diagnostic coverage, not a proof of all firewall rules. V1 must also test
host/daemon restart, ingress and persistent outbound enforcement, including
denied connections to a controlled host listener through INPUT and to a routed
destination through DOCKER-USER, while inbound 443 replies still work. The ingress
subnet `172.30.198.0/29` and ACME subnet `172.30.197.0/29` need the same separate
Docker-network/host-route conflict review as the gateway subnet.

`compose.acme.yaml` and `Caddyfile.acme` are **UNADVERTISED / UNVERIFIED**
acceptance configurations. The explicit verified entry point can select this
configuration with `--certificate-mode acme --door-hostname <stable-hostname>
--acme-state-volume <existing-certificate-volume>` instead of manual certificate
and key options. IT must prepare that separate persistent volume with UID 65532
write access; it is external and must already exist. `/data` survives recreation.
The proxy listens only on host 443, disables HTTP-01 and uses TLS-ALPN-01 with
the fixed Let's Encrypt production directory. Do not attempt issuance through
a TLS-terminating provider; use the manual/provider certificate there.

The door has restricted DNS, internal gateway and ACME networks, and the separate ingress bridge. It
uses a dedicated CONNECT proxy for ACME HTTPS, allowing only
`acme-v02.api.letsencrypt.org:443`; that proxy alone resolves through 1.1.1.1. The control proxy accepts only the
gateway source IP, so the door cannot use it to bypass the CA-only proxy.
The gateway never joins the ACME network. The separate proxy consumes the same
verified Squid pin and has no source, gateway-state or private-key mount.
The ingress bridge supplies inbound port publishing. Disabling masquerade is not a complete outbound firewall: routed LANs and Docker Desktop behavior need explicit host enforcement as described above. These settings have
only offline validation here; live Caddy proxy use and actual denial remain
unverified. Stop if the CA requires another endpoint; do not widen the rule.

**C0 is incomplete and must not be accepted:** Gate 2 §8 requires initial
issuance, renewal, expiry-warning and denied-egress receipts. No live issuance
or renewal was performed, no amendment was obtained, and source tests do not
satisfy that requirement. On the isolated acceptance host record the verified
kit/helper versions, initial public chain and expiry, renewal using the same
persistent state and public hostname, the 14-day warning, and forbidden direct
TCP, DNS and non-CA CONNECT attempts from the actual door namespace. Capture
sanitized results outside the repository. Keep the profile unadvertised until
these receipts exist; a self-signed certificate is not a substitute.

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
# Inspect or start the exact same verified configuration. Local paths stay local.
python3 scripts/check-install-kit.py --compose-action config \
  --manifest /local/manifest.json --bundle /local/manifest.sigstore.json \
  --release-tag v0.0.0-c0 --state-volume legacy_aim-gateway-state \
  --source-folder /local/export --gateway-config /local/gateway.toml \
  --certificate /local/public-certificate.pem --private-key /local/server.key \
  --door-hostname data.example.org
# Use the identical arguments with --compose-action up for explicit startup.
# No pull is performed. Inspect config output locally; do not share private paths.
python3 -m unittest discover -s scripts -p test_install_kit.py
sh install-kit/preflight.sh --report --certificate /local/public-certificate.pem
# Explicit read check: mounts only the export read-only, no networking.
sh install-kit/preflight.sh --report --check-source --source-folder /local/export \
  --manifest /local/manifest.json --bundle /local/manifest.sigstore.json \
  --release-tag v0.0.0-c0
# Explicit write check: creates/fsyncs/removes an exclusive random sentinel only.
sh install-kit/preflight.sh --report --check-state-write --state-volume legacy_aim-gateway-state \
  --manifest /local/manifest.json --bundle /local/manifest.sigstore.json \
  --release-tag v0.0.0-c0
sh install-kit/preflight.sh --report --start-probes \
  --manifest /local/manifest.json --bundle /local/manifest.sigstore.json \
  --release-tag v0.0.0-c0 --gateway-container isolated-test-gateway \
  --door-container isolated-test-door --door-hostname data.example.org
```

The probe shares `--network container:<actual-gateway>` and keeps UID 65532,
read-only root, dropped capabilities and no-new-privileges. It mounts only its
own diagnostic script. It requires diagnostic-process AIM CONNECT plus normal TLS hostname/chain
verification, then denies public DNS, direct TCP, arbitrary CONNECT, wrong-port
CONNECT, DNS recursion and forward-proxy attempts through the door helpers.
CONNECT reads a complete status line bounded to 4096 bytes and a total deadline.
Every 2xx is open (a failed negative check); only explicit 403/405/407 denials
prove denial. Malformed, partial, disconnected and other ambiguous replies are
inconclusive. Aggregate `egress` stays unknown even when all negative checks
pass, because diagnostic TLS does not prove the gateway's own control operation.
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

All selected serving helpers use `restart: unless-stopped`, matching the gateway.
Offline checks enforce that policy; daemon restart and deliberate-stop retention
still need live V1 receipts for both the control connection and same public door.
Native Windows WSL selection requires `-ServingDistro <exact-name>`; the Linux
check requires `--platform windows_wsl2 --serving-distro <same-name>`. It matches
`WSL_DISTRO_NAME` and the actual WSL2 kernel, never the caller's platform label
alone. An unrelated WSL2 utility distribution cannot establish serving readiness.
Native PowerShell execution remains unverified on this host.

The UID-source read/traverse and state-write diagnostics now exist as separate
explicit actions; they remain unknown in default read-only preparation. Live
UID permissions and sentinel cleanup on each supported host remain open C0/C8
acceptance work under §8. Signature/file verification sets `integrity`; inspection of the selected running gateway image and its local RepoDigests sets `image_digest`.
Unknown checks have null timestamps;
`generated_at` records report creation, not evidence of those checks running.
Caddy adaptation with the future signed TLS helper, initial issuance/renewal,
and Windows PowerShell 5.1 plus current PowerShell execution remain open receipts.
