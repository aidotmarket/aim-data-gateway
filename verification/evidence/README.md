//go:build evidence

# Checkpoint 8.2 :414 customer runner — A4 harness changes

Evidence-only descendant of `5235a7d147e25af752ac243a2df7ff5a8ba19220` on [gateway draft PR #26](https://github.com/aidotmarket/aim-data-gateway/pull/26). Governing specification: [runbooks `1266a797`, A4](https://github.com/aidotmarket/runbooks/blob/1266a797/specs/BQ-DATA-VERIFICATION-S1590-CP82-414-S1656-READINESS.md), §3.3, §4, harness-side §3.1/§3.2 and §5 steps 1–2. Release baseline remains `25779953b1c27e0dec5f39ba871422a6b81f8cff`.

All Go changes are `//go:build evidence` in `_test.go` files. Product source, dependencies, configuration, Dockerfile and release recipes are unchanged. This test executable is not a seller release. Local validation does not establish S1656 readiness or :414 acceptance; **:414 remains NOT_RUN**.

## Public expectations and product admission

Set all three public-only pairs; no signer private material belongs in this runner:

| Class | Variables | Required KID |
| --- | --- | --- |
| Permission | `TEST_PERMISSION_KID`, `TEST_PERMISSION_PUBLIC_HEX` | `s1656-test-permission-v1` |
| Listing | `TEST_LISTING_KID`, `TEST_LISTING_PUBLIC_HEX` | `s1656-test-listing-v1` |
| Scan-spec | `TEST_SCAN_KID`, `TEST_SCAN_PUBLIC_HEX` | `s1656-test-scan_spec-v1` |

Each hex value is a distinct 32-byte Ed25519 public key derived in guarded operator custody from the existing signer file. Fresh pairing must return exactly its expected pin in each class. Missing, additional, foreign, malformed, wrong-algorithm, swapped-class and reused-key expectations fail closed. Only scan-spec expectations enter the extra `wire.VerifyScan` check. The product channel verifies outgoing rotation before `Gateway.Handle`; a successful scan-class rotation extends that extra restriction using the product's resulting scan pins. Permission/listing rotation never extends it. `InitVerification` retains its own active/historical providers, expiry, registration, snapshot, consent, replay and source admission checks. The door's permission provider reads serialized paired snapshots and filters expiry, including rotated permission keys.

Normal product paths remain `pairing.Pair` → signed native gateway channel → `RegisterVerification` / `VerificationControl` / `Runner.Submit` → signed HTTP snapshot → durable product probe/scan reports, receipts and channel acknowledgments. The AWS/Cloudflare HTTP work/register/report paths are not used. Backend/browser flows must issue real offers and authorized work; this runner never mints customer specs or writes listing, readiness, money or epoch rows.

## Internal TLS, door and canary

The only accepted control origin is **`https://backend:8443`** (an optional trailing slash is normalized). HTTP, localhost, production, arbitrary hosts/ports, userinfo, origin queries/fragments and path prefixes are refused. Supply the exact reviewed S1656 network subnet and backend TLS-proxy IP through `CP82_COMPOSE_CIDR` and `CP82_COMPOSE_BACKEND_IP`. The existing guard requires a canonical RFC1918 IPv4 /24 or narrower and an exact private address inside it; the complete resolution must contain only that address. The final dial uses a validated IP literal on TCP 8443 without re-resolution. The subnet/IP values are explicit reviewed inputs, not inferred from the service hostname.

`CP82_TEST_CA_FILE` must identify the public ephemeral test CA PEM. The client trusts only that supplied root pool, validates certificates/expiry and the `backend` hostname with SNI, and requires TLS 1.2 or newer. Pairing uses HTTPS and the native channel uses **wss**. Environment proxies are disabled and redirects are returned without following them. Logical product snapshot GET requests under `https://api.ai.market/api/v1/verification-runners/{runner_id}/snapshot/{manifest_hash}` map only the origin to the internal proxy. Method, path, signed headers, request body and signed response bytes are unchanged. Logical response request metadata is retained for the product origin assertion. This tests evidence transport, not released production TLS/SNI.

The runner instantiates the real `internal/door.Door` on **`:8082`**, with the channel's paired gateway ID and private identity key (`gateway` KID). It owns listener startup and bounded shutdown; bind/serve failures stop the run. No host port is published here. The future environment's reviewed door proxy must forward only GET `/.well-known/aim-gateway` with its nonce query, preserve the compact JWT and reject all other methods/paths. Public routing/TLS, proxy restrictions, network policy, seller `door_url` update and the real backend readiness task are environment-side work, outside this change.

The Canary callback runs **`canary.Probe{}`**, using the actual system resolver/dialer, and appends the returned result with **`g.Log.Append("canary_result", result)`**. It requires exactly `s1656-egress-canary.ai.market` / `s1656-gw-canary.ai.market` and an empty CONNECT proxy. Errors/cancellation append no result; there is no fake closed path. Closure requires a separately reviewed runner namespace/default-deny policy, real positive controls, analytics and scheduled product correlation. These are not supplied or claimed by local unit tests. The callback's local regression exercises the product probe with an explicit **open** DNS fixture and actual local TCP connection, and verifies its durable audit body; no test connects to S1656 or Cloudflare.

The runner uses one native connection, with no hidden reconnect. After probe and successful scan acknowledgments it **stays connected** for scheduled canary correlation and freshness evidence. The product's hourly canary interval exceeds this runner's 30-minute deadline, so no newer periodic result is sent during the run. An operator sends SIGTERM/SIGINT after collecting the normal API/readiness and :414 evidence; clean cancellation succeeds only after both acknowledgments. Timeout, disconnect, terminal report and door failure remain failures. Successful exit proves acknowledgments only, never readiness/correlation or payment/findings acceptance.

## Future authorized invocation

Compile locally; running against the stack requires the separate §5 review and execution gates. The environment must first supply the owned network, internal TLS proxy/CA, restricted runner policy, door proxy, signer/public pairing pins, dedicated worker/beat, approved canary correlation and frozen actual evidence runtime version/manifest digest. Do not reuse a release digest as proof of this test executable.

```sh
rtk proxy go test -c -tags evidence -o /var/tmp/cp82-evidence-runner ./verification/evidence
```

For a future separately authorized runner already inside that network, supply:

```sh
rtk proxy env AIM_GATEWAY_IMAGE_DIGEST="$TEST_IMAGE_DIGEST" \
  CP82_RUNNER_ENABLE=1 CP82_RUNNER_BACKEND=https://backend:8443 \
  CP82_COMPOSE_CIDR="$CP82_COMPOSE_CIDR" \
  CP82_COMPOSE_BACKEND_IP="$CP82_COMPOSE_BACKEND_IP" \
  CP82_TEST_CA_FILE="$CP82_TEST_CA_FILE" \
  CP82_RUNNER_DIR=/owned-state/cp82-414-fresh-run \
  TEST_PAIRING_CODE="$TEST_PAIRING_CODE" TEST_SCANNER_VERSION="$TEST_SCANNER_VERSION" \
  TEST_PERMISSION_KID=s1656-test-permission-v1 TEST_PERMISSION_PUBLIC_HEX="$TEST_PERMISSION_PUBLIC_HEX" \
  TEST_LISTING_KID=s1656-test-listing-v1 TEST_LISTING_PUBLIC_HEX="$TEST_LISTING_PUBLIC_HEX" \
  TEST_SCAN_KID=s1656-test-scan_spec-v1 TEST_SCAN_PUBLIC_HEX="$TEST_SCAN_PUBLIC_HEX" \
  /var/tmp/cp82-evidence-runner -test.run '^TestRunnerS1656$' -test.v -test.timeout 35m
```

The parent directory must exist; the run directory must not. Only the synthetic 20-row CSV in `runner_fixture_test.go` is materialized/configured as a source. Retain `state/audit`, `state/verification-audit.jsonl` and browser/API/cache/Redis/worker evidence privately. State contains private customer-side identity/receipt/commitment keys and requires guarded custody/disposal. Without `CP82_RUNNER_ENABLE=1`, the entry point skips before filesystem/network operations.

## Local validation and identity

Focused tests cover all-class expectations and swaps; product scan rotation/admission with retired-key refusal and historical retention; door identity/nonce/signature and permission rotation/expiry; canary probe/audit, cancellation and foreign namespace/proxy refusal; TLS/CA/hostname/expiry, wss, exact destination/port/DNS and redirect/origin/proxy guards. Native signed registration/probe/scan frames are compared byte for byte against the gen2 capture through `channel.Client` over local test TLS/wss.

```sh
rtk proxy go build ./...
rtk proxy go test ./...
rtk proxy go vet ./...
rtk proxy go test -tags evidence ./verification/evidence
rtk proxy go test -race -tags evidence ./verification/evidence -run TestRunner -count=1
rtk proxy python3 scripts/count-lines.py
rtk proxy python3 scripts/gen-outbound-doc.py --check
```

Release identity uses the unchanged pinned Dockerfile builder, identical platform/toolchain and `VERSION=0.0.0-dev`, separately for an archived pristine `25779953` and this candidate. The extracted `/aim-gateway` binaries must have identical SHA-256 and `cmp` success. Evidence-tagged test packaging stays outside release/default-tag builds and the source-line/dial inventory. Full commands, output (including intermediate failures), binaries and identity proof are retained privately in `/var/tmp/cp82-a4-private/`; final results are recorded below after validation. No S1656/DNS/Cloudflare provisioning or connected acceptance is part of this build. Future execution still requires fresh current Council review of the exact candidates, the S1656 ownership/lock and custody gates, and one logical real narrative request with at most one counted retry under Max Event `0b0955b1`; teardown/no-effect evidence is required before any environment success claim.

A4 local validation (2026-10-09): default build/tests/vet, the complete evidence suite, focused runner race tests, evidence vet/executable compilation, module budget, outbound inventory and diff checks all pass. The live S1656 test skips. Source gate: **9274 / 9275** gateway non-test lines. Both pinned Dockerfile-builder release binaries (Go 1.27.1, linux/arm64, `VERSION=0.0.0-dev`) are **25,559,164 bytes**, SHA-256 **`351bc52ab9b63b31b1a978c20640cd05445cbe9460c12a2ad507ef89cb7f7e95`**; `cmp` passes against pristine `25779953`. Every source diff from the release base is evidence-tagged test code; remaining diffs are this evidence documentation. Private logs include the initial cleanup compile error and two corrected test-fixture assertions (HTTP-client request cloning and rotated payload `platform_key_id`); failures were retained. No stack connection, network-policy deployment, environment configuration, DNS or Cloudflare mutation was performed.
