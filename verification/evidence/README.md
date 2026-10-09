//go:build evidence

# Checkpoint 8.2 :414 customer runner (closure amendment A3)

This is an evidence-only harness for [runbooks PR #505](https://github.com/aidotmarket/runbooks/pull/505), based on gateway `25779953b1c27e0dec5f39ba871422a6b81f8cff`. It is **not a release artifact**. Every added Go file requires `-tags evidence`; no existing source, configuration, module file or release recipe changes. The committed synthetic fixture is the `SyntheticFixture` constant in `runner_fixture.go`: a 20-row CSV materialized in a fresh private directory. Only that directory is configured as a source.

## Transport and product paths

At backend `113856e0`, the native `aim_gateway` protocol uses:

| Operation | Normal backend route and implementation reused |
| --- | --- |
| Pair gateway identity | HTTP `POST /api/v1/gateway-channel/pair`, `pairing.Pair` |
| Register verification receipt key | `scan_report/register` signed audit frame on WebSocket `/api/v1/gateway-channel`, `Gateway.RegisterVerification`, `Keys.Registration` |
| Take paired work/specs | Same WebSocket, `channel.Client`, `Gateway.VerificationControl`, `Runner.Submit` |
| Fetch signed source snapshot | HTTP `GET /api/v1/verification-runners/{runner_id}/snapshot/{manifest_hash}`, product request signer and `wire.VerifySnapshot` |
| Probe and scan reports/receipts | Same WebSocket, product scanner, report builder, receipt signer, durable ledger/outbox, signed audit envelopes and backend acknowledgments |

The HTTP `/verification-runners/register`, `/{runner_id}/work` and `/{runner_id}/report` handlers accept AWS/Cloudflare runners, not `aim_gateway`. Using those handlers would replace the gateway protocol. The harness therefore uses the native gateway channel plus its native HTTP snapshot route. Work is requested by the real website flow and dispatched by the backend; there is no fabricated customer work poll or locally issued spec.

Transport substitutions are confined to:

1. Supplying the test origin to `pairing.Pair` and the equivalent `ws://` URL to `channel.Client` through their existing injection points. Request bodies, hello signing, resume/ack handling and wire frames remain product code.
2. Mapping the product snapshot request's logical `https://api.ai.market` origin to the test origin in `testTransport`, before any network operation. Method, path, authorization signature and body are unchanged. The response's `Request` metadata is restored to the logical request so the product's origin assertion succeeds; response status, headers, body and signed snapshot bytes are unchanged. This is a test transport substitution, not evidence of production TLS.
3. Disabling environment proxies and redirects. Only HTTP origins with the exact hostname `localhost`, `127.0.0.1`, or S1656's backend Compose service `backend` are accepted. Userinfo, path prefixes, queries, fragments, other hosts and all HTTPS base URLs (including `https://api.ai.market`) are refused. Unmapped outbound origins are rejected before dialing.

`EvidenceChannel` is evidence-tagged callback wiring matching `Gateway.Run`. It omits the download door and external DNS canary, which are outside :414, and uses one native connection so disconnects remain visible failures. The harness requires pairing scan pins to match the explicit test public key and verifies each received probe/scan with `wire.VerifyScan`; product `Submit` repeats verification and performs normal snapshot, consent, replay and source admission. It never calls private scanner symbols; those existing symbols are used only by the gen2 comparison test. Commitment and receipt keys come from product CSPRNG/storage code.

## Running against S1656 (future operator action)

No stack execution or S1656 changes are part of this PR. The operator must first have the authorized test environment and browser journey ready: backend with the gateway routes above, frontend with `GatewayVerificationFlow`, real Redis/workers, Stripe TEST, a test-only scan signer trusted by the test backend, pairing scan pins, and an accepted test image digest/scanner version. The harness does not provision any of these or permit a production endpoint override. Any narrative-call budget is owned by the separately authorized browser/API run.

Generate a single-use pairing code through the test website's normal gateway flow. Set `TEST_SCAN_KID`, `TEST_SCAN_PUBLIC_HEX`, `TEST_SCANNER_VERSION`, `TEST_IMAGE_DIGEST` and `TEST_PAIRING_CODE` to those test values. The public key is 32-byte Ed25519, hex encoded; no signer private key is given to the harness. From the gateway repository root:

```sh
rtk proxy go test -c -tags evidence -o /var/tmp/cp82-evidence-runner ./verification/evidence
rtk proxy env AIM_GATEWAY_IMAGE_DIGEST="$TEST_IMAGE_DIGEST" \
  CP82_RUNNER_ENABLE=1 CP82_RUNNER_BACKEND=http://localhost:18000 \
  CP82_RUNNER_DIR=/var/tmp/cp82-414-fresh-run \
  TEST_PAIRING_CODE="$TEST_PAIRING_CODE" \
  TEST_SCANNER_VERSION="$TEST_SCANNER_VERSION" \
  TEST_SCAN_KID="$TEST_SCAN_KID" TEST_SCAN_PUBLIC_HEX="$TEST_SCAN_PUBLIC_HEX" \
  /var/tmp/cp82-evidence-runner -test.run '^TestRunnerS1656$' \
  -test.v -test.timeout 35m
```

The `CP82_RUNNER_DIR` parent must exist and the directory itself must not exist. The product image-digest registration field is explicit test provenance, not a claim that this executable is a released image. For a runner already placed on the S1656 Compose network, set `CP82_RUNNER_BACKEND=http://backend:8000`; this PR does not attach a container or alter that network. The runner has a 30-minute deadline. Without `CP82_RUNNER_ENABLE=1`, the live entry point skips before any filesystem or network operation. The test executable packaging also keeps test transport out of the repository's default dial-site inventory, which scans source files without evaluating build tags.

The runner publishes inventory of the synthetic fixture through the native channel. In the real test website, select that gateway/file, create the listing/source binding and let the backend issue its signed offer. Run the free probe, then the normal authorized paid scan. The runner waits for backend-issued work and stops successfully only after cumulative channel acknowledgments include both probe and successful scan reports. Terminal reports, disconnects and timeout fail the run. It does not manufacture quotes, consent, offers, authorization, epochs, captures or findings, and does not accept a prebuilt spec from a file.

Retain the local `state/audit` frames and `state/verification-audit.jsonl` with the browser/API evidence. The state directory also contains private customer-side keys; retain it privately. A successful runner exit proves only acknowledgment of those frames. :414 (i)-(iv) still require the real browser/API checks of preauthorization refusal, before/after findings, cache/Redis and backend/worker logs. Runner execution alone does not prove them.

## Local validation and release identity

```sh
rtk proxy go build ./...
rtk proxy go test ./...
rtk proxy go test -tags evidence ./verification/evidence -run TestRunner -count=1 -v
rtk proxy go test -race -tags evidence ./verification/evidence -run TestRunner -count=1
```

The host tests cover allowed test origins and production/deceptive origins. The transport test checks unchanged signed bytes and refusal before forwarding. The gen2 comparison uses the existing `newHarness.scan` capture path to construct native registration/probe/scan frames, then compares every byte received through the real `channel.Client` on an isolated `httptest` WebSocket, including the signed report/receipt bodies and audit envelopes. These tests do not connect to S1656.

For release identity, compare an archived pristine base with this checkout using the unchanged Dockerfile build command, with identical platform/toolchain and `VERSION=0.0.0-dev`:

```sh
rtk proxy env CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -ldflags='-s -w -buildid= -X main.version=0.0.0-dev' \
  -o /private/evidence/aim-gateway ./cmd/aim-gateway
rtk proxy shasum -a 256 /private/evidence/aim-gateway
```

This is the release/default-tag recipe. A plain local `go build -o ... ./cmd/aim-gateway` also embeds Git revision and dirty status by default; hashes from clean/dirty trees differ solely for that provenance and cannot establish release identity. Preserve both observations in the validation report instead of calling those local builds byte-identical.

Validation for this change used Go 1.27.1 on darwin/arm64: default `go build ./...` before and after passed, `go test ./...` passed, and the three local runner tests passed with and without `-race`. The S1656 entry point skipped. The pristine-base and final-checkout release-recipe binaries both have SHA-256 `fde275c095121dab949e1a552f9d7204e03c805cc7238d2674cd24e4c658c358`; `cmp` returned success. Full private logs, the initial failures and both plain local builds are retained in `/var/tmp/cp82-414-private/`. The initial dial-site failure was resolved by test-executable packaging, without changing the dial audit or any other existing file. No stack connection, deployment or container operation was performed.
