# Data flow and egress

```text
Customer folders --read-only--> gateway --HTTPS control--> api.ai.market:443
                                      |
                                      +--internal HTTP door--> seller TLS proxy --> buyer
```

The customer mounts `/config/gateway.toml` read-only, `/sources/<name>` read-only, and `/state` as the only writable volume. The gateway reads those sources and maintains its identity, block index, byte ledger, and audit chain locally. It has no cloud credentials for the customer's storage.

## What leaves the host for ai.market

- **Phase 1, automatic:** opaque gateway-keyed file ids, neutral or customer-configured display aliases, size, media type, timestamps, and gateway-keyed content commitments. No raw SHA-256, path, file name, directory name, or column name is sent.
- **Phase 2, one file after the seller confirms:** the raw SHA-256, renamed and filtered column names, inferred types, row count, null rates rounded to 5%, and bucketed distinct counts. No cell values, minima, maxima, top values, or free text are sent.
- **Operations:** signed `hello`, inventory/description, offer and prepare acknowledgements, revocation acknowledgements, cumulative receipts, `canary_result`, errors, and the gateway's signed audit entries. See [outbound messages](outbound-messages.md) for vector examples. The audit view shows the exact sent bodies.
- **Public sample exception:** a separately authorized seller action on the website may publish selected sample bytes under the platform sample limits. It is not part of automatic gateway metadata.

File bytes do not go to ai.market during delivery. They leave the host only through the seller-controlled door to the authorized buyer. The buyer's browser verifies downloaded bytes locally against the listing SHA-256; it does not upload the file for verification.

## Network paths

The only successful outbound destination from the gateway is `api.ai.market:443`, directly or by HTTP CONNECT through the customer's allowlisting proxy. The gateway also attempts canary DNS resolution under the ai.market canary zone and TLS connection to `egress-canary.ai.market:443`; both must fail. A successful canary makes the installation unsupported and blocks new permissions. The customer must enforce deny-all egress except the control destination, including the documented DNS restriction.

The only inbound gateway port is the internal HTTP door. The seller's reverse proxy terminates HTTPS for buyer downloads and ai.market's periodic signed door probe. There is no inbound management UI, tunnel, telemetry endpoint, or auto-update channel.

## Verification flow

Server-to-gateway `scan_spec` messages are Ed25519 compact JWS signed by the dedicated scan-spec key. They bind the runner, persistent listing source UUID, published listing version, snapshot hash, consent time, authorization and nonce. Scan D6 choices are separately signed, bounded companions; the gateway validates their fixed ASCII enum vocabulary (NFKC is the identity for accepted values). Python-canonical spec/report/snapshot bytes are carried in canonical unpadded base64url, preserving float and escaping semantics independently of the gateway audit encoding.

The only additional outbound HTTP path is the authenticated snapshot GET at `https://api.ai.market/api/v1/verification-runners/{runner_id}/snapshot/{manifest_hash}`, through the same channel/proxy client. A receipt-key-signed request binds exact method/path, gateway/runner, a fresh random nonce and UTC time. Redirects and oversized responses are refused. The signed snapshot contains existing 32-hex file IDs, 64-hex SHA-256 hashes and sizes, never paths. Listing delivery hashes and verification snapshot hashes remain distinct.

Admission checks signature, schema, bindings and current offer metadata without opening a source. SQLite `BEGIN IMMEDIATE` consumes nonce/authorization and listing/UTC-day quota atomically under WAL/FULL; the identity-key local audit is synced before dispatch. The separate single worker and one pending slot leave heartbeats, revocation, delivery, canary and ordinary descriptions independent. E7 inspects original schema names locally after admission, before aggregate computation, and effective rules and offer containment are checked at every member open.

The shared scanner verifies pinned bytes in two complete passes. Every reachable supported member is traversed; unsupported containers are disclosed skips, never expanded. Mutation refuses the entire scan. The independent commitment key HMACs typed ASCII gateway/file/hash preimages; ordered content framing uses the unchanged gateway file IDs directly. Scanner working memory is bounded at 128 MiB additional, with a 30-minute deadline, 16 MiB records/scalars, 1,000 columns and a 32,768-byte fact envelope. The existing eight download buffers remain additional live allocations, not part of a claimed whole-container 128 MiB limit.

`scan_report` uses the existing six-field identity-key audit chain. Its exact decoded probe, successful, terminal or registration document is bounded; successful/terminal/probe receipts use the separate receipt key. No hidden column names, raw values, samples, paths, arbitrary error strings or inferred D6 choices leave. The full frame remains at most 1 MiB and decoded documents at most 700 KiB. Results commit to the local outbox before audit append; stable IID plus exact body reconciles append-before-SQL crashes. Server ack/resume proves storage, not report acceptance or payment settlement.

Keys are three separate trust domains: gateway identity, gateway receipt, and independent commitment secret. ai.market permission/listing/scan-spec public-key classes remain distinct. Bootstrap extends an existing listing-key trust only while scan pins are empty. Later scan-key rotation requires the outgoing scan key; old pins expire for new work after seven days and are retained for historical verification.
