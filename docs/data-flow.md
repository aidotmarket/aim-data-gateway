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
