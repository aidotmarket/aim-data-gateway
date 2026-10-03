# Threat model

This is the Gate 1 and Gate 2 v1 boundary for a seller-hosted AIM Data gateway. The customer chooses mounted sources, the local offer ceiling, egress policy, and the public HTTPS door.

## Assets and boundaries

| Boundary | Assets and allowed flow |
| --- | --- |
| Customer host → container | Read-only source mounts and config; one writable `/state` volume holds identity, secret, ledger, and chained audit log. The container has UID 65532, read-only root, no capabilities, no new privileges, and no host socket. |
| Container → ai.market control plane | One pinned TLS dial path to `api.ai.market:443`, directly or through the customer's allowlisting CONNECT proxy. Signed gateway messages carry metadata, canary results, receipts, and audit entries. |
| ai.market → container over that channel | Signed listing and permission instructions, key rotation, minimum version, and revocation. The gateway checks signatures, file/version binding, expiry, local offer ceiling, and optional local approval. |
| Buyer → seller door | Buyer receives a signed permission after purchase and downloads bytes directly through the seller's HTTPS reverse proxy. ai.market never relays file bytes. |

The seller's door hostname and TLS certificate may identify the seller to a buyer; the seller acknowledges this before publishing. The door sees the buyer's network address. Permissions carry no buyer identity.

## Attackers and controls

| Attacker | Risk | Mitigation |
| --- | --- | --- |
| Compromised ai.market | Tries to make arbitrary files offerable, issue broad downloads, or change gateway code. | Non-custodial deployment: ai.market cannot mount sources, change config, or self-update the image. A listing-key instruction is signed by a dedicated KMS key and must fit the local offer ceiling; optional local approval closes the remote offer path. A separate KMS permission key signs one file/version/order permission with deadlines. The gateway checks each before serving. |
| Buyer or stolen permission | Replays a token or drains a file repeatedly. | Permission binds to gateway, order, file id and SHA-256. Start and transfer deadlines, durable `jti` ledger, per-byte serve counts and revocation limit reuse. The gateway verifies each 8 MiB block against its local block list before writing bytes. A matching cumulative receipt is needed for settlement, with a problem path for mismatch. |
| Network attacker | Intercepts control traffic, opens unexpected egress, or probes the door. | Pinned TLS chain and one dial path; customer deny-all egress except `api.ai.market:443`. DNS/TCP/proxy canary probes and ai.market observations mark open egress unsupported. The door requires HTTPS at the seller's proxy. Signed nonce response proves door identity; backend door checks pin the resolved IP and refuse redirects/private addresses. |
| Local user on host | Reads mounted data, state, or Docker control. | Customer controls host access and mount ownership. The container is non-root, has only read-only source/config mounts, one state volume, no Docker socket, no host namespaces, no added devices or capabilities. Startup self-check refuses visible weakening. |
| Malicious or changed file | Escapes a source root, leaks values or paths, or swaps bytes after listing. | No symlink escape or non-regular file in inventory. Phase 1 uses gateway-keyed ids and commitments; phase 2 requires seller confirmation and sends structure only. The local rename/drop map is applied before column names leave. SHA-256 binds listing and permission, and block verification precedes each response. |

Every outbound body is durably appended to the signed, hash-chained local audit log before transmission and relayed to the seller's "What we receive" view. The two ai.market signing keys are separate non-exportable Cloud KMS keys behind a signing service with audit logging and key rotation. These controls limit a compromised service but do not protect against full control of the customer's host.

## Verification boundaries

| Threat | Control |
| --- | --- |
| Unsigned work, wrong runner/audience/key/version, altered policy or snapshot | Closed canonical schemas, dedicated Ed25519 scan key, registered receipt-key UUID, signed immutable snapshot, exact policy/hash/D6 binding and bounded decoders. No source opens before metadata admission. |
| Replay, concurrent connections, quota bypass or restart | Durable unique nonce and authorization, exact-spec idempotency, SQLite immediate transaction, combined listing/day ten limit, clock high-water and exclusive local worker ownership. Restart consumes unfinished work and reports failure rather than retrying. |
| Hidden columns or rule changes | Actual original schema intersection after durable admission/audit; affected IDs only, including no-op renames. Offer, ceiling and E7 checks recur on each open. |
| Byte substitution or path escape | Pinned SHA/size, contained `os.Root` opens, two byte-verification passes and whole-operation `artifact_changed` refusal. No supported member is partially published. |
| Crash or unavailable disk/audit | FULL admission before reads, accepted-event fsync before dispatch, durable report before append, exact-body outbox reconciliation, fixed refusal codes. Ledger/audit failures open zero source files. |
| Value/path leakage or reconstruction | Frozen aggregate families and occupancy suppression, bounded fact/report sizes, local-only raw parsing and schema inspection, fixed errors and seller-chosen fixed-vocabulary D6. No sample/path transport. |
| Key confusion or customer hand configuration | Independent 0600 atomic local secrets, backend-issued receipt-key UUID, scan pins at pairing or one-time signed bootstrap, outgoing-class rotation and retained historical pins. Missing keys fail closed. |

The seller controls the host, executable and local keys. Receipts establish declared runner provenance, not hardware attestation. Findings are a seller-published point-in-time scan; they do not establish accuracy, legality, fitness, ongoing availability or future delivered-byte identity. Public wording must distinguish ai.market-authored code from owner-controlled execution, keep findings unedited, and show the frozen scanner/listing version. Existing historical published wording remains unchanged.

Retain consent and local events for at least 30 days; prune only terminal admissions with no pending report or hold. Ack alone is not evidence of hold settlement. The worker therefore does not automatically erase admissions based solely on an acknowledgment. Never delete ordinary delivery audit history or recreate the volume to retry old verification.
