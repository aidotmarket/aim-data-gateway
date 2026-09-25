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
