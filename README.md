# AIM Data gateway

SPDX-License-Identifier: Apache-2.0

AIM Data is a small, self hosted gateway for sellers who keep data on their own infrastructure. It will describe files to ai.market, serve purchased files directly to buyers through the seller's HTTPS door, and report deliveries. File bytes do not pass through ai.market.

Listing management, pricing, licences, samples, earnings and payouts remain on the ai.market website. This repository does not provide a management UI, cloud SDK, relay, or auto update path.

## Prepare your machine

Files stay on your infrastructure. Buyers receive copies. ai.market receives only the information you approve about your files. Use a dedicated folder containing only files you intend to sell.

Use your own secure web address by default. Your IT team needs a public web address, a valid certificate and permission to accept secure web connections. If a third-party service handles those connections, it can see file bytes. Its plan must permit this delivery. Ask IT to review the [preparation guide](docs/release-runbook.md#c0-preparation-status) before choosing a service.

The early preparation checks are for Linux servers, Linux cloud machines and Windows 11 Home with WSL2. Exact supported versions still need clean installation tests. This kit does not target Mac. The optional Cloudflare connection and company upstream connection remain unavailable for customer installation until their separate tests pass. Use your own secure web address and ask IT to review the guide.

On Windows, the PC must stay awake with Docker running. After a reboot, downloads may wait until you sign in and Docker starts. Your company may need a paid Docker Desktop licence. IT must confirm the licence and availability plan before installation. See [Docker's licence terms](https://docs.docker.com/subscription-billing/desktop-license/).

1. Ask IT to read the guide and run the local preparation check below.
2. Resolve each reported issue. An unknown result needs a separate check by IT.
3. Keep the saved connection and web address during repairs or upgrades. Follow the released installation guide for an existing connection.

This early kit does not prove that downloads work. It does not provide the new automatic test download. The planned release will run a 4 KB test every two minutes and about 200 KB of full checks at setup, reconnect, address change and recovery. Those checks are not available in the released gateway used by this preparation kit. Outside download checks and a separate buyer download are still required before claiming setup is complete.

The check does not install, start or upload anything by default. Share only its short report if you choose to do so. A handoff to IT can include the platform, chosen connection, kit version and checklist status. Send it yourself. Keep passwords, private paths and connection secrets out of that handoff.

## Technical details for your IT team

Use these local commands to check preparation. Python 3.9 or newer is needed for the Linux check. Windows also needs the Linux check inside the serving WSL2 distribution.

```sh
sh install-kit/preflight.sh --report
# For a cloud VM, add --platform linux_cloud.
# From PowerShell on Windows:
# .\install-kit\preflight.ps1 -Report
# Then inside WSL2:
# sh install-kit/preflight.sh --report --platform windows_wsl2
```

Exit 1 means a failure. Exit 2 means checks remain unknown. Neither is a ready-to-install claim. The machine-readable report contains only bounded check codes, outcomes and UTC timestamps. The native Windows check never changes firmware, WSL, power, startup or licence settings. IT applies any host changes explicitly under company policy. See the [C0 verification and evidence procedure](docs/release-runbook.md#c0-preparation-status).

`run` loads `/config/gateway.toml` (or `AIM_GATEWAY_CONFIG`) and uses `/state` (or `AIM_GATEWAY_STATE`). On an empty state volume, released v0.2.4 uses `AIM_PAIRING_CODE` once. C0 does not add the C2 masked `pair` command or wire a new pairing path. Its secret-free profiles are preparation for an already-paired v0.2.4 volume. Do not put bootstrap secrets into the new kit. Later runs load the saved identity and pins, recover the ledger, serve the configured HTTP door, and maintain the outbound control channel. `preview <file-id>` computes the exact local phase 1 and phase 2 payloads without sending them. The design authority is [Gate 1](https://github.com/aidotmarket/runbooks/blob/main/specs/BQ-AIM-DATA-GATEWAY-S1741-GATE1.md) and [Gate 2](https://github.com/aidotmarket/runbooks/blob/main/specs/BQ-AIM-DATA-GATEWAY-S1741-GATE2.md), including Gate 2 Amendment B.

### Existing installation with Compose

Copy `gateway.example.toml` to `gateway.toml`, create `data/`, and place the files to offer there. Set the one-time `AIM_PAIRING_CODE` in `compose.yaml`, then run `docker compose up --build -d`. Remove the pairing code after the first successful start. The seller's reverse proxy must terminate HTTPS and forward the door to port 8080. `/state` is a named volume; keep it across upgrades. To approve a pending offer when local approval is enabled, run `docker compose exec aim-gateway /aim-gateway approve <file-id>`.

The container runs as UID 65532 with a read-only root filesystem, zero capabilities, no new privileges, no Docker socket, and no host network or host process namespace. Its only writable mount is `/state`. The gateway checks these controls before reading configuration or state and refuses to start if any is loosened. The customer must restrict outbound access to `api.ai.market:443` with an allowlisting CONNECT proxy or firewall and restricted DNS. The canary checks direct DNS, direct TCP, and the configured proxy on each channel connection and hourly; an open result blocks publishing and new permissions at ai.market.

Release Compose assets pin the signed image by digest. See the [security policy](SECURITY.md), [threat model](docs/threat-model.md), [data flow and egress statement](docs/data-flow.md), and [outbound message examples](docs/outbound-messages.md).

### Audit log recovery

At startup, a line without a terminating newline at the end of the last audit file is treated as an interrupted write. The fragment is preserved as `audit/torn-<unix-nanos>.fragment`, the file is truncated to the last valid line and synced, and one recovery line is logged to stderr. A newline-terminated invalid line or damage anywhere earlier still stops startup. Audit entries are synced before transmission, so the recovered fragment was never sent.

### Seller-requested verification

The gateway has four functions: describe seller-selected sources, serve signed purchased-file deliveries, report delivery, and run seller-requested verification probes/scans in place. Verification uses the shared open-source `verification` package. It sends only the approved aggregate facts and signed control records; raw values, samples, paths and parser errors stay local.

Use the website to request a free probe and review the quote. Paid scans are not open yet: ai.market refuses to start one until its final payment and data-handling sign-offs are complete, and this note will be removed when they open. Once open, you start a paid scan deliberately from the website. The gateway independently checks signed consent, the retained published member set, effective offer ceiling, and column rules. A configured rename (including a no-op rename) or drop affecting an original column refuses verification: “Some columns of this data are hidden in your gateway settings, so it can't be verified.” Rules for nonexistent columns do not affect eligibility. An admitted refusal still consumes authorization and the listing's daily quota of ten probes/scans combined.

`verification_enabled` defaults true on scanner-capable builds and can be set false locally. Released Compose assets provide their pinned image digest automatically. Existing paired volumes accept a one-time listing-key-signed scan-key bootstrap; receipt/commitment keys are generated locally. No hand-set key or re-pairing is needed. Unregistered development builds cannot accept work.

```sh
aim-gateway preview --verify <32-hex-file-id> [--spec-id <id>]
```

Preview selects a retained signed scan for the whole listing, never just that file. Completed work prints the exact saved report; pending work prints a labelled deterministic fact manifest and policy without invented receipt times/signatures. Multiple matching scans require `--spec-id`. It makes no network request, consumes no consent/quota, and writes no ledger or audit record. Ordinary D9 preview remains available.

Keep the seller-owned state volume. `gateway.db` retains consent, nonce, quota, clock high-water, exact specs/snapshots and the report outbox; `verification-audit.jsonl` is a local-only signed event chain. Restart interrupts admitted unfinished work and emits a paid terminal failure instead of rerunning it. Never erase replay state to retry. Removing the verifier stops new verification while historical findings and ordinary gateway delivery remain separate.
