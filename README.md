# AIM Data gateway

AIM Data is a small, self hosted gateway for sellers who keep data on their own infrastructure. It will describe files to ai.market, serve purchased files directly to buyers through the seller's HTTPS door, and report deliveries. File bytes do not pass through ai.market.

Listing management, pricing, licences, samples, earnings and payouts remain on the ai.market website. This repository does not provide a management UI, cloud SDK, relay, or auto update path.

`run` loads `/config/gateway.toml` (or `AIM_GATEWAY_CONFIG`) and uses `/state` (or `AIM_GATEWAY_STATE`). On an empty state volume, supply `AIM_PAIRING_CODE` once. Later runs load the saved identity and pins, recover the ledger, serve the configured HTTP door, and maintain the outbound control channel. `preview <file-id>` computes the exact local phase 1 and phase 2 payloads without sending them. The design authority is [Gate 1](https://github.com/aidotmarket/ai-market/tree/main/runbooks/specs/BQ-AIM-DATA-GATEWAY-S1741-GATE1.md) and [Gate 2](https://github.com/aidotmarket/ai-market/tree/main/runbooks/specs/BQ-AIM-DATA-GATEWAY-S1741-GATE2.md), including Gate 2 Amendment B.

This branch covers the B3 gateway channel. The B4 canary, start-up self-check, local approval command, and compose file are still separate work.
