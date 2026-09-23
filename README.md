# AIM Data gateway

AIM Data is a small, self hosted gateway for sellers who keep data on their own infrastructure. It will describe files to ai.market, serve purchased files directly to buyers through the seller's HTTPS door, and report deliveries. File bytes do not pass through ai.market.

Listing management, pricing, licences, samples, earnings and payouts remain on the ai.market website. This repository does not provide a management UI, cloud SDK, relay, or auto update path.

This branch is the foundation only. `run` validates local configuration and exits; it does not yet pair, connect, or serve files. `preview <file-id>` computes the local phase 1 and phase 2 payloads. The design authority is [Gate 1](https://github.com/aidotmarket/ai-market/tree/main/runbooks/specs/BQ-AIM-DATA-GATEWAY-S1741-GATE1.md) and [Gate 2](https://github.com/aidotmarket/ai-market/tree/main/runbooks/specs/BQ-AIM-DATA-GATEWAY-S1741-GATE2.md).
