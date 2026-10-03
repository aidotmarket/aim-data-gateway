# Gateway image release

The `Release` workflow builds the existing `v<semver>` tag. A tag push publishes
the image and release assets; a manual workflow dispatch is a dry run and does
not push an image or create a release.

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

Before publishing a scanner-capable image, run `go vet ./...`, `gofmt -l .`, `go test ./...`, and `go test -race ./internal/ledger ./internal/verification ./internal/channel ./internal/audit` (allow up to fifteen minutes). Run reproducibility, line/module budgets, vector digest, generated outbound documentation and Compose/license self-checks, plus the existing SBOM/vulnerability, Cosign and attestation workflow. Report actual non-test line count even if it exceeds 7,250; do not edit the counter or exclude scanner code.

The release Compose renderer supplies `AIM_GATEWAY_IMAGE_DIGEST` from the same verified pinned image digest used for the service. The hardening check requires an exact match; local builds cannot claim a released digest. This is automatic release provenance, not a seller-entered trust key. Backend registration still enforces version/digest allowlists. A source-built development gateway without release provenance does not register for paid work.

Pair responses add `scan_spec_keys`. Upgrade an existing state volume without re-pairing: accept the listing-key-signed one-time bootstrap only while scan pins are absent. Local receipt and commitment secrets are generated independently with atomic 0600 persistence and directory fsync. Receipt identity is the backend acknowledgment's opaque UUID, never a hash or gateway file ID. Registration is proof-of-possession under the identity-key channel audit. A binary upgrade re-registers the same retained receipt public key with the new version/digest and requires a new acknowledgment before accepting new work.

Default local `verification_enabled` is true for the ready scanner release; a seller may turn it off. Backend gateway/verification service flags must both be enabled only when 1b/1c/1d integration is ready. No seller allowlist or second backend verification flag is introduced. This chunk does not deploy backend keys, issue paid work, settle money or establish Gate 4 acceptance.

Chunk 1 Gate 4 remains a separately authorized website/released-image journey: record exact backend/frontend/gateway SHAs, image/scanner version and spec revision; run free probe, quote, deliberate paid start/JIT card setup if needed, captured full findings, unedited publication and public badge. Compare epoch/spec/snapshot/member hashes, inner receipt, consent/audit and server received-message view. Prove actual provider usage and independent 2x cost bounded $1–25 with exactly one capture; use synthetic privacy markers rather than customer values. Demonstrate E7 before quote/no hold, mutation FAILED_VOIDED/no capture, restart/replay refusal, signed-binding tamper refusal, projection isolation and Remove verifier preserving delivery. AWS/R2 are deferred.

Rollback stops new verification with the backend service flag and/or local `verification_enabled=false`, settles/voids accepted work, and retains the volume, admissions, outbox, keys, epochs and audit history. Downgrade only after work is terminal. Do not restore legacy live install-addressed verification or delete Stripe objects. Published findings remain historical.
