# Security policy

Report suspected vulnerabilities privately to **security@ai.market**. Include the affected image digest or commit, a reproduction, and impact. Do not open a public issue containing an exploit or customer data.

## Supported versions

The latest released minor version receives security fixes. Older versions may be refused permissions by ai.market's announced minimum version. Check the release notes and image digest before upgrading.

## Verify a release image

Use cosign v3.1.3 or newer. Release signatures use the cosign v3 bundle format in OCI referrers; cosign v2.x reports `no signatures found`. Use the digest from the release Compose asset or the pairing response. Replace `<digest>` with its 64 hexadecimal characters and `v1.2.3` with the release tag:

```sh
image=ghcr.io/aidotmarket/aim-gateway@sha256:<digest>
tag=v1.2.3
cosign verify "$image" \
  --certificate-identity-regexp '^https://github\.com/aidotmarket/aim-data-gateway/\.github/workflows/release\.yml@refs/tags/v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify "oci://$image" -R aidotmarket/aim-data-gateway \
  --signer-workflow aidotmarket/aim-data-gateway/.github/workflows/release.yml \
  --source-ref "refs/tags/$tag" --predicate-type https://slsa.dev/provenance/v1
gh attestation verify "oci://$image" -R aidotmarket/aim-data-gateway \
  --signer-workflow aidotmarket/aim-data-gateway/.github/workflows/release.yml \
  --source-ref "refs/tags/$tag" --predicate-type https://spdx.dev/Document/v2.3
```

Verify the release assets with `sha256sum -c checksums.txt`. The SPDX JSON describes that exact image digest. The release workflow checks two independent OCI exports against the pushed digest, scans fixable high and critical findings, signs the image keylessly, and verifies both attestations before publishing assets.

## First release package visibility

After the first image push, an aidotmarket organization admin must make the GHCR package ghcr.io/aidotmarket/aim-gateway public in GitHub package settings. The release workflow checks an anonymous manifest pull before signing and publishing release assets. It fails if the package is still private. After changing visibility, rerun the failed release workflow.

## Reproduce the build

Check out the signed release tag. Set `SOURCE_DATE_EPOCH` to the tagged commit's Unix timestamp and build twice with Docker Buildx, `--platform linux/amd64 --provenance=false --sbom=false --build-arg SOURCE_DATE_EPOCH=<timestamp> --build-arg VERSION=<tag without v>` and `--output type=oci,dest=<path>,rewrite-timestamp=true`. Compare the `containerimage.digest` values from `--metadata-file`. `scripts/release-image.sh` implements this procedure. The Dockerfile pins both base images by digest and builds a static binary. Reproduction requires those image digests and the pinned Go module graph to remain available.

## Host and update boundary

The gateway has no self-update path. Only the customer changes its image. The source Compose file builds locally; a release Compose file uses `ghcr.io/aidotmarket/aim-gateway@sha256:<digest>`. Keep the read-only root, UID 65532, dropped capabilities, no-new-privileges, the three allowed mount classes, and deny-all egress except `api.ai.market:443`. The gateway's canary probes must fail to connect or resolve.

## Golden-vector contract

`scripts/check-vector-digest.py` verifies every committed vector against `contract/VECTORS.sha256`. The SHA-256 of that manifest is **`b41878847daddd74eb4e14a10b9a54db19b16139361800e0310d48b866bd534b`**. The private backend copy pins this same manifest SHA (S1732 pattern). The public CI proves its own vector set and pin; cross-repository equivalence is the comparison of these two pinned constants, not a CI fetch of the private backend.
