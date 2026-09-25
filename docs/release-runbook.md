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
