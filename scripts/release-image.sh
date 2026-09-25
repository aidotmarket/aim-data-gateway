#!/usr/bin/env bash
set -euo pipefail

# MODE=push prepares a tagged release for a later push after scanning.
# MODE=dry-run attests an existing tag locally.
# MODE=local is for an untagged checkout's offline reproducibility check.
tag=${TAG:?TAG is required}
mode=${MODE:?MODE is required}
if [[ $mode == local ]]; then
  commit=${COMMIT_REF:-HEAD}
else
  [[ $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]]
  [[ $mode == push || $mode == dry-run ]]
  commit="refs/tags/$tag"
fi
mkdir -p dist build-check
epoch=$(git show -s --format=%ct "$(git rev-list -n 1 "$commit")")
cache_flag=--no-cache
if [[ $mode == local && ${BUILD_NO_CACHE:-true} == false ]]; then
  cache_flag=--progress=auto
fi
for pass in 1 2; do
  docker buildx build "$cache_flag" --platform linux/amd64 --build-arg "SOURCE_DATE_EPOCH=$epoch" --build-arg "VERSION=${tag#v}" \
    --provenance=false --sbom=false \
    --output "type=oci,dest=build-check/image-$pass.oci.tar,rewrite-timestamp=true" \
    --metadata-file "build-check/image-$pass.json" .
done
first=$(python3 -c 'import json;print(json.load(open("build-check/image-1.json"))["containerimage.digest"])')
second=$(python3 -c 'import json;print(json.load(open("build-check/image-2.json"))["containerimage.digest"])')
[[ $first == "$second" ]] || { echo "image digest mismatch: $first != $second" >&2; exit 1; }
echo "reproducible image digest: $first"
printf '%s\n' "$first" > build-check/digest
