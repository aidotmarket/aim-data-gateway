#!/usr/bin/env bash
set -euo pipefail
tag=${TAG:?TAG is required}
[[ $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]]
expected=$(cat build-check/digest)
[[ $expected =~ ^sha256:[0-9a-f]{64}$ ]]
epoch=$(git show -s --format=%ct "$(git rev-list -n 1 "refs/tags/$tag")")
image=ghcr.io/aidotmarket/aim-gateway
docker buildx build --platform linux/amd64 --build-arg "SOURCE_DATE_EPOCH=$epoch" \
  --provenance=false --sbom=false \
  --output "type=image,name=$image:$tag,push=true,oci-mediatypes=true,rewrite-timestamp=true,unpack=false" \
  --metadata-file build-check/pushed.json .
pushed=$(python3 -c 'import json;print(json.load(open("build-check/pushed.json"))["containerimage.digest"])')
[[ $expected == "$pushed" ]] || { echo "pushed digest differs: $pushed" >&2; exit 1; }
echo "pushed image: $image@$pushed"
