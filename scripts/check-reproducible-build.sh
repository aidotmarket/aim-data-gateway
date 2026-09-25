#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
first=$(mktemp -d)
second=$(mktemp -d)
trap 'rm -rf "$first" "$second"' EXIT
for dir in "$first" "$second"; do
  mkdir "$dir/cache"
  GOCACHE="$dir/cache" CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o "$dir/aim-gateway" ./cmd/aim-gateway
done
sha256sum "$first/aim-gateway" "$second/aim-gateway"
cmp "$first/aim-gateway" "$second/aim-gateway"
