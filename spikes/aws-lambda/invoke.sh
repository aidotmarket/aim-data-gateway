#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd -- "$(rtk proxy dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$HERE/common.sh"
: "${1:?event JSON file required}"
awscli lambda invoke --function-name "$FUNCTION" --cli-read-timeout 910 --cli-binary-format raw-in-base64-out --payload "fileb://$1" "$TMP/result.json" >&2
rtk proxy cat "$TMP/result.json"
