#!/usr/bin/env bash
set -euo pipefail
exec rtk proxy python3 "${BASH_SOURCE[0]%/*}/aws-verifier-release.py" "$@"
