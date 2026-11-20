#!/bin/sh
# Read-only by default. All output is fixed copy or bounded report fields.
set -eu
kit_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if ! command -v python3 >/dev/null 2>&1; then
    echo 'The local check needs Python 3. Ask IT to install Python 3, then run this check again.' >&2
    exit 1
fi
exec python3 "$kit_dir/../scripts/check-install-kit.py" --preflight "$@"
