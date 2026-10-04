#!/usr/bin/env bash
set -euo pipefail
: "${AWS_PROFILE:?set AWS_PROFILE}" "${REGION:?set REGION}" "${FUNCTION:?set FUNCTION}"
[[ "$FUNCTION" =~ ^[a-zA-Z0-9_-]+$ ]] && (( ${#FUNCTION} <= 58 )) || { printf 'Invalid FUNCTION (maximum 58 characters)\n' >&2; exit 1; }
[[ "$REGION" =~ ^[a-z0-9-]+$ ]] || { printf 'Invalid REGION\n' >&2; exit 1; }
export AWS_PAGER=""
awscli() { rtk proxy aws --profile "$AWS_PROFILE" --region "$REGION" "$@"; }
ROLE="${FUNCTION}-spike"
REPO=$(printf '%s' "${FUNCTION}-spike" | rtk proxy tr '[:upper:]' '[:lower:]')
LOG_GROUP="/aws/lambda/$FUNCTION"
# Never mask an authentication, permission or network failure as absence.
exists() {
 local expected="$1"; shift
 if awscli "$@" > /dev/null 2> "$TMP/error"; then return 0; fi
 if rtk proxy rg -q "$expected" "$TMP/error"; then return 1; fi
 rtk proxy cat "$TMP/error" >&2; exit 1
}
TMP=$(rtk proxy mktemp -d)
trap 'rtk proxy rm -rf "$TMP"' EXIT
