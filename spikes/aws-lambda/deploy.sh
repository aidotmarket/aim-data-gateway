#!/usr/bin/env bash
# Operator-only. Running this creates billable resources; the spike author never runs it.
set -euo pipefail
HERE=$(cd -- "$(rtk proxy dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$HERE/common.sh"
: "${BUCKET:?set BUCKET}" "${MEMORY_MB:?set MEMORY_MB}"
# Parameter syntax bounds keep these literal IAM JSON documents safe.
[[ "$BUCKET" =~ ^[a-z0-9][a-z0-9.-]+[a-z0-9]$ ]] || { printf 'Invalid BUCKET\n' >&2; exit 1; }
[[ "$MEMORY_MB" =~ ^[0-9]+$ ]] && (( MEMORY_MB >= 128 && MEMORY_MB <= 10240 )) || { printf 'Invalid MEMORY_MB\n' >&2; exit 1; }
ACCOUNT=$(awscli sts get-caller-identity --query Account --output text)
REGISTRY="$ACCOUNT.dkr.ecr.$REGION.amazonaws.com"
IMAGE="$REGISTRY/$REPO:spike"
if ! exists RepositoryNotFoundException ecr describe-repositories --repository-names "$REPO"; then awscli ecr create-repository --repository-name "$REPO" > /dev/null; fi
awscli ecr get-login-password | rtk proxy docker login --username AWS --password-stdin "$REGISTRY"
rtk proxy docker build --platform linux/arm64 --provenance=false -f "$HERE/Dockerfile" -t "$IMAGE" "$HERE/../.."
rtk proxy docker push "$IMAGE"
if ! exists ResourceNotFoundException logs describe-log-streams --log-group-name "$LOG_GROUP" --limit 1; then awscli logs create-log-group --log-group-name "$LOG_GROUP"; fi
rtk proxy tee "$TMP/trust.json" > /dev/null <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}
JSON
rtk proxy tee "$TMP/policy.json" > /dev/null <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::$BUCKET/spike/*"},{"Effect":"Allow","Action":["logs:CreateLogStream","logs:PutLogEvents"],"Resource":"arn:aws:logs:$REGION:$ACCOUNT:log-group:$LOG_GROUP:log-stream:*"}]}
JSON
if ! exists NoSuchEntity iam get-role --role-name "$ROLE"; then awscli iam create-role --role-name "$ROLE" --assume-role-policy-document "file://$TMP/trust.json" > /dev/null; else awscli iam update-assume-role-policy --role-name "$ROLE" --policy-document "file://$TMP/trust.json"; fi
awscli iam put-role-policy --role-name "$ROLE" --policy-name spike-only --policy-document "file://$TMP/policy.json"
ROLE_ARN=$(awscli iam get-role --role-name "$ROLE" --query Role.Arn --output text)
if exists ResourceNotFoundException lambda get-function --function-name "$FUNCTION"; then
 awscli lambda wait function-updated-v2 --function-name "$FUNCTION"
 awscli lambda update-function-code --function-name "$FUNCTION" --image-uri "$IMAGE" --architectures arm64 > /dev/null
 awscli lambda wait function-updated-v2 --function-name "$FUNCTION"
 awscli lambda update-function-configuration --function-name "$FUNCTION" --role "$ROLE_ARN" --timeout 900 --memory-size "$MEMORY_MB" > /dev/null
else
 # IAM can be visible before Lambda can assume the role. Retry only that known error.
 for attempt in {1..12}; do
  if awscli lambda create-function --function-name "$FUNCTION" --package-type Image --code "ImageUri=$IMAGE" --role "$ROLE_ARN" --timeout 900 --memory-size "$MEMORY_MB" --architectures arm64 > /dev/null 2> "$TMP/error"; then break; fi
  if ! rtk proxy rg -q 'role defined for the function cannot be assumed' "$TMP/error" || [[ "$attempt" == 12 ]]; then rtk proxy cat "$TMP/error" >&2; exit 1; fi
  rtk proxy sleep 5
 done
 awscli lambda wait function-active-v2 --function-name "$FUNCTION"
fi
awscli lambda wait function-updated-v2 --function-name "$FUNCTION"
printf 'Ready: %s (%s MB, arm64, 900 seconds)\n' "$FUNCTION" "$MEMORY_MB"
