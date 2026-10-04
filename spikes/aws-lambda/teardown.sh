#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd -- "$(rtk proxy dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$HERE/common.sh"
if exists ResourceNotFoundException lambda get-function --function-name "$FUNCTION"; then awscli lambda delete-function --function-name "$FUNCTION"; fi
if exists NoSuchEntity iam get-role --role-name "$ROLE"; then
 if exists NoSuchEntity iam get-role-policy --role-name "$ROLE" --policy-name spike-only; then awscli iam delete-role-policy --role-name "$ROLE" --policy-name spike-only; fi
 awscli iam delete-role --role-name "$ROLE"
fi
if exists RepositoryNotFoundException ecr describe-repositories --repository-names "$REPO"; then awscli ecr delete-repository --repository-name "$REPO" --force > /dev/null; fi
if exists ResourceNotFoundException logs describe-log-streams --log-group-name "$LOG_GROUP" --limit 1; then awscli logs delete-log-group --log-group-name "$LOG_GROUP"; fi
