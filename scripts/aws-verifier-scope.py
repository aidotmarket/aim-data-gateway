#!/usr/bin/env python3
"""Offline pre-setup scope compiler; no AWS calls or third-party modules.

Input: {connection_id,bucket,region,keys,prefixes,sse_kms_key_arn?}.
Output: quick-create scope parameters, exact object ARNs, aggregate policy size.
Call this before minting a setup token (backend integration belongs to 2c).
"""
import argparse
import json
from pathlib import Path
import re
import sys

TEMPLATE = Path(__file__).resolve().parents[1] / "deploy/aws-verifier.yaml"
REGIONS = ("eu-north-1", "eu-west-1", "eu-central-1", "us-east-1", "us-west-2")
NO_VALUE = object()


def resolve(value, parameters, conditions):
    """Resolve the template's native intrinsics for offline policy sizing."""
    if isinstance(value, list):
        result = [resolve(v, parameters, conditions) for v in value]
        return [v for v in result if v is not NO_VALUE]
    if not isinstance(value, dict):
        return value
    if "Ref" in value:
        return NO_VALUE if value["Ref"] == "AWS::NoValue" else parameters[value["Ref"]]
    if "Fn::GetAtt" in value:
        return parameters[".".join(value["Fn::GetAtt"])]
    if "Fn::Sub" in value:
        return re.sub(r"\$\{([^}]+)\}", lambda m: str(parameters[m[1]]), value["Fn::Sub"])
    if "Fn::If" in value:
        name, yes, no = value["Fn::If"]
        return resolve(yes if resolve(conditions[name], parameters, conditions) else no,
                       parameters, conditions)
    if "Fn::Equals" in value:
        a, b = resolve(value["Fn::Equals"], parameters, conditions)
        return str(a) == str(b)
    if "Fn::Not" in value:
        return not resolve(value["Fn::Not"][0], parameters, conditions)
    if "Fn::Join" in value:
        sep, items = value["Fn::Join"]
        return sep.join(str(x) for x in resolve(items, parameters, conditions))
    if "Fn::Split" in value:
        sep, item = value["Fn::Split"]
        return resolve(item, parameters, conditions).split(sep)
    if "Fn::Select" in value:
        index, items = value["Fn::Select"]
        return resolve(items, parameters, conditions)[int(index)]
    return {k: resolve(v, parameters, conditions) for k, v in value.items()}


def compile_scope(source):
    def refuse():
        raise ValueError("aws_source_scope_unrepresentable")

    if not isinstance(source, dict) or set(source) - {
        "connection_id", "bucket", "region", "keys", "prefixes", "sse_kms_key_arn"
    }:
        refuse()
    connection, bucket, region = (source.get(k, "") for k in ("connection_id", "bucket", "region"))
    if not isinstance(region, str) or region not in REGIONS:
        raise ValueError("aws_region_unsupported")
    if not isinstance(connection, str) or not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", connection
    ) or not isinstance(bucket, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        refuse()
    keys, prefixes = source.get("keys"), source.get("prefixes")
    if not isinstance(keys, list) or not isinstance(prefixes, list) or not 1 <= len(keys) + len(prefixes) <= 50:
        refuse()
    for entry in keys + prefixes:
        # Native CommaDelimitedList trims members; JSON and IAM metacharacters
        # cannot be round-tripped. Refuse these spellings rather than rename data.
        if (not isinstance(entry, str) or not entry or entry != entry.strip()
                or "${" in entry or re.search(r'[,\x00-\x1f\x7f*?"\\]', entry)
                or len(entry.encode("utf-8")) > 1024):
            refuse()
    kms = source.get("sse_kms_key_arn", "")
    if not isinstance(kms, str) or (kms and not re.fullmatch(
        rf"arn:aws:kms:{region}:[0-9]{{12}}:key/[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}", kms
    )):
        refuse()
    params = {"ConnectionId": connection, "Bucket": bucket, "BucketRegion": region,
              "ReadKeys": ",".join(keys), "ReadPrefixes": ",".join(prefixes), "SseKmsKeyArn": kms}
    # Deterministic resource names, 12-digit account and six-character Secrets
    # Manager suffix make this an upper bound independent of the seller account.
    name = f"aim-aws-verifier-{connection}"
    common = f"{region}:999999999999"
    values = {**params, "ReadKeys": keys or [""], "ReadPrefixes": prefixes or [""],
              "AWS::Region": region, "AWS::AccountId": "999999999999",
              "VerifierSecret": f"arn:aws:secretsmanager:{common}:secret:{name}-xxxxxx",
              "Ledger.Arn": f"arn:aws:dynamodb:{common}:table/{name}"}
    template = json.loads(TEMPLATE.read_text())
    policies = template["Resources"]["ExecutionRole"]["Properties"]["Policies"]
    documents = [resolve(p["PolicyDocument"], values, template["Conditions"]) for p in policies]
    # IAM excludes whitespace. Counting even whitespace within string values is
    # conservative; UTF-8 bytes also safely bound characters for non-ASCII keys.
    size = sum(len(json.dumps(p, ensure_ascii=False, separators=(",", ":")).encode()) for p in documents)
    if size > 10240:
        refuse()
    # Lambda also caps the serialized application environment at 4 KiB. Use the
    # binary's maximum version length, so
    # an IAM-representable scope cannot fail only after the seller starts setup.
    values.update({"Ledger": name, "LogGroup": f"/aws/lambda/{name}",
                   "RegistrationToken": "x" * 43, "ScannerVersion": "x" * 128,
                   "ExpectedCodeHash": "sha256:" + "0" * 64,
                   "ApiBaseUrl": "https://api.ai.market"})
    env = resolve(template["Resources"]["VerifierFunction"]["Properties"]["Environment"]["Variables"],
                  values, template["Conditions"])
    env_size = len(json.dumps(env, ensure_ascii=False, separators=(",", ":")).encode())
    if env_size > 4096:
        refuse()
    return {"parameters": params, "object_arns": documents[0]["Statement"][0]["Resource"],
            "inline_policy_characters_upper_bound": size, "environment_bytes_upper_bound": env_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="Scope JSON file, or - for stdin; never include the token")
    args = parser.parse_args()
    try:
        source = json.loads(sys.stdin.read() if args.source == "-" else Path(args.source).read_text())
        print(json.dumps(compile_scope(source), ensure_ascii=False))
    except (ValueError, TypeError, KeyError) as error:
        # Do not echo raw keys, source documents or exception strings.
        code = "aws_region_unsupported" if str(error) == "aws_region_unsupported" else "aws_source_scope_unrepresentable"
        print(code, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
