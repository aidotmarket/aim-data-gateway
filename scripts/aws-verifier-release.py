#!/usr/bin/env python3
"""Reproducible offline build, then explicit existing-bucket publication.

Dry-run is the default and makes no AWS/signing/publication calls. Publication
requires a five-region manifest and existing smoke functions/identity/buckets.
All subprocesses go through RTK; binary/SBOM outputs bypass output filtering.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REGIONS = {"eu-north-1", "eu-west-1", "eu-central-1", "us-east-1", "us-west-2"}
IDENTITY = "https://github.com/aidotmarket/aim-data-gateway/.github/workflows/aws-verifier-release.yml@refs/tags/aws-verifier-v"


def run(*args, env=None, capture_stderr=False):
    return subprocess.check_output(["rtk", "proxy", *map(str, args)], cwd=ROOT, env=env,
                                   stderr=subprocess.PIPE if capture_stderr else None).decode().strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(version, out):
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="aws-verifier-build-") as temp:
        zips = []
        for n in (1, 2):
            directory = Path(temp) / str(n)
            directory.mkdir()
            # Independent caches exercise compilation twice, not just ZIP packing.
            env = {**os.environ, "GOOS": "linux", "GOARCH": "arm64", "CGO_ENABLED": "0",
                   "GOCACHE": str(directory / "cache"), "GOFLAGS": "", "GOEXPERIMENT": ""}
            run("go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
                "-ldflags=-s -w -buildid=", "-o", directory / "bootstrap", "./cmd/aim-aws-verifier", env=env)
            path = directory / "bootstrap.zip"
            # ZIP_STORED avoids platform/zlib differences. Fixed DOS timestamp,
            # single root entry, Unix executable mode; no paths/comments/extras.
            info = zipfile.ZipInfo("bootstrap", date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100755 << 16
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr(info, (directory / "bootstrap").read_bytes())
            zips.append(path)
            print(f"build_{n}_zip_sha256={digest(path)}", flush=True)
        if zips[0].read_bytes() != zips[1].read_bytes():
            raise RuntimeError("ZIP reproducibility mismatch")
        shutil.copyfile(zips[0], out / "bootstrap.zip")
        shutil.copyfile(Path(temp) / "1" / "bootstrap", out / "bootstrap")
    shutil.copyfile(ROOT / "deploy/aws-verifier.yaml", out / "aws-verifier.yaml")
    sha = digest(out / "bootstrap.zip")
    code_sha = base64.b64encode(bytes.fromhex(sha)).decode()
    record = {"scanner_version": version, "image_digest": "sha256:" + sha,
              "CodeSha256": code_sha, "go_version": run("go", "version"),
              "commit": run("git", "rev-parse", "HEAD"),
              "compiled_modules": run("go", "version", "-m", out / "bootstrap").splitlines()}
    (out / "build.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"reproducible_zip=PASS\nimage_digest=sha256:{sha}\nCodeSha256={code_sha}", flush=True)
    return record


def manifest(path):
    entries = json.loads(path.read_text())
    if not isinstance(entries, list) or len(entries) != 5 or {e.get("region") for e in entries} != REGIONS:
        raise ValueError("manifest must contain each of the five supported regions exactly once")
    for e in entries:
        if (set(e) != {"region", "bucket", "smoke_function_arn"}
                or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", e["bucket"])
                or not re.fullmatch(rf"arn:aws:lambda:{e['region']}:[0-9]{{12}}:function:[A-Za-z0-9_-]+", e["smoke_function_arn"])):
            raise ValueError("invalid regional bucket/smoke function manifest")
    return entries


def sign(path, bundle, version):
    if not bundle.exists():
        run("cosign", "sign-blob", "--yes", "--bundle", bundle, path)
    run("cosign", "verify-blob", "--bundle", bundle,
        "--certificate-identity", IDENTITY + version,
        "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", path)


def upload(entry, key, path):
    # Existing versioned buckets have public read only for release objects.
    # No bucket creation/policy/ACL/credential/delete commands in this script.
    try:
        response = json.loads(run("aws", "s3api", "put-object", "--region", entry["region"],
                                  "--bucket", entry["bucket"], "--key", key, "--body", path,
                                  "--if-none-match", "*", "--content-type",
                                  "application/zip" if path.suffix == ".zip" else "application/json",
                                  capture_stderr=True))
    except subprocess.CalledProcessError as error:
        stderr = (error.stderr or b"").decode(errors="replace")
        if "An error occurred (PreconditionFailed) when calling the PutObject operation" not in stderr:
            raise RuntimeError("publication put-object failed: " + stderr) from error
        with tempfile.TemporaryDirectory(prefix="aws-verifier-existing-") as temp:
            existing = Path(temp) / "object"
            response = json.loads(run("aws", "s3api", "get-object", "--region", entry["region"],
                                      "--bucket", entry["bucket"], "--key", key, existing))
            if digest(existing) != digest(path):
                raise RuntimeError("existing publication object SHA-256 mismatch")
    version = response.get("VersionId")
    if not version or version == "null":
        raise RuntimeError("publication did not return an immutable object version")
    url = (f"https://{entry['bucket']}.s3.{entry['region']}.amazonaws.com/"
           + urllib.parse.quote(key, safe="/") + "?" + urllib.parse.urlencode({"versionId": version}))
    # Anonymous regional, version-specific download; fail on redirect/byte change.
    with urllib.request.urlopen(url, timeout=120) as response:
        if response.geturl() != url or response.read() != path.read_bytes():
            raise RuntimeError("anonymous versioned download equality failed")
    return {"bucket": entry["bucket"], "key": key, "object_version": version,
            "url": url, "sha256": digest(path)}


def publish(record, entries, out):
    # Validate every region before writing any public release object. Existing
    # operator-provisioned smoke functions must already contain this exact ZIP.
    # Preparing/invoking those functions is a separately authorized operator step.
    for e in entries:
        if json.loads(run("aws", "s3api", "get-bucket-versioning", "--region", e["region"],
                          "--bucket", e["bucket"])).get("Status") != "Enabled":
            raise RuntimeError("artifact bucket versioning must already be enabled")
        function = json.loads(run("aws", "lambda", "get-function", "--region", e["region"],
                                  "--function-name", e["smoke_function_arn"]))["Configuration"]
        if (function["CodeSha256"] != record["CodeSha256"] or function["Runtime"] != "provided.al2023"
                or function["Architectures"] != ["arm64"] or function.get("State") != "Active"
                or function.get("LastUpdateStatus") != "Successful"):
            raise RuntimeError("actual regional Lambda CodeSha256/runtime smoke identity mismatch")
    if not (out / "aws-verifier.spdx.json").exists():
        run("syft", out / "bootstrap", "-o", f"spdx-json={out / 'aws-verifier.spdx.json'}")
    run("grype", f"sbom:{out / 'aws-verifier.spdx.json'}", "--only-fixed", "--fail-on", "high")
    for filename in ("bootstrap.zip", "aws-verifier.yaml", "aws-verifier.spdx.json"):
        sign(out / filename, out / (filename + ".sigstore.json"), record["scanner_version"])
    catalog = {**record, "regions": []}
    prefix = f"aws-verifier/{record['scanner_version']}/{record['image_digest'][7:]}"
    for e in entries:
        objects = {}
        for filename in ("bootstrap.zip", "aws-verifier.yaml", "aws-verifier.spdx.json",
                         "bootstrap.zip.sigstore.json", "aws-verifier.yaml.sigstore.json",
                         "aws-verifier.spdx.json.sigstore.json"):
            objects[filename] = upload(e, f"{prefix}/{filename}", out / filename)
        catalog["regions"].append({"region": e["region"], "actual_CodeSha256": record["CodeSha256"],
                                   "objects": objects})
    path = out / "catalog.json"
    path.write_text(json.dumps(catalog, sort_keys=True, indent=2) + "\n")
    sign(path, out / "catalog.json.sigstore.json", record["scanner_version"])
    receipts = []
    for e in entries:
        receipts.append({"region": e["region"], "catalog": upload(e, f"{prefix}/catalog.json", path),
                         "signature": upload(e, f"{prefix}/catalog.json.sigstore.json", out / "catalog.json.sigstore.json")})
    (out / "publication.json").write_text(json.dumps(receipts, indent=2) + "\n")
    print("regional_publication_download_equality=PASS", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="scanner version, without aws-verifier-v prefix")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/aws-verifier")
    parser.add_argument("--mode", choices=("dry-run", "publish", "publish-built"), default="dry-run")
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?", args.version):
        parser.error("version must be semver")
    out = args.output.resolve()
    if args.mode != "dry-run":
        if not args.manifest:
            parser.error("publication requires an existing-bucket manifest")
        entries = manifest(args.manifest)
        tag = "aws-verifier-v" + args.version
        if (os.environ.get("GITHUB_REPOSITORY") != "aidotmarket/aim-data-gateway"
                or os.environ.get("GITHUB_REF") != "refs/tags/" + tag
                or run("git", "rev-list", "-n", "1", "refs/tags/" + tag) != run("git", "rev-parse", "HEAD")):
            parser.error("publication requires the exact repository/tag commit and GitHub OIDC workflow")
    if args.mode == "publish-built":
        record = json.loads((out / "build.json").read_text())
        sha = digest(out / "bootstrap.zip")
        if (record["scanner_version"] != args.version or record["commit"] != run("git", "rev-parse", "HEAD")
                or record["image_digest"] != "sha256:" + sha
                or record["CodeSha256"] != base64.b64encode(bytes.fromhex(sha)).decode()
                or (out / "aws-verifier.yaml").read_bytes() != (ROOT / "deploy/aws-verifier.yaml").read_bytes()):
            raise RuntimeError("built release inputs changed")
    else:
        record = build(args.version, out)
    if args.mode == "dry-run":
        print("dry_run=PASS (no AWS calls, signing or publication)", flush=True)
    else:
        publish(record, entries, out)


if __name__ == "__main__":
    main()
