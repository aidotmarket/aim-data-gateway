#!/usr/bin/env python3
"""Build reproducible release inputs and export a frozen template; never create repositories.

The catalog is a candidate until separately authorized real-account smoke and
publication. Build/sign/publish artifact workflows grant no seller authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import tarfile
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "deploy/cloudflare-verifier"
IDENTITY = "https://github.com/aidotmarket/aim-data-gateway/.github/workflows/cloudflare-verifier-release.yml@refs/tags/cloudflare-verifier-v"


def run(*args, env=None, cwd=ROOT):
    # Operators may use their ordinary command proxy without changing artifacts.
    prefix = shlex.split(os.environ.get("COMMAND_PROXY", ""))
    return subprocess.check_output(prefix + list(map(str, args)), cwd=cwd, env=env).decode().strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(tree):
    return {p.relative_to(tree).as_posix(): digest(p) for p in sorted(tree.rglob("*"))
            if p.is_file() and ".git" not in p.parts}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def build(version, output, verify_committed=False):
    if run("go", "version").split()[2] != "go1.27.1":
        raise ValueError("use repository-pinned Go 1.27.1")
    output.mkdir(parents=True, exist_ok=True)
    binaries, bundles = [], []
    with tempfile.TemporaryDirectory(prefix="cloudflare-verifier-build-") as temp:
        for n in (1, 2):
            directory = Path(temp) / str(n)
            directory.mkdir()
            env = {**os.environ, "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "GOAMD64": "v1", "GOTOOLCHAIN": "local", "GOENV": "off",
                   "GOCACHE": str(directory / "cache"), "GOFLAGS": "", "GOEXPERIMENT": "",
                   "GOPROXY": "off", "GOSUMDB": "off"}
            binary = directory / "aim-cloudflare-verifier"
            run("go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
                f"-ldflags=-s -w -buildid= -X main.releaseID=cloudflare-verifier-v{version} -X main.scannerVersion={version}",
                "-o", binary, "./cmd/aim-cloudflare-verifier", env=env)
            bundle = directory / "worker.mjs"
            run(TEMPLATE / "node_modules/.bin/esbuild", "worker.ts", "--bundle", "--format=esm",
                "--platform=neutral", "--external:cloudflare:*", "--external:node:*", "--outfile=" + str(bundle), cwd=TEMPLATE)
            binaries.append(binary.read_bytes())
            bundles.append(bundle.read_bytes())
            print(f"build_{n}_binary_sha256={digest(binary)}", flush=True)
            print(f"build_{n}_bundle_sha256={digest(bundle)}", flush=True)
        if binaries[0] != binaries[1] or bundles[0] != bundles[1]:
            raise RuntimeError("binary or Worker reproducibility mismatch")
        if verify_committed:
            if (TEMPLATE / "aim-cloudflare-verifier").read_bytes() != binaries[0]:
                raise RuntimeError("committed binary differs from reproducible build")
            if (TEMPLATE / "worker.mjs").read_bytes() != bundles[0]:
                raise RuntimeError("committed bundle differs from reproducible build")
        (output / "aim-cloudflare-verifier").write_bytes(binaries[0])
        (output / "aim-cloudflare-verifier").chmod(0o755)
        (output / "worker.mjs").write_bytes(bundles[0])
    record = {"release_id": "cloudflare-verifier-v" + version, "scanner_version": version,
              "binary_sha256": digest(output / "aim-cloudflare-verifier"),
              "worker_identity": {"mode": "bundle", "sha256": digest(output / "worker.mjs")},
              "bundle_sha256": digest(output / "worker.mjs"),
              "source_commit": run("git", "rev-parse", "HEAD"),
              "compiled_modules": run("go", "version", "-m", output / "aim-cloudflare-verifier").splitlines(),
              "go_version": run("go", "version"),
              "worker_lockfile_sha256": digest(TEMPLATE / "package-lock.json")}
    (output / "build.json").write_text(json.dumps(record, indent=2) + "\n")
    print("binary_bundle_reproducibility=PASS", flush=True)
    return record


def verify_built(record, output, version):
    if (record["source_commit"] != run("git", "rev-parse", "HEAD")
            or record["release_id"] != "cloudflare-verifier-v" + version
            or record["scanner_version"] != version
            or record["binary_sha256"] != digest(output / "aim-cloudflare-verifier")
            or record["worker_identity"] != {"mode": "bundle", "sha256": digest(output / "worker.mjs")}
            or record["worker_lockfile_sha256"] != digest(TEMPLATE / "package-lock.json")):
        raise ValueError("release inputs changed")


def source_archive(path):
    # Audit/rebuild source travels with the frozen template, without extra files
    # in the Dockerfile. A deterministic archive avoids generated source counts.
    sources = [ROOT / name for name in ("go.mod", "go.sum", "LICENSE")]
    for directory in ("cmd/aim-cloudflare-verifier", "internal/cloudflareverification",
                      "verification", "internal/wire", "internal/config", "internal/ids", "internal/inventory"):
        sources += [p for p in (ROOT / directory).rglob("*") if p.is_file()
                    and (p.suffix == ".pem" or (p.suffix == ".go" and not p.name.endswith("_test.go")))]
    with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as archive:
        for source in sorted(sources):
            info = archive.gettarinfo(source, source.relative_to(ROOT).as_posix())
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            with source.open("rb") as content:
                archive.addfile(info, content)


def export(record, output):
    tree = output / "template"
    if tree.exists():
        shutil.rmtree(tree)
    tree.mkdir()
    for name in ("worker.ts", "crypto.ts", "state.ts", "worker-configuration.d.ts",
                 "wrangler.jsonc", "Dockerfile", ".dev.vars.example", "package.json", "package-lock.json",
                 "tsconfig.json", ".gitignore"):
        shutil.copyfile(TEMPLATE / name, tree / name)
    for name in ("aim-cloudflare-verifier", "worker.mjs"):
        shutil.copyfile(output / name, tree / name)
    (tree / "aim-cloudflare-verifier").chmod(0o755)
    shutil.copyfile(ROOT / "docs/cloudflare-verifier.md", tree / "README.md")
    config = json.loads((tree / "wrangler.jsonc").read_text())
    # Identity is deployment metadata, never embedded in the hashed Worker.
    config["vars"]["DEPLOYMENT_CONFIG"] = canonical({
        "connection_id": "", "bucket": "", "prefix": "", "jurisdiction": "default", "keys": [],
        "release_id": record["release_id"], "scanner_version": record["scanner_version"],
        "binary_sha256": record["binary_sha256"], "worker_identity": record["worker_identity"]}).decode()
    (tree / "wrangler.jsonc").write_text(json.dumps(config, indent=2) + "\n")
    source_archive(tree / "source.tar")
    files = manifest(tree)
    (output / "template-manifest.json").write_bytes(canonical(files) + b"\n")
    # A deterministic local commit permits later exact export without account access.
    epoch = run("git", "show", "-s", "--format=%ct", "HEAD")
    env = {**os.environ, "GIT_AUTHOR_NAME": "ai.market release", "GIT_COMMITTER_NAME": "ai.market release",
           "GIT_AUTHOR_EMAIL": "release@ai.market", "GIT_COMMITTER_EMAIL": "release@ai.market",
           "GIT_AUTHOR_DATE": epoch + " +0000", "GIT_COMMITTER_DATE": epoch + " +0000"}
    run("git", "init", "--initial-branch=main", tree)
    run("git", "add", ".", cwd=tree)
    run("git", "-c", "commit.gpgsign=false", "commit", "-m", record["release_id"], env=env, cwd=tree)
    commit = run("git", "rev-parse", "HEAD", cwd=tree)
    repo = "https://github.com/aidotmarket/" + record["release_id"]
    raw = repo.replace("github.com", "raw.githubusercontent.com") + "/" + commit
    artifact = "https://github.com/aidotmarket/aim-data-gateway/releases/download/" + record["release_id"]
    catalog = {"release_id": record["release_id"], "scanner_version": record["scanner_version"],
               "binary_sha256": record["binary_sha256"], "worker_identity": record["worker_identity"],
               "template_repo_url": repo, "template_commit": commit,
               "template_tree_sha256": hashlib.sha256(canonical(files)).hexdigest(),
               "deploy_button_url": "https://deploy.workers.cloudflare.com/?url=" + quote(repo, safe=""),
               "binary_url": raw + "/aim-cloudflare-verifier", "bundle_url": raw + "/worker.mjs",
               "bundle_sha256": record["bundle_sha256"], "config_sha256": digest(tree / "wrangler.jsonc"),
               "signature_url": artifact + "/catalog.json.sigstore.json",
               "sbom_url": artifact + "/cloudflare-verifier.spdx.json"}
    (output / "catalog.json").write_bytes(canonical({"default": catalog}) + b"\n")
    (output / "CATALOG-CANDIDATE.txt").write_text(
        "Artifact export only. URLs reserve a future immutable repository/release.\n"
        "Do not enable the backend catalog until full button/bucket registration/poll/probe smoke.\n"
        "no_bundle module byte equality and seller image reproducibility are unmeasured.\n")
    run("git", "archive", "--format=tar", "--output=" + str(output / "template.tar"), "HEAD", cwd=tree)
    run("git", "bundle", "create", output / "template.git.bundle", "HEAD", cwd=tree)
    shutil.rmtree(tree / ".git")
    print("template_export=PASS (no external repository created)", flush=True)


def sign(output, version):
    tag = "cloudflare-verifier-v" + version
    if (os.environ.get("GITHUB_REPOSITORY") != "aidotmarket/aim-data-gateway"
            or os.environ.get("GITHUB_REF") != "refs/tags/" + tag
            or run("git", "rev-list", "-n", "1", tag) != run("git", "rev-parse", "HEAD")):
        raise ValueError("signing requires exact repository/tag workflow identity")
    record = json.loads((output / "build.json").read_text())
    verify_built(record, output, version)
    entry = json.loads((output / "catalog.json").read_text())["default"]
    files = manifest(output / "template")
    if (entry["template_tree_sha256"] != hashlib.sha256(canonical(files)).hexdigest()
            or entry["config_sha256"] != digest(output / "template/wrangler.jsonc")
            or entry["binary_sha256"] != record["binary_sha256"]
            or entry["worker_identity"] != record["worker_identity"]):
        raise ValueError("catalog/template bytes changed")
    run("syft", output / "aim-cloudflare-verifier", "-o", "spdx-json=" + str(output / "cloudflare-verifier.spdx.json"))
    run("grype", "sbom:" + str(output / "cloudflare-verifier.spdx.json"), "--only-fixed", "--fail-on", "high")
    run("syft", "dir:" + str(output / "template"), "-o", "spdx-json=" + str(output / "cloudflare-worker.spdx.json"))
    run("grype", "sbom:" + str(output / "cloudflare-worker.spdx.json"), "--only-fixed", "--fail-on", "high")
    digests = {name: digest(output / name) for name in ("aim-cloudflare-verifier", "worker.mjs", "template.tar", "template.git.bundle", "catalog.json", "build.json")}
    (output / "digests.json").write_bytes(canonical(digests) + b"\n")
    paths = [output / name for name in ("aim-cloudflare-verifier", "worker.mjs", "catalog.json",
             "template.tar", "template.git.bundle", "template-manifest.json", "cloudflare-verifier.spdx.json", "cloudflare-worker.spdx.json", "build.json", "digests.json")]
    paths += [output / "template/wrangler.jsonc"]
    for path in paths:
        bundle = output / (path.name + ".sigstore.json")
        run("cosign", "sign-blob", "--yes", "--bundle", bundle, path)
        run("cosign", "verify-blob", "--bundle", bundle, "--certificate-identity", IDENTITY + version,
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/cloudflare-verifier")
    parser.add_argument("--verify-committed", action="store_true")
    parser.add_argument("--sign", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?", args.version):
        parser.error("version must be semver")
    output = args.output.resolve()
    record = build(args.version, output, args.verify_committed)
    export(record, output)
    if args.sign:
        sign(output, args.version)


if __name__ == "__main__":
    main()
