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
IDENTITY = "https://github.com/aidotmarket/aim-data-gateway/.github/workflows/cloudflare-verifier-release.yml@refs/tags/"
APPROVED_IMAGE = "docker.io/aidotmarket/aim-cloudflare-verifier@sha256:194576cdeea50798511acebb0ebd294841ffb1a1553c91f7e134c38c8813f087"
BINARY_SOURCE = "2b1e4692bda7516e27a55f5cc4219e3305f1929e"  # v0.1.2 source, Go 1.27.2
APPROVED_BINARY = "305f12ed690b29891398dd39ebf3aa84d7fcda8d4bcb58703fe30e1085c15488"
IMAGE_REPO = "docker.io/aidotmarket/aim-cloudflare-verifier"
DISTRIBUTIONS = {
    "oauth-install-r1": {"version": "0.1.2", "source": BINARY_SOURCE,
                         "binary": APPROVED_BINARY, "image": APPROVED_IMAGE, "go": "1.27.2"},
    "oauth-install-r2": {"version": "0.2.0", "source": "HEAD",
                         "binary": None, "image": None, "go": "1.27.3"},
}


def distribution_spec(version, distribution):
    spec = DISTRIBUTIONS.get(distribution)
    if spec is None or version != spec["version"]:
        raise ValueError("unknown distribution/version pair")
    return spec


def workflow_release(tag=None, distribution=None):
    if tag is not None:
        distribution = tag.removeprefix("cloudflare-verifier-")
        if tag != "cloudflare-verifier-" + distribution:
            raise ValueError("invalid distribution tag")
    spec = distribution_spec(DISTRIBUTIONS.get(distribution, {}).get("version"), distribution)
    return {"distribution": distribution, "version": spec["version"], "go": spec["go"], "source": spec["source"],
            "build_image": str(spec["image"] is None).lower()}


def linker_flags(version):
    return f"-ldflags=-s -w -buildid= -X main.releaseID=cloudflare-verifier-v{version} -X main.scannerVersion={version}"


def release_tag(version, distribution=None):
    if distribution:
        distribution_spec(version, distribution)
    return "cloudflare-verifier-" + distribution if distribution else "cloudflare-verifier-v" + version


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


def build(version, output, verify_committed=False, distribution=None):
    release_tag(version, distribution)
    spec = distribution_spec(version, distribution) if distribution else {"go": "1.27.2"}
    if run("go", "version", env={**os.environ, "GOTOOLCHAIN": "local"}).split()[2] != "go" + spec["go"]:
        raise ValueError("use repository-pinned Go " + spec["go"])
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
            source = ROOT
            if distribution:
                source = directory / "source"
                source.mkdir()
                archive = directory / "source.tar"
                run("git", "archive", "--format=tar", "--output=" + str(archive), spec["source"])
                with tarfile.open(archive) as inputs:
                    inputs.extractall(source, filter="data")
            run("go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
                linker_flags(version),
                "-o", binary, "./cmd/aim-cloudflare-verifier", env=env, cwd=source)
            if distribution and spec["binary"]:
                if digest(binary) != spec["binary"]:
                    raise ValueError("rebuilt binary differs from approved binary")
                if binary.read_bytes() != (TEMPLATE / "aim-cloudflare-verifier").read_bytes():
                    raise ValueError("committed binary differs from rebuilt binary")
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
              "compiled_modules": run("go", "version", "-m", output / "aim-cloudflare-verifier", env={**os.environ, "GOTOOLCHAIN": "local"}).splitlines(),
              "go_version": run("go", "version", env={**os.environ, "GOTOOLCHAIN": "local"}),
              "worker_lockfile_sha256": digest(TEMPLATE / "package-lock.json")}
    if distribution:
        if spec["binary"] and record["binary_sha256"] != spec["binary"]:
            raise ValueError("OAuth binary differs from approved image binary")
        record.update(distribution_revision=distribution, approved_image=spec["image"],
                      binary_source_commit=record["source_commit"] if spec["source"] == "HEAD" else spec["source"])
    (output / "build.json").write_text(json.dumps(record, indent=2) + "\n")
    print("frozen_binary_pin_and_bundle_reproducibility=PASS" if spec.get("binary") else "binary_bundle_reproducibility=PASS", flush=True)
    return record


def verify_built(record, output, version, distribution=None):
    release_tag(version, distribution)
    if distribution:
        spec = distribution_spec(version, distribution)
        if (record.get("distribution_revision") != distribution or record.get("approved_image") != spec["image"]
                or record.get("binary_source_commit") != (record["source_commit"] if spec["source"] == "HEAD" else spec["source"])
                or (spec["binary"] and record["binary_sha256"] != spec["binary"])):
            raise ValueError("OAuth release pins changed")
    if (record["source_commit"] != run("git", "rev-parse", "HEAD")
            or record["release_id"] != "cloudflare-verifier-v" + version
            or record["scanner_version"] != version
            or record["binary_sha256"] != digest(output / "aim-cloudflare-verifier")
            or record["worker_identity"] != {"mode": "bundle", "sha256": digest(output / "worker.mjs")}
            or record["bundle_sha256"] != digest(output / "worker.mjs")
            or record["worker_lockfile_sha256"] != digest(TEMPLATE / "package-lock.json")):
        raise ValueError("release inputs changed")


def container_image(record):
    spec = distribution_spec(record["scanner_version"], record["distribution_revision"])
    image = spec["image"] or record.get("container_image", "")
    if not re.fullmatch(re.escape(IMAGE_REPO) + r"@sha256:[0-9a-f]{64}", image):
        raise ValueError("release needs an exact verifier container image digest")
    return image


def build_image(record, output, push=False):
    spec = distribution_spec(record["scanner_version"], record["distribution_revision"])
    if spec["image"]:
        return  # Frozen distributions retain their already approved image.
    verify_built(record, output, spec["version"], record["distribution_revision"])
    epoch = run("git", "show", "-s", "--format=%ct", record["binary_source_commit"])
    with tempfile.TemporaryDirectory(prefix="cloudflare-verifier-image-") as temp:
        context = Path(temp) / "context"
        context.mkdir()
        shutil.copyfile(TEMPLATE / "Dockerfile", context / "Dockerfile")
        shutil.copyfile(output / "aim-cloudflare-verifier", context / "aim-cloudflare-verifier")
        (context / "aim-cloudflare-verifier").chmod(0o755)
        digests = []
        for n in ((1,) if push else (1, 2)):
            metadata, archive = Path(temp) / f"{n}.json", Path(temp) / f"{n}.oci.tar"
            target = (f"type=image,name={IMAGE_REPO}:v{spec['version']},push=true,unpack=false" if push else
                      f"type=oci,dest={archive},name={IMAGE_REPO}:v{spec['version']}")
            run("docker", "buildx", "build", "--no-cache", "--platform", "linux/amd64",
                "--provenance=false", "--sbom=false", "--build-arg", "SOURCE_DATE_EPOCH=" + epoch,
                "--output", target + ",rewrite-timestamp=true,oci-mediatypes=true",
                "--metadata-file", metadata, context)
            value = json.loads(metadata.read_text())["containerimage.digest"]
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
                raise ValueError("invalid image build digest")
            digests.append(value)
            if not push and n == 1:
                shutil.copyfile(archive, output / "image.oci.tar")
        if len(set(digests)) != 1 or (push and container_image(record) != IMAGE_REPO + "@" + digests[0]):
            raise ValueError("image reproducibility/push digest mismatch")
    record["container_image"] = IMAGE_REPO + "@" + digests[0]
    (output / "build.json").write_text(json.dumps(record, indent=2) + "\n")
    print("container_image=" + record["container_image"], flush=True)


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
        "jurisdiction": "default",
        "release_id": record["release_id"], "scanner_version": record["scanner_version"],
        "binary_sha256": record["binary_sha256"], "worker_identity": record["worker_identity"]}).decode()
    distribution = record.get("distribution_revision")
    tag = release_tag(record["scanner_version"], distribution)
    if distribution:
        config["containers"][0]["image"] = container_image(record)
        config["triggers"]["crons"] = []  # Installer enables only after readback.
        config["vars"]["BOOTSTRAP_INSTALL"] = "{}"  # Per-intent metadata; never a credential.
        (tree / ".dev.vars.example").write_text('REGISTRATION_TOKEN=""\nBOOTSTRAP_WAKE_SECRET=""\n')
        package = json.loads((tree / "package.json").read_text())
        package["cloudflare"]["bindings"].pop("RUN_NOW_SECRET", None)
        (tree / "package.json").write_text(json.dumps(package, indent=2) + "\n")
    (tree / "wrangler.jsonc").write_text(json.dumps(config, indent=2) + "\n")
    if distribution:
        run("git", "archive", "--format=tar", "--output=" + str(tree / "source.tar"), record["binary_source_commit"], "--",
            "go.mod", "go.sum", "LICENSE", "cmd/aim-cloudflare-verifier", "internal/cloudflareverification",
            "verification", "internal/wire", "internal/config", "internal/ids", "internal/inventory")
    else:
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
    run("git", "-c", "commit.gpgsign=false", "commit", "-m", tag, env=env, cwd=tree)
    commit = run("git", "rev-parse", "HEAD", cwd=tree)
    repo = "https://github.com/aidotmarket/" + tag
    raw = repo.replace("github.com", "raw.githubusercontent.com") + "/" + commit
    artifact = "https://github.com/aidotmarket/aim-data-gateway/releases/download/" + tag
    catalog = {"release_id": record["release_id"], "scanner_version": record["scanner_version"],
               "binary_sha256": record["binary_sha256"], "worker_identity": record["worker_identity"],
               "template_repo_url": repo, "template_commit": commit,
               "template_tree_sha256": hashlib.sha256(canonical(files)).hexdigest(),
               "deploy_button_url": "https://deploy.workers.cloudflare.com/?url=" + quote(repo, safe=""),
               "binary_url": raw + "/aim-cloudflare-verifier", "bundle_url": raw + "/worker.mjs",
               "bundle_sha256": record["bundle_sha256"], "config_sha256": digest(tree / "wrangler.jsonc"),
               "container_image": config["containers"][0]["image"],
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


def sign(output, version, distribution=None):
    tag = release_tag(version, distribution)
    if version == "0.1.1" and not distribution:
        raise ValueError("frozen v0.1.1 signing is prohibited; use its original source tag")
    if (os.environ.get("GITHUB_REPOSITORY") != "aidotmarket/aim-data-gateway"
            or os.environ.get("GITHUB_REF") != "refs/tags/" + tag
            or run("git", "rev-list", "-n", "1", tag) != run("git", "rev-parse", "HEAD")):
        raise ValueError("signing requires exact repository/tag workflow identity")
    record = json.loads((output / "build.json").read_text())
    verify_built(record, output, version, distribution)
    entry = json.loads((output / "catalog.json").read_text())["default"]
    files = manifest(output / "template")
    if (entry["template_tree_sha256"] != hashlib.sha256(canonical(files)).hexdigest()
            or entry["config_sha256"] != digest(output / "template/wrangler.jsonc")
            or entry["container_image"] != container_image(record)
            or entry["container_image"] != json.loads((output / "template/wrangler.jsonc").read_text())["containers"][0]["image"]
            or entry["binary_sha256"] != record["binary_sha256"]
            or entry["worker_identity"] != record["worker_identity"]):
        raise ValueError("catalog/template bytes changed")
    run("syft", output / "aim-cloudflare-verifier", "-o", "spdx-json=" + str(output / "cloudflare-verifier.spdx.json"))
    run("grype", "sbom:" + str(output / "cloudflare-verifier.spdx.json"), "--only-fixed", "--fail-on", "high")
    run("syft", "dir:" + str(output / "template"), "-o", "spdx-json=" + str(output / "cloudflare-worker.spdx.json"))
    run("grype", "sbom:" + str(output / "cloudflare-worker.spdx.json"), "--only-fixed", "--fail-on", "high")
    image_sbom = []
    if distribution and DISTRIBUTIONS[distribution]["image"] is None:
        image_sbom = [output / "cloudflare-container.spdx.json"]
        run("syft", "oci-archive:" + str(output / "image.oci.tar"), "-o", "spdx-json=" + str(image_sbom[0]))
        run("grype", "sbom:" + str(image_sbom[0]), "--only-fixed", "--fail-on", "high")
    digests = {name: digest(output / name) for name in ("aim-cloudflare-verifier", "worker.mjs", "template.tar", "template.git.bundle", "catalog.json", "build.json")}
    (output / "digests.json").write_bytes(canonical(digests) + b"\n")
    paths = [output / name for name in ("aim-cloudflare-verifier", "worker.mjs", "catalog.json",
             "template.tar", "template.git.bundle", "template-manifest.json", "cloudflare-verifier.spdx.json", "cloudflare-worker.spdx.json", "build.json", "digests.json")]
    paths += [output / "template/wrangler.jsonc"] + image_sbom
    for path in paths:
        bundle = output / (path.name + ".sigstore.json")
        run("cosign", "sign-blob", "--yes", "--bundle", bundle, path)
        run("cosign", "verify-blob", "--bundle", bundle, "--certificate-identity", IDENTITY + tag,
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", help="Must match the distribution table; omitted means table version")
    parser.add_argument("--distribution", required=True, choices=DISTRIBUTIONS)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/cloudflare-verifier")
    parser.add_argument("--verify-committed", action="store_true")
    parser.add_argument("--sign", action="store_true")
    args = parser.parse_args()
    args.version = args.version or DISTRIBUTIONS[args.distribution]["version"]
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?", args.version):
        parser.error("version must be semver")
    output = args.output.resolve()
    record = build(args.version, output, args.verify_committed or bool(DISTRIBUTIONS[args.distribution]["binary"]), args.distribution)
    build_image(record, output)
    export(record, output)
    if args.sign:
        sign(output, args.version, args.distribution)


if __name__ == "__main__":
    main()
