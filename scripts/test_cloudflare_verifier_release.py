#!/usr/bin/env python3
"""Offline release identity/template checks; no cloud, signing or network calls."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("cloudflare-verifier-release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_distribution_table_and_workflow_mapping(self):
        for distribution, version, source, toolchain in [
                ("oauth-install-r1", "0.1.2", release.BINARY_SOURCE, "1.27.2"),
                ("oauth-install-r2", "0.2.0", "HEAD", "1.27.3")]:
            tag = "cloudflare-verifier-" + distribution
            self.assertEqual(release.release_tag(version, distribution), tag)
            self.assertEqual(release.distribution_spec(version, distribution)["source"], source)
            selected = release.workflow_release(tag)
            self.assertEqual(selected, release.workflow_release(distribution=distribution))
            self.assertEqual((selected["distribution"], selected["version"], selected["go"]),
                             (distribution, version, toolchain))
            self.assertEqual(selected["source"], source)
        for version, distribution in [("0.1.2", "unknown"), ("0.2.0", "oauth-install-r1"),
                                      ("0.1.2", "oauth-install-r2"), ("0.2.1", "oauth-install-r2")]:
            with self.assertRaises(ValueError):
                release.release_tag(version, distribution)
        for tag in ["cloudflare-verifier-oauth-install-r99", "oauth-install-r2", "v0.2.0"]:
            with self.assertRaises(ValueError):
                release.workflow_release(tag)
        # A future release is only a table row, including workflow selection.
        with mock.patch.dict(release.DISTRIBUTIONS, {"oauth-install-r3": {
                **release.DISTRIBUTIONS["oauth-install-r2"], "version": "0.2.1"}}):
            self.assertEqual(release.workflow_release("cloudflare-verifier-oauth-install-r3")["version"], "0.2.1")
        workflow = (release.ROOT / ".github/workflows/cloudflare-verifier-release.yml").read_text()
        self.assertIn("tags: ['cloudflare-verifier-oauth-install-r*']", workflow)
        self.assertIn("selected = release.workflow_release(os.environ['RELEASE_TAG'] or None", workflow)
        self.assertIn("selected = release.workflow_release(os.environ['RELEASE_TAG'])", workflow)
        self.assertIn("if: github.event_name == 'push'", workflow)
        self.assertIn('git archive "$BINARY_SOURCE_REF" go.mod go.sum', workflow)
        self.assertNotIn("0.1.2", workflow)

    def test_release_build_stamps_table_version(self):
        # Native builds can execute the actual production linker flags offline.
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "verifier"
            for spec in release.DISTRIBUTIONS.values():
                version = spec["version"]
                release.run("go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
                            release.linker_flags(version), "-o", binary, "./cmd/aim-cloudflare-verifier")
                self.assertEqual(release.run(binary, "version").split(),
                                 ["cloudflare-verifier-v" + version, version, release.digest(binary)])
            release.run("go", "build", "-mod=readonly", "-o", binary, "./cmd/aim-cloudflare-verifier")
            self.assertEqual(release.run(binary, "version").split()[:2], ["dev", "dev"])

    def test_r2_build_uses_head_and_rejects_reproducibility_mismatch(self):
        real_run = release.run
        for mismatch in (False, True):
            with self.subTest(mismatch=mismatch), tempfile.TemporaryDirectory() as temp:
                out = Path(temp)
                builds = []
                def commands(*args, **kwargs):
                    if args[:2] == ("git", "archive"):
                        self.assertEqual(args[-1], "HEAD")
                        return real_run(*args, **kwargs)
                    if args[:2] == ("go", "build"):
                        self.assertIn("main.scannerVersion=0.2.0", args[5])
                        self.assertIn("main.releaseID=cloudflare-verifier-v0.2.0", args[5])
                        self.assertEqual(kwargs["env"]["GOTOOLCHAIN"], "local")
                        self.assertEqual(kwargs["env"]["GOPROXY"], "off")
                        builds.append(kwargs["cwd"])
                        Path(args[args.index("-o") + 1]).write_bytes(b"changed" if mismatch and len(builds) == 2 else b"r2")
                        return ""
                    if args[:2] == ("go", "version"):
                        return "go version go1.27.3 linux/amd64"
                    if str(args[0]).endswith("esbuild"):
                        Path(args[-1].removeprefix("--outfile=")).write_bytes(b"bundle")
                        return ""
                    return real_run(*args, **kwargs)
                with mock.patch.object(release, "run", side_effect=commands):
                    if mismatch:
                        with self.assertRaisesRegex(RuntimeError, "reproducibility mismatch"):
                            release.build("0.2.0", out, distribution="oauth-install-r2")
                        self.assertFalse((out / "build.json").exists())
                    else:
                        record = release.build("0.2.0", out, distribution="oauth-install-r2")
                        self.assertEqual(record["binary_source_commit"], real_run("git", "rev-parse", "HEAD"))
                        release.verify_built(record, out, "0.2.0", "oauth-install-r2")
                self.assertEqual(len(set(builds)), 2)

    def test_r2_image_catalog_export_and_signing_bind_same_image(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            for name in ("aim-cloudflare-verifier", "worker.mjs"):
                (out / name).write_bytes((release.TEMPLATE / name).read_bytes())
            record = {"release_id": "cloudflare-verifier-v0.2.0", "scanner_version": "0.2.0",
                      "binary_sha256": release.digest(out / "aim-cloudflare-verifier"),
                      "worker_identity": {"mode": "bundle", "sha256": release.digest(out / "worker.mjs")},
                      "bundle_sha256": release.digest(out / "worker.mjs"),
                      "distribution_revision": "oauth-install-r2", "approved_image": None,
                      "source_commit": release.run("git", "rev-parse", "HEAD"),
                      "binary_source_commit": release.run("git", "rev-parse", "HEAD"),
                      "worker_lockfile_sha256": release.digest(release.TEMPLATE / "package-lock.json")}
            with self.assertRaisesRegex(ValueError, "exact verifier container image"):
                release.container_image(record)
            real_run = release.run
            image_calls, pushed = [], []
            image_digest = "sha256:" + "a" * 64
            def commands(*args, **kwargs):
                if args[:3] != ("docker", "buildx", "build"):
                    return real_run(*args, **kwargs)
                context = args[-1]
                self.assertEqual(set(p.name for p in context.iterdir()), {"Dockerfile", "aim-cloudflare-verifier"})
                self.assertEqual(release.digest(context / "aim-cloudflare-verifier"), record["binary_sha256"])
                self.assertEqual((context / "aim-cloudflare-verifier").stat().st_mode & 0o777, 0o755)
                self.assertIn("--no-cache", args)
                self.assertIn("--provenance=false", args)
                self.assertIn("SOURCE_DATE_EPOCH=" + real_run("git", "show", "-s", "--format=%ct", "HEAD"), args)
                target = args[args.index("--output") + 1]
                image_calls.append(target)
                if "push=true" not in target:
                    Path(target.split("dest=")[1].split(",")[0]).write_bytes(b"OCI")
                Path(args[args.index("--metadata-file") + 1]).write_text(json.dumps({
                    "containerimage.digest": (pushed[0] if pushed else image_digest)}))
                return ""
            with mock.patch.object(release, "run", side_effect=commands):
                release.build_image(record, out)
                self.assertEqual(len(image_calls), 2)
                self.assertTrue(all("push=true" not in c for c in image_calls))
                release.build_image(record, out, push=True)
                pushed.append("sha256:" + "b" * 64)
                with self.assertRaisesRegex(ValueError, "push digest mismatch"):
                    release.build_image(record, out, push=True)
                with self.assertRaisesRegex(ValueError, "reproducibility/push digest mismatch"):
                    # Make the two local image builds disagree.
                    pushed.clear()
                    def disagree(*args, **kwargs):
                        result = commands(*args, **kwargs)
                        if args[:3] == ("docker", "buildx", "build"):
                            pushed.append("sha256:" + "b" * 64)
                        return result
                    with mock.patch.object(release, "run", side_effect=disagree):
                        release.build_image(record, out)
            release.export(record, out)
            catalog_path = out / "catalog.json"
            entry = json.loads(catalog_path.read_text())["default"]
            config = json.loads((out / "template/wrangler.jsonc").read_text())
            self.assertEqual(entry["container_image"], release.IMAGE_REPO + "@" + image_digest)
            self.assertEqual(entry["container_image"], config["containers"][0]["image"])
            self.assertEqual(entry["config_sha256"], release.digest(out / "template/wrangler.jsonc"))
            self.assertEqual(len(entry), 15)
            with mock.patch.dict("os.environ", {"GITHUB_REPOSITORY": "aidotmarket/aim-data-gateway",
                    "GITHUB_REF": "refs/tags/cloudflare-verifier-oauth-install-r2"}), \
                    mock.patch.object(release, "run", return_value=record["source_commit"]):
                entry["container_image"] = release.APPROVED_IMAGE
                catalog_path.write_bytes(release.canonical({"default": entry}))
                with self.assertRaisesRegex(ValueError, "catalog/template bytes changed"):
                    release.sign(out, "0.2.0", "oauth-install-r2")

    def test_catalog_and_frozen_template_export(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            for name in ("aim-cloudflare-verifier", "worker.mjs"):
                (output / name).write_bytes((release.TEMPLATE / name).read_bytes())
            binary = release.digest(output / "aim-cloudflare-verifier")
            bundle = release.digest(output / "worker.mjs")
            record = {"release_id": "cloudflare-verifier-v0.1.0", "scanner_version": "0.1.0",
                      "binary_sha256": binary, "worker_identity": {"mode": "bundle", "sha256": bundle},
                      "bundle_sha256": bundle}
            release.export(record, output)
            catalog = json.loads((output / "catalog.json").read_text())["default"]
            self.assertEqual(set(catalog), set("release_id scanner_version binary_sha256 worker_identity template_repo_url template_commit template_tree_sha256 deploy_button_url binary_url bundle_url bundle_sha256 config_sha256 signature_url sbom_url container_image".split()))
            self.assertEqual(catalog["template_tree_sha256"], hashlib.sha256(release.canonical(release.manifest(output / "template"))).hexdigest())
            self.assertEqual(catalog["binary_sha256"], binary)
            self.assertEqual(catalog["worker_identity"], record["worker_identity"])
            self.assertEqual(catalog["bundle_sha256"], bundle)
            self.assertNotIn("image_digest", catalog)
            self.assertIn("url=https%3A%2F%2Fgithub.com", catalog["deploy_button_url"])
            self.assertEqual(len(catalog["template_commit"]), 40)
            self.assertTrue((output / "template.git.bundle").exists())
            self.assertFalse((output / "template/.git").exists())
            self.assertTrue((output / "template/source.tar").exists())
            config = json.loads((output / "template/wrangler.jsonc").read_text())
            self.assertEqual(catalog["container_image"], config["containers"][0]["image"])
            self.assertEqual(catalog["config_sha256"], release.digest(output / "template/wrangler.jsonc"))
            self.assertEqual(config["main"], "worker.mjs")
            self.assertTrue(config["no_bundle"])
            self.assertEqual(config["containers"][0]["scheduling_policy"], "default")
            self.assertEqual(config["containers"][0]["instance_type"], "standard-2")
            self.assertEqual(config["containers"][0]["max_instances"], 1)
            self.assertEqual(config["migrations"][0]["new_sqlite_classes"], ["CloudflareVerifier"])
            self.assertNotIn("account_id", config)
            self.assertEqual(set(json.loads(config["vars"]["DEPLOYMENT_CONFIG"])),
                             set("release_id scanner_version binary_sha256 worker_identity jurisdiction".split()))
            tree_hash = catalog["template_tree_sha256"]
            release.export(record, output)
            again = json.loads((output / "catalog.json").read_text())["default"]
            self.assertEqual(again["template_tree_sha256"], tree_hash)
            self.assertEqual(again["template_commit"], catalog["template_commit"])

    def test_changed_artifacts_refuse_signing(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            (out / "aim-cloudflare-verifier").write_bytes(b"binary")
            (out / "worker.mjs").write_bytes(b"bundle")
            record = {"source_commit": "pinned", "release_id": "cloudflare-verifier-v0.1.0",
                      "scanner_version": "0.1.0", "binary_sha256": release.digest(out / "aim-cloudflare-verifier"),
                      "worker_identity": {"mode": "bundle", "sha256": release.digest(out / "worker.mjs")},
                      "bundle_sha256": release.digest(out / "worker.mjs"),
                      "worker_lockfile_sha256": release.digest(release.TEMPLATE / "package-lock.json")}
            with mock.patch.object(release, "run", return_value="pinned"):
                release.verify_built(record, out, "0.1.0")
                (out / "worker.mjs").write_bytes(b"changed")
                with self.assertRaises(ValueError):
                    release.verify_built(record, out, "0.1.0")
                with self.assertRaises(ValueError):
                    release.verify_built(record, out, "0.2.0")

    def test_oauth_distribution_keeps_binary_identity_and_immutable_artifact_names(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            for name in ("aim-cloudflare-verifier", "worker.mjs"):
                (out / name).write_bytes((release.TEMPLATE / name).read_bytes())
            record = {"release_id": "cloudflare-verifier-v0.1.2", "scanner_version": "0.1.2",
                      "binary_sha256": release.digest(out / "aim-cloudflare-verifier"),
                      "worker_identity": {"mode": "bundle", "sha256": release.digest(out / "worker.mjs")},
                      "bundle_sha256": release.digest(out / "worker.mjs"), "distribution_revision": "oauth-install-r1",
                      "approved_image": release.APPROVED_IMAGE, "binary_source_commit": release.BINARY_SOURCE, "source_commit": "pinned",
                      "worker_lockfile_sha256": release.digest(release.TEMPLATE / "package-lock.json")}
            self.assertEqual(record["binary_sha256"], release.APPROVED_BINARY)
            release.export(record, out)
            catalog = json.loads((out / "catalog.json").read_text())["default"]
            config = json.loads((out / "template/wrangler.jsonc").read_text())
            self.assertEqual(json.loads(config["vars"]["DEPLOYMENT_CONFIG"])["release_id"], "cloudflare-verifier-v0.1.2")
            self.assertEqual(catalog["scanner_version"], "0.1.2")
            self.assertTrue(catalog["template_repo_url"].endswith("/cloudflare-verifier-oauth-install-r1"))
            self.assertIn("/cloudflare-verifier-oauth-install-r1/", catalog["signature_url"])
            self.assertEqual(config["containers"][0]["image"], release.APPROVED_IMAGE)
            self.assertEqual(catalog["container_image"], release.APPROVED_IMAGE)
            self.assertEqual(config["triggers"]["crons"], [])
            self.assertNotIn("RUN_NOW_SECRET", (out / "template/.dev.vars.example").read_text())
            self.assertNotIn("RUN_NOW_SECRET", (out / "template/package.json").read_text())
            (out / "build.json").write_text(json.dumps(record))
            tag = release.release_tag("0.1.2", "oauth-install-r1")
            def commands(*args, **kwargs):
                return "pinned" if args[0] == "git" else ""
            with mock.patch.dict("os.environ", {"GITHUB_REPOSITORY": "aidotmarket/aim-data-gateway", "GITHUB_REF": "refs/tags/" + tag}), mock.patch.object(release, "run", side_effect=commands) as run:
                release.sign(out, "0.1.2", "oauth-install-r1")
                checks = [c.args for c in run.call_args_list if c.args[:2] == ("cosign", "verify-blob")]
                self.assertTrue(checks)
                self.assertTrue(all(release.IDENTITY + tag in c for c in checks))
            with self.assertRaises(ValueError):
                release.sign(out, "0.1.1")
            for version, distribution in [("0.1.1", "oauth-install-r1"), ("0.1.2", "unknown")]:
                with self.assertRaises(ValueError):
                    release.release_tag(version, distribution)

    def test_wrong_path_toolchain_refuses_before_build(self):
        # Stub the local version; never invoke Go or allow auto-switching.
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "output"
            with mock.patch.dict("os.environ", {"GOTOOLCHAIN": "auto"}), \
                    mock.patch.object(release, "run", return_value="go version go1.27.1 linux/amd64") as run:
                with self.assertRaisesRegex(ValueError, r"use repository-pinned Go 1\.27\.2"):
                    release.build("0.1.2", output, distribution="oauth-install-r1")
            run.assert_called_once()
            self.assertEqual(run.call_args.args, ("go", "version"))
            self.assertEqual(run.call_args.kwargs["env"]["GOTOOLCHAIN"], "local")
            self.assertFalse(output.exists())

    def test_oauth_rebuilt_binary_mismatch_refuses(self):
        # Exercise both builds and the mandatory template check even without
        # --verify-committed. Compilation is stubbed; source export is real.
        real_run = release.run
        approved = b"approved rebuilt binary"
        for mismatch_build, changed_template in [(1, False), (2, False), (1, True)]:
            with self.subTest(build=mismatch_build, template=changed_template), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                template = root / "template"
                template.mkdir()
                (template / "aim-cloudflare-verifier").write_bytes(b"stale" if changed_template else approved)
                builds = []

                def commands(*args, **kwargs):
                    if args[:2] == ("git", "archive"):
                        self.assertEqual(args[-1], release.BINARY_SOURCE)
                        return real_run(*args, **kwargs)
                    if args[:2] == ("go", "version"):
                        return "go version go1.27.2 linux/amd64"
                    if args[:2] == ("go", "build"):
                        source = kwargs["cwd"]
                        self.assertNotEqual(source, release.ROOT)
                        self.assertTrue((source / "cmd/aim-cloudflare-verifier/main.go").is_file())
                        self.assertEqual(kwargs["env"]["GOTOOLCHAIN"], "local")
                        self.assertIn("main.scannerVersion=0.1.2", args[5])
                        builds.append(source)
                        binary = Path(args[args.index("-o") + 1])
                        binary.write_bytes(b"mismatch" if len(builds) == mismatch_build and not changed_template else approved)
                        return ""
                    if str(args[0]).endswith("esbuild"):
                        Path(args[-1].removeprefix("--outfile=")).write_bytes(b"bundle")
                        return ""
                    self.fail(f"unexpected command: {args}")

                message = "committed binary differs" if changed_template else "rebuilt binary differs"
                with mock.patch.object(release, "TEMPLATE", template), \
                        mock.patch.dict(release.DISTRIBUTIONS["oauth-install-r1"], {"binary": hashlib.sha256(approved).hexdigest()}), \
                        mock.patch.object(release, "run", side_effect=commands):
                    with self.assertRaisesRegex(ValueError, message):
                        release.build("0.1.2", root / "output", distribution="oauth-install-r1")
                self.assertEqual(len(builds), mismatch_build)
                self.assertEqual(len(set(builds)), len(builds))
                self.assertFalse((root / "output/build.json").exists())
                self.assertFalse((root / "output/aim-cloudflare-verifier").exists())

    def test_restricted_dockerfile_and_proxy_export(self):
        self.assertEqual((release.TEMPLATE / "Dockerfile").read_text().splitlines(),
                         ["FROM scratch", "COPY aim-cloudflare-verifier /aim-cloudflare-verifier",
                          'ENTRYPOINT ["/aim-cloudflare-verifier"]'])
        self.assertIn('export { ContainerProxy } from "@cloudflare/containers"',
                      (release.TEMPLATE / "worker.ts").read_text())
        self.assertIn("ContainerProxy", (release.TEMPLATE / "worker.mjs").read_text())
        self.assertEqual((release.TEMPLATE / ".dev.vars.example").read_text(),
                         'REGISTRATION_TOKEN=""\nRUN_NOW_SECRET=""\n')


if __name__ == "__main__":
    unittest.main()
