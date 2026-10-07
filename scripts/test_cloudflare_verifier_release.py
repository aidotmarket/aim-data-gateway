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
            self.assertEqual(set(catalog), set("release_id scanner_version binary_sha256 worker_identity template_repo_url template_commit template_tree_sha256 deploy_button_url binary_url bundle_url bundle_sha256 config_sha256 signature_url sbom_url".split()))
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
                      "worker_lockfile_sha256": release.digest(release.TEMPLATE / "package-lock.json")}
            with mock.patch.object(release, "run", return_value="pinned"):
                release.verify_built(record, out, "0.1.0")
                (out / "worker.mjs").write_bytes(b"changed")
                with self.assertRaises(ValueError):
                    release.verify_built(record, out, "0.1.0")
                with self.assertRaises(ValueError):
                    release.verify_built(record, out, "0.2.0")

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
