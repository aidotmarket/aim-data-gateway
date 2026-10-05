#!/usr/bin/env python3
"""Offline release boundary tests, invoked by go test ./deploy."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import sys
from unittest.mock import patch
import zipfile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("aws-verifier-release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_reproducible_zip_layout_and_code_sha(self):
        calls = []

        def fake_run(*args, **kwargs):
            calls.append((args, kwargs))
            if args[:2] == ("go", "build"):
                Path(args[args.index("-o") + 1]).write_bytes(b"synthetic-arm64-bootstrap")
            return "fixture"

        with tempfile.TemporaryDirectory() as temp, patch.object(release, "run", fake_run):
            out = Path(temp)
            with contextlib.redirect_stdout(io.StringIO()):
                result = release.build("1.0.0", out)
            with zipfile.ZipFile(out / "bootstrap.zip") as archive:
                self.assertEqual(archive.namelist(), ["bootstrap"])
                info = archive.getinfo("bootstrap")
                self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0))
                self.assertEqual(info.external_attr >> 16, 0o100755)
                self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
                self.assertEqual(info.extra, b"")
            sha = hashlib.sha256((out / "bootstrap.zip").read_bytes()).digest()
            self.assertEqual(result["image_digest"], "sha256:" + sha.hex())
            self.assertEqual(result["CodeSha256"], base64.b64encode(sha).decode())
            builds = [(args, opts) for args, opts in calls if args[:2] == ("go", "build")]
            self.assertEqual(len(builds), 2)
            self.assertNotEqual(builds[0][1]["env"]["GOCACHE"], builds[1][1]["env"]["GOCACHE"])
            for args, opts in builds:
                self.assertIn("-mod=readonly", args)
                self.assertIn("-trimpath", args)
                self.assertEqual(opts["env"]["GOARCH"], "arm64")
                self.assertEqual(opts["env"]["CGO_ENABLED"], "0")

    def test_download_equality_explicit_versions_and_immutable_put(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bootstrap.zip"
            path.write_bytes(b"fixture")
            entry = {"region": "eu-north-1", "bucket": "public-fixture"}
            calls = []

            def fake_run(*args, **kwargs):
                calls.append(args)
                return '{"VersionId":"version+/="}'

            class Download(io.BytesIO):
                def geturl(self):
                    return self.url

            def download(url, **kwargs):
                response = Download(path.read_bytes())
                response.url = url
                return response

            def changed_download(url):
                response = Download(b"changed")
                response.url = url
                return response

            with patch.object(release, "run", fake_run), patch.object(release.urllib.request, "urlopen", download):
                result = release.upload(entry, "aws-verifier/1.0.0/hash/bootstrap.zip", path)
            self.assertEqual(result["object_version"], "version+/=")
            self.assertIn("versionId=version%2B%2F%3D", result["url"])
            self.assertEqual(calls[0][-4:-2], ("--if-none-match", "*"))
            with patch.object(release, "run", fake_run), patch.object(
                release.urllib.request, "urlopen", lambda *a, **k: changed_download(a[0])
            ):
                with self.assertRaises(RuntimeError):
                    release.upload(entry, "key", path)
            with patch.object(release, "run", return_value='{"VersionId":"null"}'):
                with self.assertRaises(RuntimeError):
                    release.upload(entry, "key", path)

    def test_double_build_mismatch_refuses_release(self):
        count = 0

        def run(*args, **kwargs):
            nonlocal count
            if args[:2] == ("go", "build"):
                count += 1
                Path(args[args.index("-o") + 1]).write_bytes(bytes([count]))
            return "fixture"

        with tempfile.TemporaryDirectory() as temp, patch.object(release, "run", run):
            out = Path(temp)
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
                release.build("1.0.0", out)
            self.assertFalse((out / "build.json").exists())

    def test_five_region_catalog_and_publication_receipts(self):
        entries = [{"region": r, "bucket": "public-" + r, "smoke_function_arn": "fixture"}
                   for r in sorted(release.REGIONS)]
        record = {"CodeSha256": "actual-provider-hash", "image_digest": "sha256:" + "a" * 64,
                  "scanner_version": "1.0.0"}
        calls, uploads = [], []

        def run(*args, **kwargs):
            calls.append(args)
            if args[:3] == ("aws", "s3api", "get-bucket-versioning"):
                return '{"Status":"Enabled"}'
            if args[:3] == ("aws", "lambda", "get-function"):
                return json.dumps({"Configuration": {"CodeSha256": record["CodeSha256"],
                                  "Runtime": "provided.al2023", "Architectures": ["arm64"],
                                  "State": "Active", "LastUpdateStatus": "Successful"}})
            if args[0] == "syft":
                Path(str(args[-1]).split("=", 1)[1]).write_text('{"spdxVersion":"SPDX-2.3"}')
            return "fixture"

        def sign(path, bundle, version):
            self.assertTrue(path.exists())
            bundle.write_text("fixture-keyless-signature")

        def upload(entry, key, path):
            # All five provider identities checked before the first public write.
            self.assertEqual(sum(c[:3] == ("aws", "lambda", "get-function") for c in calls), 5)
            uploads.append((entry["region"], key))
            return {"object_version": "fixture-version", "sha256": release.digest(path)}

        with tempfile.TemporaryDirectory() as temp, patch.object(release, "run", run), \
                patch.object(release, "sign", sign), patch.object(release, "upload", upload):
            out = Path(temp)
            for name in ["bootstrap", "bootstrap.zip", "aws-verifier.yaml"]:
                (out / name).write_bytes(b"fixture")
            with contextlib.redirect_stdout(io.StringIO()):
                release.publish(record, entries, out)
            catalog = json.loads((out / "catalog.json").read_text())
            self.assertEqual({e["region"] for e in catalog["regions"]}, release.REGIONS)
            self.assertTrue(all(e["actual_CodeSha256"] == record["CodeSha256"] for e in catalog["regions"]))
            self.assertTrue(all(len(e["objects"]) == 6 for e in catalog["regions"]))
            self.assertEqual(len(json.loads((out / "publication.json").read_text())), 5)
            self.assertEqual(len(uploads), 40)

    def test_five_region_manifest_and_smoke_before_publication(self):
        entries = [{"region": r, "bucket": "public-" + r,
                    "smoke_function_arn": f"arn:aws:lambda:{r}:123456789012:function:verifier-smoke"}
                   for r in sorted(release.REGIONS)]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "manifest.json"
            path.write_text(json.dumps(entries))
            self.assertEqual(release.manifest(path), entries)
            for invalid in [entries[:4], entries + entries[:1], entries[:4] + entries[:1]]:
                path.write_text(json.dumps(invalid))
                with self.assertRaises(ValueError):
                    release.manifest(path)
            calls = []

            def run(*args, **kwargs):
                calls.append(args)
                if args[:3] == ("aws", "s3api", "get-bucket-versioning"):
                    return '{"Status":"Enabled"}'
                return json.dumps({"Configuration": {"CodeSha256": "WRONG", "Runtime": "provided.al2023", "Architectures": ["arm64"]}})

            with patch.object(release, "run", run), patch.object(release, "upload") as upload:
                with self.assertRaises(RuntimeError):
                    release.publish({"CodeSha256": "EXPECTED"}, entries, Path(temp))
                upload.assert_not_called()
            self.assertEqual(len(calls), 2)

    def test_sign_and_verify_keyless_blob_identity(self):
        with patch.object(release, "run") as run:
            release.sign(Path("bootstrap.zip"), Path("bundle.json"), "1.0.0")
            sign, verify = [call.args for call in run.call_args_list]
            self.assertEqual(sign[:3], ("cosign", "sign-blob", "--yes"))
            self.assertNotIn("--key", sign)
            self.assertIn("cosign", verify)
            self.assertIn(release.IDENTITY + "1.0.0", verify)
            self.assertIn("https://token.actions.githubusercontent.com", verify)

    def test_all_subprocesses_use_rtk(self):
        with patch.object(release.subprocess, "check_output", return_value=b"ok") as command:
            self.assertEqual(release.run("go", "version"), "ok")
            self.assertEqual(command.call_args.args[0], ["rtk", "proxy", "go", "version"])


if __name__ == "__main__":
    unittest.main()
