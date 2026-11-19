"""Offline C0 regression tests. Never contact Docker, AIM or a provider."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("install_kit", Path(__file__).with_name("check-install-kit.py"))
kit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kit)
PROBE_SPEC = importlib.util.spec_from_file_location("network_probe", kit.ROOT / "install-kit/own-https/network-probe.py")
probe = importlib.util.module_from_spec(PROBE_SPEC)
PROBE_SPEC.loader.exec_module(probe)


class KitContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("KD_BRIDGE_JOB_SCRATCH"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for relative in kit.FILES:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(kit.ROOT / relative, path)

    def mutate(self, relative, change):
        path = self.root / relative
        document = json.loads(path.read_text())
        change(document)
        path.write_text(json.dumps(document))

    def test_source_contracts(self):
        kit.check(self.root)

    def test_gateway_pin_and_provenance_must_match(self):
        for field, value in (("image", "ghcr.io/aidotmarket/aim-gateway:latest"),
                             ("environment", {}), ("environment", {"AIM_PAIRING_CODE": "PRIVATE-MARKER"})):
            with self.subTest(field=field, value=value):
                original = (self.root / "install-kit/compose.yaml").read_text()
                self.mutate("install-kit/compose.yaml", lambda d: d["services"]["aim-gateway"].__setitem__(field, value))
                with self.assertRaises(kit.ContractError):
                    kit.check(self.root)
                (self.root / "install-kit/compose.yaml").write_text(original)

    def test_hardening_network_mount_and_helper_mutations(self):
        changes = [("user", "0:0"), ("read_only", False), ("cap_drop", []), ("cap_add", ["NET_ADMIN"]),
                   ("security_opt", []), ("privileged", True), ("network_mode", "host"),
                   ("pid", "host"), ("dns", ["1.1.1.1"]), ("ports", ["8080:8080"]),
                   ("networks", {"gateway": {}, "internet": {}}), ("volumes", ["/:/host:ro"])]
        for field, value in changes:
            with self.subTest(field=field):
                original = (self.root / "install-kit/compose.yaml").read_text()
                self.mutate("install-kit/compose.yaml", lambda d: d["services"]["aim-gateway"].__setitem__(field, value))
                with self.assertRaises(kit.ContractError):
                    kit.check(self.root)
                (self.root / "install-kit/compose.yaml").write_text(original)
        for relative, service in (("install-kit/compose.yaml", "connect-proxy"),
                                  ("install-kit/own-https/compose.yaml", "https-door"),
                                  ("install-kit/cloudflare-named/compose.yaml", "named-tunnel")):
            for field, value in (("sysctls", {}), ("volumes", ["/state:/state:ro"]),
                                 ("image", "helper:latest"), ("networks", {"gateway": {}, "default": {}})):
                with self.subTest(service=service, field=field):
                    original = (self.root / relative).read_text()
                    self.mutate(relative, lambda d: d["services"][service].__setitem__(field, value))
                    with self.assertRaises(kit.ContractError):
                        kit.check(self.root)
                    (self.root / relative).write_text(original)

    def test_optional_profile_cannot_be_advertised(self):
        self.mutate("install-kit/cloudflare-named/compose.yaml", lambda d: d["services"]["named-tunnel"].__setitem__("profiles", []))
        with self.assertRaises(kit.ContractError):
            kit.check(self.root)

    def test_proxy_cannot_allow_other_hosts_or_parent_fallback(self):
        path = self.root / "install-kit/squid.conf"
        for line in ("http_access allow all", "cache_peer example.invalid parent 3128 0 default", "acl aim_control dstdomain .ai.market"):
            original = path.read_text()
            path.write_text(original + "\n" + line)
            with self.assertRaises(kit.ContractError):
                kit.check(self.root)
            path.write_text(original)

    def test_no_private_artifact_or_symlink(self):
        path = self.root / "install-kit/cloudflare-named/config.yaml"
        path.write_text(path.read_text() + "\nAIM_PAIRING_CODE=example-not-a-code\n")
        with self.assertRaises(kit.ContractError):
            kit.check(self.root)
        path.unlink()
        path.symlink_to(kit.ROOT / "install-kit/cloudflare-named/config.yaml")
        with self.assertRaises(kit.ContractError):
            kit.check(self.root)

    def manifest(self):
        return {"schema_version": 1, "kit_version": kit.KIT_VERSION, "gateway_version": "0.2.4",
                "images": {"gateway": kit.GATEWAY_IMAGE, **{name: "example.invalid/helper@sha256:" + "a" * 64 for name in ("squid", "tls_proxy", "probe", "cloudflared")}},
                "files": {name: hashlib.sha256((self.root / name).read_bytes()).hexdigest() for name in kit.FILES}}

    def verify(self, manifest, signature_ok=True):
        path = self.root / "manifest.json"
        path.write_text(json.dumps(manifest))
        with patch.object(kit.shutil, "which", return_value="cosign"), patch.object(kit, "run", return_value=subprocess.CompletedProcess([], 0 if signature_ok else 1, "PRIVATE-MARKER", "PRIVATE-MARKER")) as run:
            result = kit.verified_release(path, self.root / "bundle.json", "v1.2.3", self.root)
            argv = run.call_args.args[0]
            self.assertIn("--offline", argv)
            self.assertIn("https://github.com/aidotmarket/aim-data-gateway/.github/workflows/release.yml@refs/tags/v1.2.3", argv)
            return result

    def test_signed_release_binds_every_file_and_image(self):
        self.assertEqual(self.verify(self.manifest())["gateway"], kit.GATEWAY_IMAGE)
        manifest = self.manifest()
        for mutation in (lambda d: d["files"].pop("install-kit/preflight.sh"),
                         lambda d: d["files"].__setitem__("../private", "a" * 64),
                         lambda d: d["files"].__setitem__("install-kit/preflight.sh", "0" * 64),
                         lambda d: d["images"].__setitem__("probe", "python:latest"),
                         lambda d: d["images"].__setitem__("gateway", "gateway@sha256:" + "0" * 64),
                         lambda d: d.__setitem__("gateway_version", "0.2.5")):
            changed = copy.deepcopy(manifest)
            mutation(changed)
            with self.assertRaises(kit.ContractError):
                self.verify(changed)
        with self.assertRaises(kit.ContractError) as error:
            self.verify(manifest, signature_ok=False)
        self.assertNotIn("PRIVATE-MARKER", str(error.exception))
        with self.assertRaises(kit.ContractError):
            kit.verified_release(None, None, None, self.root)

    def test_duplicate_fields_rejected(self):
        path = self.root / "duplicate.json"
        path.write_text('{"images":{},"images":{}}')
        with self.assertRaises(kit.ContractError):
            kit.load_json(path)


class PreflightContracts(unittest.TestCase):
    def args(self, *extra):
        from argparse import Namespace
        return Namespace(report=True, platform="linux_cloud", certificate=None, manifest=None,
                         bundle=None, release_tag=None, start_probes=False, gateway_container=None, **dict(extra))

    def test_readonly_report_is_bounded_and_sanitized(self):
        output = io.StringIO()
        with patch.object(kit, "check"), patch.object(kit.shutil, "which", return_value="docker"), patch.object(kit, "run", return_value=subprocess.CompletedProcess([], 1, "PRIVATE-PATH", "SECRET")) as run, contextlib.redirect_stdout(output):
            self.assertEqual(kit.preflight(self.args()), 1)
        report = json.loads(output.getvalue())
        self.assertLess(len(output.getvalue()), 8192)
        self.assertEqual(set(report), {"schema_version", "kit_version", "platform", "generated_at", "checks"})
        self.assertEqual({row["code"] for row in report["checks"]}, set(kit.CHECKS))
        self.assertEqual(len(report["checks"]), len(kit.CHECKS))
        self.assertNotIn("SECRET", output.getvalue())
        self.assertNotIn("PRIVATE-PATH", output.getvalue())
        for call in run.call_args_list:
            self.assertEqual(call.args[0][0], "docker")
            self.assertIn(call.args[0][1], ("info", "compose"))
        for row in report["checks"]:
            self.assertEqual(set(row), {"code", "outcome", "checked_at"})
            if row["code"] in ("egress", "integrity", "state_write", "source_uid", "tls_inspection"):
                self.assertEqual(row["outcome"], "unknown")

    def test_certificate_expiry_within_fourteen_days_is_a_failure(self):
        args = self.args()
        args.certificate = "/private/example.pem"
        output = io.StringIO()
        with patch.object(kit, "check"), patch.object(kit.shutil, "which", return_value=None), patch.object(kit, "run", return_value=subprocess.CompletedProcess([], 1, "", "PRIVATE")) as run, contextlib.redirect_stdout(output):
            kit.preflight(args)
        self.assertIn("1209600", run.call_args.args[0])
        report = json.loads(output.getvalue())
        self.assertEqual(next(row["outcome"] for row in report["checks"] if row["code"] == "tls_proxy"), "fail")

    def test_probe_execution_fails_before_docker_when_release_inputs_missing(self):
        args = self.args()
        args.start_probes = True
        with patch.object(kit, "check"), patch.object(kit.shutil, "which", return_value=None), patch.object(kit, "run") as run:
            with self.assertRaises(kit.ContractError):
                kit.preflight(args)
            run.assert_not_called()

    def test_probe_does_not_treat_open_routes_as_denied(self):
        self.assertFalse(probe.denied(lambda: True))
        self.assertTrue(probe.denied(lambda: False))
        def blocked():
            raise TimeoutError()
        self.assertTrue(probe.denied(blocked))

    def test_allowed_control_failure_prevents_isolation_pass(self):
        with patch.object(probe, "allowed_aim_tls", return_value=False), patch.object(probe, "tcp") as tcp:
            self.assertEqual(probe.main(), 1)
            tcp.assert_not_called()


if __name__ == "__main__":
    unittest.main()
