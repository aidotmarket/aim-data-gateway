"""Offline C0 regression tests. Never contact Docker, AIM or a provider."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import types
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("install_kit", Path(__file__).with_name("check-install-kit.py"))
kit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kit)
PROBE_ARGS = ["probe.py", "--door-hostname", "data.example.org", "--dns-upstream", "127.0.0.1"]
PROBE_PATH = kit.ROOT / "install-kit/own-https/network-probe.py"
probe = types.ModuleType("network_probe")
# Import the fixture without creating bytecode inside the public install kit.
exec(compile(PROBE_PATH.read_text(), str(PROBE_PATH), "exec"), probe.__dict__)


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
                self.mutate("install-kit/compose.yaml", lambda d: d["x-kit-services"]["aim-gateway"].__setitem__(field, value))
                with self.assertRaises(kit.ContractError):
                    kit.check(self.root)
                (self.root / "install-kit/compose.yaml").write_text(original)

    def test_hardening_network_mount_and_helper_mutations(self):
        changes = [("user", "0:0"), ("read_only", False), ("read_only", 1), ("cap_drop", []), ("cap_add", ["NET_ADMIN"]),
                   ("security_opt", []), ("privileged", True), ("network_mode", "host"),
                   ("pid", "host"), ("dns", ["1.1.1.1"]), ("ports", ["8080:8080"]),
                   ("networks", {"gateway": {}, "internet": {}}), ("volumes", ["/:/host:ro"])]
        for field, value in changes:
            with self.subTest(field=field):
                original = (self.root / "install-kit/compose.yaml").read_text()
                self.mutate("install-kit/compose.yaml", lambda d: d["x-kit-services"]["aim-gateway"].__setitem__(field, value))
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
                    self.mutate(relative, lambda d: d["x-kit-services"][service].__setitem__(field, value))
                    with self.assertRaises(kit.ContractError):
                        kit.check(self.root)
                    (self.root / relative).write_text(original)

    def test_optional_profile_cannot_be_advertised(self):
        self.mutate("install-kit/cloudflare-named/compose.yaml", lambda d: d["x-kit-services"]["named-tunnel"].__setitem__("profiles", []))
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

    def test_unexpected_local_artifact_cannot_enter_public_kit(self):
        (self.root / "install-kit/local-settings.json").write_text('{}')
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

    def test_signed_helper_tags_are_rejected_for_every_role(self):
        for key in ("squid", "tls_proxy", "cloudflared", "probe"):
            manifest = self.manifest()
            manifest["images"][key] = "helper:latest"
            with self.subTest(role=key), self.assertRaises(kit.ContractError):
                self.verify(manifest)

    def test_duplicate_fields_rejected(self):
        path = self.root / "duplicate.json"
        path.write_text('{"images":{},"images":{}}')
        with self.assertRaises(kit.ContractError):
            kit.load_json(path)


class PreflightContracts(unittest.TestCase):
    def args(self, *extra):
        from argparse import Namespace
        return Namespace(report=True, platform="linux_cloud", certificate=None, manifest=None,
                         bundle=None, release_tag=None, start_probes=False, gateway_container=None, door_container=None,
                         check_source=False, check_state_write=False, source_folder=None, state_volume=None,
                         serving_distro=None, **dict(extra))

    def test_readonly_report_is_bounded_and_sanitized(self):
        docker_commands = [
            ["docker", "info", "--format", "{{.OSType}}"],
            ["docker", "compose", "version", "--short"],
        ]
        linux_commands = [
            ["ip", "-json", "route", "show", "table", "all"],
            ["ss", "-H", "-ltn", "sport = :443"],
        ]
        for platform in ("linux", "darwin"):
            commands = docker_commands + (linux_commands if platform == "linux" else [])
            for returncode in (0, 1):
                output = io.StringIO()
                private_outputs = []

                def diagnostic(argv):
                    marker = "PRIVATE-" + "-".join(argv[:2])
                    stdout = marker * 8192
                    stderr = ("SECRET-" + marker) * 8192
                    private_outputs.extend((marker, "SECRET-" + marker))
                    # Valid route JSON exercises successful Linux diagnostics too.
                    if argv[0] == "ip":
                        stdout = json.dumps([{"dst": "default", "private": stdout}])
                    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

                with self.subTest(platform=platform, returncode=returncode), patch.object(kit, "check"), patch.object(kit.sys, "platform", platform), patch.object(kit.os, "uname", return_value=types.SimpleNamespace(machine="x86_64")), patch.object(kit.shutil, "which", side_effect=lambda name: "/fixture/" + name), patch.object(kit, "run", side_effect=diagnostic) as run, contextlib.redirect_stdout(output):
                    self.assertEqual(kit.preflight(self.args()), 1)
                self.assertEqual([call.args[0] for call in run.call_args_list], commands)
                report = json.loads(output.getvalue())
                self.assertLess(len(output.getvalue()), 8192)
                self.assertEqual(set(report), {"schema_version", "kit_version", "platform", "generated_at", "helpers", "checks"})
                self.assertEqual({row["code"] for row in report["checks"]}, set(kit.CHECKS))
                self.assertEqual(len(report["checks"]), len(kit.CHECKS))
                for private in private_outputs:
                    self.assertNotIn(private, output.getvalue())
                for row in report["checks"]:
                    self.assertEqual(set(row), {"code", "outcome", "checked_at"})
                    if row["outcome"] == "unknown":
                        self.assertIsNone(row["checked_at"])
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

    def test_probe_preserves_only_explicit_tristate_verdicts(self):
        self.assertIs(probe.denied(lambda: True), True)
        self.assertIs(probe.denied(lambda: False), False)
        for value in (None, 0, 1, b"", [], object()):
            self.assertIsNone(probe.denied(lambda: value))
        def blocked():
            raise TimeoutError()
        self.assertIsNone(probe.denied(blocked))

    def test_allowed_control_failure_prevents_isolation_pass(self):
        with patch.object(probe.sys, "argv", PROBE_ARGS), patch.object(probe, "allowed_aim_tls", return_value=False), patch.object(probe, "tcp") as tcp:
            self.assertEqual(probe.main(), 1)
            tcp.assert_not_called()

    def test_probe_shares_actual_namespace_and_always_confirms_cleanup(self):
        args = self.args()
        args.start_probes = True
        args.gateway_container = "test-gateway"
        args.door_container = "test-door"
        args.door_hostname = "data.example.org"
        container = {"Id": "abcdef", "Image": "sha256:local-id", "Config": {"Image": kit.GATEWAY_IMAGE, "User": "65532:65532", "Env": ["AIM_GATEWAY_IMAGE_DIGEST=" + kit.GATEWAY_DIGEST]},
                     "State": {"Running": True}, "HostConfig": {"ReadonlyRootfs": True, "CapDrop": ["ALL"], "Privileged": False, "SecurityOpt": ["no-new-privileges:true"], "NetworkMode": "kit", "Dns": ["127.0.0.1"]},
                     "NetworkSettings": {"Networks": {"kit": {"NetworkID": "network-1", "IPAddress": "172.30.196.2"}}},
                     "Mounts": [{"Destination": name, "RW": name == "/state", "Type": "volume" if name == "/state" else "bind"} for name in ("/config/gateway.toml", "/sources/data", "/state")]}
        for cleanup_ok, door_present, image_matches, dns_matches, hostname_matches in (
                (True, True, True, True, True), (False, True, True, True, True),
                (True, False, True, True, True), (True, True, False, True, True),
                (True, True, True, False, True), (True, True, True, True, False)):
            calls = []
            def fake_run(argv):
                calls.append(argv)
                if argv[1] == "inspect":
                    if argv[-1] == "test-door":
                        if not door_present:
                            return subprocess.CompletedProcess(argv, 1, "", "")
                        return subprocess.CompletedProcess(argv, 0, json.dumps({"Id": "door-id", "State": {"Running": True},
                            "Config": {"Image": "example.invalid/tls@sha256:" + "1" * 64, "Env": ["DOOR_HOSTNAME=" + ("data.example.org" if hostname_matches else "other.example.org")]},
                            "HostConfig": {"Dns": ["127.0.0.1"] if dns_matches else ["1.1.1.1"]},
                            "NetworkSettings": {"Networks": {"kit": {"NetworkID": "network-1", "IPAddress": "172.30.196.4"}}}}), "")
                    return subprocess.CompletedProcess(argv, 0, json.dumps(container), "")
                if argv[1] == "image":
                    return subprocess.CompletedProcess(argv, 0, json.dumps([kit.GATEWAY_IMAGE] if image_matches else []), "")
                if argv[1] == "network":
                    return subprocess.CompletedProcess(argv, 0, '[{"Internal":true}]', "")
                if argv[1] == "run":
                    return subprocess.CompletedProcess(argv, 0, ("door-negative-probes:pass\n" if "--door" in argv else "isolation-negative-probes:pass\n"), "")
                if argv[1] == "rm":
                    return subprocess.CompletedProcess(argv, 0 if cleanup_ok else 1, "", "")
                raise AssertionError("unexpected external action")
            output = io.StringIO()
            with self.subTest(cleanup_ok=cleanup_ok), patch.object(kit, "check"), patch.object(kit.sys, "platform", "linux"), patch.object(kit.os, "uname", return_value=types.SimpleNamespace(machine="x86_64")), patch.object(kit.shutil, "which", return_value=None), patch.object(kit, "verified_release", return_value={"probe": "example.invalid/probe@sha256:" + "0" * 64, "tls_proxy": "example.invalid/tls@sha256:" + "1" * 64}), patch.object(kit, "run", side_effect=fake_run), contextlib.redirect_stdout(output):
                if cleanup_ok and door_present and image_matches and dns_matches and hostname_matches:
                    self.assertEqual(kit.preflight(args), 1)  # Docker CLI is deliberately absent in this fixture.
                    report = json.loads(output.getvalue())
                    self.assertEqual(next(row["outcome"] for row in report["checks"] if row["code"] == "egress"), "unknown")
                else:
                    with self.assertRaises(kit.ContractError):
                        kit.preflight(args)
            if not door_present or not image_matches or not dns_matches or not hostname_matches:
                self.assertFalse(any(argv[1] == "run" for argv in calls))
                self.assertEqual(output.getvalue(), "")
                continue
            if cleanup_ok:
                door_probe = [argv for argv in calls if "--door" in argv]
                self.assertEqual(len(door_probe), 1)
                self.assertIn("container:door-id", door_probe[0])
                self.assertEqual(report["helpers"], {"https-door": "running", "named-tunnel": "unselected"})
            started = next(argv for argv in calls if argv[1] == "run")
            self.assertIn("container:abcdef", started)
            for argv in (call for call in calls if call[1] == "run"):
                self.assertEqual(argv[argv.index("--door-hostname") + 1], "data.example.org")
                self.assertEqual(argv[argv.index("--dns-upstream") + 1], "127.0.0.1")
            self.assertIn("--pull=never", started)
            self.assertEqual(sum("type=bind," in arg for arg in started), 1)
            self.assertEqual(calls[-1][1:3], ["rm", "--force"])
            if not cleanup_ok:
                self.assertEqual(output.getvalue(), "")


class RevisionContracts(unittest.TestCase):
    setUp = KitContracts.setUp
    manifest = KitContracts.manifest
    def compose_args(self):
        return types.SimpleNamespace(manifest="manifest.json", bundle="bundle.json", release_tag="v1.2.3",
            state_volume="legacy-company_aim-gateway-state", source_folder=str(self.root),
            gateway_config=str(self.root / "README.md"), certificate=str(self.root / "README.md"),
            private_key=str(self.root / "README.md"), certificate_mode="manual", door_hostname="data.example.org", compose_action="up")

    def test_raw_templates_have_no_executable_services(self):
        for relative in ("compose.yaml", "own-https/compose.yaml", "own-https/compose.acme.yaml", "cloudflare-named/compose.yaml"):
            self.assertNotIn("services", kit.load_json(self.root / "install-kit" / relative))

    def test_both_profiles_require_dns_hostname_and_bind_it_to_door(self):
        for mode in ("manual", "acme"):
            args = self.compose_args()
            args.certificate_mode = mode
            args.acme_state_volume = "certificates"
            for hostname in (None, "", "172.30.196.4", "bad-.example.org", "a..org", "a" * 64 + ".org", "data.example.org"):
                args.door_hostname = hostname
                with self.subTest(mode=mode, hostname=hostname), patch.object(kit, "verified_release", return_value=self.manifest()["images"]), patch.object(kit, "existing_volume", side_effect=lambda name: name):
                    if hostname == "data.example.org":
                        document = kit.pinned_compose(args, self.root)
                        self.assertEqual(document["services"]["https-door"]["environment"]["DOOR_HOSTNAME"], hostname)
                    else:
                        with self.assertRaises(kit.ContractError):
                            kit.pinned_compose(args, self.root)

    def test_startup_rejects_missing_manifest_tag_and_other_digest_before_compose(self):
        for variable in ("SQUID_IMAGE", "TLS_PROXY_IMAGE", "CLOUDFLARED_IMAGE"):
            for override in (None, "helper:latest", "example.invalid/helper@sha256:" + "b" * 64):
                args = self.compose_args()
                if override is None:
                    args.manifest = None
                images = self.manifest()["images"]
                # Use the real missing-input check, with all Docker/Cosign calls recorded.
                original_verify = kit.verified_release
                def verify(*arguments):
                    if arguments[0] is None:
                        return original_verify(None, None, None, self.root)
                    return images
                with self.subTest(variable=variable, override=override), patch.object(kit, "verified_release", side_effect=verify), patch.dict(os.environ, {} if override is None else {variable: override}), patch.object(kit, "run") as run:
                    with patch.object(kit, "ROOT", self.root), self.assertRaises(kit.ContractError):
                        kit.compose_action(args)
                    run.assert_not_called()

    def test_legacy_external_volume_and_verified_pins_ignore_project_name(self):
        args = self.compose_args()
        images = self.manifest()["images"]
        def inspect(argv):
            self.assertEqual(argv[:3], ["docker", "volume", "inspect"])
            return subprocess.CompletedProcess(argv, 0, args.state_volume, "")
        with patch.object(kit, "verified_release", return_value=images), patch.object(kit, "run", side_effect=inspect):
            document = kit.pinned_compose(args, self.root)
        self.assertEqual(document["name"], "aim-install-kit")
        self.assertEqual(document["volumes"]["aim-gateway-state"], {"external": True, "name": args.state_volume})
        self.assertEqual(document["services"]["connect-proxy"]["image"], images["squid"])
        self.assertEqual(document["services"]["https-door"]["image"], images["tls_proxy"])
        for service in document["services"].values():
            self.assertEqual(service["restart"], "unless-stopped")

    def test_compose_start_and_inspection_use_same_literal_verified_config(self):
        documents = []
        def run(argv, **kwargs):
            if argv[1] == "volume":
                return subprocess.CompletedProcess(argv, 0, "legacy-company_aim-gateway-state", "")
            if argv[1] == "ps":
                return subprocess.CompletedProcess(argv, 0, "", "")
            self.assertEqual(argv[:2], ["docker", "compose"])
            self.assertIn("-", argv)
            documents.append(json.loads(kwargs["input"]))
            if "up" in argv:
                self.assertEqual(argv[-2:], ["--pull", "never"])
            return subprocess.CompletedProcess(argv, 0, "", "")
        args = self.compose_args()
        with patch.object(kit, "ROOT", self.root), patch.object(kit, "verified_release", return_value=self.manifest()["images"]), patch.object(kit, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            kit.compose_action(args)
            args.compose_action = "config"
            kit.compose_action(args)
        self.assertEqual(documents[0], documents[1])
        self.assertNotIn("${", json.dumps(documents[0]))
        for service in documents[0]["services"].values():
            self.assertRegex(service["image"], r"@sha256:[0-9a-f]{64}$")

    def test_cutover_refuses_running_legacy_writer_and_allows_stopped_or_own(self):
        args = self.compose_args()
        for running, own, writable, permitted in ((True, False, True, False),
                (False, False, True, True), (True, True, True, True), (True, False, False, True)):
            container = {"State": {"Running": running},
                "Config": {"Image": kit.GATEWAY_IMAGE, "Labels": {
                    "com.docker.compose.project": "aim-install-kit" if own else "legacy",
                    "com.docker.compose.service": "aim-gateway", "com.docker.compose.oneoff": "False"}},
                "Mounts": [{"Type": "volume", "Name": args.state_volume, "RW": writable, "Destination": "/state"}]}
            compose_calls = []
            def run(argv, **kwargs):
                if argv[1] == "volume":
                    output = args.state_volume
                elif argv[1] == "ps":
                    self.assertIn("volume=" + args.state_volume, argv)
                    output = "abcdef123456\n"
                elif argv[1] == "inspect":
                    output = json.dumps([container])
                else:
                    self.assertEqual(argv[:2], ["docker", "compose"])
                    self.assertEqual(argv[argv.index("--project-name") + 1], "aim-install-kit")
                    compose_calls.append(argv)
                    output = ""
                return subprocess.CompletedProcess(argv, 0, output, "")
            with self.subTest(running=running, own=own, writable=writable), patch.object(kit, "ROOT", self.root), patch.object(kit, "verified_release", return_value=self.manifest()["images"]), patch.object(kit, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                if permitted:
                    kit.compose_action(args)
                    kit.compose_action(args)
                    self.assertEqual(len(compose_calls), 2)
                else:
                    with self.assertRaises(kit.ContractError):
                        kit.compose_action(args)
                    self.assertEqual(compose_calls, [])

    def test_volume_writer_inspection_fails_closed(self):
        for results in ((1, ""), (0, "not-an-id"), (0, "abcdef123456")):
            with self.subTest(results=results), patch.object(kit, "run", return_value=subprocess.CompletedProcess([], results[0], results[1], "")):
                with self.assertRaises(kit.ContractError):
                    kit.exclusive_state_writer("legacy_state", "aim-install-kit")

    def test_own_gateway_does_not_hide_another_writer(self):
        own = {"State": {"Running": True}, "Config": {"Image": kit.GATEWAY_IMAGE,
            "Labels": {"com.docker.compose.project": "aim-install-kit",
                       "com.docker.compose.service": "aim-gateway", "com.docker.compose.oneoff": "False"}},
            "Mounts": [{"Type": "volume", "Name": "legacy_state", "RW": True, "Destination": "/state"}]}
        other = copy.deepcopy(own)
        other["Config"]["Labels"]["com.docker.compose.project"] = "legacy"
        for containers in ([own, other], [own, own]):
            with self.subTest(containers=containers), patch.object(kit, "run", side_effect=[
                subprocess.CompletedProcess([], 0, "abcdef123456\nabcdef123457\n", ""),
                subprocess.CompletedProcess([], 0, json.dumps(containers), "")]):
                with self.assertRaises(kit.ContractError):
                    kit.exclusive_state_writer("legacy_state", "aim-install-kit")

    def test_missing_external_volume_creates_nothing(self):
        with patch.object(kit, "verified_release", return_value=self.manifest()["images"]), patch.object(kit, "run", return_value=subprocess.CompletedProcess([], 1, "", "")) as run:
            with self.assertRaises(kit.ContractError):
                kit.pinned_compose(self.compose_args(), self.root)
            self.assertEqual(len(run.call_args_list), 1)
            self.assertEqual(run.call_args.args[0][:3], ["docker", "volume", "inspect"])

    def test_acme_persistent_state_and_separate_ca_egress(self):
        args = self.compose_args()
        args.certificate_mode = "acme"
        args.acme_state_volume = "legacy_certificates"
        args.door_hostname = "data.example.org"
        with patch.object(kit, "verified_release", return_value=self.manifest()["images"]), patch.object(kit, "existing_volume", side_effect=lambda name: name):
            document = kit.pinned_compose(args, self.root)
        self.assertTrue(document["networks"]["acme"]["internal"])
        self.assertEqual(set(document["services"]["https-door"]["networks"]), {"gateway", "acme", "door-ingress"})
        self.assertEqual(set(document["services"]["aim-gateway"]["networks"]), {"gateway"})
        self.assertEqual(document["volumes"]["acme-certificates"], {"external": True, "name": "legacy_certificates"})
        self.assertIn({"type": "volume", "source": "acme-certificates", "target": "/data"}, document["services"]["https-door"]["volumes"])
        self.assertNotIn("/data", str(document["services"]["https-door"]["tmpfs"]))
        args.acme_state_volume = args.state_volume
        with patch.object(kit, "verified_release", return_value=self.manifest()["images"]), patch.object(kit, "existing_volume", side_effect=lambda name: name):
            with self.assertRaises(kit.ContractError):
                kit.pinned_compose(args, self.root)
        path = self.root / "install-kit/own-https/acme-squid.conf"
        path.write_text(path.read_text() + "http_access allow all\n")
        with self.assertRaises(kit.ContractError):
            kit.check(self.root)

    def test_uid_source_and_state_checks_are_distinct_and_remove_only_sentinel(self):
        for read_status, write_status in ((1, 0), (0, 1)):
            programs = []
            def run(argv):
                if argv[1] == "volume":
                    return subprocess.CompletedProcess(argv, 0, "legacy_state", "")
                if argv[1] == "rm":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                self.assertEqual(argv[1], "run")
                self.assertIn("none", argv)
                self.assertIn("65532:65532", argv)
                self.assertIn("--pull=never", argv)
                program = argv[-1]
                programs.append(program)
                try:
                    if "os.walk" in program:
                        fixture = self.root / "read-fixture"
                        fixture.write_bytes(b"data")
                        with patch.object(os, "walk", return_value=iter([(str(self.root), [], [fixture.name])])), patch.object(os, "access", return_value=read_status == 0):
                            exec(compile(program, "<source-permission-fixture>", "exec"), {})
                    elif write_status:
                        with patch.object(tempfile, "mkstemp", side_effect=PermissionError):
                            exec(compile(program, "<state-permission-fixture>", "exec"), {})
                    else:
                        sentinel = self.root / "identity"
                        sentinel.write_bytes(b"unchanged identity")
                        exec(compile(program.replace("dir='/check'", "dir=" + repr(str(self.root))), "<state-permission-fixture>", "exec"), {})
                        self.assertEqual(sentinel.read_bytes(), b"unchanged identity")
                        self.assertFalse(list(self.root.glob('.aim-permission-*')))
                    status = 0
                except PermissionError:
                    status = 1
                return subprocess.CompletedProcess(argv, status, "", "")
            with patch.object(kit, "run", side_effect=run):
                self.assertEqual(kit.filesystem_probe("pinned", source=str(self.root)), "pass" if read_status == 0 else "fail")
                self.assertEqual(kit.filesystem_probe("pinned", volume="legacy_state"), "pass" if write_status == 0 else "fail")
            self.assertIn("'rb'", programs[0])
            self.assertIn("tempfile.mkstemp", programs[1])
            self.assertNotIn("gateway.db", programs[1])
            self.assertIn("os.unlink(path)", programs[1])

    def test_serving_wsl_mixed_versions_in_both_directions(self):
        for serving, utility, expected in (("4.4.0-Microsoft", "microsoft-standard-WSL2", "fail"), ("6.6.0-microsoft-standard-WSL2", "Microsoft", "pass")):
            with patch.dict(os.environ, {"WSL_DISTRO_NAME": "Serving"}), patch.object(Path, "read_text", return_value=serving):
                self.assertEqual(kit.serving_wsl("Serving"), expected)
                self.assertEqual(kit.serving_wsl("Utility"), "unknown")
                self.assertEqual(kit.serving_wsl(None), "unknown")

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is unavailable; native WSL fixture requires Windows/PowerShell")
    def test_native_serving_wsl_mixed_versions(self):
        source = (kit.ROOT / "install-kit/preflight.ps1").read_text()
        function = re.search(r"function Get-ServingWslVersion.*?\n}", source, re.S)[0]
        script = function + r"""
$one = @('  NAME STATE VERSION', '* Serving Running 1', '  Utility Stopped 2')
$two = @('  NAME STATE VERSION', '* Serving Running 2', '  Utility Stopped 1')
if ((Get-ServingWslVersion $one 'Serving') -ne '1') { exit 1 }
if ((Get-ServingWslVersion $two 'Serving') -ne '2') { exit 2 }
if ($null -ne (Get-ServingWslVersion $one 'Missing')) { exit 3 }
if ($null -ne (Get-ServingWslVersion $one '')) { exit 4 }
"""
        result = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)


class CcRevisionContracts(unittest.TestCase):
    setUp = KitContracts.setUp
    mutate = KitContracts.mutate
    def test_every_service_refuses_missing_restart_and_added_access(self):
        for relative in kit.EXPECTED_COMPOSE:
            original = (self.root / relative).read_text()
            for service in json.loads(original)["x-kit-services"]:
                for field, value in (("volumes", ["/:/host:ro"]), ("volumes", ["/var/run:/hostrun:ro"]),
                                     ("volumes", ["${EXPORT_FOLDER}:/srv:ro"]), ("dns", ["9.9.9.9"]),
                                     ("command", ["other"]), ("healthcheck", {"test": ["CMD", "true"]}),
                                     ("tmpfs", ["/host"]), ("restart", None)):
                    with self.subTest(relative=relative, service=service, field=field, value=value):
                        def change(document):
                            selected = document["x-kit-services"][service]
                            if value is None:
                                selected.pop(field, None)
                            else:
                                selected[field] = value
                        self.mutate(relative, change)
                        with self.assertRaises(kit.ContractError):
                            kit.check(self.root)
                        (self.root / relative).write_text(original)

    def test_connection_directives_are_closed(self):
        cases = {
            "install-kit/own-https/Caddyfile": [lambda s: s.replace("    tls /certs/server.pem /certs/server.key", ""),
                lambda s: s + "\n:9000 {\n file_server\n}\n",
                lambda s: s.replace("172.30.196.2:8080", "other:8080")],
            "install-kit/own-https/Caddyfile.acme": [lambda s: s.replace("disable_http_challenge", "# disable_http_challenge")],
            "install-kit/cloudflare-named/config.yaml": [lambda s: s.replace("172.30.196.2:8080", "other:8080"),
                lambda s: s.replace("    service: http://", "service: http://")],
        }
        for relative, changes in cases.items():
            path = self.root / relative
            original = path.read_text()
            for change in changes:
                with self.subTest(relative=relative):
                    path.write_text(change(original))
                    with self.assertRaises(kit.ContractError):
                        kit.check(self.root)
                    path.write_text(original)

    def test_ingress_is_separate_from_gateway_and_no_masquerade(self):
        for relative in ("install-kit/own-https/compose.yaml", "install-kit/own-https/compose.acme.yaml"):
            document = kit.load_json(self.root / relative)
            self.assertIn("door-ingress", document["x-kit-services"]["https-door"]["networks"])
            ingress = document["networks"]["door-ingress"]
            self.assertFalse(ingress.get("internal", False))
            self.assertEqual(ingress["driver_opts"]["com.docker.network.bridge.enable_ip_masquerade"], "false")
            original = (self.root / relative).read_text()
            self.mutate(relative, lambda d: d["networks"]["door-ingress"]["driver_opts"].clear())
            with self.assertRaises(kit.ContractError):
                kit.check(self.root)
            (self.root / relative).write_text(original)

    def test_door_namespace_negative_probe_detects_open_outbound(self):
        for opened in (True, False):
            def tcp(*args):
                if opened:
                    return unittest.mock.MagicMock()
                raise ConnectionRefusedError()
            with patch.object(probe.sys, "argv", PROBE_ARGS + ["--door"]), patch("builtins.open", unittest.mock.mock_open(read_data="nameserver 127.0.0.1\n")), patch.object(probe, "tcp", side_effect=tcp), patch.object(probe, "dns_answer", return_value=True), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(probe.main(), 1 if opened else 0)
                self.assertEqual(output.getvalue(), "" if opened else "door-negative-probes:pass\n")

    def test_signature_only_sets_integrity_and_unattempted_times_are_null(self):
        args = PreflightContracts.args(self)
        args.manifest = "manifest.json"
        with patch.object(kit, "check"), patch.object(kit, "verified_release", return_value={}), patch.object(kit.shutil, "which", return_value=None), contextlib.redirect_stdout(io.StringIO()) as output:
            kit.preflight(args)
        rows = {row["code"]: row for row in json.loads(output.getvalue())["checks"]}
        self.assertEqual(rows["integrity"]["outcome"], "pass")
        self.assertIsNotNone(rows["integrity"]["checked_at"])
        for code in ("image_digest", "source_uid", "state_write", "egress"):
            self.assertEqual(rows[code]["outcome"], "unknown")
            self.assertIsNone(rows[code]["checked_at"])

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell unavailable; Windows behavior still needs V1 receipts")
    def test_windows_hypervisor_power_and_native_stderr(self):
        source = (kit.ROOT / "install-kit/preflight.ps1").read_text()
        functions = "\n".join(re.search(r"function " + name + r".*?\n}", source, re.S)[0]
                              for name in ("Test-Virtualization", "Get-CurrentPowerIndices", "Invoke-ReadOnlyNative"))
        script = functions + r"""
$ErrorActionPreference = 'Stop'
$off = @([pscustomobject]@{VirtualizationFirmwareEnabled=$false})
$on = @([pscustomobject]@{VirtualizationFirmwareEnabled=$true})
if (-not (Test-Virtualization $true $off)) { exit 1 }
if (Test-Virtualization $false $off) { exit 2 }
if (-not (Test-Virtualization $false $on)) { exit 3 }
$rows = @('Minimum Possible Setting: 0x00000000', 'Maximum Possible Setting: 0xffffffff',
 'Possible Settings increment: 0x00000001', 'Current AC Power Setting Index: 0x00000000',
 'Current DC Power Setting Index: 0x00000001')
$indices = @(Get-CurrentPowerIndices $rows)
if ($indices.Count -ne 2 -or $indices[1].Groups[1].Value -ne '0x00000001') { exit 4 }
$result = Invoke-ReadOnlyNative (Get-Process -Id $PID).Path @('-NoProfile', '-Command', '[Console]::Error.WriteLine("private"); exit 1')
if ($result.ExitCode -ne 1 -or $ErrorActionPreference -ne 'Stop') { exit 5 }
"""
        result = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)


class ConnectStatusContracts(unittest.TestCase):
    def socket(self, blocks):
        class Socket:
            def __init__(self): self.blocks = iter(blocks); self.pending = b""
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def sendall(self, value): pass
            def settimeout(self, value): pass
            def recv(self, length):
                if not self.pending: self.pending = next(self.blocks, b"")
                value, self.pending = self.pending[:length], self.pending[length:]
                return value
        return Socket()

    def response(self, blocks, inspected_door=False):
        with patch.object(probe, "tcp", return_value=self.socket(blocks)):
            return probe.connect("proxy", 3128, "example.com:443", inspected_door=inspected_door)

    @contextlib.contextmanager
    def tls_context(self, failure=None, certificate=b"server certificate"):
        context = unittest.mock.MagicMock()
        def wrap(sock, **kwargs):
            self.assertEqual(kwargs["server_hostname"], "data.example.org")
            self.assertIs(kwargs["suppress_ragged_eofs"], False)
            if failure:
                raise failure
            sock.tls = True  # Successful wrap_socket includes the TLS handshake.
            sock.getpeercert = unittest.mock.Mock(return_value=certificate)
            return sock
        context.wrap_socket.side_effect = wrap
        with patch.object(probe.ssl, "SSLContext", return_value=context) as factory:
            yield context
        factory.assert_called_with(probe.ssl.PROTOCOL_TLS_CLIENT)
        self.assertIs(context.check_hostname, False)
        self.assertEqual(context.verify_mode, probe.ssl.CERT_NONE)

    def test_full_probe_shipped_door_layout_and_forbidden_success(self):
        self.assertIn(":8443 {", (kit.ROOT / "install-kit/own-https/Caddyfile").read_text())
        targets = [("172.30.196.3", 3128, b"example.com:443"),
                   ("172.30.196.3", 3128, b"api.ai.market:80")]
        targets += [("172.30.196.4", port, b"example.com:443") for port in (3128, 8080, 8443)]
        cases = [(None, None, denial, None) for denial in (None, 400, 403, 405)]
        cases += [(target, code, 403, None) for target in targets for code in range(200, 300)]
        cases += [(None, None, None, failure) for failure in (probe.ssl.SSLEOFError(), ConnectionResetError())]
        for opened, status, denial, tls_failure in cases:
            parent = self
            def tcp(host, port):
                target = (host, port)
                if host == "1.1.1.1":
                    raise ConnectionRefusedError()
                if host == "172.30.196.4" and port != 8443 and (opened is None or target != opened[:2]):
                    raise ConnectionRefusedError()
                class Reply:
                    tls = False
                    def __enter__(self): return self
                    def __exit__(self, *args): pass
                    def sendall(self, data):
                        if port == 8443:
                            parent.assertTrue(self.tls, "CONNECT must be sent inside TLS")
                            self.getpeercert.assert_called_once_with(binary_form=True)
                        code = status if opened and target == opened[:2] and opened[2] in data else (denial if port == 8443 else 403)
                        blocks = [] if code is None else [b"HTTP/", ("1.1 %d Reply\r\n\r\n" % code).encode()]
                        self.sock = parent.socket(blocks)
                    def settimeout(self, value): pass
                    def recv(self, length): return self.sock.recv(length)
                return Reply()
            with self.subTest(opened=opened, status=status, denial=denial, tls_failure=tls_failure), self.tls_context(failure=tls_failure), patch.object(probe.sys, "argv", PROBE_ARGS), patch.object(probe, "allowed_aim_tls", return_value=True), patch("builtins.open", unittest.mock.mock_open(read_data="nameserver 127.0.0.1\n")), patch.object(probe, "tcp", side_effect=tcp), patch.object(probe, "dns_answer", return_value=True), contextlib.redirect_stdout(io.StringIO()) as output:
                passes = opened is None and tls_failure is None
                self.assertEqual(probe.main(), 0 if passes else 1)
                self.assertEqual(output.getvalue(), "isolation-negative-probes:pass\n" if passes else "")

    def test_tls_door_requires_handshake_and_certificate(self):
        for failure in (probe.ssl.SSLEOFError(), ConnectionResetError(), TimeoutError()):
            with self.subTest(failure=failure), self.tls_context(failure=failure), patch.object(probe, "tcp", return_value=self.socket([])):
                self.assertIsNone(probe.connect("172.30.196.4", 8443, "example.com:443", inspected_door=True, door_hostname="data.example.org"))
        with self.tls_context(certificate=None), patch.object(probe, "tcp", return_value=self.socket([])):
            self.assertIsNone(probe.connect("172.30.196.4", 8443, "example.com:443", inspected_door=True, door_hostname="data.example.org"))
        with patch.object(probe, "tcp", side_effect=ConnectionRefusedError):
            self.assertIsNone(probe.connect("172.30.196.4", 8443, "example.com:443", inspected_door=True, door_hostname="data.example.org"))

    def test_tls_door_clean_close_and_final_non_2xx_are_denial(self):
        for code in [None] + list(range(300, 600)):
            blocks = [] if code is None else [("HTTP/1.1 %d Reply\r\n\r\n" % code).encode()]
            with self.subTest(code=code), self.tls_context(), patch.object(probe, "tcp", return_value=self.socket(blocks)):
                self.assertIs(probe.connect("172.30.196.4", 8443, "example.com:443", inspected_door=True, door_hostname="data.example.org"), True)

    def test_tls_door_informational_responses_require_final_status(self):
        hints = b"HTTP/1.1 103 Early Hints\r\nLink: </example>\r\n\r\n"
        continue_response = b"HTTP/1.1 100 Continue\r\n\r\n"
        cases = [
            (hints + b"HTTP/1.1 200 Connection Established\r\n\r\n", False),
            (continue_response + b"HTTP/1.1 403 Forbidden\r\n\r\n", True),
            (hints, None),
            (hints + b"HTTP/1.1 200 Partial", None),
            (continue_response * 5 + b"HTTP/1.1 200 Connected\r\n\r\n", False),
            (continue_response * 6 + b"HTTP/1.1 403 Forbidden\r\n\r\n", None),
        ]
        for reply, expected_denial in cases:
            with self.subTest(reply=reply), self.tls_context(), patch.object(probe, "tcp", return_value=self.socket([reply])):
                self.assertIs(probe.denied(lambda: probe.connect("172.30.196.4", 8443, "example.com:443", inspected_door=True, door_hostname="data.example.org")), expected_denial)

    def test_all_connect_paths_validate_every_response(self):
        hints = b"HTTP/1.1 103 Early Hints\r\n"
        malformed = [
            b"invalid header\r\n", b"bad name: value\r\n", b": value\r\n",
            b"Name : value\r\n", b" folded: value\r\n", b"Name: bad\x00value\r\n",
            b"Name: bad\x7fvalue\r\n", b"Name: value\n", b"\n",
            b"Name: " + b"x" * 4090 + b"\r\n", b"X: y\r\n" * 65,
        ]
        for code in (200, 403):
            final = ("HTTP/1.1 %d Reply\r\n" % code).encode()
            replies = [hints + header + b"\r\n" + final + b"\r\n" for header in malformed]
            replies += [final + header + b"\r\n" for header in malformed]
            replies += [final, hints + b"\r\n" + final]
            for status in (b"HTTP/1.1\t403 Bad\r\n", b"HTTP/1.1  403 Bad\r\n",
                           b"HTTP/1.1 403 Bad\n", b"HTTP/1.1 403 Bad\x00\r\n",
                           b"HTTP/1.2 403 Bad\r\n", b"HTTP/1.1 099 Bad\r\n",
                           b"HTTP/1.1 101 Switching Protocols\r\n"):
                replies += [status + b"\r\n" + final + b"\r\n",
                            hints + b"\r\n" + status + b"\r\n"]
            for reply in replies:
                with self.subTest(code=code, reply=reply[:80]):
                    self.assertIsNone(self.response([reply]))
                    with self.tls_context(), patch.object(probe, "tcp", return_value=self.socket([reply])):
                        self.assertIsNone(probe.denied(lambda: probe.connect(
                            "172.30.196.4", 8443, "example.com:443", inspected_door=True, door_hostname="data.example.org")))
                    with patch.object(probe, "tcp", return_value=self.socket([reply])), patch.object(probe.ssl, "create_default_context") as context:
                        self.assertFalse(probe.allowed_aim_tls())
                        context.assert_not_called()

    def test_complete_valid_headers_and_informational_plaintext(self):
        hints = b"HTTP/1.1 100 Continue\r\n\r\n"
        headers = b"X-Token!#$%&'*+.^_`|~: \tvalue\xff\r\nEmpty:\r\n\r\n"
        for code, expected in ((200, False), (403, True)):
            reply = hints + ("HTTP/1.0 %d Reply\r\n" % code).encode() + headers
            self.assertIs(self.response([reply]), expected)
            with self.tls_context(), patch.object(probe, "tcp", return_value=self.socket([reply])):
                self.assertIs(probe.denied(lambda: probe.connect(
                    "172.30.196.4", 8443, "example.com:443", inspected_door=True, door_hostname="data.example.org")), expected)
        with patch.object(probe, "tcp", return_value=self.socket([hints + b"HTTP/1.1 200 OK\r\n\r\n"])), patch.object(probe.ssl, "create_default_context") as context:
            self.assertTrue(probe.allowed_aim_tls())
            context.return_value.wrap_socket.assert_called_once()

    def test_framing_is_validated_on_all_http_paths(self):
        bad = [
            b"Content-Length: invalid\r\n",
            b"Content-Length: 3\r\nContent-Length: 7\r\n",
            b"Content-Length: 3, 7\r\n", b"Content-Length: -1\r\n",
            b"Content-Length: +3\r\n", b"Content-Length: 3.0\r\n",
            b"Content-Length: \r\n", b"Content-Length: 3,\r\n",
            b"Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
            b"Transfer-Encoding: unknown\r\n", b"Transfer-Encoding: gzip, chunked\r\n",
            b"Transfer-Encoding: chunked, chunked\r\n",
            b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
            b"Transfer-Encoding: chunked;foo=bar\r\n", b"Transfer-Encoding:\r\n",
        ]
        good = [b"", b"Content-Length: 0\r\n", b"Content-Length: 3\r\n",
                b"Content-Length: 3\r\ncontent-length: 3\r\n",
                b"Content-Length: 3, 3\r\nContent-Length: 3\r\n",
                b"Transfer-Encoding: ChUnKeD\r\n"]
        for code in (200, 403):
            final = ("HTTP/1.1 %d Reply\r\n" % code).encode()
            cases = [(final + headers + b"\r\n", None) for headers in bad]
            cases += [(b"HTTP/1.1 103 Hints\r\n" + headers + b"\r\n" + final + b"\r\n", None)
                      for headers in bad + good[1:]]
            cases += [(final + headers + b"\r\n", code == 403) for headers in good]
            cases += [(b"HTTP/1.0 403 Denied\r\nTransfer-Encoding: chunked\r\n\r\n", None),
                      (b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", None)]
            for reply, expected in cases:
                for door in (False, True):
                    with self.subTest(code=code, reply=reply, door=door):
                        self.assertIs(probe.denied(lambda: self.response([reply], inspected_door=door)), expected)
                with self.subTest(code=code, reply=reply, tls=True), self.tls_context(), patch.object(probe, "tcp", return_value=self.socket([reply])):
                    self.assertIs(probe.denied(lambda: probe.connect(
                        "172.30.196.4", 8443, "example.com:443", inspected_door=True, door_hostname="data.example.org")), expected)
                if expected is None:
                    with patch.object(probe, "tcp", return_value=self.socket([reply])), patch.object(probe.ssl, "create_default_context") as context:
                        self.assertFalse(probe.allowed_aim_tls())
                        context.assert_not_called()

    def test_header_bounds_and_final_header_deadline(self):
        status = b"HTTP/1.1 403 Forbidden\r\n"
        for headers in (b"X: y\r\n" * 64 + b"\r\n",
                        b"X:" + b"x" * 4090 + b"\r\n\r\n"):
            self.assertIs(self.response([status + headers]), True)
        # A final status alone cannot decide while its headers stall.
        ticks = [0] * (len(status) + 1) + [probe.TIMEOUT]
        with patch.object(probe.time, "monotonic", side_effect=ticks):
            self.assertIsNone(self.response([status + b"\r\n"]))

    def test_tls_door_informational_stream_is_bounded(self):
        responses = []
        def stream():
            while True:
                responses.append(103)
                yield b"HTTP/1.1 103 Early Hints\r\n\r\n"
        # A peer that never stops sending 1xx must be bounded even if time stalls.
        with self.tls_context(), patch.object(probe, "tcp", return_value=self.socket(stream())), patch.object(probe.time, "monotonic", return_value=0):
            self.assertIsNone(probe.connect("172.30.196.4", 8443, "example.com:443", inspected_door=True, door_hostname="data.example.org"))
            self.assertEqual(len(responses), 6)

    def test_tls_door_informational_read_shares_original_deadline(self):
        reply = b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 Connected\r\n\r\n"
        # Expire the original deadline just as the final status would start.
        ticks = [0] * (len(b"HTTP/1.1 103 Early Hints\r\n\r\n") + 1) + [probe.TIMEOUT]
        with self.tls_context(), patch.object(probe, "tcp", return_value=self.socket([reply])), patch.object(probe.time, "monotonic", side_effect=ticks):
            self.assertIsNone(probe.connect("172.30.196.4", 8443, "example.com:443", inspected_door=True, door_hostname="data.example.org"))

    def test_tls_door_unclean_close_and_bad_replies_are_inconclusive(self):
        for line in (b"garbage\n", b"HTTP/1.1 200 OK", b"HTTP/1.1 403 Denied", b"x" * 4096):
            with self.subTest(line=line[:30]), self.tls_context(), patch.object(probe, "tcp", return_value=self.socket([line])):
                self.assertIsNone(probe.connect("172.30.196.4", 8443, "example.com:443", inspected_door=True, door_hostname="data.example.org"))
        for failure in (probe.ssl.SSLEOFError, ConnectionResetError, TimeoutError):
            with self.subTest(failure=failure), self.tls_context(), patch.object(probe, "tcp", return_value=self.socket([])), patch.object(probe, "status_line", side_effect=failure):
                self.assertIsNone(probe.connect("172.30.196.4", 8443, "example.com:443", inspected_door=True, door_hostname="data.example.org"))

    def test_only_door_refusal_or_explicit_protocol_rejection_is_denial(self):
        with patch.object(probe, "tcp", side_effect=ConnectionRefusedError):
            self.assertIs(probe.connect("door", 3128, "example.com:443", inspected_door=True, door_hostname="data.example.org"), True)
            self.assertIsNone(probe.connect("proxy", 3128, "example.com:443"))
        self.assertIs(self.response([b"HTTP/1.0 400 Bad Request\r\n\r\n"], inspected_door=True), True)
        self.assertIsNone(self.response([b"HTTP/1.0 400 Bad Request\r\n\r\n"]))
        for line in (b"", b"garbage\n", b"HTTP/1.1 200 OK", b"HTTP/1.1 503 Error\r\n"):
            self.assertIsNone(self.response([line], inspected_door=True))
        with patch.object(probe, "tcp", side_effect=TimeoutError):
            self.assertIsNone(probe.connect("door", 3128, "example.com:443", inspected_door=True, door_hostname="data.example.org"))

    def test_proxy_only_explicit_policy_statuses_are_denial(self):
        for code in range(200, 600):
            reply = ("HTTP/1.1 %d Reply\r\nContent-Length: 0\r\n\r\n" % code).encode()
            expected = None if code == 204 else False if code < 300 else True if code in (403, 405, 407) else None
            with self.subTest(code=code):
                self.assertIs(self.response([reply]), expected)
                self.assertIs(self.response([reply], inspected_door=True),
                              None if code == 204 else code >= 300)

    def test_probe_arguments_require_sni_name_and_inspected_upstream(self):
        for argv in (["probe.py"], ["probe.py", "--door"],
                     ["probe.py", "--door-hostname", "data.example.org"],
                     ["probe.py", "--dns-upstream", "127.0.0.1"],
                     PROBE_ARGS[:-1] + ["1.1.1.1"],
                     ["probe.py", "--door-hostname", "172.30.196.4", "--dns-upstream", "127.0.0.1"]):
            with self.subTest(argv=argv), patch.object(probe.sys, "argv", argv), patch.object(probe, "tcp") as tcp, contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(probe.main(), 1)
                tcp.assert_not_called()
                self.assertEqual(output.getvalue(), "")
        with patch.object(probe, "tcp") as tcp:
            self.assertIsNone(probe.connect("172.30.196.4", 8443, "example.com:443", inspected_door=True))
            tcp.assert_not_called()

    def test_all_success_codes_and_segmented_status_fail_negative_probe(self):
        for code in (200, 204, 299):
            line = ("HTTP/1.1 %d Connected\r\n\r\n" % code).encode()
            for blocks in ([line], [line[:5], line[5:11], line[11:]]):
                self.assertIs(self.response(blocks), False)
        self.assertIs(self.response([b"HTTP/1.0 403 Denied\r\n\r\n"]), True)

    def test_malformed_partial_overlong_and_disconnect_are_inconclusive(self):
        for line in (b"garbage\r\n", b"HTTP/1.1 two Failed\r\n", b"HTTP/1.1 200 OK", b"HTTP/1.1 999 Bad\n", b"x" * 4096, b"", b"HTTP/1.1 503 Unavailable\r\n"):
            self.assertIsNone(self.response([line]))
        self.assertIsNone(probe.denied(lambda: None))
        with patch.object(probe, "tcp", side_effect=ConnectionRefusedError):
            self.assertIsNone(probe.connect("gateway", 3128, "example.com:443"))


class NegativeEvidenceContracts(unittest.TestCase):
    question = b"\x07example\x03com\x00\x00\x01\x00\x01"

    def packet(self, flags=0x8180, answers=b"", count=0, question=None,
               authority=b"", authority_count=0, additional=b"", additional_count=0):
        return (probe.struct.pack("!6H", 0x5319, flags, 1, count, authority_count, additional_count)
                + (self.question if question is None else question) + answers + authority + additional)

    def record(self, kind=1, value=b"\x01\x02\x03\x04", owner=b"\xc0\x0c"):
        return owner + probe.struct.pack("!HHIH", kind, 1, 60, len(value)) + value

    def answer(self, packet):
        sock = unittest.mock.MagicMock()
        sock.recv.return_value = packet
        with patch.object(probe.socket, "socket", return_value=sock):
            sock.__enter__.return_value = sock
            result = probe.dns_answer("1.1.1.1")
        sock.connect.assert_called_once_with(("1.1.1.1", 53))
        sock.recv.assert_called_once_with(513)
        return result

    def malformed_packets(self):
        positive = self.packet(answers=self.record(), count=1)
        bad_authority = []
        for kind, value in ((1, b"abc"), (28, b"abc"), (2, b"\xc0\xff"),
                            (6, b"\xc0\x0c\xc0\x0c"), (15, b"\x00"),
                            (16, b"\x07bad"), (99, b"opaque")):
            packet = bytearray(self.packet() + self.record(kind=kind, value=value))
            packet[8:10] = b"\x00\x01"
            bad_authority.append(bytes(packet))
        # Compression pointers must target a previously parsed label boundary,
        # not a zero byte in the question type/class that resembles a root name.
        packet = bytearray(self.packet() + self.record(owner=b"\xc0\x19"))
        packet[8:10] = b"\x00\x01"
        bad_authority.append(bytes(packet))
        return bad_authority + [
            b"x", b"\x00\x00" + self.packet()[2:], self.packet(flags=0x0180),
            self.packet(flags=0x8380), self.packet(flags=0x8980), self.packet(flags=0x81c0),
            self.packet(question=self.question.replace(b"example", b"another")),
            self.packet(question=self.question[:-1] + b"\x02"),
            self.packet(question=self.question[:-3] + b"\x1c\x00\x01"),
            self.packet(question=b"\xc0\x0c\x00\x01\x00\x01"),
            self.packet(question=b"\xff\xff"),
            self.packet(count=1), positive[:-1], self.packet() + b"junk",
            self.packet(answers=self.record(value=b"abc"), count=1),
            self.packet(answers=self.record(kind=5, value=b"\xc0\xff"), count=1),
            self.packet(flags=0x8183, answers=self.record(), count=1),
            self.packet(answers=self.record(owner=b"\x05other\x03com\x00"), count=1),
            self.packet(flags=0x8182),  # SERVFAIL does not confirm policy denial.
            self.packet() + b"x" * 513,
        ] + [positive[:end] for end in range(len(positive))]

    def test_dns_malformed_truncated_unrelated_and_unsupported_are_inconclusive(self):
        for packet in self.malformed_packets():
            with self.subTest(packet=packet):
                self.assertIsNone(self.answer(packet))

    def test_dns_matching_negative_and_positive_evidence(self):
        for flags in (0x8183, 0x8185):
            with self.subTest(flags=flags):
                self.assertIs(self.answer(self.packet(flags=flags)), True)
        positive = self.packet(answers=self.record(), count=1)
        self.assertIs(self.answer(positive), False)
        alias = b"\x05alias\x03com\x00"
        chain = self.record(kind=5, value=alias) + self.record(owner=alias)
        self.assertIs(self.answer(self.packet(answers=chain, count=2)), False)
        # NODATA requires a parsed SOA in authority, not just zero answers.
        soa = self.record(kind=6, value=b"\xc0\x0c\xc0\x0c" + b"\x00" * 20)
        for flags in (0x8180, 0x8183, 0x8185):
            self.assertIs(self.answer(self.packet(flags=flags, authority=soa, authority_count=1)), True)
        self.assertIsNone(self.answer(self.packet()))
        self.assertIsNone(self.answer(self.packet(additional=soa, additional_count=1)))

    def referral(self):
        ns = self.record(kind=2, value=b"\x02ns\x03com\x00", owner=b"\x03com\x00")
        return self.packet(authority=ns, authority_count=1)

    def test_dns_referral_is_inconclusive(self):
        self.assertIsNone(self.answer(self.referral()))

    def test_nodata_soa_owner_must_be_ancestor_at_label_boundary(self):
        for owner, expected in ((b"\x03net\x00", None), (b"\x03org\x00", None),
                                (b"\x05ample\x03com\x00", None),
                                (b"\x03com\x00", True), (b"\x00", True),
                                (b"\x07EXAMPLE\x03COM\x00", True), (b"\xc0\x0c", True)):
            soa = self.record(kind=6, owner=owner, value=b"\xc0\x0c\xc0\x0c" + b"\x00" * 20)
            packet = self.packet(authority=soa, authority_count=1)
            with self.subTest(owner=owner):
                self.assertIs(self.answer(packet), expected)
            for argv in (PROBE_ARGS, PROBE_ARGS + ["--door"]):
                sock = unittest.mock.MagicMock()
                sock.__enter__.return_value = sock
                sock.recv.return_value = packet
                with self.subTest(owner=owner, argv=argv), patch.object(probe.sys, "argv", argv), patch("builtins.open", unittest.mock.mock_open(read_data="nameserver 127.0.0.11\n")), patch.object(probe, "allowed_aim_tls", return_value=True), patch.object(probe, "tcp_denied", return_value=True), patch.object(probe, "connect", return_value=True), patch.object(probe.socket, "socket", return_value=sock), contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(probe.main(), 0 if expected else 1)
                    self.assertEqual(bool(output.getvalue()), expected is True)

    def test_embedded_servfail_needs_kernel_refusal_of_inspected_upstream(self):
        servfail = self.packet(flags=0x8182)
        for upstream in (None, "1.1.1.1", "127.0.0.1"):
            for host in ("127.0.0.11", "1.1.1.1"):
                for receipt in (OSError(probe.errno.ECONNREFUSED, "refused"), OSError(probe.errno.EACCES, "prohibited"),
                                OSError(probe.errno.EHOSTUNREACH, "router"), OSError(probe.errno.ENETUNREACH, "router"),
                                OSError(probe.errno.EPERM, "permission"), TimeoutError(),
                                self.packet(flags=0x8185), self.packet(answers=self.record(), count=1)):
                    for packet in (servfail, servfail[:-1], servfail + b"junk", b"\x00\x00" + servfail[2:],
                                   self.packet(flags=0x8182, answers=self.record(), count=1)):
                        resolver, direct = unittest.mock.MagicMock(), unittest.mock.MagicMock()
                        resolver.__enter__.return_value = resolver
                        direct.__enter__.return_value = direct
                        resolver.recv.return_value = packet
                        if isinstance(receipt, bytes):
                            direct.recv.return_value = receipt
                        else:
                            direct.recv.side_effect = receipt
                        corroborate = host == "127.0.0.11" and upstream == "127.0.0.1" and packet == servfail
                        passes = corroborate and isinstance(receipt, OSError) and receipt.errno in (probe.errno.ECONNREFUSED, probe.errno.EACCES)
                        with self.subTest(host=host, upstream=upstream, receipt=receipt, packet=packet), patch.object(probe.socket, "socket", side_effect=[resolver, direct]) as create:
                            self.assertIs(probe.dns_answer(host, upstream), True if passes else None)
                            self.assertEqual(create.call_count, 2 if corroborate else 1)
                            if corroborate:
                                direct.connect.assert_called_once_with(("127.0.0.1", 53))
                                direct.send.assert_called_once_with(resolver.send.call_args.args[0])

    def test_both_markers_follow_fresh_embedded_upstream_evidence(self):
        for argv in (PROBE_ARGS, PROBE_ARGS + ["--door"]):
            for refused in (True, False, True):
                def socket(*args):
                    sock = unittest.mock.MagicMock()
                    sock.__enter__.return_value = sock
                    def recv(size):
                        host = sock.connect.call_args.args[0][0]
                        if host == "127.0.0.11":
                            return self.packet(flags=0x8182)
                        if host == "127.0.0.1" and not refused:
                            raise TimeoutError()
                        raise ConnectionRefusedError()
                    sock.recv.side_effect = recv
                    return sock
                with self.subTest(argv=argv, refused=refused), patch.object(probe.sys, "argv", argv), patch("builtins.open", unittest.mock.mock_open(read_data="nameserver 127.0.0.11\n")), patch.object(probe, "allowed_aim_tls", return_value=True), patch.object(probe, "tcp_denied", return_value=True), patch.object(probe, "connect", return_value=True), patch.object(probe.socket, "socket", side_effect=socket), contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(probe.main(), 0 if refused else 1)
                    self.assertEqual(bool(output.getvalue()), refused)

    def test_every_dns_target_requires_positive_denial_before_namespace_pass(self):
        for argv, hosts, marker in ((PROBE_ARGS + ["--door"], ["127.0.0.1", "1.1.1.1"], "door-negative-probes:pass\n"),
                                    (PROBE_ARGS, ["127.0.0.1", "1.1.1.1", "172.30.196.3", "172.30.196.4"], "isolation-negative-probes:pass\n")):
            for bad_host in hosts:
                negative = self.packet(flags=0x8185)
                soa = self.record(kind=6, value=b"\xc0\x0c\xc0\x0c" + b"\x00" * 20)
                for packet in [negative, self.packet(flags=0x8183), self.packet(authority=soa, authority_count=1),
                               self.packet(), self.referral(), b"x", b"\x00\x00" + negative[2:],
                               self.packet(answers=self.record(), count=1)]:
                    sock = unittest.mock.MagicMock()
                    sock.__enter__.return_value = sock
                    sock.recv.side_effect = lambda size: packet if sock.connect.call_args.args[0][0] == bad_host else negative
                    with self.subTest(argv=argv, host=bad_host, packet=packet), patch.object(probe.sys, "argv", argv), patch("builtins.open", unittest.mock.mock_open(read_data="nameserver 127.0.0.1\n")), patch.object(probe, "allowed_aim_tls", return_value=True), patch.object(probe, "tcp_denied", return_value=True), patch.object(probe, "connect", return_value=True), patch.object(probe.socket, "socket", return_value=sock), contextlib.redirect_stdout(io.StringIO()) as output:
                        passes = packet in (negative, self.packet(flags=0x8183),
                                            self.packet(authority=soa, authority_count=1))
                        self.assertEqual(probe.main(), 0 if passes else 1)
                        self.assertEqual(output.getvalue(), marker if passes else "")

    def test_mixed_resolvers_are_all_tested_and_unknown_suppresses_both_markers(self):
        for argv in (PROBE_ARGS, PROBE_ARGS + ["--door"]):
            for extra in ("fd00::53", "fe80::53%eth0", "not-an-address", ""):
                for verdict in (True, None):
                    resolv = "  nameserver 127.0.0.1 # local\n\tnameserver " + extra + "; other\n"
                    with self.subTest(argv=argv, extra=extra, verdict=verdict), patch.object(probe.sys, "argv", argv), patch("builtins.open", unittest.mock.mock_open(read_data=resolv)), patch.object(probe, "allowed_aim_tls", return_value=True), patch.object(probe, "tcp_denied", return_value=True), patch.object(probe, "connect", return_value=True), patch.object(probe, "dns_answer", side_effect=lambda host, upstream: verdict if host == extra else True) as dns, contextlib.redirect_stdout(io.StringIO()) as output:
                        self.assertEqual(probe.main(), 0 if verdict is True else 1)
                        tested = [call.args[0] for call in dns.call_args_list]
                        self.assertIn("127.0.0.1", tested)
                        self.assertIn(extra, tested)
                        self.assertEqual(bool(output.getvalue()), verdict is True)

    def test_dns_address_family_and_scoped_ipv6_peer(self):
        for host, family, peer in (("127.0.0.1", probe.socket.AF_INET, ("127.0.0.1", 53)),
                                   ("fd00::53", probe.socket.AF_INET6, ("fd00::53", 53, 0, 0)),
                                   ("fe80::53%eth0", probe.socket.AF_INET6, ("fe80::53", 53, 0, 7))):
            sock = unittest.mock.MagicMock()
            sock.__enter__.return_value = sock
            sock.recv.return_value = self.packet(flags=0x8185)
            with self.subTest(host=host), patch.object(probe.socket, "socket", return_value=sock) as create, patch.object(probe.socket, "getaddrinfo", return_value=[(family, probe.socket.SOCK_DGRAM, 17, "", peer)]) as resolve:
                self.assertIs(probe.dns_answer(host), True)
                create.assert_called_once_with(family, probe.socket.SOCK_DGRAM)
                sock.connect.assert_called_once_with(peer)
                if family == probe.socket.AF_INET6:
                    resolve.assert_called_once_with(host, 53, family, probe.socket.SOCK_DGRAM, 0, probe.socket.AI_NUMERICHOST)
                else:
                    resolve.assert_not_called()
        with patch.object(probe.socket, "socket") as create:
            for host in ("", "not-an-address", "127.0.0.1.invalid"):
                self.assertIsNone(probe.dns_answer(host))
            create.assert_not_called()
        with patch.object(probe.socket, "getaddrinfo", side_effect=OSError), patch.object(probe.socket, "socket") as create:
            self.assertIsNone(probe.dns_answer("fe80::53%absent"))
            create.assert_not_called()

    def test_reject_receipts_pass_but_silent_drop_blocks_both_namespaces(self):
        for argv in (PROBE_ARGS, PROBE_ARGS + ["--door"]):
            for failure, expected in ((ConnectionRefusedError(), True),
                                      (OSError(probe.errno.EACCES, "ICMPv6 prohibited"), True),
                                      (OSError(probe.errno.EHOSTUNREACH, "router unreachable"), False),
                                      (OSError(probe.errno.ENETUNREACH, "router unreachable"), False),
                                      (TimeoutError(), False), (ConnectionResetError(), False)):
                sock = unittest.mock.MagicMock()
                sock.__enter__.return_value = sock
                sock.recv.side_effect = failure
                with self.subTest(argv=argv, failure=failure), patch.object(probe.sys, "argv", argv), patch("builtins.open", unittest.mock.mock_open(read_data="nameserver 127.0.0.1\n")), patch.object(probe, "allowed_aim_tls", return_value=True), patch.object(probe, "tcp", side_effect=ConnectionRefusedError), patch.object(probe, "connect", return_value=True), patch.object(probe.socket, "socket", return_value=sock), contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(probe.main(), 0 if expected else 1)
                    self.assertEqual(bool(output.getvalue()), expected)

    def test_local_dns_reject_send_error_needs_queued_icmp_receipt(self):
        for send_code in (probe.errno.EPERM, probe.errno.EACCES):
            for receipt, expected in ((ConnectionRefusedError(), True),
                                      (OSError(probe.errno.EACCES, "ICMPv6 prohibited"), True),
                                      (TimeoutError(), None)):
                sock = unittest.mock.MagicMock()
                sock.__enter__.return_value = sock
                sock.send.side_effect = OSError(send_code, "local OUTPUT reject")
                sock.recv.side_effect = receipt
                with self.subTest(send_code=send_code, receipt=receipt), patch.object(probe.socket, "socket", return_value=sock):
                    self.assertIs(probe.dns_answer("127.0.0.11"), expected)
                    sock.recv.assert_called_once_with(513)

    def test_internal_no_route_requires_kernel_error_and_matching_namespace_routes(self):
        header = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
        connected = "eth0 00C41EAC 00000000 0001 0 0 0 F0FFFFFF 0 0 0\n"
        default = "eth0 00000000 01C41EAC 0003 0 0 0 00000000 0 0 0\n"
        target_route = "eth0 01010101 00000000 0001 0 0 0 FFFFFFFF 0 0 0\n"
        cases = [(header + connected, True), (header + connected + default, False),
                 (header + connected + target_route, False), ("garbage\n", False),
                 (header + "eth0 bad\n", False),
                 (header + connected.replace("00C41EAC", "FFFFFFFFF"), False)]
        for routes, expected in cases:
            for code in (probe.errno.ENETUNREACH, probe.errno.EHOSTUNREACH, probe.errno.ETIMEDOUT):
                failure = OSError(code, "fixture")
                verdict = True if expected and code == probe.errno.ENETUNREACH else None
                sock = unittest.mock.MagicMock()
                sock.__enter__.return_value = sock
                sock.send.side_effect = failure
                with self.subTest(routes=routes, code=code), patch("builtins.open", unittest.mock.mock_open(read_data=routes)) as read, patch.object(probe, "tcp", side_effect=failure), patch.object(probe.socket, "socket", return_value=sock):
                    self.assertIs(probe.tcp_denied("1.1.1.1", 443), verdict)
                    self.assertIs(probe.dns_answer("1.1.1.1"), verdict)
                    if code == probe.errno.ENETUNREACH:
                        read.assert_called_with("/proc/net/route", encoding="ascii")
        with patch("builtins.open", side_effect=PermissionError), patch.object(probe, "tcp", side_effect=OSError(probe.errno.ENETUNREACH, "fixture")):
            self.assertIsNone(probe.tcp_denied("1.1.1.1", 443))

    def test_transport_errors_and_non_boolean_results_never_become_denial(self):
        for failure in (TimeoutError, ConnectionResetError, ConnectionRefusedError, OSError, ValueError):
            def action(): raise failure()
            with self.subTest(failure=failure):
                self.assertIsNone(probe.denied(action))
                if failure is not ValueError:
                    with patch.object(probe.socket, "socket", side_effect=failure):
                        self.assertIsNone(probe.dns_answer("1.1.1.1"))
        for value in (None, 0, 1, b"", [], object()):
            self.assertIsNone(probe.denied(lambda: value))
        self.assertIs(probe.denied(lambda: False), False)
        self.assertIs(probe.denied(lambda: True), True)

    def test_direct_tcp_evidence_is_explicit_and_connection_is_closed(self):
        sock = unittest.mock.MagicMock()
        with patch.object(probe, "tcp", return_value=sock):
            self.assertIs(probe.denied(lambda: probe.tcp_denied("1.1.1.1", 443)), False)
        sock.__exit__.assert_called_once()
        sock.__exit__.side_effect = ConnectionRefusedError
        with patch.object(probe, "tcp", return_value=sock):
            self.assertIsNone(probe.denied(lambda: probe.tcp_denied("1.1.1.1", 443)))
        for failure in (ConnectionRefusedError, TimeoutError, ConnectionResetError, OSError):
            with self.subTest(failure=failure), patch.object(probe, "tcp", side_effect=failure):
                self.assertIs(probe.denied(lambda: probe.tcp_denied("1.1.1.1", 443)),
                              True if failure is ConnectionRefusedError else None)

    def test_direct_tcp_inconclusive_blocks_both_namespace_pass_markers(self):
        for argv in (PROBE_ARGS, PROBE_ARGS + ["--door"]):
            for value in (False, None):
                with self.subTest(argv=argv, value=value), patch.object(probe.sys, "argv", argv), patch("builtins.open", unittest.mock.mock_open(read_data="nameserver 127.0.0.1\n")), patch.object(probe, "allowed_aim_tls", return_value=True), patch.object(probe, "tcp_denied", return_value=value), patch.object(probe, "connect", return_value=True), patch.object(probe, "dns_answer", return_value=True), contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(probe.main(), 1)
                    self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
