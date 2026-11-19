#!/usr/bin/env python3
"""C0 static contracts and explicit local preparation. No gateway protocol code.

Compose files use the JSON subset of YAML so offline checks need no YAML module.
This is a preparation scaffold, not a released or certified installation kit.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
GATEWAY_DIGEST = "sha256:11723451cf98e191ad4563067d1191c687768041ceee2ff1147e7cf22ae4cbd6"
GATEWAY_IMAGE = "ghcr.io/aidotmarket/aim-gateway@" + GATEWAY_DIGEST
KIT_VERSION = "0.0.0-c0"
CHECKS = "platform virtualization wsl docker_installed docker_running linux_containers sleep_policy signin_start docker_licence source_uid state_write hardening image_digest subnet_port connect_proxy egress tls_inspection upstream_proxy tunnel public_dns firewall tls_proxy integrity".split()
FILES = (
    "scripts/check-install-kit.py", "install-kit/preflight.sh", "install-kit/preflight.ps1",
    "install-kit/compose.yaml", "install-kit/squid.conf", "install-kit/own-https/compose.yaml",
    "install-kit/own-https/Caddyfile", "install-kit/own-https/Caddyfile.acme",
    "install-kit/own-https/network-probe.py", "install-kit/cloudflare-named/compose.yaml",
    "install-kit/cloudflare-named/config.yaml", "README.md", "docs/release-runbook.md",
)


class ContractError(ValueError):
    """Fixed errors only: do not echo input, subprocess output or local paths."""


def require(condition, message):
    if not condition:
        raise ContractError(message)


def load_json(path):
    def closed(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "The settings repeat a field. Restore the signed kit, then rerun the check.")
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=closed)


def check(root=ROOT):
    """Offline source checks. A pass is never a clean-host/network receipt."""
    base = load_json(root / "install-kit/compose.yaml")
    own = load_json(root / "install-kit/own-https/compose.yaml")
    tunnel = load_json(root / "install-kit/cloudflare-named/compose.yaml")
    require(set(base) == {"name", "services", "networks", "volumes"}, "Restore the original kit network settings, then rerun the check.")
    require(set(base["services"]) == {"aim-gateway", "connect-proxy"}, "Restore the original kit services, then rerun the check.")
    gateway = base["services"]["aim-gateway"]
    require(gateway["image"] == GATEWAY_IMAGE, "The gateway release has changed. Restore the signed v0.2.4 preparation kit, then rerun the check.")
    require(gateway["environment"] == {"AIM_GATEWAY_IMAGE_DIGEST": GATEWAY_DIGEST}, "The release information does not match. Restore the signed kit, then rerun the check.")
    require(gateway["networks"] == {"gateway": {"ipv4_address": "172.30.196.2"}}, "The gateway network has changed. Restore the signed kit, then rerun the check.")
    require(base["networks"] == {"gateway": {"internal": True, "ipam": {"config": [{"subnet": "172.30.196.0/28"}]}}, "control-outbound": {}}, "The network limits have changed. Restore the signed kit, then rerun the check.")
    require(base["volumes"] == {"aim-gateway-state": {}}, "The saved connection storage has changed. Restore the signed kit and retain the existing storage.")
    require(gateway["volumes"] == ["${GATEWAY_CONFIG:?Choose the local gateway settings}:/config/gateway.toml:ro", "${EXPORT_FOLDER:?Choose a dedicated export folder}:/sources/data:ro", "aim-gateway-state:/state"], "The file access settings have changed. Restore the signed kit, then rerun the check.")
    services = {**base["services"], **own["services"], **tunnel["services"]}
    require(set(own) == {"services"} and set(own["services"]) == {"https-door"}
            and set(tunnel) == {"services", "networks"} and set(tunnel["services"]) == {"named-tunnel"}
            and tunnel["networks"] == {"tunnel-outbound": {}}, "Extra connection settings were added. Restore the signed kit, then rerun the check.")
    expected_networks = {
        "aim-gateway": {"gateway": {"ipv4_address": "172.30.196.2"}},
        "connect-proxy": {"gateway": {"ipv4_address": "172.30.196.3"}, "control-outbound": {}},
        "https-door": {"gateway": {"ipv4_address": "172.30.196.4"}},
        "named-tunnel": {"gateway": {"ipv4_address": "172.30.196.5"}, "tunnel-outbound": {}},
    }
    for name, service in services.items():
        require(set(service) <= {"image", "user", "read_only", "cap_drop", "security_opt", "dns", "environment", "volumes", "networks", "healthcheck", "restart", "sysctls", "command", "tmpfs", "ports", "profiles"}
                and service["networks"] == expected_networks[name], "Extra container access was added. Restore the signed kit, then rerun the check.")
        require(service.get("user") == "65532:65532" and service.get("read_only") is True
                and service.get("cap_drop") == ["ALL"] and service.get("security_opt") == ["no-new-privileges:true"],
                "A required safety setting has changed. Restore the signed kit without relaxing access, then rerun the check.")
        require(not set(service) & {"build", "privileged", "network_mode", "pid", "devices", "cap_add", "entrypoint"}, "Extra container access was added. Restore the signed kit, then rerun the check.")
        if name != "aim-gateway":
            require("environment" not in service and (name == "https-door" or "ports" not in service), "A helper has extra settings or listeners. Restore the signed kit, then rerun the check.")
            require(service.get("sysctls") == {"net.ipv4.ip_forward": "0"}, "A helper may route traffic. Restore the signed kit, then rerun the check.")
            require(service["image"] in {"${SQUID_IMAGE:?A signed helper image pin is required}", "${TLS_PROXY_IMAGE:?A signed helper image pin is required}", "${CLOUDFLARED_IMAGE:?A signed helper image pin is required}"}, "A helper release is missing. Obtain the signed kit before starting containers.")
            require(all(not any(word in mount for word in ("/sources", "/state", "gateway.toml", "docker.sock")) and mount.endswith(":ro") for mount in service.get("volumes", [])), "A helper has extra file access. Restore the signed kit, then rerun the check.")
    require(services["connect-proxy"]["command"] == ["squid", "-N", "-f", "/etc/squid/squid.conf"]
            and services["connect-proxy"]["volumes"] == ["./squid.conf:/etc/squid/squid.conf:ro"]
            and services["https-door"]["command"] == ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
            and services["named-tunnel"]["command"] == ["tunnel", "--no-autoupdate", "--config", "/etc/cloudflared/config.yaml", "run"],
            "A helper startup command has changed. Restore the signed kit, then rerun the check.")
    require(set(path.relative_to(root).as_posix() for path in (root / "install-kit").rglob("*") if path.is_file())
            == {name for name in FILES if name.startswith("install-kit/")}, "The kit contains unexpected files. Obtain a clean public kit and keep private settings outside it.")
    require("ports" not in gateway and gateway["dns"] == ["127.0.0.1"], "The gateway is exposed to another network. Restore the signed kit, then rerun the check.")
    require(own["services"]["https-door"]["networks"] == {"gateway": {"ipv4_address": "172.30.196.4"}}, "The certificate helper has extra network access. Restore the signed kit, then rerun the check.")
    require(own["services"]["https-door"]["ports"] == ["443:8443"], "The secure web listener has changed. Restore the signed kit, then rerun the check.")
    require(tunnel["services"]["named-tunnel"]["profiles"] == ["unadvertised-cloudflare-named"] and "--no-autoupdate" in tunnel["services"]["named-tunnel"]["command"], "The optional connection was enabled too early. Restore the signed kit and use your own secure web address.")
    squid = (root / "install-kit/squid.conf").read_text()
    rules = [line.strip() for line in squid.splitlines() if line.strip() and not line.startswith("#")]
    require(rules == ["http_port 3128", "pid_filename /tmp/squid.pid", "cache_log /dev/null", "access_log none", "cache_store_log none", "cache deny all", "via off", "forwarded_for delete", "acl CONNECT method CONNECT", "acl tls_port port 443", "acl aim_control dstdomain api.ai.market", "http_access allow CONNECT tls_port aim_control", "http_access deny all"], "The outbound limits have changed. Restore the signed kit and ask IT for an inspection exemption if needed.")
    for filename in ("Caddyfile", "Caddyfile.acme"):
        source = (root / "install-kit/own-https" / filename).read_text()
        require("reverse_proxy 172.30.196.2:8080" in source and 'Cache-Control "no-store"' in source and 'Referrer-Policy "no-referrer"' in source and "admin off" in source, "The web forwarding settings have changed. Restore the signed kit, then rerun the check.")
        require(not any(term in source for term in ("log {", "dns ", "encode ", "redir ", "forward_proxy")), "The web forwarding settings add unsupported behavior. Restore the signed kit, then rerun the check.")
    require("disable_http_challenge" in (root / "install-kit/own-https/Caddyfile.acme").read_text(), "The certificate check uses an unsupported method. Restore the signed kit and ask IT to review it.")
    require("UNADVERTISED" in (root / "install-kit/cloudflare-named/config.yaml").read_text()
            and "UNADVERTISED" in squid, "An unverified option was advertised. Restore the preparation kit and use your own secure web address.")
    for relative in FILES:
        path = root / relative
        require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root.resolve()), "Part of the kit is missing or linked elsewhere. Restore the complete signed kit, then rerun the check.")
        if relative.startswith("install-kit/"):
            text = path.read_text()
            require(not re.search(r"-----BEGIN .*PRIVATE KEY-----|(?i:eyJ[a-z0-9_-]{20,}\.[a-z0-9_-]+\.)|AIM_PAIRING_CODE|TUNNEL_TOKEN", text), "The kit contains private connection information. Obtain a clean public kit and keep private information on your machine.")


def run(argv, **kwargs):
    # Never print diagnostics: third-party errors can contain secrets or paths.
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False, **kwargs)
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(argv, 1, "", "")


def verified_release(manifest_path, bundle_path, release_tag, root=ROOT):
    require(manifest_path and bundle_path and release_tag and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", release_tag), "Signed release information is missing. Obtain the released kit and verification bundle before starting containers.")
    require(shutil.which("cosign"), "The release checker is missing. Ask IT to install Cosign, then verify the released kit again.")
    result = run(["cosign", "verify-blob", "--offline", "--bundle", str(bundle_path),
                  "--certificate-identity", "https://github.com/aidotmarket/aim-data-gateway/.github/workflows/release.yml@refs/tags/" + release_tag,
                  "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", str(manifest_path)])
    require(result.returncode == 0, "The release signature could not be verified. Stop and obtain the unchanged kit and verification bundle from the release guide.")
    manifest = load_json(Path(manifest_path))
    require(set(manifest) == {"schema_version", "kit_version", "gateway_version", "images", "files"}
            and manifest["schema_version"] == 1 and manifest["kit_version"] == KIT_VERSION
            and manifest["gateway_version"] == "0.2.4", "The release information is incompatible. Obtain the matching preparation kit, then rerun the check.")
    require(set(manifest["files"]) == set(FILES), "The release does not cover the complete kit. Obtain the complete signed kit, then rerun the check.")
    for relative, expected in manifest["files"].items():
        path = root / relative
        require(not path.is_symlink() and re.fullmatch(r"[0-9a-f]{64}", expected)
                and hashlib.sha256(path.read_bytes()).hexdigest() == expected, "A kit file does not match the signed release. Stop and obtain a fresh unchanged kit.")
    images = manifest["images"]
    require(set(images) == {"gateway", "squid", "tls_proxy", "probe", "cloudflared"}
            and images["gateway"] == GATEWAY_IMAGE
            and all(isinstance(value, str) and re.fullmatch(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", value) for value in images.values()),
            "A release image is missing or unpinned. Obtain the signed helper releases before starting containers.")
    return images


def preflight(args):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    outcomes = dict.fromkeys(CHECKS, "unknown")
    messages = []
    def result(code, outcome, message):
        outcomes[code] = outcome
        messages.append(message)
    target = sys.platform.startswith("linux") and os.uname().machine == "x86_64"
    result("platform", "pass" if target else "fail", "This check targets Linux on x64. Exact supported versions still need clean installation tests. Ask IT to review the release guide.")
    if not shutil.which("docker"):
        result("docker_installed", "fail", "Docker is missing. Ask IT to install Docker Engine and Compose, then rerun this check.")
    else:
        outcomes["docker_installed"] = "pass"
        info = run(["docker", "info", "--format", "{{.OSType}}"])
        result("docker_running", "pass" if info.returncode == 0 else "fail", "Docker was checked. If it is stopped, start Docker and rerun this check.")
        outcomes["linux_containers"] = "pass" if info.returncode == 0 and info.stdout.strip() == "linux" else "fail" if info.returncode == 0 else "unknown"
        if run(["docker", "compose", "version", "--short"]).returncode:
            result("docker_installed", "fail", "Docker Compose is missing. Ask IT to install Compose, then rerun this check.")
    check()
    # Static source validation alone is not a pass for live hardening or isolation.
    images = None
    if args.manifest or args.bundle or args.release_tag or args.start_probes:
        images = verified_release(args.manifest, args.bundle, args.release_tag)
        outcomes["image_digest"] = "pass"
    if args.certificate:
        cert = run(["openssl", "x509", "-in", args.certificate, "-noout", "-checkend", "1209600"])
        result("tls_proxy", "unknown" if cert.returncode == 0 else "fail", "The certificate needs renewal or could not be read. Ask IT to check it and renew it if it expires within 14 days, then rerun this check." if cert.returncode else "The local certificate lasts more than 14 days. Ask IT to complete the separate public address and forwarding checks.")
    if target and shutil.which("ip") and shutil.which("ss"):
        routes = run(["ip", "-json", "route", "show", "table", "all"])
        listeners = run(["ss", "-H", "-ltn", "sport = :443"])
        if not routes.returncode and not listeners.returncode:
            entries = json.loads(routes.stdout)
            conflict = any(ipaddress.ip_network(row["dst"], strict=False).overlaps(ipaddress.ip_network("172.30.196.0/28")) for row in entries if row.get("dst") not in (None, "default") and ":" not in row["dst"])
            result("subnet_port", "fail" if conflict or listeners.stdout.strip() else "unknown", "The network or web listener may already be in use. Ask IT to compare Docker networks and host routes before starting the kit.")
    if args.start_probes:
        require(target and images is not None, "The network checks need a Linux host and verified release. Run them inside the serving Linux system after release verification.")
        require(args.gateway_container and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", args.gateway_container), "The running gateway was not selected. Ask IT to select the isolated test gateway, then rerun the network check.")
        inspected = run(["docker", "inspect", "--format", "{{json .}}", args.gateway_container])
        require(inspected.returncode == 0, "The gateway container could not be read. Start the isolated test gateway, then rerun the check.")
        container = json.loads(inspected.stdout)
        require(container["Config"]["Image"] == GATEWAY_IMAGE and container["State"]["Running"], "The selected gateway is not running the expected release. Start the isolated v0.2.4 test gateway, then rerun the check.")
        host = container["HostConfig"]
        require(container["Config"]["User"] == "65532:65532" and host["ReadonlyRootfs"]
                and host["CapDrop"] == ["ALL"] and not host.get("CapAdd") and not host["Privileged"]
                and "no-new-privileges:true" in host["SecurityOpt"] and host["NetworkMode"] != "host",
                "The running gateway is missing a safety setting. Restore the signed profile, then rerun the check.")
        outcomes["hardening"] = "pass"
        require("AIM_GATEWAY_IMAGE_DIGEST=" + GATEWAY_DIGEST in container["Config"].get("Env", [])
                and host.get("Dns") == ["127.0.0.1"] and len(container["NetworkSettings"]["Networks"]) == 1,
                "The running release or network limits do not match. Restore the signed gateway profile, then rerun the check.")
        require(not any(value.startswith("AIM_PAIRING_CODE=") for value in container["Config"].get("Env", [])),
                "The running container still has private setup information. Follow the existing release guide to remove it, retain saved storage, then rerun this check.")
        attachments = list(container["NetworkSettings"]["Networks"].values())
        network = run(["docker", "network", "inspect", attachments[0]["NetworkID"]])
        require(network.returncode == 0 and json.loads(network.stdout)[0]["Internal"] is True
                and attachments[0]["IPAddress"] == "172.30.196.2",
                "The running gateway is on the wrong network. Restore the isolated signed profile, then rerun the check.")
        mounts = container.get("Mounts", [])
        require({mount["Destination"] for mount in mounts} == {"/config/gateway.toml", "/sources/data", "/state"}
                and len(mounts) == 3 and all(mount["RW"] == (mount["Destination"] == "/state") for mount in mounts)
                and next(mount for mount in mounts if mount["Destination"] == "/state")["Type"] == "volume",
                "The running gateway has unexpected file access. Restore the signed profile and retain its named saved storage before rerunning this check.")
        name = "aim-c0-probe-" + uuid.uuid4().hex
        try:
            probe = run(["docker", "run", "--name", name, "--pull=never", "--network", "container:" + container["Id"],
                         "--user", "65532:65532", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                         "--mount", "type=bind,src=" + str(ROOT / "install-kit/own-https/network-probe.py") + ",dst=/probe.py,readonly",
                         images["probe"], "python3", "-B", "/probe.py"])
        finally:
            removed = run(["docker", "rm", "--force", name])
            require(removed.returncode == 0, "The temporary check could not be stopped or removed. Ask IT to inspect the diagnostic containers before continuing setup.")
        require(probe.returncode == 0 and probe.stdout.strip() == "isolation-negative-probes:pass", "A network safety check failed or could not finish. Stop setup and ask IT to inspect the isolated gateway network. Do not widen access.")
        outcomes["egress"] = "pass"
    messages.extend([
        "Local preparation cannot prove downloads work. Ask IT to complete the separate release and outside checks.",
        "If the connection is silent, the machine or Docker may be stopped. Run this check on the serving machine.",
        "If your company intercepts secure connections, ask IT for an ai.market inspection exemption. The company upstream option is unsupported until its separate tests pass.",
        "Files stay on your machine. Buyers receive copies. ai.market receives only approved information about them.",
        "Use your own secure web address. Third-party connection services can see file bytes and must permit this delivery. Ask IT to review the guide before choosing one.",
    ])
    report = {"schema_version": 1, "kit_version": KIT_VERSION, "platform": args.platform,
              "generated_at": now, "checks": [{"code": code, "outcome": outcome, "checked_at": now} for code, outcome in outcomes.items()]}
    if args.report:
        print(json.dumps(report, separators=(",", ":")))
    else:
        print("\n".join(messages))
    return 1 if "fail" in outcomes.values() else 2  # Unknown never means ready.


def main():
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            self.exit(1, "The check options were not recognized. Read the installation guide and rerun the documented command.\n")
    parser = Parser(description="Check the preparation kit locally. Read the release guide before starting checks that create a container.")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--platform", choices=("linux_server", "linux_cloud", "windows_wsl2"), default="linux_server")
    parser.add_argument("--certificate")
    parser.add_argument("--manifest")
    parser.add_argument("--bundle")
    parser.add_argument("--release-tag")
    parser.add_argument("--start-probes", action="store_true", help="explicitly start a temporary diagnostic container against the selected test gateway")
    parser.add_argument("--gateway-container")
    args = parser.parse_args()
    try:
        if args.preflight:
            return preflight(args)
        require(not any((args.report, args.start_probes, args.manifest, args.bundle, args.release_tag, args.certificate, args.gateway_container)), "Choose the local preparation check before selecting these options. Follow the installation guide and rerun the command.")
        check()
        print("C0 static contracts: PASS (platforms, signatures and networks remain unverified)")
        return 0
    except ContractError as error:
        print(str(error), file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError):
        print("The local settings could not be checked. Restore the unchanged preparation kit and ask IT to rerun the check.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
