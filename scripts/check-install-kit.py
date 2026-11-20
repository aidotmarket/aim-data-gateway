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
    "install-kit/own-https/network-probe.py", "install-kit/own-https/compose.acme.yaml",
    "install-kit/own-https/acme-squid.conf", "install-kit/cloudflare-named/compose.yaml",
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


def template(path):
    document = load_json(path)
    require("services" not in document, "Use the verified Compose entry point from the release guide.")
    document["services"] = document.pop("x-kit-services")
    return document


# Closed source contracts share only invariant hardening, not mutable input files.
COMMON = {"user": "65532:65532", "read_only": True, "cap_drop": ["ALL"],
          "security_opt": ["no-new-privileges:true"], "restart": "unless-stopped"}
INGRESS = {"driver": "bridge", "driver_opts": {"com.docker.network.bridge.enable_ip_masquerade": "false"},
           "ipam": {"config": [{"subnet": "172.30.198.0/29"}]}}


def helper(image, command, volumes, networks, **settings):
    return dict(COMMON, image=image, command=command, volumes=volumes, networks=networks,
                sysctls={"net.ipv4.ip_forward": "0"}, **settings)


GATEWAY = dict(COMMON, image=GATEWAY_IMAGE, dns=["127.0.0.1"],
    environment={"AIM_GATEWAY_IMAGE_DIGEST": GATEWAY_DIGEST},
    volumes=["${GATEWAY_CONFIG:?Choose the local gateway settings}:/config/gateway.toml:ro",
             "${EXPORT_FOLDER:?Choose a dedicated export folder}:/sources/data:ro", "aim-gateway-state:/state"],
    networks={"gateway": {"ipv4_address": "172.30.196.2"}},
    healthcheck={"test": ["CMD", "/aim-gateway", "healthcheck"], "interval": "30s", "timeout": "5s", "retries": 3})
CONTROL_PROXY = helper("${SQUID_IMAGE:?A signed helper image pin is required}",
    ["squid", "-N", "-f", "/etc/squid/squid.conf"], ["./squid.conf:/etc/squid/squid.conf:ro"],
    {"gateway": {"ipv4_address": "172.30.196.3"}, "control-outbound": {}},
    tmpfs=["/tmp:rw,noexec,nosuid,size=16m,uid=65532,gid=65532"])
MANUAL_DOOR = helper("${TLS_PROXY_IMAGE:?A signed helper image pin is required}",
    ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"],
    ["./own-https/Caddyfile:/etc/caddy/Caddyfile:ro",
     "${TLS_CERTIFICATE:?Choose the public certificate}:/certs/server.pem:ro",
     "${TLS_PRIVATE_KEY:?Choose the protected private key}:/certs/server.key:ro"],
    {"gateway": {"ipv4_address": "172.30.196.4"}, "door-ingress": {}},
    dns=["127.0.0.1"], ports=["443:8443"],
    environment={"DOOR_HOSTNAME": "${DOOR_HOSTNAME:?Select a stable DNS-only hostname}"},
    tmpfs=["/config:rw,noexec,nosuid,size=8m,uid=65532,gid=65532", "/data:rw,noexec,nosuid,size=8m,uid=65532,gid=65532"])
ACME_DOOR = dict(MANUAL_DOOR,
    volumes=["./own-https/Caddyfile.acme:/etc/caddy/Caddyfile:ro", "acme-certificates:/data"],
    networks={"gateway": {"ipv4_address": "172.30.196.4"}, "acme": {"ipv4_address": "172.30.197.2"}, "door-ingress": {}},
    tmpfs=["/config:rw,noexec,nosuid,size=8m,uid=65532,gid=65532"],
    environment={"HTTPS_PROXY": "http://172.30.197.3:3128", "HTTP_PROXY": "http://172.30.197.3:3128",
                 "NO_PROXY": "172.30.196.2", "DOOR_HOSTNAME": "${DOOR_HOSTNAME:?Select a stable DNS-only hostname}"})
CA_PROXY = dict(CONTROL_PROXY, dns=["1.1.1.1"],
    volumes=["./own-https/acme-squid.conf:/etc/squid/squid.conf:ro"],
    networks={"acme": {"ipv4_address": "172.30.197.3"}, "ca-outbound": {}})
TUNNEL = helper("${CLOUDFLARED_IMAGE:?A signed helper image pin is required}",
    ["tunnel", "--no-autoupdate", "--config", "/etc/cloudflared/config.yaml", "run"],
    ["./cloudflare-named/config.yaml:/etc/cloudflared/config.yaml:ro",
     "${TUNNEL_CREDENTIAL_FILE:?Choose the protected local credential file}:/run/credentials/tunnel.json:ro"],
    {"gateway": {"ipv4_address": "172.30.196.5"}, "tunnel-outbound": {}}, profiles=["unadvertised-cloudflare-named"])
EXPECTED_COMPOSE = {
    "install-kit/compose.yaml": {"name": "aim-install-kit",
        "x-kit-services": {"aim-gateway": GATEWAY, "connect-proxy": CONTROL_PROXY},
        "networks": {"gateway": {"internal": True, "ipam": {"config": [{"subnet": "172.30.196.0/28"}]}}, "control-outbound": {}},
        "volumes": {"aim-gateway-state": {"external": True, "name": "${STATE_VOLUME:?Select the exact existing paired volume name}"}}},
    "install-kit/own-https/compose.yaml": {"x-kit-services": {"https-door": MANUAL_DOOR},
        "networks": {"door-ingress": INGRESS}},
    "install-kit/own-https/compose.acme.yaml": {"x-kit-services": {"https-door": ACME_DOOR, "acme-proxy": CA_PROXY},
        "networks": {"acme": {"internal": True, "ipam": {"config": [{"subnet": "172.30.197.0/29"}]}},
                     "ca-outbound": {}, "door-ingress": INGRESS},
        "volumes": {"acme-certificates": {"external": True, "name": "${ACME_STATE_VOLUME:?Select the existing UID-65532 certificate volume}"}}},
    "install-kit/cloudflare-named/compose.yaml": {"x-kit-services": {"named-tunnel": TUNNEL},
        "networks": {"tunnel-outbound": {}}},
}


def directives(source):
    return tuple(line.rstrip() for line in source.splitlines() if line.strip() and not line.lstrip().startswith("#"))


EXPECTED_CONFIG = {
    "install-kit/squid.conf": directives('''
http_port 3128
pid_filename /tmp/squid.pid
cache_log /dev/null
access_log none
cache_store_log none
cache deny all
via off
forwarded_for delete
acl gateway_source src 172.30.196.2/32
acl CONNECT method CONNECT
acl tls_port port 443
acl aim_control dstdomain api.ai.market
http_access allow gateway_source CONNECT tls_port aim_control
http_access deny all
'''),
    "install-kit/own-https/acme-squid.conf": directives('''
http_port 3128
pid_filename /tmp/squid.pid
cache_log /dev/null
access_log none
cache_store_log none
cache deny all
via off
forwarded_for delete
dns_nameservers 1.1.1.1
acl certificate_source src 172.30.197.2/32
acl CONNECT method CONNECT
acl tls_port port 443
acl acme_ca dstdomain acme-v02.api.letsencrypt.org
http_access allow certificate_source CONNECT tls_port acme_ca
http_access deny all
'''),
    "install-kit/own-https/Caddyfile": directives('''
{
    admin off
    auto_https off
}
:8443 {
    tls /certs/server.pem /certs/server.key
    header Cache-Control "no-store"
    header Referrer-Policy "no-referrer"
    reverse_proxy 172.30.196.2:8080
}
'''),
    "install-kit/own-https/Caddyfile.acme": directives('''
{
    admin off
    http_port 8081
    https_port 8443
}
{$DOOR_HOSTNAME} {
    tls {
        issuer acme {
            dir https://acme-v02.api.letsencrypt.org/directory
            disable_http_challenge
        }
    }
    header Cache-Control "no-store"
    header Referrer-Policy "no-referrer"
    reverse_proxy 172.30.196.2:8080
}
:8443 {
    respond 403
}
'''),
    "install-kit/cloudflare-named/config.yaml": directives('''
tunnel: 00000000-0000-0000-0000-000000000000
credentials-file: /run/credentials/tunnel.json
ingress:
  - hostname: downloads.example.invalid
    service: http://172.30.196.2:8080
  - service: http_status:404
'''),
}


def check(root=ROOT):
    """Offline source checks. A pass is never a clean-host/network receipt."""
    for relative, expected in EXPECTED_COMPOSE.items():
        require(json.dumps(load_json(root / relative), sort_keys=True) == json.dumps(expected, sort_keys=True),
                "Container access or recovery settings changed. Restore the signed kit, then rerun the check.")
    for relative, expected in EXPECTED_CONFIG.items():
        require(directives((root / relative).read_text()) == expected,
                "Connection rules changed. Restore the signed kit, then rerun the check.")
    require(set(path.relative_to(root).as_posix() for path in (root / "install-kit").rglob("*") if path.is_file())
            == {name for name in FILES if name.startswith("install-kit/")},
            "The kit contains unexpected files. Obtain a clean public kit and keep private settings outside it.")
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


def existing_volume(name):
    require(name and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", name),
            "Select the exact existing paired volume name. No storage will be created.")
    inspected = run(["docker", "volume", "inspect", "--format", "{{.Name}}", name])
    require(inspected.returncode == 0 and inspected.stdout.strip() == name,
            "The selected saved storage is absent. Stop and locate the original paired volume.")
    return name


def local_file(value):
    require(value and Path(value).is_file(), "Select the required local file before starting the kit.")
    return str(Path(value).resolve())


def require_door_hostname(value):
    valid = value and len(value) <= 253 and re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", value)
    try:
        ipaddress.ip_address(value)
        valid = False  # An IP literal would omit TLS SNI.
    except ValueError:
        pass
    require(valid, "Select a stable DNS-only hostname for the HTTPS door.")


def pinned_compose(args, root=None):
    root = root or ROOT
    # Verify before Docker inspection or config generation. No caller image substitutions.
    images = verified_release(args.manifest, args.bundle, args.release_tag, root)
    check(root)
    for variable, image in (("SQUID_IMAGE", "squid"), ("TLS_PROXY_IMAGE", "tls_proxy"), ("CLOUDFLARED_IMAGE", "cloudflared")):
        require(not os.environ.get(variable) or os.environ[variable] == images[image],
                "A helper image override differs from the signed release. Remove it and retry.")
    volume = existing_volume(args.state_volume)
    require(args.source_folder and Path(args.source_folder).is_dir(), "Select the dedicated existing export folder.")
    document = template(root / "install-kit/compose.yaml")
    acme = args.certificate_mode == "acme"
    own = template(root / ("install-kit/own-https/compose.acme.yaml" if acme else "install-kit/own-https/compose.yaml"))
    document["services"].update(own["services"])
    document["networks"].update(own["networks"])
    require_door_hostname(args.door_hostname)
    document["services"]["https-door"]["environment"]["DOOR_HOSTNAME"] = args.door_hostname
    if acme:
        document["volumes"].update(own["volumes"])
        require(args.acme_state_volume != volume, "Certificate storage must be separate from the paired gateway storage.")
        document["volumes"]["acme-certificates"]["name"] = existing_volume(args.acme_state_volume)
    document["volumes"]["aim-gateway-state"]["name"] = volume
    document["services"]["aim-gateway"]["volumes"] = [
        {"type": "bind", "source": local_file(args.gateway_config), "target": "/config/gateway.toml", "read_only": True, "bind": {"create_host_path": False}},
        {"type": "bind", "source": str(Path(args.source_folder).resolve()), "target": "/sources/data", "read_only": True, "bind": {"create_host_path": False}},
        {"type": "volume", "source": "aim-gateway-state", "target": "/state"}]
    replacements = {} if acme else {"${TLS_CERTIFICATE:?Choose the public certificate}": local_file(args.certificate),
                    "${TLS_PRIVATE_KEY:?Choose the protected private key}": local_file(args.private_key)}
    for name, key in [("connect-proxy", "squid"), ("https-door", "tls_proxy")] + ([("acme-proxy", "squid")] if acme else []):
        service = document["services"][name]
        service["image"] = images[key]
        mounts = []
        for mount in service["volumes"]:
            if mount == "acme-certificates:/data":
                mounts.append({"type": "volume", "source": "acme-certificates", "target": "/data"})
                continue
            source, target, mode = mount.rsplit(":", 2)
            source = replacements.get(source, str((root / "install-kit" / source).resolve()))
            mounts.append({"type": "bind", "source": source, "target": target, "read_only": True, "bind": {"create_host_path": False}})
        service["volumes"] = mounts
    return document


def exclusive_state_writer(volume, project):
    message = "Stop the old gateway and every other writer of the selected state volume before cutover. Storage ownership could not be confirmed."
    listed = run(["docker", "ps", "--all", "--quiet", "--filter", "volume=" + volume])
    require(listed.returncode == 0, message)
    ids = listed.stdout.split()
    require(all(re.fullmatch(r"[0-9a-f]{12,64}", value) for value in ids), message)
    if not ids:
        return
    inspected = run(["docker", "inspect", *ids])
    require(inspected.returncode == 0, message)
    try:
        containers = json.loads(inspected.stdout)
        require(isinstance(containers, list) and len(containers) == len(ids), message)
        own_writers = 0
        for container in containers:
            if not container["State"]["Running"]:
                continue
            writers = [mount for mount in container["Mounts"]
                       if mount.get("Type") == "volume" and mount.get("Name") == volume and mount["RW"]]
            if not writers:
                continue
            labels = container["Config"].get("Labels") or {}
            require(labels.get("com.docker.compose.project") == project
                    and labels.get("com.docker.compose.service") == "aim-gateway"
                    and labels.get("com.docker.compose.oneoff") == "False"
                    and container["Config"]["Image"] == GATEWAY_IMAGE
                    and len(writers) == 1 and writers[0]["Destination"] == "/state", message)
            own_writers += 1
        require(own_writers <= 1, message)
    except (ValueError, KeyError, TypeError):
        raise ContractError(message) from None


def compose_action(args):
    document = pinned_compose(args)
    # One exact digest-resolved config is used for inspection and startup.
    command = ["docker", "compose", "--project-name", document["name"], "--project-directory", str(ROOT / "install-kit"), "-f", "-", args.compose_action]
    if args.compose_action == "up":
        exclusive_state_writer(document["volumes"]["aim-gateway-state"]["name"], document["name"])
        command += ["--detach", "--pull", "never"]
    result = run(command, input=json.dumps(document).replace("$", "$$"))
    require(result.returncode == 0, "The verified Compose action failed. Ask IT to inspect the local setup.")
    if args.compose_action == "config":
        print(result.stdout, end="")
    else:
        print("Verified Compose action completed. Acceptance checks remain pending.")
    return 2


def serving_wsl(name):
    if not name or os.environ.get("WSL_DISTRO_NAME") != name:
        return "unknown"
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text().lower()
    except OSError:
        return "unknown"
    return "pass" if "microsoft-standard-wsl2" in release else "fail"


def filesystem_probe(image, source=None, volume=None):
    require(bool(source) != bool(volume), "Select exactly one file access check.")
    if source:
        require(Path(source).is_dir(), "Select the dedicated existing export folder.")
        mount = {"Type": "bind", "Source": str(Path(source).resolve()), "Target": "/check", "ReadOnly": True}
        program = """import os
for root, dirs, files in os.walk('/check', onerror=lambda error: (_ for _ in ()).throw(error)):
    if not os.access(root, os.R_OK | os.X_OK): raise PermissionError()
    for name in files:
        with open(os.path.join(root, name), 'rb') as stream: stream.read(1)
"""
    else:
        mount = {"Type": "volume", "Source": existing_volume(volume), "Target": "/check"}
        # Exclusive random sentinel only: never open an identity/database file.
        program = """import os, tempfile
fd, path = tempfile.mkstemp(prefix='.aim-permission-', dir='/check')
try:
    os.write(fd, b'permission-check'); os.fsync(fd)
finally:
    os.close(fd); os.unlink(path)
"""
    name = "aim-c0-files-" + uuid.uuid4().hex
    try:
        # --mount requires an existing bind; existing_volume is inspected before run.
        mount_arg = "type=" + mount["Type"] + ",src=" + mount["Source"] + ",dst=/check" + (",readonly" if source else "")
        require("," not in mount["Source"], "Choose a supported local path for the file check.")
        result = run(["docker", "run", "--name", name, "--pull=never", "--network", "none", "--user", "65532:65532",
                      "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--mount", mount_arg,
                      image, "python3", "-B", "-c", program])
    finally:
        removed = run(["docker", "rm", "--force", name])
        require(removed.returncode == 0, "The file diagnostic could not be removed. Ask IT to inspect it.")
    return "pass" if result.returncode == 0 else "fail"


def preflight(args):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    outcomes = dict.fromkeys(CHECKS, "unknown")
    messages = []
    helpers = {"https-door": "not_checked", "named-tunnel": "unselected"}
    def result(code, outcome, message):
        outcomes[code] = outcome
        messages.append(message)
    target = sys.platform.startswith("linux") and os.uname().machine == "x86_64"
    result("platform", "pass" if target else "fail", "Linux on x64 was detected. Exact supported versions still need clean installation tests." if target else "Linux on x64 was not detected. Run this check on the serving Linux system.")
    if args.platform == "windows_wsl2":
        outcomes["wsl"] = serving_wsl(args.serving_distro)
        if outcomes["wsl"] != "pass":
            outcomes["platform"] = "unknown"
    if not shutil.which("docker"):
        result("docker_installed", "fail", "Docker is missing. Ask IT to install Docker Engine and Compose, then rerun this check.")
    else:
        outcomes["docker_installed"] = "pass"
        info = run(["docker", "info", "--format", "{{.OSType}}"])
        result("docker_running", "pass" if info.returncode == 0 else "fail", "Docker is running." if info.returncode == 0 else "Docker did not respond. Start Docker and rerun this check.")
        outcomes["linux_containers"] = "pass" if info.returncode == 0 and info.stdout.strip() == "linux" else "fail" if info.returncode == 0 else "unknown"
        messages.append("Linux containers are selected." if outcomes["linux_containers"] == "pass" else
                        "Docker is using a different container system. Select Linux containers and rerun this check." if outcomes["linux_containers"] == "fail" else
                        "The container setting could not be read. Start Docker and rerun this check.")
        if run(["docker", "compose", "version", "--short"]).returncode:
            result("docker_installed", "fail", "Docker Compose is missing. Ask IT to install Compose, then rerun this check.")
    check()
    # Static source validation alone is not a pass for live hardening or isolation.
    images = None
    if args.manifest or args.bundle or args.release_tag or args.start_probes or args.check_source or args.check_state_write:
        images = verified_release(args.manifest, args.bundle, args.release_tag)
        outcomes["integrity"] = "pass"
    if args.check_source or args.check_state_write:
        require(target and images is not None, "File checks need Linux and a verified release.")
        if args.check_source:
            outcomes["source_uid"] = filesystem_probe(images["probe"], source=args.source_folder)
        if args.check_state_write:
            outcomes["state_write"] = filesystem_probe(images["probe"], volume=args.state_volume)
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
        require_door_hostname(args.door_hostname)
        require(args.gateway_container and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", args.gateway_container), "The running gateway was not selected. Ask IT to select the isolated test gateway, then rerun the network check.")
        inspected = run(["docker", "inspect", "--format", "{{json .}}", args.gateway_container])
        require(inspected.returncode == 0, "The gateway container could not be read. Start the isolated test gateway, then rerun the check.")
        container = json.loads(inspected.stdout)
        require(container["Config"]["Image"] == GATEWAY_IMAGE and container["State"]["Running"], "The selected gateway is not running the expected release. Start the isolated v0.2.4 test gateway, then rerun the check.")
        local_image = run(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", container["Image"]])
        require(local_image.returncode == 0 and GATEWAY_IMAGE in json.loads(local_image.stdout),
                "The running image does not have the expected local release digest. Stop and restore the signed release.")
        outcomes["image_digest"] = "pass"
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
        door_name = args.door_container
        require(door_name and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", door_name),
                "Select the running HTTPS door for the network checks.")
        door_result = run(["docker", "inspect", "--format", "{{json .}}", door_name])
        require(door_result.returncode == 0, "The selected HTTPS door could not be inspected.")
        door = json.loads(door_result.stdout)
        require(door["State"]["Running"] and door["Config"]["Image"] == images["tls_proxy"]
                and any(attachment["NetworkID"] == attachments[0]["NetworkID"] and attachment["IPAddress"] == "172.30.196.4"
                        for attachment in door["NetworkSettings"]["Networks"].values()),
                "The selected HTTPS door is absent, stopped or on the wrong release or network.")
        require(door["HostConfig"].get("Dns") == ["127.0.0.1"]
                and "DOOR_HOSTNAME=" + args.door_hostname in door["Config"].get("Env", []),
                "The door hostname or restricted DNS differs from the selected signed profile.")
        helpers["https-door"] = "running"
        name = "aim-c0-probe-" + uuid.uuid4().hex
        for owner, options, marker in ((container, [], "isolation-negative-probes:pass"),
                                      (door, ["--door"], "door-negative-probes:pass")):
            # DNS corroboration is bound to the inspected namespace owner's
            # sole upstream, never inferred from the diagnostic image's DNS.
            options += ["--door-hostname", args.door_hostname,
                        "--dns-upstream", owner["HostConfig"]["Dns"][0]]
            try:
                probe = run(["docker", "run", "--name", name, "--pull=never", "--network", "container:" + owner["Id"],
                             "--user", "65532:65532", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                             "--mount", "type=bind,src=" + str(ROOT / "install-kit/own-https/network-probe.py") + ",dst=/probe.py,readonly",
                             images["probe"], "python3", "-B", "/probe.py"] + options)
            finally:
                removed = run(["docker", "rm", "--force", name])
                require(removed.returncode == 0, "The temporary check could not be stopped or removed. Ask IT to inspect the diagnostic containers before continuing setup.")
            require(probe.returncode == 0 and probe.stdout.strip() == marker,
                    "A network safety check failed or could not finish. Stop setup and ask IT to inspect the selected namespaces. Do not widen access.")
        outcomes["egress"] = "unknown"  # Requires the gateway's own correlated control operation.
    messages.extend([
        "Local preparation cannot prove downloads work. Ask IT to complete the separate release and outside checks.",
        "If the connection is silent, the machine or Docker may be stopped. Run this check on the serving machine.",
        "If your company intercepts secure connections, ask IT for an ai.market inspection exemption. The company upstream option is unsupported until its separate tests pass.",
        "Files stay on your machine. Buyers receive copies. ai.market receives only approved information about them.",
        "Use your own secure web address. Third-party connection services can see file bytes and must permit this delivery. Ask IT to review the guide before choosing one.",
    ])
    report = {"schema_version": 1, "kit_version": KIT_VERSION, "platform": args.platform,
              "generated_at": now, "helpers": helpers, "checks": [{"code": code, "outcome": outcome, "checked_at": now if outcome != "unknown" else None} for code, outcome in outcomes.items()]}
    if args.report:
        print(json.dumps(report, separators=(",", ":")))
    else:
        messages.append("Preparation is incomplete. Follow the installation guide with IT. " + ("Diagnostic containers were requested; no readiness claim was made." if args.start_probes or args.check_source or args.check_state_write else "Nothing was installed, started or uploaded."))
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
    parser.add_argument("--door-container")
    parser.add_argument("--certificate-mode", choices=("manual", "acme"), default="manual")
    parser.add_argument("--acme-state-volume")
    parser.add_argument("--door-hostname")
    parser.add_argument("--compose-action", choices=("config", "up", "stop"))
    parser.add_argument("--state-volume")
    parser.add_argument("--source-folder")
    parser.add_argument("--gateway-config")
    parser.add_argument("--private-key")
    parser.add_argument("--check-source", action="store_true")
    parser.add_argument("--check-state-write", action="store_true")
    parser.add_argument("--serving-distro")
    args = parser.parse_args()
    try:
        if args.compose_action:
            return compose_action(args)
        if args.preflight:
            return preflight(args)
        require(not any((args.report, args.start_probes, args.manifest, args.bundle, args.release_tag, args.certificate, args.gateway_container, args.door_container, args.check_source, args.check_state_write, args.state_volume, args.source_folder, args.gateway_config, args.private_key, args.serving_distro, args.acme_state_volume, args.door_hostname, args.certificate_mode != "manual")), "Choose the local preparation check before selecting these options. Follow the installation guide and rerun the command.")
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
