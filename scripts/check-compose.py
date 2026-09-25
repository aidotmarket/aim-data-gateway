#!/usr/bin/env python3
"""Check the effective Compose service, including Docker's normalized mounts."""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

last_model = None


def check(path: Path) -> None:
    global last_model
    last_model = None
    source = path.read_text()
    # Compose omits unused top-level volumes (and other unused resources) from config.
    if set(re.findall(r"(?m)^([^\s#].*)$", source)) != {"services:", "volumes:"}:
        raise ValueError("only services and volumes may be declared at the top level")
    if source.count("\nvolumes:\n") != 1 or source.split("\nvolumes:\n", 1)[1] != "  aim-gateway-state:\n":
        raise ValueError("only the empty aim-gateway-state volume declaration is allowed")
    result = subprocess.run(
        ["docker", "compose", "-f", str(path), "config", "--format", "json"],
        capture_output=True, text=True,
    )
    if result.returncode:
        raise ValueError(f"docker compose config failed: {result.stderr.strip()}")
    model = json.loads(result.stdout)
    last_model = model
    if set(model) != {"name", "services", "networks", "volumes"}:
        raise ValueError("unexpected top-level Compose keys")
    project = re.sub(r"[^a-z0-9_-]", "", path.parent.resolve().name.lower()).lstrip("_-")
    if model["name"] != project:
        raise ValueError("Compose project name must use the directory default")
    networks = model.get("networks", {})
    if set(networks) != {"default"} or networks["default"] != {
        "name": f"{project}_default", "ipam": {},
    }:
        raise ValueError(f"only the implicit default network is allowed: {sorted(networks)}")
    if model["volumes"] != {
        "aim-gateway-state": {"name": f"{project}_aim-gateway-state"},
    }:
        raise ValueError("only the default aim-gateway-state volume is allowed")
    services = model["services"]
    if set(services) != {"aim-gateway"}:
        raise ValueError("aim-gateway must be the only service")
    service = services["aim-gateway"]
    # Compose includes null defaults for these keys even when they are absent.
    for key in ("command", "entrypoint"):
        if service.get(key) is None:
            service.pop(key, None)
    allowed_keys = {
        "build", "image", "user", "read_only",
        "cap_drop", "security_opt", "volumes", "ports", "environment",
        "healthcheck", "networks", "restart",
    }
    unknown_keys = set(service) - allowed_keys
    if unknown_keys:
        raise ValueError(f"forbidden service key: {sorted(unknown_keys)[0]}")
    if service.get("networks") != {"default": None}:
        raise ValueError("aim-gateway may use only the implicit default network")
    expected_build = {"context": str(path.parent.absolute()), "dockerfile": "Dockerfile"}
    if ("build" in service) == ("image" in service):
        raise ValueError("exactly one default build or pinned release image is required")
    if "build" in service and service["build"] != expected_build:
        raise ValueError("build must use only the default context and Dockerfile")
    if "image" in service and (not isinstance(service["image"], str) or
        re.fullmatch(r"ghcr.io/aidotmarket/aim-gateway@sha256:[0-9a-f]{64}",
                     service["image"]) is None):
        raise ValueError("image must be the pinned release image")
    if service.get("ports") != [{
        "mode": "ingress", "target": 8080, "published": "8080", "protocol": "tcp",
    }]:
        raise ValueError("only port 8080:8080/tcp is allowed")
    if service.get("healthcheck") != {
        "test": ["CMD", "/aim-gateway", "healthcheck"],
        "timeout": "5s", "interval": "30s", "retries": 3,
    }:
        raise ValueError("only the default gateway healthcheck is allowed")
    environment = service.get("environment", {})
    if not isinstance(environment, dict) or set(environment) - {
        "AIM_PAIRING_CODE", "AIM_GATEWAY_CONFIG", "AIM_GATEWAY_STATE",
    }:
        raise ValueError("unexpected environment variable")
    if "AIM_PAIRING_CODE" in environment and not isinstance(
        environment["AIM_PAIRING_CODE"], str
    ):
        raise ValueError("AIM_PAIRING_CODE must be a string")
    for key, expected in (
        ("AIM_GATEWAY_CONFIG", "/config/gateway.toml"),
        ("AIM_GATEWAY_STATE", "/state"),
    ):
        if key in environment and environment[key] != expected:
            raise ValueError(f"{key} must be {expected}")
    if "restart" in service and service["restart"] != "no":
        raise ValueError("only the default restart policy is allowed")
    for key, expected in (
        ("user", "65532:65532"), ("read_only", True),
        ("cap_drop", ["ALL"]), ("security_opt", ["no-new-privileges:true"]),
    ):
        if service.get(key) != expected:
            raise ValueError(f"{key} must be {expected!r}")
    base = path.parent.absolute()
    mounts = service.get("volumes")
    if not isinstance(mounts, list) or len(mounts) != 3 or (
        mounts[0] not in [
            {"type": "bind", "source": str(base / "gateway.toml"),
             "target": "/config/gateway.toml", "read_only": True, "bind": options}
            for options in ({}, {"create_host_path": True})
        ] or mounts[1] not in [
            {"type": "bind", "source": str(base / "data"),
             "target": "/sources/data", "read_only": True, "bind": options}
            for options in ({}, {"create_host_path": True})
        ] or mounts[2] not in [
            {"type": "volume", "source": "aim-gateway-state", "target": "/state",
             "volume": options}
            for options in ({}, {"nocopy": False})
        ]
    ):
        raise ValueError("only the three default mounts are allowed")


def self_check(original: str) -> None:
    replacements = {
        "user removed": ('    user: "65532:65532"\n', ""),
        "root user": ('    user: "65532:65532"', '    user: "0:0"'),
        "writable root": ("    read_only: true", "    read_only: false"),
        "capabilities": ("    cap_drop: [ALL]", "    cap_drop: []"),
        "new privileges": ("    security_opt: [no-new-privileges:true]", "    security_opt: []"),
        "entrypoint override": ("    build: .", "    build: .\n    entrypoint: [\"/bin/sh\"]"),
        "command override": ("    build: .", "    build: .\n    command: [\"version\"]"),
        "privileged": ("    build: .", "    build: .\n    privileged: true"),
        "host cgroup": ("    build: .", "    build: .\n    cgroup: host"),
        "host uts": ("    build: .", "    build: .\n    uts: host"),
        "sysctls": ("    build: .", "    build: .\n    sysctls:\n      net.ipv4.ip_forward: '1'"),
        "tmpfs": ("    build: .", "    build: .\n    tmpfs: /tmp"),
        "host-driver network": ("    build: .", "    build: .\n    networks: [hostile]"),
        "host-driver default network": ("\nvolumes:\n", "\nnetworks:\n  default:\n    driver: host\n\nvolumes:\n"),
        "host network": ("    build: .", "    build: .\n    network_mode: host"),
        "shared service network": ("    build: .", "    build: .\n    network_mode: service:x"),
        "shared container network": ("    build: .", "    build: .\n    network_mode: container:x"),
        "no network": ("    build: .", "    build: .\n    network_mode: none"),
        "host user namespace": ("    build: .", "    build: .\n    userns_mode: host"),
        "host pid": ("    build: .", "    build: .\n    pid: host"),
        "shared pid": ("    build: .", "    build: .\n    pid: container:x"),
        "host ipc": ("    build: .", "    build: .\n    ipc: host"),
        "shared ipc": ("    build: .", "    build: .\n    ipc: container:x"),
        "privileged sidecar": ("services:\n", "services:\n  sidecar:\n    image: busybox\n    privileged: true\n"),
        "host-network sidecar": ("services:\n", "services:\n  sidecar:\n    image: busybox\n    network_mode: host\n"),
        "socket sidecar": ("services:\n", "services:\n  sidecar:\n    image: busybox\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"),
        "cap add": ("    build: .", "    build: .\n    cap_add: [SYS_ADMIN]"),
        "device": ("    build: .", "    build: .\n    devices: [/dev/null:/dev/example]"),
        "docker socket": ("      - aim-gateway-state:/state", "      - /var/run/docker.sock:/var/run/docker.sock\n      - aim-gateway-state:/state"),
        "other socket": ("      - aim-gateway-state:/state", "      - /tmp/agent.sock:/state/agent.sock\n      - aim-gateway-state:/state"),
        "extra mount": ("      - aim-gateway-state:/state", "      - ./extra:/extra:ro\n      - aim-gateway-state:/state"),
        "extra source mount": ("      - aim-gateway-state:/state", "      - ./extra:/sources/extra:ro\n      - aim-gateway-state:/state"),
        "writable config": ("./gateway.toml:/config/gateway.toml:ro", "./gateway.toml:/config/gateway.toml"),
        "writable source": ("./data:/sources/data:ro", "./data:/sources/data"),
        "external state volume": ("  aim-gateway-state:\n", "  aim-gateway-state:\n    external: true\n"),
        "host-backed state volume": ("  aim-gateway-state:\n", "  aim-gateway-state:\n    driver: local\n    driver_opts:\n      type: none\n      device: //\n      o: bind\n"),
        "extra top-level volume": ("  aim-gateway-state:\n", "  aim-gateway-state:\n  extra:\n"),
        "wrong state source": ("aim-gateway-state:/state", "extra:/state"),
        "read-only state": ("aim-gateway-state:/state", "aim-gateway-state:/state:ro"),
        "privileged build": ("    build: .", "    build:\n      context: .\n      privileged: true"),
        "host-network build": ("    build: .", "    build:\n      context: .\n      network: host"),
        "entitled build": ("    build: .", "    build:\n      context: .\n      entitlements: [security.insecure]"),
        "build argument": ("    build: .", "    build:\n      context: .\n      args: {EXTRA: value}"),
        "wrong host port": ('      - "8080:8080"', '      - "8081:8080"'),
        "wrong container port": ('      - "8080:8080"', '      - "8080:8081"'),
        "extra environment": ("    healthcheck:\n", "    environment: {HOST: value}\n    healthcheck:\n"),
        "wrong config environment": ("    healthcheck:\n", "    environment: {AIM_GATEWAY_CONFIG: /etc/passwd}\n    healthcheck:\n"),
        "healthcheck disabled": ("    healthcheck:\n", "    healthcheck:\n      disable: true\n"),
        "restart always": ("    healthcheck:\n", "    restart: always\n    healthcheck:\n"),
        "top-level secret": ("\nvolumes:\n", "\nsecrets:\n  extra:\n    file: ./gateway.toml\n\nvolumes:\n"),
        "project name override": ("services:\n", "name: hostile\nservices:\n"),
    }
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "compose.yaml"
        for name, (before, after) in replacements.items():
            if before not in original:
                raise ValueError(f"self-check fixture missing: {name}")
            mutated = original.replace(before, after, 1)
            if name == "host-driver network":
                mutated = mutated.replace(
                    "\nvolumes:\n", "\nnetworks:\n  hostile:\n    driver: host\n\nvolumes:\n", 1,
                )
            path.write_text(mutated)
            try:
                check(path)
            except (ValueError, KeyError):
                continue
            raise ValueError(f"self-check accepted {name}")
    print(f"compose self-check: {len(replacements)} unsafe mutations rejected")


if __name__ == "__main__":
    try:
        args = sys.argv[1:]
        self_test = "--self-check" in args
        args = [arg for arg in args if arg != "--self-check"]
        if len(args) > 1:
            raise ValueError("usage: check-compose.py [compose-file] [--self-check]")
        source = Path(args[0] if args else "compose.yaml")
        contents = source.read_text()
        check(source)
        if self_test:
            self_check(contents)
        else:
            print("compose hardening: OK")
    except (ValueError, KeyError, OSError) as error:
        if last_model is not None:
            print("normalized Compose model:", file=sys.stderr)
            print(json.dumps(last_model, indent=2, sort_keys=True), file=sys.stderr)
        sys.exit(f"compose hardening: {error}")
