#!/usr/bin/env python3
"""Check the effective Compose service, including Docker's normalized mounts."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def check(path: Path) -> None:
    result = subprocess.run(
        ["docker", "compose", "-f", str(path), "config", "--format", "json"],
        capture_output=True, text=True,
    )
    if result.returncode:
        raise ValueError(f"docker compose config failed: {result.stderr.strip()}")
    service = json.loads(result.stdout)["services"]["aim-gateway"]
    for key, expected in (
        ("user", "65532:65532"), ("read_only", True),
        ("cap_drop", ["ALL"]), ("security_opt", ["no-new-privileges:true"]),
    ):
        if service.get(key) != expected:
            raise ValueError(f"{key} must be {expected!r}")
    for key in ("privileged", "cap_add", "devices"):
        if key in service:
            raise ValueError(f"{key} is forbidden")
    for key in ("network_mode", "pid", "ipc"):
        if service.get(key) == "host":
            raise ValueError(f"{key}: host is forbidden")
    mounts = service.get("volumes", [])
    if not mounts:
        raise ValueError("required mounts missing")
    seen = set()
    for mount in mounts:
        source = mount.get("source", "")
        target = mount.get("target", "")
        if any(part.endswith(".sock") or "docker.sock" in part for part in (source, target)):
            raise ValueError("socket mount forbidden")
        if target in seen:
            raise ValueError("duplicate mount target")
        seen.add(target)
        if target == "/config/gateway.toml":
            valid = mount.get("type") == "bind" and mount.get("read_only") is True
        elif target.startswith("/sources/") and target.count("/") == 2:
            valid = mount.get("type") == "bind" and mount.get("read_only") is True
        elif target == "/state":
            valid = mount.get("type") == "volume"
        else:
            valid = False
        if not valid:
            raise ValueError(f"forbidden or unprotected mount: {target}")
    if not {"/config/gateway.toml", "/state"} <= seen or not any(
        target.startswith("/sources/") for target in seen
    ):
        raise ValueError("required mounts missing")


def self_check(original: str) -> None:
    replacements = {
        "user removed": ('    user: "65532:65532"\n', ""),
        "root user": ('    user: "65532:65532"', '    user: "0:0"'),
        "writable root": ("    read_only: true", "    read_only: false"),
        "capabilities": ("    cap_drop: [ALL]", "    cap_drop: []"),
        "new privileges": ("    security_opt: [no-new-privileges:true]", "    security_opt: []"),
        "privileged": ("    build: .", "    build: .\n    privileged: true"),
        "host network": ("    build: .", "    build: .\n    network_mode: host"),
        "host pid": ("    build: .", "    build: .\n    pid: host"),
        "host ipc": ("    build: .", "    build: .\n    ipc: host"),
        "cap add": ("    build: .", "    build: .\n    cap_add: [SYS_ADMIN]"),
        "device": ("    build: .", "    build: .\n    devices: [/dev/null:/dev/example]"),
        "docker socket": ("      - aim-gateway-state:/state", "      - /var/run/docker.sock:/var/run/docker.sock\n      - aim-gateway-state:/state"),
        "other socket": ("      - aim-gateway-state:/state", "      - /tmp/agent.sock:/state/agent.sock\n      - aim-gateway-state:/state"),
        "extra mount": ("      - aim-gateway-state:/state", "      - ./extra:/extra:ro\n      - aim-gateway-state:/state"),
        "writable config": ("./gateway.toml:/config/gateway.toml:ro", "./gateway.toml:/config/gateway.toml"),
        "writable source": ("./data:/sources/data:ro", "./data:/sources/data"),
    }
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "compose.yaml"
        for name, (before, after) in replacements.items():
            if before not in original:
                raise ValueError(f"self-check fixture missing: {name}")
            path.write_text(original.replace(before, after, 1))
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
        sys.exit(f"compose hardening: {error}")
