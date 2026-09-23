#!/usr/bin/env python3
"""Enforce the direct import and compiled module budgets."""
import json
import os
import subprocess
import sys

def over_budget(modules, direct, bad):
    return len(modules) > 25 or len(direct) > 12 or bool(bad)

if sys.argv[1:] == ["--self-check"]:
    assert not over_budget(set(range(25)), set(range(12)), [])
    assert over_budget(set(range(26)), set(), [])
    assert over_budget(set(), set(range(13)), [])
    assert over_budget(set(), set(), ["grpc"])
    assert over_budget(set(), set(), ["protobuf"])
    assert over_budget(set(), set(), ["cgo"])
    print("module, direct dependency, grpc/protobuf and cgo limits trip: PASS")
    sys.exit(0)

env = dict(os.environ, CGO_ENABLED="0", GOFLAGS="-mod=readonly")
result = subprocess.run(["go", "list", "-deps", "-json", "./cmd/aim-gateway"], env=env,
                        text=True, capture_output=True, check=True)
decoder = json.JSONDecoder()
data = result.stdout
modules = set()
bad = []
imports = set()
while data.strip():
    package, used = decoder.raw_decode(data.lstrip())
    data = data[len(data) - len(data.lstrip()) + used:]
    module = package.get("Module", {}).get("Path")
    if module and module != "github.com/aidotmarket/aim-data-gateway":
        modules.add(module)
    if module == "github.com/aidotmarket/aim-data-gateway":
        imports.update(package.get("Imports", []))
    path = package["ImportPath"].lower()
    if "grpc" in path or "protobuf" in path or package.get("CgoFiles"):
        bad.append(package["ImportPath"])
print(f"compiled third-party modules: {len(modules)} / 25")
for module in sorted(modules):
    print(f"  {module}")
if bad:
    print("forbidden compiled packages: " + ", ".join(bad), file=sys.stderr)
all_packages = subprocess.run(["go", "list", "-json", "./..."], env=env,
                              text=True, capture_output=True, check=True).stdout
while all_packages.strip():
    package, used = decoder.raw_decode(all_packages.lstrip())
    all_packages = all_packages[len(all_packages) - len(all_packages.lstrip()) + used:]
    imports.update(package.get("Imports", []))
mod = json.loads(subprocess.run(["go", "mod", "edit", "-json"], env=env,
                                text=True, capture_output=True, check=True).stdout)
direct = {entry["Path"] for entry in mod["Require"] if not entry.get("Indirect")}
used_direct = {path for path in direct if any(p == path or p.startswith(path + "/") for p in imports)}
print(f"direct runtime dependencies: {len(used_direct)} / 12")
for module in sorted(used_direct):
    print(f"  {module}")
if over_budget(modules, used_direct, bad):
    sys.exit(1)
