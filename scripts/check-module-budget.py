#!/usr/bin/env python3
"""Check modules in the compiled dependency graph, not the full go.mod graph."""
import json
import os
import subprocess
import sys

env = dict(os.environ, CGO_ENABLED="0", GOFLAGS="-mod=readonly")
result = subprocess.run(["go", "list", "-deps", "-json", "./cmd/aim-gateway"], env=env,
                        text=True, capture_output=True, check=True)
decoder = json.JSONDecoder()
data = result.stdout
modules = set()
bad = []
while data.strip():
    package, used = decoder.raw_decode(data.lstrip())
    data = data[len(data) - len(data.lstrip()) + used:]
    module = package.get("Module", {}).get("Path")
    if module and module != "github.com/aidotmarket/aim-data-gateway":
        modules.add(module)
    path = package["ImportPath"].lower()
    if "grpc" in path or "protobuf" in path or package.get("CgoFiles"):
        bad.append(package["ImportPath"])
print(f"compiled third-party modules: {len(modules)} / 25")
for module in sorted(modules):
    print(f"  {module}")
if bad:
    print("forbidden compiled packages: " + ", ".join(bad), file=sys.stderr)
if len(modules) > 25 or bad:
    sys.exit(1)
