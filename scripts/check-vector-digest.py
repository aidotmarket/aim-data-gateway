#!/usr/bin/env python3
"""Pin SHA-256 of every committed vector file in sorted path order."""
from hashlib import sha256
from pathlib import Path
import sys

MANIFEST_SHA256 = "b41878847daddd74eb4e14a10b9a54db19b16139361800e0310d48b866bd534b"

paths = sorted(Path("contract/vectors").glob("*.json"))
actual = "".join(f"{sha256(p.read_bytes()).hexdigest()}  {p.as_posix()}\n" for p in paths)
pin = Path("contract/VECTORS.sha256")
if sys.argv[1:] == ["--update"]:
    pin.write_text(actual)
elif not paths or not pin.exists() or pin.read_text() != actual or sha256(pin.read_bytes()).hexdigest() != MANIFEST_SHA256:
    print("vector digest mismatch", file=sys.stderr)
    sys.exit(1)
else:
    print(f"vector digest: {len(paths)} files, SHA-256 manifest matches")
