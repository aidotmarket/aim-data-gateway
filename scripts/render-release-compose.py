#!/usr/bin/env python3
"""Substitute the verified image digest into the shipped Compose file."""
from pathlib import Path
import re
import sys


if __name__ == "__main__":
    if len(sys.argv) != 3 or not re.fullmatch(r"sha256:[0-9a-f]{64}", sys.argv[1]):
        sys.exit("usage: render-release-compose.py sha256:<digest> output-path")
    source = Path("compose.yaml").read_text()
    old = "    build: .\n"
    if source.count(old) != 1:
        sys.exit("expected exactly one build: . line")
    output = Path(sys.argv[2])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(source.replace(old, f"    image: ghcr.io/aidotmarket/aim-gateway@{sys.argv[1]}\n"))
