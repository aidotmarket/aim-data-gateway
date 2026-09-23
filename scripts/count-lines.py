#!/usr/bin/env python3
"""Fail when non-test Go source reaches 5,000 lines."""
from pathlib import Path
import sys

def over_budget(lines):
    return lines >= 5000

if sys.argv[1:] == ["--self-check"]:
    assert not over_budget(4999)
    assert over_budget(5000)
    print("non-test Go line limit trips: PASS")
    sys.exit(0)

files = [p for p in Path(".").rglob("*.go") if not p.name.endswith("_test.go")]
lines = sum(len(p.read_text().splitlines()) for p in files)
print(f"non-test Go lines: {lines} / 5000")
if over_budget(lines):
    sys.exit(1)
