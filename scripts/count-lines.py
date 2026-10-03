#!/usr/bin/env python3
"""Enforce S1791 Gate 2 section 8's inclusive 7,250 non-test Go line cap."""
from pathlib import Path
import sys

def over_budget(lines):
    return lines > 7250

if sys.argv[1:] == ["--self-check"]:
    assert not over_budget(7250)
    assert over_budget(7251)
    print("non-test Go line limit trips: PASS")
    sys.exit(0)

files = [p for p in Path(".").rglob("*.go") if not p.name.endswith("_test.go")]
lines = sum(len(p.read_text().splitlines()) for p in files)
print(f"non-test Go lines: {lines} / 7250")
if over_budget(lines):
    sys.exit(1)
