#!/usr/bin/env python3
"""Report non-test Go source lines. Gate 3 decides any enforcement change."""
from pathlib import Path

files = [p for p in Path(".").rglob("*.go") if not p.name.endswith("_test.go")]
lines = sum(len(p.read_text().splitlines()) for p in files)
print(f"non-test Go lines: {lines} / 5000 (report only)")
