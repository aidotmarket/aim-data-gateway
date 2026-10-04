#!/usr/bin/env python3
"""Measure shared gateway and AWS-only non-test Go against approved caps."""
from pathlib import Path
import sys

CAPS = {"gateway": 9275, "AWS": 3500}  # gateway: Chunk 2 Amendment B (measured 9,273)

def over_budget(lines, cap=9275):
    return lines > cap

def category(path):
    return "AWS" if path.parts[:2] in (("cmd", "aim-aws-verifier"), ("internal", "awsverification")) else "gateway"

if sys.argv[1:] == ["--self-check"]:
    for name, cap in CAPS.items():
        assert not over_budget(cap, cap)
        assert over_budget(cap + 1, cap)
    assert category(Path("internal/awsverification/s3.go")) == "AWS"
    assert category(Path("cmd/aim-aws-verifier/main.go")) == "AWS"
    assert category(Path("verification/scanner.go")) == "gateway"
    assert category(Path("internal/awsverification_extra/x.go")) == "gateway"
    print("gateway and AWS boundary self-checks: PASS")
    sys.exit(0)

totals = dict.fromkeys(CAPS, 0)
for path in Path(".").rglob("*.go"):
    if not path.name.endswith("_test.go"):
        totals[category(path)] += len(path.read_text().splitlines())
for name, lines in totals.items():
    print(f"{name} non-test Go lines: {lines} / {CAPS[name]}")
sys.exit(int(any(over_budget(totals[name], cap) for name, cap in CAPS.items())))
