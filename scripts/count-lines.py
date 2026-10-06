#!/usr/bin/env python3
"""Measure physical source lines against gateway, AWS and Cloudflare budgets."""
from pathlib import Path
import sys

CAPS = {"gateway": 9275, "AWS": 3500, "Cloudflare": 2500,
        "Cloudflare Worker": 1200, "Cloudflare Python": 600}

def over_budget(lines, cap=9275):
    return lines > cap

def category(path):
    if path.parts[:2] in (("cmd", "aim-aws-verifier"), ("internal", "awsverification")):
        return "AWS"
    if path.parts[:2] in (("cmd", "aim-cloudflare-verifier"), ("internal", "cloudflareverification")):
        return "Cloudflare"
    # Shared cloud-only helpers must count here, rather than escape a budget.
    if "cloudverification" in path.parts or "cloudflare" in path.stem:
        return "Cloudflare"
    return "gateway"

def worker_source(path):
    return (path.parts[:2] == ("deploy", "cloudflare-verifier")
            and path.suffix in (".ts", ".js", ".mjs")
            and not path.name.endswith((".test.ts", ".test.js", ".test.mjs", ".spec.ts", ".spec.js"))
            and path.name != "worker.mjs")  # Generated release bundle; size reported separately.

def cloud_python(path):
    return (path.suffix == ".py" and not path.name.startswith("test_")
            and (path.parts[:2] == ("deploy", "cloudflare-verifier")
                 or "cloudflare" in path.stem or path.name == "generate-r2-verification-vectors.py"))

if sys.argv[1:] == ["--self-check"]:
    for name, cap in CAPS.items():
        assert not over_budget(cap, cap)
        assert over_budget(cap + 1, cap)
    assert category(Path("internal/awsverification/s3.go")) == "AWS"
    assert category(Path("cmd/aim-aws-verifier/main.go")) == "AWS"
    assert category(Path("verification/scanner.go")) == "gateway"
    assert category(Path("internal/awsverification_extra/x.go")) == "gateway"
    assert category(Path("internal/cloudflareverification/source.go")) == "Cloudflare"
    assert category(Path("cmd/aim-cloudflare-verifier/main.go")) == "Cloudflare"
    assert category(Path("internal/cloudverification/helper.go")) == "Cloudflare"
    assert category(Path("internal/cloudflareverification_extra/x.go")) == "gateway"
    assert worker_source(Path("deploy/cloudflare-verifier/worker.ts"))
    assert not worker_source(Path("deploy/cloudflare-verifier/worker.test.ts"))
    assert not worker_source(Path("deploy/cloudflare-verifier/worker.mjs"))
    assert not worker_source(Path("deploy/cloudflare-verifier_extra/worker.ts"))
    assert cloud_python(Path("scripts/cloudflare-verifier-release.py"))
    assert cloud_python(Path("scripts/generate-r2-verification-vectors.py"))
    assert not cloud_python(Path("scripts/aws-verifier-release.py"))
    print("gateway, AWS and Cloudflare boundary self-checks: PASS")
    sys.exit(0)

totals = dict.fromkeys(CAPS, 0)
for path in Path(".").rglob("*"):
    if path.suffix == ".go" and not path.name.endswith("_test.go"):
        totals[category(path)] += len(path.read_text().splitlines())
    elif worker_source(path):
        totals["Cloudflare Worker"] += len(path.read_text().splitlines())
    elif cloud_python(path):
        totals["Cloudflare Python"] += len(path.read_text().splitlines())
for name, lines in totals.items():
    kind = "Go" if name in ("gateway", "AWS", "Cloudflare") else "source"
    print(f"{name} non-test {kind} lines: {lines} / {CAPS[name]}")
bundle = Path("deploy/cloudflare-verifier/worker.mjs")
print(f"Cloudflare generated bundle bytes: {bundle.stat().st_size if bundle.exists() else 0}")
sys.exit(int(any(over_budget(totals[name], cap) for name, cap in CAPS.items())))
