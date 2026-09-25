#!/usr/bin/env python3
"""Refuse private module bypasses and mutable module resolution."""
import os
import shlex
import sys


def check(values: dict[str, str]) -> None:
    for name in ("GONOSUMDB", "GOPRIVATE", "GONOSUMCHECK", "GOINSECURE"):
        if values.get(name):
            raise ValueError(f"{name} must be empty")
    module_modes = [flag.lstrip("-") for flag in shlex.split(values.get("GOFLAGS", ""))
                    if flag.startswith(("-mod=", "--mod="))]
    if module_modes != ["mod=readonly"]:
        raise ValueError("GOFLAGS must contain exactly one -mod=readonly")


if __name__ == "__main__":
    try:
        check(dict(os.environ))
        if sys.argv[1:] == ["--self-check"]:
            baseline = {"GOFLAGS": "-mod=readonly"}
            for mutation in ({"GOFLAGS": ""}, {"GOFLAGS": "-mod=mod"},
                             {"GOFLAGS": "-mod=readonly -mod=mod"},
                             {"GOFLAGS": "-mod=readonly --mod=mod"},
                             {"GOFLAGS": "--mod=mod"},
                             {"GOFLAGS": "--mod=readonly --mod=readonly"},
                             {"GOFLAGS": "-mod=readonly -mod=readonly"},
                             {"GONOSUMDB": "*"}, {"GOPRIVATE": "example.com"},
                             {"GONOSUMCHECK": "*"}, {"GOINSECURE": "example.com"}):
                try:
                    check(baseline | mutation)
                except ValueError:
                    continue
                raise ValueError(f"self-check accepted {mutation}")
            print("CI environment self-check: 11 mutations rejected")
        elif sys.argv[1:]:
            raise ValueError("usage: check-ci-env.py [--self-check]")
        else:
            print("CI environment: checksums enabled, modules read-only")
    except ValueError as error:
        sys.exit(f"CI environment: {error}")
