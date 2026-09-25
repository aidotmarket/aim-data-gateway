#!/usr/bin/env python3
"""Pin the full Apache-2.0 license text and its SPDX declaration."""
from hashlib import sha256
from pathlib import Path
import sys

SPDX = "SPDX-License-Identifier: Apache-2.0\n"
TEXT_SHA256 = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
HEADER = "                                 Apache License\n                           Version 2.0, January 2004\n                        http://www.apache.org/licenses/\n"


def check(contents: str) -> None:
    if not contents.startswith(SPDX + HEADER):
        raise ValueError("SPDX identifier or Apache-2.0 header mismatch")
    if sha256(contents[len(SPDX):].encode()).hexdigest() != TEXT_SHA256:
        raise ValueError("Apache-2.0 license text mismatch")


if __name__ == "__main__":
    try:
        original = Path("LICENSE").read_text()
        check(original)
        if sys.argv[1:] == ["--self-check"]:
            for changed in (original.replace("Apache-2.0", "MIT", 1), original.replace("Grant of Patent License", "Grant of Patent Licence", 1)):
                try:
                    check(changed)
                except ValueError:
                    continue
                raise ValueError("self-check accepted changed license")
            print("license self-check: 2 mutations rejected")
        elif sys.argv[1:]:
            raise ValueError("usage: check-license.py [--self-check]")
        else:
            print("license: Apache-2.0 text and SPDX match")
    except (OSError, ValueError) as error:
        sys.exit(f"license: {error}")
