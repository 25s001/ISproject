#!/usr/bin/env python3
"""Encode verified raw shellcode as the JavaScript format used by the PoC."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from build import decode_words, shellcode_javascript


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    shellcode = args.input.read_bytes()
    javascript, padded = shellcode_javascript(shellcode)
    if decode_words(javascript) != padded:
        raise ValueError("JavaScript shellcode round-trip failed")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(javascript, encoding="ascii", newline="\n")
    print(f"shellcode_sha256={hashlib.sha256(padded).hexdigest()}")
    print(f"javascript_sha256={hashlib.sha256(javascript.encode('ascii')).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
