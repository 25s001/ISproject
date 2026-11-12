#!/usr/bin/env python3
"""Copy the pinned trigger and embedded shellcode into the lab server tree."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
from pathlib import Path


UPSTREAM_COMMIT = "c95c8123fe37ea34b82f7560ae683bde7889d4eb"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runtime_destinations(
    upstream: Path,
    build_dir: Path,
    poc_root: Path,
) -> dict[Path, Path]:
    return {
        upstream / "host2_single_run" / "exploit.js":
            poc_root / "host2_single_run" / "exploit.js",
        build_dir / "shellcode.js":
            poc_root / "host2_single_run" / "shellcode.js",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("upstream_root", type=Path)
    parser.add_argument("--build-dir", type=Path)
    args = parser.parse_args()

    upstream = args.upstream_root.resolve()
    revision = subprocess.run(
        ["git", "-C", str(upstream), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if revision != UPSTREAM_COMMIT:
        raise ValueError(f"unexpected upstream commit: {revision}")

    poc_root = Path(__file__).resolve().parents[1]
    build_dir = (args.build_dir or (poc_root / "build")).resolve()
    destinations = runtime_destinations(upstream, build_dir, poc_root)

    for source, destination in destinations.items():
        if not source.is_file():
            raise FileNotFoundError(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        print(f"copied={destination}")
        print(f"sha256={sha256(destination)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
