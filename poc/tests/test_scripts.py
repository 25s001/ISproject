from __future__ import annotations

import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import lab_http_server
import build as build_script
import prepare_runtime


class EmbeddedBuildTests(unittest.TestCase):
    def test_replaces_unique_upstream_command(self) -> None:
        source = (
            f"{build_script.INCLUDE_ANCHOR}\n"
            "void exploit() {\n"
            f"    {build_script.ORIGINAL_COMMAND}\n"
            "}\n"
        )
        patched = build_script.patch_upstream_source(source)

        self.assertIn(build_script.PAYLOAD_DECLARATION, patched)
        self.assertIn(build_script.EMBEDDED_COMMAND, patched)
        self.assertNotIn(build_script.ORIGINAL_COMMAND, patched)

    def test_rejects_duplicate_upstream_commands(self) -> None:
        source = (
            f"{build_script.INCLUDE_ANCHOR}\n"
            f"{build_script.ORIGINAL_COMMAND}\n"
            f"{build_script.ORIGINAL_COMMAND}\n"
        )
        with self.assertRaisesRegex(ValueError, "expected one"):
            build_script.patch_upstream_source(source)

    def test_javascript_encoding_round_trip_and_padding(self) -> None:
        javascript, padded = build_script.shellcode_javascript(b"\x90ABC")
        self.assertEqual(build_script.decode_words(javascript), padded)
        self.assertEqual(len(padded) % 2, 0)

    def test_runtime_has_no_staged_executable(self) -> None:
        destinations = prepare_runtime.runtime_destinations(
            Path("upstream"), Path("build"), Path("poc")
        )
        self.assertEqual(
            {path.name for path in destinations},
            {"exploit.js", "shellcode.js"},
        )
        self.assertNotIn("p.exe", {path.name for path in destinations.values()})


class HttpOriginTests(unittest.TestCase):
    def test_accepts_fixed_lab_hostnames(self) -> None:
        self.assertEqual(lab_http_server.role_for_host("portal.lab.test"), "wrap")
        self.assertEqual(lab_http_server.role_for_host("exp.portal.lab.test"), "exp")

    def test_rejects_unscoped_hostname(self) -> None:
        for host in (
            "example.com",
            "portal.lab.test.evil",
            "wrap-run01.portal.lab.test",
            "exp-run01.portal.lab.test",
        ):
            with self.subTest(host=host):
                self.assertIsNone(lab_http_server.role_for_host(host))

    def test_wrapper_is_transparent_and_uses_fixed_destinations(self) -> None:
        wrapper = (
            Path(__file__).resolve().parents[1] / "host1_wrapper" / "iframe.html"
        ).read_text(encoding="utf-8")
        self.assertIn("Authorized security lab simulation", wrapper)
        self.assertIn("exp.portal.lab.test", wrapper)
        self.assertIn("http://10.10.10.80/", wrapper)
        self.assertIn("e.origin !== expectedOrigin", wrapper)


if __name__ == "__main__":
    unittest.main()
