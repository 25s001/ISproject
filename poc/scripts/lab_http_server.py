#!/usr/bin/env python3
"""Serve the two fixed lab origins required by the Chrome Site Isolation PoC."""

from __future__ import annotations

import argparse
import logging
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


HOST_ROLES = {
    "portal.lab.test": "wrap",
    "exp.portal.lab.test": "exp",
}


def role_for_host(host: str) -> str | None:
    return HOST_ROLES.get(host.lower())


class LabHandler(BaseHTTPRequestHandler):
    server_version = "ISProjectLab/1.0"

    def do_GET(self) -> None:
        host = self.headers.get("Host", "").split(":", 1)[0]
        role = role_for_host(host)
        if role is None:
            self.send_error(400, "unexpected lab host name")
            return

        root = self.server.wrapper_root if role == "wrap" else self.server.exploit_root
        request_path = PurePosixPath(unquote(urlsplit(self.path).path))
        if ".." in request_path.parts:
            self.send_error(403, "path traversal rejected")
            return

        relative = str(request_path).lstrip("/")
        if not relative:
            relative = "iframe.html" if role == "wrap" else "exploit.html"

        target = (root / relative).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            self.send_error(403, "path outside lab root rejected")
            return

        if not target.is_file():
            self.send_error(404, "file not found")
            return

        data = target.read_bytes()
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
        logging.info("client=%s host=%s path=%s status=200 bytes=%d",
                     self.client_address[0], host, request_path, len(data))

    def log_message(self, message: str, *args: object) -> None:
        logging.info("client=%s %s", self.client_address[0], message % args)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="10.10.10.20")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--log", type=Path, default=Path("http-access.log"))
    args = parser.parse_args()

    poc_root = Path(__file__).resolve().parents[1]
    LabHandler.protocol_version = "HTTP/1.1"
    server = ThreadingHTTPServer((args.bind, args.port), LabHandler)
    server.wrapper_root = (poc_root / "host1_wrapper").resolve()
    server.exploit_root = (poc_root / "host2_single_run").resolve()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(message)s",
        handlers=[logging.FileHandler(args.log, encoding="utf-8"), logging.StreamHandler()],
    )
    logging.info("serving portal/exp lab origins on http://%s:%d", args.bind, args.port)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
