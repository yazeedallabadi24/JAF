"""Dummy attacker collector for the demo. Binds to localhost only.

Logs every hit and live-decodes base64 payloads, to show what a hijacked agent leaked.
Hits are appended to c2_hits.jsonl so the dashboard can display them.

Run:  python -m c2_server.c2_listener
"""

from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from core.normalize import try_b64decode

HOST = os.getenv("C2_HOST", "127.0.0.1")
PORT = int(os.getenv("C2_PORT", "8765"))
HITS_FILE = Path(os.getenv("C2_HITS_FILE", "c2_hits.jsonl"))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        params = dict(parse_qsl(urlsplit(self.path).query))
        decoded = {k: try_b64decode(v) for k, v in params.items()}
        hit = {"ts": time.time(), "path": self.path, "decoded": decoded}
        with HITS_FILE.open("a") as fh:
            fh.write(json.dumps(hit) + "\n")
        print(f"[C2] packet received: {json.dumps(decoded)[:300]}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def main() -> None:
    print(f"[C2] dummy listener on http://{HOST}:{PORT}/collect (hits -> {HITS_FILE})")
    HTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
