"""Local documentation HTTP server for ACME Bank.

Simulates an internal/external documentation wiki at http://127.0.0.1:8888/wiki/open-banking.
Serves clean or poisoned documentation for testing Indirect Prompt Injection (IPI).

Run standalone:
    python -m c2_server.wiki_server
"""

from __future__ import annotations

import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from agent.mock_web import CLEAN_ARTICLE, POISONED_ARTICLE

HOST = os.getenv("WIKI_HOST", "127.0.0.1")
PORT = int(os.getenv("WIKI_PORT", "8888"))
WIKI_FILE = Path(os.getenv("WIKI_FILE", "wiki_page.txt"))


def get_current_wiki_content() -> str:
    if WIKI_FILE.exists():
        try:
            return WIKI_FILE.read_text(encoding="utf-8")
        except Exception:
            pass
    return POISONED_ARTICLE


def set_current_wiki_content(content: str) -> None:
    WIKI_FILE.write_text(content, encoding="utf-8")


class WikiHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        content = get_current_wiki_content()
        body = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def is_wiki_running(host: str = HOST, port: int = PORT) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            return sock.connect_ex((host, port)) == 0
    except Exception:
        return False


def ensure_wiki_running(host: str = HOST, port: int = PORT) -> None:
    """Start local wiki server in a background thread if not already running."""
    if is_wiki_running(host, port):
        return

    if not WIKI_FILE.exists():
        set_current_wiki_content(POISONED_ARTICLE)

    def _run():
        try:
            server = HTTPServer((host, port), WikiHandler)
            server.serve_forever()
        except Exception:
            pass

    t = threading.Thread(target=_run, daemon=True)
    t.start()


def main() -> None:
    if not WIKI_FILE.exists():
        set_current_wiki_content(POISONED_ARTICLE)
    print(f"[ACME Wiki Server] Serving at http://{HOST}:{PORT}/wiki/open-banking")
    server = HTTPServer((HOST, PORT), WikiHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
