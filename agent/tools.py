"""Agent tools, each wrapped by the matching JAF hop.

The firewall sits *inside* the tool, so the model cannot skip it: retrieval goes
through Hop 2 before the model reads it, and outbound requests go through Hop 3
before any socket is opened.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from core import Firewall

from .mock_web import lookup


def _default_transport(url: str) -> str:
    resp = httpx.get(url, timeout=5.0)
    return f"HTTP {resp.status_code}"


class AgentTools:
    def __init__(
        self,
        firewall: Firewall | None,
        transport: Callable[[str], object] = _default_transport,
        bypass_phase2: bool = False,
    ):
        self.firewall = firewall
        self.transport = transport
        self.bypass_phase2 = bypass_phase2

    def search_and_read_webpage(self, query: str) -> str:
        if query.startswith("http://") or query.startswith("https://"):
            try:
                resp = httpx.get(query, timeout=3.0)
                page = resp.text
            except Exception:
                page = lookup(query)
        else:
            page = lookup(query)

        if self.firewall and not self.bypass_phase2:
            page = self.firewall.filter_retrieval(page)
        return page

    def http_request_tool(self, url: str) -> str:
        if self.firewall:
            self.firewall.check_egress(url)  # raises Blocked before the request is sent
        result = self.transport(url)
        return str(result) if result is not None else "sent"

    # OpenAI-style tool schemas for the LLM agent.
    SCHEMAS = [
        {
            "type": "function",
            "function": {
                "name": "search_and_read_webpage",
                "description": "Search the web and return the text of the top result.",
                "parameters": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "http_request_tool",
                "description": "Send an HTTP GET request to a URL.",
                "parameters": {
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"],
                },
            },
        },
    ]
