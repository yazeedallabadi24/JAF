"""Agent Tools for Web Research and Outbound HTTP Interaction.

Provides LangChain-compatible tools:
1. `search_and_read_webpage`: Fetches external web content (subject to Phase 2 inspection).
2. `http_request_tool`: Sends outbound HTTP requests (subject to Phase 3 inspection).
"""

import logging
from typing import Dict, Any, Optional
from urllib.request import urlopen, Request

# Optional langchain_core tool decorator fallback
try:
    from langchain_core.tools import tool
except ImportError:
    def tool(func):
        def _invoke(arg, **kwargs):
            if isinstance(arg, dict):
                return func(**arg)
            return func(arg)
        func.invoke = _invoke
        return func

from agent.mock_web import fetch_mock_article

logger = logging.getLogger("JAF_Tools")

# Runtime WAF hooks injected dynamically by the orchestrator
_ACTIVE_WAF_CONTEXT: Dict[str, Any] = {
    "phase2_retrieval_guard": None,
    "phase3_egress_firewall": None,
    "protection_mode": "unprotected",  # "unprotected", "phase2_active", "phase3_active"
    "trace": [],
}


def set_waf_context(phase2_guard=None, phase3_firewall=None, mode: str = "unprotected"):
    """Set the active WAF hook instances for tool-call interception."""
    _ACTIVE_WAF_CONTEXT["phase2_retrieval_guard"] = phase2_guard
    _ACTIVE_WAF_CONTEXT["phase3_egress_firewall"] = phase3_firewall
    _ACTIVE_WAF_CONTEXT["protection_mode"] = mode
    _ACTIVE_WAF_CONTEXT["trace"].clear()


def get_waf_trace() -> list:
    """Retrieve recorded trace events from the current tool calls."""
    return list(_ACTIVE_WAF_CONTEXT.get("trace", []))


@tool
def search_and_read_webpage(query_or_url: str) -> str:
    """Search for and read the full text of an external web article or technical documentation."""
    logger.info(f"Tool invoked: search_and_read_webpage('{query_or_url}')")
    article = fetch_mock_article(query_or_url)
    raw_content = article["content"]

    mode = _ACTIVE_WAF_CONTEXT.get("protection_mode", "unprotected")
    phase2 = _ACTIVE_WAF_CONTEXT.get("phase2_retrieval_guard")

    # Phase 2 Interception: Untrusted Web Retrieval Gate
    if mode in ["phase2_active", "fully_protected"] and phase2:
        logger.info("Executing Phase 2 Retrieval Gate on external webpage content...")
        result = phase2.inspect_and_sanitize(raw_content, source_url=article["url"])
        _ACTIVE_WAF_CONTEXT["trace"].append({
            "phase": "phase2_retrieval",
            "threat_detected": result["threat_detected"],
            "latency_ms": result["latency_ms"],
            "quarantined_chunks": result["quarantined_chunks"],
            "action": "SURGICAL_SANITIZE_CHUNK" if result["threat_detected"] else "PASS",
        })
        if result["threat_detected"]:
            logger.warning(f"Phase 2 Sanitized {len(result['quarantined_chunks'])} malicious chunk(s)!")
        return result["sanitized_text"]
    else:
        # Pass raw poisoned content directly into context
        _ACTIVE_WAF_CONTEXT["trace"].append({
            "phase": "phase2_retrieval",
            "threat_detected": article["is_poisoned"],
            "latency_ms": 0.0,
            "action": "BYPASSED_UNPROTECTED",
        })
        return raw_content


@tool
def http_request_tool(url: str) -> str:
    """Send an outbound HTTP GET request to verify a URL, invoke a webhook, or query an external API."""
    logger.info(f"Tool invoked: http_request_tool('{url}')")
    mode = _ACTIVE_WAF_CONTEXT.get("protection_mode", "unprotected")
    phase3 = _ACTIVE_WAF_CONTEXT.get("phase3_egress_firewall")

    # Phase 3 Interception: Outbound Tool & URL Egress Firewall
    if mode in ["phase3_active", "fully_protected"] and phase3:
        logger.info("Executing Phase 3 Egress Firewall on outbound URL...")
        inspection = phase3.inspect_egress(url, tool_name="http_request_tool")
        _ACTIVE_WAF_CONTEXT["trace"].append({
            "phase": "phase3_egress",
            "threat_detected": inspection["is_blocked"],
            "latency_ms": inspection["latency_ms"],
            "exfiltration_risk_score": inspection["risk_score"],
            "action": "CIRCUIT_BREAKER_BLOCKED" if inspection["is_blocked"] else "ALLOW_EGRESS",
            "details": inspection,
        })

        if inspection["is_blocked"]:
            logger.error(f"Phase 3 BLOCKED outbound call: {url} (Risk Score: {inspection['risk_score']})")
            return f"SECURITY BLOCKED: Outbound request to '{url}' was rejected by JAF Egress Firewall. Reason: {inspection['reason']}"

    # If unprotected or allowed by firewall, execute HTTP request
    try:
        req = Request(url, headers={"User-Agent": "JAF-Agent/1.0"})
        with urlopen(req, timeout=3.0) as resp:
            content = resp.read().decode("utf-8", errors="replace")
            _ACTIVE_WAF_CONTEXT["trace"].append({
                "phase": "phase3_egress",
                "threat_detected": False,
                "latency_ms": 0.0,
                "action": "TRANSMITTED_TO_NETWORK",
                "status_code": resp.status,
            })
            return f"HTTP 200 OK: {content}"
    except Exception as e:
        # Fallback to simulated in-memory C2 recording if socket connections are restricted
        if "8765" in url or "attacker-c2" in url:
            from c2_server.c2_listener import record_simulated_packet
            pkt = record_simulated_packet(url)
            _ACTIVE_WAF_CONTEXT["trace"].append({
                "phase": "phase3_egress",
                "threat_detected": False,
                "latency_ms": 0.0,
                "action": "TRANSMITTED_TO_C2_SIMULATED",
                "packet_id": pkt["id"],
            })
            return f"HTTP 200 OK (C2 Recorded): {pkt['id']}"
        return f"HTTP Request Result: {e}"
