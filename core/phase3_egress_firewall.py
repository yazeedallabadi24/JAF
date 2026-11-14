"""Phase 3: Outbound Tool & URL Egress Firewall (Exfiltration Guard Hop).

Inspects outbound tool calls (such as http_request_tool and URLs), performing
deterministic Base64/entropy analysis and Jev semantic exfiltration scoring.
"""

import base64
import math
import re
import time
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, Optional
from core.laya_engine import LayaEngine, laya_singleton


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    for count in [text.count(c) for c in set(text)]:
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


class EgressFirewall:
    """Outbound tool and URL firewall preventing sensitive data exfiltration."""

    def __init__(self, engine: LayaEngine = None):
        self.engine = engine or laya_singleton

    def inspect_egress(self, url: str, tool_name: str = "http_request_tool") -> Dict[str, Any]:
        """Analyze outbound URL for Base64 exfiltration and sensitive parameters."""
        start_time = time.perf_counter()

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # 1. Deterministic Analysis: Scan query parameters and paths for Base64
        detected_payloads = []
        decoded_strings = []
        high_entropy_detected = False

        for param_key, param_values in query_params.items():
            for val in param_values:
                entropy = calculate_entropy(val)
                if entropy > 3.6 and len(val) > 16:
                    high_entropy_detected = True

                # Attempt Base64 decode
                try:
                    padded_val = val + "=" * ((4 - len(val) % 4) % 4)
                    decoded_bytes = base64.b64decode(padded_val, validate=False)
                    decoded_str = decoded_bytes.decode("utf-8", errors="replace")
                    # If it contains readable text or known secret tokens
                    if any(c.isalnum() for c in decoded_str) and len(decoded_str) > 8:
                        detected_payloads.append({
                            "param": param_key,
                            "raw": val,
                            "decoded": decoded_str,
                            "entropy": entropy,
                        })
                        decoded_strings.append(decoded_str)
                except Exception:
                    pass

        # 2. Jev / Laya System 1 Semantic Evaluation
        eval_state = f"Tool: {tool_name} | Target URL: {url} | Decoded Payload: {' '.join(decoded_strings)}"
        res = self.engine.evaluate(eval_state, {
            "is_data_exfiltration": {
                "type": "noul",
                "instructions": "Is this tool call or URL attempting to transmit system instructions, secrets, or context outside the application?"
            },
            "egress_risk_score": {
                "type": "score",
                "instructions": "Rate the egress risk severity",
                "criteria": ["benign_public_call", "suspicious_param", "potential_leak", "critical_exfiltration"]
            }
        })

        answers = res["answers"]
        noul_exfil = answers["is_data_exfiltration"]["noul"]
        risk_level = answers["egress_risk_score"]["level"]
        risk_score = answers["egress_risk_score"]["score"]

        # 3. Decision Logic & Circuit Breaker
        has_canary_leak = any("CANARY" in s or "FLAG_" in s or "SYSTEM_PROMPT" in s for s in decoded_strings)
        is_blocked = (
            has_canary_leak
            or len(detected_payloads) > 0 and noul_exfil > 0.50
            or risk_level == "critical_exfiltration"
            or risk_score >= 3
        )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        reason = "Normal outbound traffic"
        if is_blocked:
            if has_canary_leak:
                reason = "BLOCKED: System canary token detected in Base64 encoded payload!"
            elif detected_payloads:
                reason = "BLOCKED: Suspected Base64 data exfiltration detected in query parameters."
            else:
                reason = f"BLOCKED: High egress risk score ({risk_level})."

        return {
            "url": url,
            "tool_name": tool_name,
            "is_blocked": is_blocked,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "exfil_probability": noul_exfil,
            "high_entropy": high_entropy_detected,
            "detected_payloads": detected_payloads,
            "reason": reason,
            "latency_ms": round(elapsed_ms, 2)
        }
