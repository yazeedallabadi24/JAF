"""JAF Full-Lifecycle WAF Orchestrator.

Coordinates Phase 1 (Ingress), Phase 2 (Retrieval Gate), and Phase 3 (Egress Firewall)
across different execution modes for demonstration and production deployment.
"""

import time
from typing import Dict, Any, Optional

from core.laya_engine import LayaEngine, laya_singleton
from core.phase1_direct_ingress import DirectIngressGuard
from core.phase2_retrieval_gate import RetrievalGate
from core.phase3_egress_firewall import EgressFirewall
from agent.tools import set_waf_context, get_waf_trace


class JAFOrchestrator:
    """Master controller managing the 3-hop System 1 security graph."""

    def __init__(self, engine: Optional[LayaEngine] = None):
        self.engine = engine or laya_singleton
        self.ingress_guard = DirectIngressGuard(self.engine)
        self.retrieval_gate = RetrievalGate(self.engine)
        self.egress_firewall = EgressFirewall(self.engine)

    def execute_agent_workflow(
        self,
        user_prompt: str,
        protection_mode: str,
        agent_callable,
    ) -> Dict[str, Any]:
        """Execute the full agent workflow under the selected protection posture.

        Args:
            user_prompt: Input from the user.
            protection_mode: 'unprotected', 'phase2_active', 'phase3_active', or 'fully_protected'.
            agent_callable: Callable running the agent (e.g. agent_runner.invoke).
        """
        start_time = time.perf_counter()
        trace = []

        # Configure tool interception context
        set_waf_context(
            phase2_guard=self.retrieval_gate,
            phase3_firewall=self.egress_firewall,
            mode=protection_mode
        )

        prompt_to_send = user_prompt
        ingress_result = None

        # -------------------------------------------------------------
        # Phase 1: Direct Ingress Guard
        # -------------------------------------------------------------
        if protection_mode in ["phase2_active", "phase3_active", "fully_protected"]:
            ingress_result = self.ingress_guard.inspect_prompt(user_prompt)
            trace.append({
                "hop": "Phase 1: Direct Ingress",
                "latency_ms": ingress_result["latency_ms"],
                "threat_detected": ingress_result["threat_detected"],
                "action": "BLOCK" if ingress_result["is_blocked"] else ("SANITIZE" if ingress_result["threat_detected"] else "PASS"),
                "details": ingress_result,
            })

            if ingress_result["is_blocked"]:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return {
                    "final_output": "SECURITY HALT: Prompt rejected by JAF Direct Ingress Guard due to detected jailbreak/injection directives.",
                    "protection_mode": protection_mode,
                    "total_latency_ms": round(elapsed_ms, 2),
                    "waf_hops_executed": trace,
                    "attack_succeeded": False,
                    "circuit_breaker_tripped": True,
                }
            prompt_to_send = ingress_result["sanitized_prompt"]
        else:
            trace.append({
                "hop": "Phase 1: Direct Ingress",
                "latency_ms": 0.0,
                "threat_detected": False,
                "action": "BYPASSED_UNPROTECTED",
            })

        # -------------------------------------------------------------
        # Execute LangChain Agent (Calls tools with Phase 2 and 3 hooks)
        # -------------------------------------------------------------
        try:
            agent_output = agent_callable(prompt_to_send)
        except Exception as e:
            agent_output = f"Agent Execution Terminated: {e}"

        # Collect tool execution traces (Phase 2 & Phase 3)
        tool_traces = get_waf_trace()
        for tt in tool_traces:
            phase_name = "Phase 2: Retrieval Gate" if tt.get("phase") == "phase2_retrieval" else "Phase 3: Egress Firewall"
            trace.append({
                "hop": phase_name,
                "latency_ms": tt.get("latency_ms", 0.0),
                "threat_detected": tt.get("threat_detected", False),
                "action": tt.get("action", "EXECUTED"),
                "details": tt,
            })

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Determine if attack succeeded (checked via C2 logs or outgoing calls)
        from c2_server.c2_listener import get_captured_packets
        c2_packets = get_captured_packets()
        attack_succeeded = any(p.get("has_canary_flag") for p in c2_packets)

        return {
            "final_output": agent_output,
            "protection_mode": protection_mode,
            "total_latency_ms": round(elapsed_ms, 2),
            "waf_hops_executed": trace,
            "attack_succeeded": attack_succeeded,
            "c2_packets_captured": len(c2_packets),
        }


# Global singleton orchestrator
orchestrator_singleton = JAFOrchestrator()
