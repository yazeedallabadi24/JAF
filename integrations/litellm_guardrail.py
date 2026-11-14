"""LiteLLM proxy guardrail: send every prompt through the JAF API before it reaches a model.

Protects every app behind the proxy without changing app code. Calls the JAF HTTP
service, so the proxy needs no JAF dependencies.

litellm config.yaml:
    guardrails:
      - guardrail_name: jaf-ingress
        litellm_params:
          guardrail: integrations.litellm_guardrail.JAFGuardrail
          mode: pre_call
    environment_variables:
      JAF_URL: http://jaf.jaf.svc.cluster.local:8080

Status: written against LiteLLM's CustomGuardrail interface; not yet run against a live proxy.
"""

from __future__ import annotations

import os

import httpx
from fastapi import HTTPException
from litellm.integrations.custom_guardrail import CustomGuardrail

JAF_URL = os.getenv("JAF_URL", "http://127.0.0.1:8080")
JAF_TIMEOUT_S = float(os.getenv("JAF_TIMEOUT_S", "3"))
FAIL_CLOSED = os.getenv("JAF_FAIL_MODE", "open").lower() == "closed"


def _last_user_text(messages: list[dict]) -> str:
    for msg in reversed(messages or []):
        if msg.get("role") == "user":
            content = msg.get("content")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                return "\n".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


class JAFGuardrail(CustomGuardrail):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.http = httpx.AsyncClient(timeout=JAF_TIMEOUT_S)

    async def async_pre_call_hook(self, user_api_key_dict, cache, data: dict, call_type):
        text = _last_user_text(data.get("messages", []))
        if not text:
            return data
        try:
            resp = await self.http.post(f"{JAF_URL}/v1/inspect/ingress", json={"text": text})
            resp.raise_for_status()
            verdict = resp.json()
        except httpx.HTTPError:
            if FAIL_CLOSED:
                raise HTTPException(status_code=503, detail="JAF unavailable (fail-closed)")
            return data
        if verdict.get("enforced") and verdict.get("action") == "block":
            raise HTTPException(
                status_code=403,
                detail={"error": "blocked by JAF", "category": verdict.get("category"),
                        "rules": [f.get("rule_id") for f in verdict.get("findings", []) if f.get("rule_id")]},
            )
        return data
