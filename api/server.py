"""HTTP API so any app or gateway (LiteLLM, Envoy, a sidecar) can use JAF, not just Python agents.

Run:  uvicorn api.server:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import logging

from fastapi import FastAPI
from pydantic import BaseModel, Field

from core import Firewall, Verdict

logging.basicConfig(level=logging.INFO, format="%(message)s")

app = FastAPI(title="JAF - Jev Agent Firewall", version="0.2.0")
firewall = Firewall()


class TextIn(BaseModel):
    text: str = Field(..., max_length=200_000)


class EgressIn(BaseModel):
    url: str = Field(..., max_length=16_000)
    method: str = "GET"
    body: str | None = Field(None, max_length=200_000)


@app.get("/healthz")
def healthz() -> dict:
    s = firewall.settings
    return {
        "status": "ok",
        "mode": s.mode,
        "fail_mode": s.fail_mode,
        "jev": s.jev_model if firewall.engine else "disabled (no OPENROUTER_API_KEY)",
    }


# Plain `def` handlers: FastAPI runs them in a threadpool, so the sync Jev client doesn't block the loop.
@app.post("/v1/inspect/ingress", response_model=Verdict)
def ingress(req: TextIn) -> Verdict:
    return firewall.inspect_ingress(req.text)


@app.post("/v1/inspect/retrieval", response_model=Verdict)
def retrieval(req: TextIn) -> Verdict:
    return firewall.inspect_retrieval(req.text)


@app.post("/v1/inspect/egress", response_model=Verdict)
def egress(req: EgressIn) -> Verdict:
    return firewall.inspect_egress(req.url, req.method, req.body)
