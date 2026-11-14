import httpx
import pytest

from core.config import Settings
from core.jev_client import JevClient, JevUnavailable, build_request, parse_response
from core.verdict import Category, Hop

SAMPLE = {
    "id": "gen-1",
    "model": "typesafe/jev-1.13-20260917",
    "answers": {
        "is_attack": {"type": "noul", "noul": 0.93, "confidence": 0.9},
        "category": {
            "type": "choice",
            "choice": "prompt_injection",
            "probabilities": {"prompt_injection": 0.8, "none": 0.1},
            "confidence": 0.8,
        },
    },
    "usage": {"input_tokens": 400, "output_tokens": 10, "cost": 0.00002},
}


def test_request_shape():
    req = build_request("typesafe/jev-1.13", "hello", Hop.INGRESS)
    assert req["questions"]["is_attack"]["type"] == "noul"
    assert req["questions"]["category"]["type"] == "choice"
    assert set(req["questions"]["category"]["criteria"]) == {c.value for c in Category}


def test_parse_response():
    d = parse_response(SAMPLE)
    assert d.p_attack == 0.93
    assert d.category == Category.PROMPT_INJECTION
    assert d.cost_usd == 0.00002


def test_refusal_raises():
    with pytest.raises(JevUnavailable):
        parse_response({"answers": {"is_attack": {"type": "refusal"}}})


def _client(handler) -> JevClient:
    s = Settings(openrouter_api_key="test-key")
    return JevClient(s, http=httpx.Client(transport=httpx.MockTransport(handler)))


def test_client_success():
    client = _client(lambda req: httpx.Response(200, json=SAMPLE))
    assert client.classify("x", Hop.INGRESS).p_attack == 0.93


def test_client_http_error_raises_unavailable():
    client = _client(lambda req: httpx.Response(429, json={"error": "rate limited"}))
    with pytest.raises(JevUnavailable):
        client.classify("x", Hop.INGRESS)
