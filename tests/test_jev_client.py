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


def test_harmful_question_only_on_ingress():
    ingress = build_request("m", "x", Hop.INGRESS, check_harmful=True)
    retrieval = build_request("m", "x", Hop.RETRIEVAL, check_harmful=True)
    off = build_request("m", "x", Hop.INGRESS, check_harmful=False)
    assert "is_harmful" in ingress["questions"]
    assert "is_harmful" not in retrieval["questions"]
    assert "is_harmful" not in off["questions"]


def test_parse_harmful_answer_and_refusal():
    data = {**SAMPLE, "answers": {**SAMPLE["answers"], "is_harmful": {"type": "noul", "noul": 0.9}}}
    assert parse_response(data).p_harmful == 0.9
    data["answers"]["is_harmful"] = {"type": "refusal"}
    assert parse_response(data).p_harmful == 1.0
    assert parse_response(SAMPLE).p_harmful is None


def test_client_retries_once_on_transient_error():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(503) if len(calls) == 1 else httpx.Response(200, json=SAMPLE)

    assert _client(handler).classify("x", Hop.INGRESS).p_attack == 0.93
    assert len(calls) == 2


def test_client_does_not_retry_client_errors():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(400, json={"error": "bad request"})

    with pytest.raises(JevUnavailable):
        _client(handler).classify("x", Hop.INGRESS)
    assert len(calls) == 1


def test_directive_question_only_on_retrieval():
    retrieval = build_request("m", "x", Hop.RETRIEVAL, check_directives=True)
    ingress = build_request("m", "x", Hop.INGRESS, check_directives=True)
    assert "addresses_ai" in retrieval["questions"]
    assert "addresses_ai" not in ingress["questions"]


def test_parse_directive_answer():
    data = {**SAMPLE, "answers": {**SAMPLE["answers"], "addresses_ai": {"type": "noul", "noul": 0.88}}}
    assert parse_response(data).p_directive == 0.88
