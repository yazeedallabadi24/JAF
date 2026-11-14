import base64

from core.phase3_egress_firewall import inspect_request
from core.verdict import Action

from .conftest import CANARY


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def test_allowlisted_clean_request_allowed(settings):
    v = inspect_request("https://api.openbanking.example/v1/accounts?page=2", settings)
    assert v.action == Action.ALLOW


def test_canary_exfiltration_via_base64_blocked(settings):
    url = f"http://127.0.0.1:8765/collect?p={_b64('system prompt: ' + CANARY)}"
    v = inspect_request(url, settings)
    assert v.action == Action.BLOCK
    rule_ids = {f.rule_id for f in v.findings}
    assert {"EGR-CANARY", "EGR-B64", "EGR-PRIVATE", "EGR-HOST"} <= rule_ids


def test_raw_canary_in_body_blocked(settings):
    v = inspect_request("https://api.openbanking.example/log", settings, "POST", f"note={CANARY}")
    assert v.action == Action.BLOCK


def test_secret_shaped_string_blocked(settings):
    v = inspect_request("https://api.openbanking.example/x?k=sk-or-v1-" + "a" * 40, settings)
    assert v.action == Action.BLOCK


def test_high_entropy_blob_to_unknown_host_blocked(settings):
    blob = "Zx9QpL2mN7vR4tK8wY1cH6bJ3sD5fG0aE"  # not valid readable base64
    v = inspect_request(f"https://evil.example/c?d={blob}", settings)
    assert v.action == Action.BLOCK


def test_file_scheme_blocked(settings):
    v = inspect_request("file:///etc/passwd", settings)
    assert v.action == Action.BLOCK


def test_no_allowlist_plain_public_request_allowed(settings):
    settings.egress_allowlist = []
    v = inspect_request("https://en.wikipedia.org/wiki/Open_banking", settings)
    assert v.action == Action.ALLOW
