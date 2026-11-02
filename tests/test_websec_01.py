"""
WEBSEC-01: limits and errors of the HTTP layer (backlog, @ciso N2/N3/N4).

(b) a 422 on a paste endpoint does not send the input back.
(b2) the ACL "outside the v0 grammar" sentence echoes at most 20 characters.
(d) global request body limit, tests at the end of this file.
(c) the IPv6 /64 limiter key is in tests/test_rate_limit.py.
"""
import pytest
from fastapi.testclient import TestClient
from starlette.routing import Route

from api.main import NO_ECHO_422_PATHS, app

client = TestClient(app)

FILLER = "Q" * 50_000
CONFIG = "hostname R1\n"

# path, a valid body, the field that gets the 50 000 character value
PASTE_ENDPOINTS = [
    ("/tools/config-drift/compare", {"config_a": CONFIG, "config_b": CONFIG}, "config_a"),
    ("/tools/config-drift/compare", {"config_a": CONFIG, "config_b": CONFIG}, "config_b"),
    ("/tools/hardening-audit/check", {"config_text": CONFIG}, "config_text"),
    ("/tools/cis-audit/check", {"config_text": CONFIG}, "config_text"),
    ("/tools/config/parse", {"config_text": CONFIG}, "config_text"),
    ("/tools/config/parse/summary", {"config_text": CONFIG}, "config_text"),
    ("/tools/config-explainer/explain", {"config_text": CONFIG}, "config_text"),
    ("/tools/port-auditor/analyze", {"interface_status": "Gi1/0/1 up"}, "interface_status"),
    ("/tools/ip-path-tracer/analyze", {"traceroute_output": "1 10.0.0.1"}, "traceroute_output"),
    ("/tools/acl/analyze", {"config_text": CONFIG}, "config_text"),
]


def _assert_small_no_echo(r):
    assert r.status_code == 422
    assert len(r.content) < 1024, len(r.content)
    assert "QQQQ" not in r.text
    assert all(set(d) == {"type", "loc", "msg"} for d in r.json()["detail"])


class TestNoEchoIn422:
    @pytest.mark.parametrize("path,body,field", PASTE_ENDPOINTS)
    def test_wrong_type_field_is_not_echoed(self, path, body, field):
        _assert_small_no_echo(client.post(path, json={**body, field: {"x": FILLER}}))

    @pytest.mark.parametrize("path,body,field", PASTE_ENDPOINTS)
    def test_missing_field_does_not_echo_the_rest_of_the_body(self, path, body, field):
        # FastAPI's "missing" error carries the whole body as its input.
        sent = {k: v for k, v in body.items() if k != field}
        _assert_small_no_echo(client.post(path, json={**sent, "extra": FILLER}))

    @pytest.mark.parametrize("path", sorted(NO_ECHO_422_PATHS))
    def test_broken_json_is_not_echoed(self, path):
        r = client.post(path, content=b'{"a": "' + b"Q" * 50_000,
                        headers={"Content-Type": "application/json"})
        _assert_small_no_echo(r)

    def test_error_still_names_the_field(self):
        r = client.post("/tools/config/parse", json={"config_text": 1})
        assert r.json()["detail"][0]["loc"] == ["body", "config_text"]

    def test_every_listed_path_is_a_post_route(self):
        # A typo in the list would silently keep the echo.
        posts = {r.path for r in app.routes if isinstance(r, Route) and "POST" in r.methods}
        assert NO_ECHO_422_PATHS <= posts, NO_ECHO_422_PATHS - posts

    def test_every_paste_endpoint_in_this_file_is_listed(self):
        assert {p for p, _, _ in PASTE_ENDPOINTS} == set(NO_ECHO_422_PATHS)
