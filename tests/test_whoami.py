"""Tests for /tools/whoami (client IP echo, curl-first content negotiation)."""

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)

CURL_UA = {"User-Agent": "curl/8.6.0", "Accept": "*/*"}
BROWSER_UA = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


def test_whoami_curl_gets_plain_ip():
    resp = client.get("/tools/whoami", headers=CURL_UA)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert resp.text.strip() == "testclient"


def test_whoami_browser_gets_json():
    resp = client.get("/tools/whoami", headers=BROWSER_UA)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    body = resp.json()
    assert body["ip"] == "testclient"
    assert body["method"] == "GET"


def test_whoami_respects_x_forwarded_for_first_entry():
    headers = dict(CURL_UA)
    headers["X-Forwarded-For"] = "203.0.113.7, 10.0.0.1, 10.0.0.2"
    resp = client.get("/tools/whoami", headers=headers)
    assert resp.text.strip() == "203.0.113.7"


def test_whoami_ip_always_plain():
    headers = dict(BROWSER_UA)
    headers["X-Forwarded-For"] = "198.51.100.42"
    resp = client.get("/tools/whoami/ip", headers=headers)
    assert resp.headers["content-type"].startswith("text/plain")
    assert resp.text.strip() == "198.51.100.42"


def test_whoami_json_always_json_for_curl():
    headers = dict(CURL_UA)
    headers["X-Forwarded-For"] = "198.51.100.42"
    resp = client.get("/tools/whoami/json", headers=headers)
    assert resp.headers["content-type"].startswith("application/json")
    body = resp.json()
    assert body["ip"] == "198.51.100.42"
    assert body["user_agent"] == "curl/8.6.0"
    assert body["x_forwarded_for"] == "198.51.100.42"


def test_whoami_json_accept_header_on_base_endpoint():
    headers = {"User-Agent": "curl/8.6.0", "Accept": "application/json"}
    resp = client.get("/tools/whoami", headers=headers)
    assert resp.headers["content-type"].startswith("application/json")


def test_whoami_never_reflects_sensitive_headers():
    headers = dict(CURL_UA)
    headers["Cookie"] = "session=secret"
    headers["Authorization"] = "Bearer secret-token"
    resp = client.get("/tools/whoami/json", headers=headers)
    body_str = resp.text.lower()
    assert "secret" not in body_str
    assert "authorization" not in body_str
    assert "cookie" not in body_str


def test_whoami_all_plain_listing():
    headers = dict(CURL_UA)
    headers["X-Forwarded-For"] = "203.0.113.7"
    resp = client.get("/tools/whoami/all", headers=headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "ip: 203.0.113.7" in resp.text
    assert "user_agent: curl/8.6.0" in resp.text
    assert "remote_host:" in resp.text


def test_whoami_per_field_endpoints():
    headers = dict(CURL_UA)
    headers["X-Forwarded-For"] = "203.0.113.7"
    headers["Accept-Language"] = "pl-PL,pl;q=0.9"
    assert client.get("/tools/whoami/ua", headers=headers).text.strip() == "curl/8.6.0"
    assert client.get("/tools/whoami/lang", headers=headers).text.strip() == "pl-PL,pl;q=0.9"
    assert client.get("/tools/whoami/forwarded", headers=headers).text.strip() == "203.0.113.7"
    assert client.get("/tools/whoami/method", headers=headers).text.strip() == "GET"


def test_whoami_unknown_field_404():
    resp = client.get("/tools/whoami/nope", headers=CURL_UA)
    assert resp.status_code == 404
    assert "valid:" in resp.text


def test_whoami_json_has_port_mime_remote_host():
    headers = dict(CURL_UA)
    headers["X-Forwarded-For"] = "203.0.113.7"
    headers["X-Forwarded-Port"] = "51234"
    body = client.get("/tools/whoami/json", headers=headers).json()
    assert body["port"] == "51234"
    assert body["mime"] == "*/*"
    assert "remote_host" in body
