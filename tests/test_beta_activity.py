"""
Public beta, variant A (BETA-A, 2026-10-05): signed tester token + activity
record in MailerLite. Pins the @ciso conditions (DATA/ciso-public-beta-privacy
2026-10-04, section 1.5):

W1  only tool paths count (tools live outside /api); page-load fetches do not
W2  the request body never reaches a log or a MailerLite call
W3  v1.<id>.<b64url(hmac)>, compare_digest, >= 32-byte secret, no secret = no token
W4  activity = PUT /subscribers/{id} with only `fields`; backfill is read-only
W5  dates only (beta_first_use while empty, beta_last_use)
    + same answer shape for a new and an existing address, daily dedup.
No test reaches MailerLite: every client is an httpx.MockTransport.
"""
import asyncio
import datetime
import json
import logging

import httpx
import pytest
from fastapi.testclient import TestClient

from api import beta
from api import rate_limit as rl
from api.main import app
from api.routers import subscribe as sub

SECRET = "s" * 40
OTHER_SECRET = "o" * 40
SID = "170000000000000042"
CANARY = "CANARY-enable-secret-5-$1$x9Qz$SHOULDNEVERLEAVE"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("BETA_TOKEN_SECRET_PREVIOUS", raising=False)
    monkeypatch.setenv("BETA_TOKEN_SECRET", SECRET)
    monkeypatch.setenv("MAILERLITE_API_KEY", "ml-test-key")
    monkeypatch.setattr(sub, "MAILERLITE_API_KEY", "ml-test-key")
    beta.reset_for_tests()
    yield
    beta.reset_for_tests()


@pytest.fixture
def spawned(monkeypatch):
    """Capture background writes instead of scheduling them."""
    coros = []
    monkeypatch.setattr(beta, "_spawn", coros.append)
    yield coros
    for c in coros:
        c.close()


class FakeMailerLite:
    def __init__(self, get_status=200, fields=None, groups=None, put_status=200,
                 post_status=201, raise_on=None):
        self.requests = []
        self.get_status = get_status
        self.fields = fields if fields is not None else {}
        self.groups = groups if groups is not None else [{"id": sub.GATED_TOOLS_GROUP_ID}]
        self.put_status = put_status
        self.post_status = post_status
        self.raise_on = raise_on

    def handler(self, request: httpx.Request):
        self.requests.append(request)
        if self.raise_on == request.method:
            raise httpx.ConnectError("boom")
        if request.method == "GET":
            if self.get_status != 200:
                return httpx.Response(self.get_status, json={"message": "nope"})
            return httpx.Response(200, json={"data": {
                "id": SID, "email": "a@b.co", "status": "active",
                "fields": self.fields, "groups": self.groups}})
        if request.method == "PUT":
            return httpx.Response(self.put_status, json={"data": {"id": SID}})
        if request.method == "POST":
            return httpx.Response(self.post_status, json={"data": {"id": SID}})
        return httpx.Response(405)

    def client(self):
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


@pytest.fixture
def ml(monkeypatch):
    fake = FakeMailerLite()
    monkeypatch.setattr(beta, "_client", fake.client)
    monkeypatch.setattr(sub, "_client", fake.client)
    return fake


@pytest.fixture
def client():
    return TestClient(app)


def _run(coros):
    for c in list(coros):
        asyncio.run(c)
    coros.clear()


# ---------------------------------------------------------------- W3 token

def test_token_round_trip_and_format():
    tok = beta.issue_token(SID)
    version, sid, sig = tok.split(".")
    assert (version, sid) == ("v1", SID)
    assert "=" not in sig and "+" not in sig and "/" not in sig
    assert beta.verify_token(tok) == SID


@pytest.mark.parametrize("mutate", [
    lambda t: t[:-2] + ("AA" if not t.endswith("AA") else "BB"),       # forged signature
    lambda t: t.replace(SID, "170000000000000043"),                     # other subscriber
    lambda t: "v2" + t[2:],                                             # wrong version
    lambda t: t + ".extra",
    lambda t: "",
    lambda t: "v1..",
    lambda t: "v1.abc." + t.split(".")[2],                              # non-numeric id
])
def test_forged_or_malformed_token_rejected(mutate):
    assert beta.verify_token(mutate(beta.issue_token(SID))) is None


def test_token_signed_with_other_secret_rejected(monkeypatch):
    monkeypatch.setenv("BETA_TOKEN_SECRET", OTHER_SECRET)
    foreign = beta.issue_token(SID)
    monkeypatch.setenv("BETA_TOKEN_SECRET", SECRET)
    assert beta.verify_token(foreign) is None


def test_previous_secret_accepted_during_rotation(monkeypatch):
    old = beta.issue_token(SID)
    monkeypatch.setenv("BETA_TOKEN_SECRET", OTHER_SECRET)
    assert beta.verify_token(old) is None
    monkeypatch.setenv("BETA_TOKEN_SECRET_PREVIOUS", SECRET)
    assert beta.verify_token(old) == SID
    assert beta.issue_token(SID) != old  # new tokens use the current secret


@pytest.mark.parametrize("value", [None, "", "short-secret"])
def test_no_or_short_secret_means_no_token(monkeypatch, capsys, value):
    if value is None:
        monkeypatch.delenv("BETA_TOKEN_SECRET")
    else:
        monkeypatch.setenv("BETA_TOKEN_SECRET", value)
    assert beta.issue_token(SID) is None
    assert beta.verify_token("v1.%s.abc" % SID) is None
    out = capsys.readouterr().out
    assert "BETA_TOKEN_SECRET" in out
    if value:
        assert value not in out  # the warning never carries the value


def test_bad_subscriber_id_gets_no_token():
    assert beta.issue_token(None) is None
    assert beta.issue_token("12a") is None
    assert beta.issue_token("1.2") is None


# ---------------------------------------------------------------- subscribe

@pytest.mark.parametrize("status", [200, 201])
def test_subscribe_same_answer_for_new_and_existing(client, ml, status):
    ml.post_status = status
    r = client.post("/api/subscribe", json={"email": "a@b.co"})
    body = r.json()
    assert set(body) == {"success", "message", "token"}
    assert body["success"] is True and body["message"] == "Subscribed"
    assert beta.verify_token(body["token"]) == SID


def test_subscribe_payload_never_sets_status_or_resubscribe(client, ml):
    client.post("/api/subscribe", json={"email": "a@b.co"})
    (req,) = ml.requests
    sent = json.loads(req.content)
    assert set(sent) == {"email", "groups"}


def test_subscribe_without_secret_works_as_before(client, ml, monkeypatch):
    monkeypatch.delenv("BETA_TOKEN_SECRET")
    body = client.post("/api/subscribe", json={"email": "a@b.co"}).json()
    assert body["success"] is True and body["token"] is None


def test_subscribe_dev_mode_has_no_token(client, ml, monkeypatch):
    monkeypatch.setattr(sub, "MAILERLITE_API_KEY", "")
    body = client.post("/api/subscribe", json={"email": "a@b.co"}).json()
    assert body["success"] is True and body["token"] is None
    assert ml.requests == []


# ---------------------------------------------------------------- W4 backfill

def test_backfill_existing_gated_subscriber_gets_token_read_only(client, ml):
    body = client.post("/api/beta/token", json={"email": "a+x@b.co"}).json()
    assert beta.verify_token(body["token"]) == SID
    assert [r.method for r in ml.requests] == ["GET"]
    assert ml.requests[0].url.raw_path.endswith(b"/subscribers/a%2Bx@b.co")


@pytest.mark.parametrize("case", ["unknown", "other_group", "no_groups"])
def test_backfill_never_creates_and_answers_same_shape(client, ml, case):
    if case == "unknown":
        ml.get_status = 404
    elif case == "other_group":
        ml.groups = [{"id": "999"}]
    else:
        def no_groups(request):
            ml.requests.append(request)
            return httpx.Response(200, json={"data": {"id": SID, "fields": {}}})
        ml.handler = no_groups
    body = client.post("/api/beta/token", json={"email": "nobody@b.co"}).json()
    assert set(body) == {"token"}
    sid = beta.verify_token(body["token"])
    assert sid is not None and sid != SID and len(sid) == 18   # decoy, same shape
    assert all(r.method == "GET" for r in ml.requests)
    again = client.post("/api/beta/token", json={"email": "Nobody@b.co"}).json()
    assert again == body  # stable decoy


def test_backfill_without_secret_or_key_returns_null(client, ml, monkeypatch):
    monkeypatch.delenv("BETA_TOKEN_SECRET")
    assert client.post("/api/beta/token", json={"email": "a@b.co"}).json() == {"token": None}
    assert ml.requests == []


def test_backfill_is_rate_limited(client, ml, monkeypatch):
    monkeypatch.setattr(rl, "ENABLED", True)
    monkeypatch.setattr(rl, "limiter", rl.SlidingWindowLimiter())
    codes = [client.post("/api/beta/token", json={"email": "a@b.co"}).status_code for _ in range(6)]
    assert codes[:5] == [200] * 5 and codes[5] == 429


# ---------------------------------------------------------------- W1 middleware

def _tool_post(client, token, text="hostname r1\n"):
    return client.post("/tools/config/parse", json={"config_text": text},
                       headers={"X-Beta-Token": token} if token else {})


def test_valid_token_on_tool_counts_once_per_day(client, spawned):
    tok = beta.issue_token(SID)
    assert _tool_post(client, tok).status_code == 200
    assert _tool_post(client, tok).status_code == 200
    assert client.get("/tools/whoami/json", headers={"X-Beta-Token": tok}).status_code == 200
    assert len(spawned) == 1


def test_get_tool_counts(client, spawned):
    r = client.get("/tools/whoami/json", headers={"X-Beta-Token": beta.issue_token(SID)})
    assert r.status_code == 200 and len(spawned) == 1


def test_dedup_is_per_day_and_per_subscriber(spawned):
    d1, d2 = datetime.date(2026, 10, 5), datetime.date(2026, 10, 6)
    assert beta.note_activity(SID, d1) is True
    assert beta.note_activity(SID, d1) is False
    assert beta.note_activity("170000000000000099", d1) is True
    assert beta.note_activity(SID, d2) is True
    assert len(spawned) == 3


@pytest.mark.parametrize("method,path", [
    ("GET", "/health"), ("GET", "/meta/version"), ("GET", "/api"), ("GET", "/"),
    ("GET", "/app-gate.js"), ("GET", "/analyze/advisories"), ("GET", "/profiles/list"),
])
def test_non_tool_and_page_load_paths_not_counted(client, spawned, method, path):
    client.request(method, path, headers={"X-Beta-Token": beta.issue_token(SID)})
    assert spawned == []


def test_subscribe_and_backfill_not_counted(client, ml, spawned):
    tok = beta.issue_token(SID)
    client.post("/api/subscribe", json={"email": "a@b.co"}, headers={"X-Beta-Token": tok})
    client.post("/api/beta/token", json={"email": "a@b.co"}, headers={"X-Beta-Token": tok})
    assert spawned == []


def test_is_tool_path_table():
    assert beta.is_tool_path("POST", "/generate/snmpv3")
    assert beta.is_tool_path("POST", "/analyze/cve")
    assert beta.is_tool_path("GET", "/mitigate/list")
    assert beta.is_tool_path("GET", "/api/kev/watch")
    assert beta.is_tool_path("GET", "/export/security-report")
    assert not beta.is_tool_path("POST", "/api/subscribe")
    assert not beta.is_tool_path("POST", "/api/beta/token")
    assert not beta.is_tool_path("DELETE", "/profiles/delete/x")
    assert not beta.is_tool_path("GET", "/static/app-core.js")


def test_invalid_missing_or_failed_not_counted(client, spawned):
    tok = beta.issue_token(SID)
    _tool_post(client, None)
    _tool_post(client, tok[:-3] + "xyz")
    r = client.post("/tools/config/parse", json={}, headers={"X-Beta-Token": tok})
    assert r.status_code == 422
    assert spawned == []


def test_no_secret_nothing_counted(client, spawned, monkeypatch):
    tok = beta.issue_token(SID)
    monkeypatch.delenv("BETA_TOKEN_SECRET")
    assert _tool_post(client, tok).status_code == 200
    assert spawned == []


# ---------------------------------------------------------------- W4/W5 write

def _write(ml, day=datetime.date(2026, 10, 5)):
    asyncio.run(beta.record_activity(SID, day))
    return ml.requests


def test_first_use_set_only_while_empty(ml):
    reqs = _write(ml)
    assert [r.method for r in reqs] == ["GET", "PUT"]
    put = reqs[1]
    assert put.url.path.endswith(f"/subscribers/{SID}")
    assert json.loads(put.content) == {"fields": {
        "beta_first_use": "2026-10-05", "beta_last_use": "2026-10-05"}}


def test_existing_first_use_kept_put_only_fields(ml):
    ml.fields = {"beta_first_use": "2026-10-01", "beta_last_use": "2026-10-02"}
    reqs = _write(ml)
    body = json.loads(reqs[1].content)
    assert body == {"fields": {"beta_last_use": "2026-10-05"}}
    assert not {"status", "groups", "resubscribe", "email"} & set(body)


def test_never_posts_and_skips_unknown_subscriber(ml):
    ml.get_status = 404
    reqs = _write(ml)
    assert [r.method for r in reqs] == ["GET"]


@pytest.mark.parametrize("setup", ["put_500", "get_500", "network"])
def test_mailerlite_errors_swallowed_without_personal_data(ml, capsys, setup):
    if setup == "put_500":
        ml.put_status = 500
    elif setup == "get_500":
        ml.get_status = 500
    else:
        ml.raise_on = "GET"
    _write(ml)  # must not raise
    out = capsys.readouterr()
    assert "beta activity" in out.out
    for leak in (SID, "a@b.co", SECRET, "ml-test-key"):
        assert leak not in out.out + out.err


def test_no_api_key_no_call(ml, monkeypatch):
    monkeypatch.delenv("MAILERLITE_API_KEY")
    assert _write(ml) == []


# ---------------------------------------------------------------- W2 body

def test_body_never_reaches_logs_or_mailerlite(client, ml, spawned, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    tok = beta.issue_token(SID)
    r = _tool_post(client, tok, text=f"hostname r1\nenable secret 5 {CANARY}\n")
    assert r.status_code == 200
    assert len(spawned) == 1
    _run(spawned)
    assert [q.method for q in ml.requests] == ["GET", "PUT"]
    for q in ml.requests:
        assert CANARY not in str(q.url)
        assert CANARY.encode() not in q.content
        assert b"config" not in q.content
    out = capsys.readouterr()
    assert CANARY not in out.out + out.err
    assert CANARY not in caplog.text
    assert tok not in out.out + out.err + caplog.text
