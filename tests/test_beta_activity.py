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
import re

import httpx
import pytest
from fastapi.testclient import TestClient

from api import beta
from api import rate_limit as rl
from api.main import app
from api.routers import subscribe as sub

SECRET = "s" * 40
OTHER_SECRET = "o" * 40
SID = "186000000000000042"   # inside [ID_MIN, ID_MAX] (FIX-5a)
# Test range (env BETA_ID_MIN/BETA_ID_MAX, FIX-5b); synthetic, not real bounds.
ID_MIN = 184000000000000000
ID_MAX = 190000000000000000
CANARY = "CANARY-enable-secret-5-$1$x9Qz$SHOULDNEVERLEAVE"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("BETA_TOKEN_SECRET_PREVIOUS", raising=False)
    monkeypatch.setenv("BETA_TOKEN_SECRET", SECRET)
    monkeypatch.setenv("MAILERLITE_API_KEY", "ml-test-key")
    monkeypatch.setenv("BETA_ID_MIN", str(ID_MIN))
    monkeypatch.setenv("BETA_ID_MAX", str(ID_MAX))
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
        self.sid = SID

    def handler(self, request: httpx.Request):
        self.requests.append(request)
        if self.raise_on == request.method:
            raise httpx.ConnectError("boom")
        if request.method == "GET":
            if self.get_status != 200:
                return httpx.Response(self.get_status, json={"message": "nope"})
            return httpx.Response(200, json={"data": {
                "id": self.sid, "email": "a@b.co", "status": "active",
                "fields": self.fields, "groups": self.groups}})
        if request.method == "PUT":
            return httpx.Response(self.put_status, json={"data": {"id": SID}})
        if request.method == "POST":
            return httpx.Response(self.post_status, json={"data": {"id": self.sid}})
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


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_subscribe_partial_logs_status_without_address(client, ml, capsys, status):
    """SUB-LOG: a MailerLite error is visible in the log (status only, no e-mail)."""
    ml.post_status = status
    body = client.post("/api/subscribe", json={"email": "secret.user@b.co"}).json()
    assert body == {"success": True, "message": "Subscribed (partial)", "token": None}
    out = capsys.readouterr().out
    assert f"status={status}" in out
    assert "secret.user" not in out and "b.co" not in out


def test_subscribe_offline_logs_error_type_without_address(client, ml, capsys):
    ml.raise_on = "POST"
    body = client.post("/api/subscribe", json={"email": "secret.user@b.co"}).json()
    assert body["message"] == "Subscribed (offline)" and body["token"] is None
    out = capsys.readouterr().out
    assert "ConnectError" in out
    assert "secret.user" not in out and "b.co" not in out


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
    assert ID_MIN <= int(sid) <= ID_MAX
    assert all(r.method == "GET" for r in ml.requests)
    again = client.post("/api/beta/token", json={"email": "Nobody@b.co"}).json()
    assert again == body  # stable decoy


# ---------------------------------------------------------------- FIX-5a backfill range

NEWER_SID = str(ID_MAX + 123456789)   # member who joined after MAX
OLDER_SID = str(ID_MIN - 1)


def test_backfill_member_inside_range_gets_real_token(client, ml):
    for sid in (str(ID_MIN), SID, str(ID_MAX)):
        ml.sid = sid
        body = client.post("/api/beta/token", json={"email": "a@b.co"}).json()
        assert beta.verify_token(body["token"]) == sid


@pytest.mark.parametrize("member_sid", [NEWER_SID, OLDER_SID])
def test_backfill_member_outside_range_gets_decoy_like_unknown(client, ml, member_sid):
    ml.sid = member_sid
    member = client.post("/api/beta/token", json={"email": "new@b.co"}).json()
    ml.get_status = 404
    unknown = client.post("/api/beta/token", json={"email": "new@b.co"}).json()
    # Same address: a member outside the range and an unknown address answer
    # byte for byte the same, so the answer says nothing about membership.
    assert member == unknown
    assert set(member) == {"token"}
    sid = beta.verify_token(member["token"])
    assert sid != member_sid and len(sid) == 18
    assert ID_MIN <= int(sid) <= ID_MAX
    assert sid == beta.decoy_subscriber_id("new@b.co")
    assert all(r.method == "GET" for r in ml.requests)


def test_subscribe_still_gives_real_token_outside_range(client, ml):
    ml.sid = NEWER_SID
    body = client.post("/api/subscribe", json={"email": "new@b.co"}).json()
    assert body["success"] is True and body["message"] == "Subscribed"
    assert beta.verify_token(body["token"]) == NEWER_SID


@pytest.mark.parametrize("value", [None, "", "abc", "1.5", str(ID_MAX + 1)])
def test_in_backfill_range_rejects_bad_or_outside(value):
    assert beta.in_backfill_range(value) is False


# ---------------------------------------------------------------- FIX-5/5b decoy shape

# Three SYNTHETIC ids with the layout of real ids of this account (bit 10 = 1,
# bits 11-19 = 0, 18 digits; layout checked on real ids 2026-10-07). Generated
# at random - not subscriber ids. Real ids never go into the repo (public).
REAL_MAILERLITE_IDS = ("185075479462544912", "188535520745228265", "189754571138008129")


def _fixed_bits(value):
    return (int(value) >> 10) & 0x3FF


def test_real_ids_have_the_constant_bits():
    for x in REAL_MAILERLITE_IDS:
        assert len(x) == 18
        assert _fixed_bits(x) == 0b0000000001          # bit 10 = 1, bits 11-19 = 0
        assert beta.has_real_id_shape(x)
    assert beta.ID_FIXED_MASK == 0x3FF << 10 and beta.ID_FIXED_VALUE == 1 << 10


@pytest.mark.parametrize("value", [None, "", "abc", "0", "186000000000000042",
                                   str(int("185075479462544912") ^ (1 << 15))])
def test_has_real_id_shape_rejects_other_layouts(value):
    assert beta.has_real_id_shape(value) is False


def test_decoy_has_real_id_shape():
    real_fixed = {_fixed_bits(x) for x in REAL_MAILERLITE_IDS}
    for i in range(2000):
        sid = beta.decoy_subscriber_id(f"user{i}@example.com")
        assert len(sid) == 18 and sid.isdigit()
        assert ID_MIN < int(sid) < ID_MAX
        assert not sid.startswith("11")          # no padding artefact
        assert {_fixed_bits(sid)} == real_fixed  # same constant bits as real ids
        assert beta.has_real_id_shape(sid)
        assert beta.issue_token(sid) is not None  # passes the id regex


def test_decoy_free_bits_vary():
    lows = {int(beta.decoy_subscriber_id(f"user{i}@example.com")) & 0x3FF for i in range(2000)}
    assert len(lows) > 800   # bits 0-9 spread, ~860 distinct expected of 1024


def test_decoy_stays_inside_real_bounds(monkeypatch):
    lo, hi = sorted(int(x) for x in REAL_MAILERLITE_IDS[:2])
    monkeypatch.setenv("BETA_ID_MIN", str(lo))
    monkeypatch.setenv("BETA_ID_MAX", str(hi))
    for i in range(500):
        sid = int(beta.decoy_subscriber_id(f"user{i}@example.com"))
        assert lo < sid < hi and beta.has_real_id_shape(sid)


def test_decoy_is_deterministic_per_email():
    a = beta.decoy_subscriber_id("someone@example.com")
    assert beta.decoy_subscriber_id("someone@example.com") == a
    assert beta.decoy_subscriber_id("  SomeOne@Example.com ") == a


def test_decoy_differs_per_email_and_spreads():
    ids = {beta.decoy_subscriber_id(f"user{i}@example.com") for i in range(2000)}
    assert len(ids) == 2000
    span = ID_MAX - ID_MIN
    # uniform across the range: every quarter gets a fair share
    quarters = [0, 0, 0, 0]
    for x in ids:
        quarters[min(3, (int(x) - ID_MIN) * 4 // span)] += 1
    assert all(q > 400 for q in quarters)
    # leading digits vary across the range, not a fixed prefix
    assert {x[:3] for x in ids} == {"184", "185", "186", "187", "188", "189"}


def test_decoy_depends_on_secret(monkeypatch):
    a = beta.decoy_subscriber_id("someone@example.com")
    monkeypatch.setenv("BETA_TOKEN_SECRET", "z" * 40)
    assert beta.decoy_subscriber_id("someone@example.com") != a


def test_decoy_without_secret_is_none(monkeypatch):
    monkeypatch.delenv("BETA_TOKEN_SECRET")
    assert beta.decoy_subscriber_id("someone@example.com") is None


# ---------------------------------------------------------------- FIX-5b range from env

def test_id_range_from_env():
    assert beta.id_range() == (ID_MIN, ID_MAX)
    assert beta.in_backfill_range(str(ID_MIN)) and beta.in_backfill_range(str(ID_MAX))


@pytest.mark.parametrize("lo,hi", [
    (None, None), ("", str(ID_MAX)), (str(ID_MIN), None),
    ("abc", str(ID_MAX)), (str(ID_MIN), "1e18"), ("-5", str(ID_MAX)),
    (str(ID_MAX), str(ID_MIN)),                      # reversed
    (str(ID_MIN), str(ID_MIN + (1 << 20))),          # too narrow
])
def test_missing_or_invalid_range_means_no_decoy_and_no_backfill(client, ml, monkeypatch, lo, hi):
    for name, value in (("BETA_ID_MIN", lo), ("BETA_ID_MAX", hi)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    assert beta.id_range() is None
    assert beta.decoy_subscriber_id("someone@example.com") is None
    assert beta.in_backfill_range(SID) is False
    # member and unknown answer the same: no token, no MailerLite call
    assert client.post("/api/beta/token", json={"email": "a@b.co"}).json() == {"token": None}
    ml.get_status = 404
    assert client.post("/api/beta/token", json={"email": "a@b.co"}).json() == {"token": None}
    assert ml.requests == []
    # /api/subscribe is not affected by the range
    assert beta.verify_token(client.post("/api/subscribe", json={"email": "a@b.co"}).json()["token"]) == SID


def test_range_change_moves_decoys(monkeypatch):
    a = beta.decoy_subscriber_id("someone@example.com")
    monkeypatch.setenv("BETA_ID_MAX", str(ID_MAX + 10**15))
    b = beta.decoy_subscriber_id("someone@example.com")
    assert a != b and ID_MIN < int(b) < ID_MAX + 10**15


def test_no_real_id_constants_left_in_code():
    import pathlib
    src = pathlib.Path(beta.__file__).read_text()
    assert not hasattr(beta, "DECOY_ID_MIN") and not hasattr(beta, "DECOY_ID_MAX")
    for x in REAL_MAILERLITE_IDS:
        assert x not in src
    # no 18-digit literal with the real-id layout anywhere in the module
    assert not [n for n in re.findall(r"\d{18}", src) if beta.has_real_id_shape(n)]


# ---------------------------------------------------------------- FIX-5b scripts/ml_group_id_range.py

def _load_range_script():
    import importlib.util
    import pathlib
    path = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "ml_group_id_range.py"
    spec = importlib.util.spec_from_file_location("ml_group_id_range", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_range_script_constants_match_beta():
    mod = _load_range_script()
    assert (mod.ID_FIXED_MASK, mod.ID_FIXED_VALUE) == (beta.ID_FIXED_MASK, beta.ID_FIXED_VALUE)
    assert mod.DEFAULT_GROUP_ID == sub.GATED_TOOLS_GROUP_ID


def test_range_script_paginates_and_prints_no_email():
    mod = _load_range_script()
    pages = {
        None: {"data": [{"id": REAL_MAILERLITE_IDS[0], "email": "leak1@x.co"},
                        {"id": REAL_MAILERLITE_IDS[1], "email": "leak2@x.co"}],
               "meta": {"next_cursor": "c2"}},
        "c2": {"data": [{"id": REAL_MAILERLITE_IDS[2], "email": "leak3@x.co"},
                        {"id": "186000000000000042", "email": "leak4@x.co"}],
               "meta": {"next_cursor": None}},
    }
    urls = []

    def fake_get(url, key):
        urls.append(url)
        assert key == "k"
        cursor = dict(p.split("=", 1) for p in url.split("?", 1)[1].split("&")).get("cursor")
        return pages[cursor]

    ids = list(mod.iter_ids("k", "184092079999157302", "active", get_json=fake_get))
    assert len(urls) == 2 and "/groups/184092079999157302/subscribers?" in urls[0]
    assert "cursor=c2" in urls[1] and "filter%5Bstatus%5D=active" in urls[0]
    out = "\n".join(mod.summarize({"active": len(ids)}, sorted(ids)))
    assert "@" not in out and "leak" not in out
    assert "members total: 4" in out
    assert "min id: 185075479462544912" in out and "max id: 189754571138008129" in out
    assert "3/4 match, 1 DO NOT MATCH" in out


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
