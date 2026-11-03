"""
WEBSEC-01: limits and errors of the HTTP layer (backlog, @ciso N2/N3/N4).

(b) a 422 on a paste endpoint does not send the input back.
(b2) the ACL "outside the v0 grammar" sentence echoes at most 20 characters.
(d) global request body limit, tests at the end of this file.
(c) the IPv6 /64 limiter key is in tests/test_rate_limit.py.
"""
import asyncio

import pytest
from fastapi.testclient import TestClient
from starlette.routing import Route

from api import body_limit as bl
from api import rate_limit as rl
from api.main import NO_ECHO_422_PATHS, app
from services.acl_engine import STATUS_NOT_EVALUATED, parse_acls

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


class TestAclReasonEcho:
    """(b2) @ciso, ACL-01.5 review: the first word of a line came back without a limit."""

    WORD = "Z" * 10_000
    PASTE = "ip access-list extended E\n permit ip any any\n %s tail\n" % WORD

    def _reason(self):
        r = client.post("/tools/acl/analyze", json={"config_text": self.PASTE})
        assert r.status_code == 200
        items = r.json()["lint"]["acls"][0]["not_evaluated"]
        assert len(items) == 1
        return items[0]["reason"]

    def test_long_first_word_echo_is_at_most_20_characters(self):
        reason = self._reason()
        assert reason == "entry '%s'... is outside the v0 grammar" % ("Z" * 20)
        assert reason.split("'")[1] == "Z" * 20

    def test_engine_sentence_is_bounded_too(self):
        parsed = parse_acls(self.PASTE)
        entry = parsed.acls["E"].entries[-1]
        assert entry.status == STATUS_NOT_EVALUATED
        assert "Z" * 21 not in entry.reason

    def test_short_word_stays_whole_without_dots(self):
        parsed = parse_acls("ip access-list extended E\n frobnicate tail\n")
        assert parsed.acls["E"].entries[-1].reason == "entry 'frobnicate' is outside the v0 grammar"

    def test_exactly_20_characters_has_no_dots(self):
        word = "x" * 20
        parsed = parse_acls("ip access-list extended E\n %s tail\n" % word)
        assert parsed.acls["E"].entries[-1].reason == "entry '%s' is outside the v0 grammar" % word


def _post_routes():
    out = []
    for route in app.routes:
        if isinstance(route, Route) and "POST" in route.methods:
            out.append(route.path.replace("{name}", "x").replace("{", "").replace("}", ""))
    return sorted(set(out))


def _chunks(total, size=64 * 1024):
    def gen():
        sent = 0
        while sent < total:
            yield b"x" * min(size, total - sent)
            sent += size
    return gen()


JSON_HEADERS = {"Content-Type": "application/json"}
ONE_MB = 1_000_000


class TestBodyLimit:
    """(d) @ciso N4."""

    def test_route_list_is_not_empty(self):
        assert len(_post_routes()) >= 28

    @pytest.mark.parametrize("path", _post_routes())
    def test_1_mb_on_any_post_is_413(self, path):
        r = client.post(path, content=b"x" * ONE_MB, headers=JSON_HEADERS)
        assert r.status_code == 413, r.text[:200]
        assert len(r.content) < 200
        assert "KB" in r.json()["detail"]

    @pytest.mark.parametrize("path", [
        "/tools/subnet/info", "/tools/acl/analyze", "/tools/config/parse",
        "/tools/config-drift/compare", "/generate/snmpv3",
    ])
    def test_chunked_1_mb_without_content_length_is_413(self, path):
        r = client.post(path, content=_chunks(ONE_MB), headers=JSON_HEADERS)
        assert "content-length" not in r.request.headers
        assert r.status_code == 413, r.text[:200]

    def test_short_form_limit_is_the_default(self):
        over = b"x" * (bl.DEFAULT_MAX + 1)
        assert client.post("/tools/subnet/info", content=over, headers=JSON_HEADERS).status_code == 413
        at = b"x" * bl.DEFAULT_MAX
        assert client.post("/tools/subnet/info", content=at, headers=JSON_HEADERS).status_code == 422

    @pytest.mark.parametrize("path", sorted(bl.PASTE_PATHS))
    def test_paste_limit_boundary(self, path):
        over = b"x" * (bl.PASTE_MAX + 1)
        assert client.post(path, content=over, headers=JSON_HEADERS).status_code == 413
        at = b"x" * bl.PASTE_MAX
        assert client.post(path, content=at, headers=JSON_HEADERS).status_code == 422

    def test_paste_limit_is_under_1_mb(self):
        assert bl.DEFAULT_MAX < bl.PASTE_MAX < ONE_MB

    def test_every_paste_limit_path_is_a_post_route(self):
        assert bl.PASTE_PATHS <= set(_post_routes())

    def test_413_is_rejected_before_the_body_is_read(self):
        async def never_receive():
            raise AssertionError("the body was read")

        sent = []

        async def send(message):
            sent.append(message)

        async def downstream(scope, receive, send):
            raise AssertionError("the request reached the application")

        scope = {"type": "http", "method": "POST", "path": "/tools/subnet/info",
                 "headers": [(b"content-length", b"1000000")]}
        asyncio.run(bl.BodyLimitMiddleware(downstream)(scope, never_receive, send))
        assert sent[0]["status"] == 413

    def test_413_carries_the_cors_header(self):
        r = client.post("/tools/subnet/info", content=b"x" * ONE_MB,
                        headers={**JSON_HEADERS, "Origin": "https://netdevops.thebackroom.ai"})
        assert r.status_code == 413
        assert "access-control-allow-origin" in r.headers

    def test_oversized_requests_count_against_the_sender(self, monkeypatch):
        monkeypatch.setattr(rl, "ENABLED", True)
        monkeypatch.setattr(rl, "limiter", rl.SlidingWindowLimiter())
        headers = {**JSON_HEADERS, "X-Forwarded-For": "70.0.0.9, 172.71.0.1"}
        for _ in range(60):
            assert client.post("/tools/subnet/info", content=b"x" * ONE_MB,
                               headers=headers).status_code == 413
        assert client.post("/tools/subnet/info", content=b"x" * ONE_MB,
                           headers=headers).status_code == 429

    def test_get_is_not_affected(self):
        assert client.get("/meta/version").status_code == 200

    def test_bad_content_length_falls_back_to_counting(self):
        async def run():
            seen = []

            async def receive():
                return {"type": "http.request", "body": b"abc", "more_body": False}

            async def downstream(scope, receive, send):
                seen.append(await receive())

            scope = {"type": "http", "method": "POST", "path": "/x",
                     "headers": [(b"content-length", b"not-a-number")]}
            await bl.BodyLimitMiddleware(downstream)(scope, receive, None)
            return seen
        assert asyncio.run(run())[0]["body"] == b"abc"


# Generated, sized like real output of one 48-port access switch per stack member.
_RUN_PORT = """interface GigabitEthernet{s}/0/{p}
 description USER-ACCESS-FLOOR{s}-PORT{p}
 switchport access vlan 110
 switchport mode access
 switchport voice vlan 210
 switchport port-security maximum 3
 switchport port-security violation restrict
 switchport port-security
 authentication event fail action next-method
 authentication event server dead action authorize vlan 110
 authentication host-mode multi-domain
 authentication open
 authentication order dot1x mab
 authentication priority dot1x mab
 authentication port-control auto
 authentication periodic
 authentication timer reauthenticate server
 mab
 dot1x pae authenticator
 spanning-tree portfast
 spanning-tree bpduguard enable
 service-policy input POLICY-ACCESS-IN
 service-policy output POLICY-ACCESS-OUT
 ip dhcp snooping limit rate 15
!
"""
_SHOW_INT_PORT = """GigabitEthernet{s}/0/{p} is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is 00a3.8e11.{p:04x} (bia 00a3.8e11.{p:04x})
  Description: USER-ACCESS-FLOOR{s}-PORT{p}
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)
  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX
  input flow-control is on, output flow-control is unsupported
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input 00:00:02, output 00:00:00, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: Class-based queueing
  Output queue: 0/40 (size/max)
  5 minute input rate 2000 bits/sec, 2 packets/sec
  5 minute output rate 12000 bits/sec, 9 packets/sec
     12345678 packets input, 1234567890 bytes, 0 no buffer
     Received 123456 broadcasts (98765 multicasts)
     0 runts, 0 giants, 0 throttles
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 watchdog, 98765 multicast, 0 pause input
     0 input packets with dribble condition detected
     87654321 packets output, 9876543210 bytes, 0 underruns
     0 output errors, 0 collisions, 1 interface resets
     0 unknown protocol drops
     0 babbles, 0 late collision, 0 deferred
     0 lost carrier, 0 no carrier, 0 pause output
     0 output buffer failures, 0 output buffers swapped out
"""
_STATUS_PORT = "Gi{s}/0/{p}    USER-ACCESS-{p:<10}connected    110        a-full a-1000 10/100/1000BaseTX\n"


def _stack(members, template):
    return "".join(template.format(s=s, p=p) for s in range(1, members + 1) for p in range(1, 49))


class TestLargestRealPastesFit:
    """DONE (d): legal pastes stay inside the limit. Sized for a stack of nine 48-port members."""

    MEMBERS = 9
    RUN = "hostname STACK\n!\n" + _stack(MEMBERS, _RUN_PORT)

    @pytest.mark.parametrize("path", [
        "/tools/hardening-audit/check", "/tools/config/parse",
        "/tools/config/parse/summary", "/tools/config-explainer/explain",
    ])
    def test_one_full_config(self, path):
        assert client.post(path, json={"config_text": self.RUN}).status_code == 200

    def test_config_drift_takes_two_full_configs(self):
        other = self.RUN.replace("voice vlan 210", "voice vlan 211")
        r = client.post("/tools/config-drift/compare", json={"config_a": self.RUN, "config_b": other})
        assert r.status_code == 200
        assert len(r.request.content) > bl.DEFAULT_MAX  # a flat 256 KB would refuse it

    def test_port_auditor_takes_show_interfaces_of_the_whole_stack(self):
        r = client.post("/tools/port-auditor/analyze", json={
            "interface_status": _stack(self.MEMBERS, _STATUS_PORT),
            "interface_detail": _stack(self.MEMBERS, _SHOW_INT_PORT)})
        assert r.status_code == 200
        assert r.json()["total_ports"] == self.MEMBERS * 48
        assert len(r.request.content) > bl.DEFAULT_MAX  # a flat 256 KB would refuse it

    def test_acl_500_rules_fit(self):
        paste = "ip access-list extended E\n" + "".join(
            " %d permit tcp 10.%d.0.0 0.0.255.255 any eq 443\n" % (10 * i, i % 250) for i in range(1, 501))
        assert client.post("/tools/acl/analyze", json={"config_text": paste}).status_code == 200

    def test_acl_over_its_character_limit_gets_the_tool_message(self):
        # 100 001 characters fit the body limit, so the answer is ACL's own sentence.
        r = client.post("/tools/acl/analyze", json={"config_text": "!" * 100_001})
        assert r.status_code == 413
        assert "Paste too large" in r.json()["detail"]

    def test_chunked_request_under_the_limit_works(self):
        body = b'{"config_text": "hostname R1"}'
        r = client.post("/tools/config/parse", content=iter([body[:10], body[10:]]), headers=JSON_HEADERS)
        assert "content-length" not in r.request.headers
        assert r.status_code == 200
