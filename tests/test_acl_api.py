"""
ACL-01.3: POST /tools/acl/analyze + auto-packets (services/acl_packets.py).

Acceptance from the ACL-01 backlog entry (CEO repo projects/netdevops/backlog.md)
and spec_acl-01_v0_2026-10-22.md sections 4-5:
- trace deterministic and in line with a manual reading on 10 packets
  (TestTenPackets: every expected verdict below was worked out by hand from the
  ACL text, the reasoning is in each case's comment);
- auto-packets from rule edges (exact port, port +/- 1, address on the wildcard
  boundary, first address outside it), at most 10 per ACL;
- response time < 200 ms for an ACL of up to 500 lines;
- untrusted input: size caps before the lint, no input echoed in errors,
  short error sentences, no stack trace.
"""

import json
import statistics
import time

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.routers import acl as acl_router
from services.acl_engine import Packet, parse_acls, trace
from services.acl_packets import MAX_PACKETS_PER_ACL, auto_packets

client = TestClient(app)
URL = "/tools/acl/analyze"


def _post(text, **extra):
    body = {"config_text": text}
    body.update(extra)
    return client.post(URL, json=body)


# Effective order (sequence numbers, Q2): lines 3, 4, 5, 6, 8 (seq 50), 7 (seq 60), 9, 10, 11.
# Line 7 is written before line 8 but has the higher seq, so it is checked after it.
# No explicit final deny: whatever passes line 11 hits the implicit deny.
EDGE_IN = """ip access-list extended EDGE-IN
 remark SSH only from the management /24
 10 permit tcp 10.1.1.0 0.0.0.255 host 192.0.2.10 eq 22
 20 deny tcp any host 192.0.2.10 eq 22 log
 30 permit tcp any host 192.0.2.20 range 8080 8090
 40 permit tcp any 192.0.2.0 0.0.0.255 established
 60 permit udp 10.0.0.0 0.0.255.0 any eq snmp
 50 permit udp any host 192.0.2.53 eq domain
 70 deny tcp any any neq 443
 80 permit icmp any any
 90 permit 47 host 198.51.100.1 host 192.0.2.1
"""
ORDER = [3, 4, 5, 6, 8, 7, 9, 10, 11]


def _pkt(src, dst, protocol, sport=None, dport=None, established=False):
    return {"acl": "EDGE-IN", "src": src, "dst": dst, "protocol": protocol,
            "src_port": sport, "dst_port": dport, "established": established}


# (id, packet, verdict, matched_line, path lines checked in order, {line: reason fragment})
TEN_PACKETS = [
    # P1: 10.1.1.77 is inside 10.1.1.0 0.0.0.255, dst is the host, port 22 = eq 22
    # -> the very first rule (line 3) permits.
    ("P1 mgmt SSH", _pkt("10.1.1.77", "192.0.2.10", "tcp", 50000, 22),
     "permit", 3, [3], {}),
    # P2: 10.1.2.1 is one /24 above the management block, so line 3 fails on src;
    # line 4 (tcp any -> host 192.0.2.10 eq 22) matches -> deny.
    ("P2 SSH from outside mgmt", _pkt("10.1.2.1", "192.0.2.10", "tcp", 50000, 22),
     "deny", 4, [3, 4], {3: "src 10.1.2.1 ∉ 10.1.1.0 0.0.0.255"}),
    # P3: 8090 is the top edge of range 8080 8090 (inclusive). Line 3 fails on src,
    # line 4 on dst (192.0.2.20 is not host 192.0.2.10), line 5 matches -> permit.
    ("P3 range top edge", _pkt("203.0.113.5", "192.0.2.20", "tcp", 40000, 8090),
     "permit", 5, [3, 4, 5], {4: "dst 192.0.2.20 ∉ host 192.0.2.10"}),
    # P4: 8091 = first port above the range, line 5 fails on dst port. Line 6 needs
    # established, the packet is a new session. Lines 8 and 7 are udp. Line 9
    # (deny tcp any any neq 443): 8091 != 443 -> deny on line 9.
    ("P4 range top + 1", _pkt("203.0.113.5", "192.0.2.20", "tcp", 40000, 8091),
     "deny", 9, [3, 4, 5, 6, 8, 7, 9],
     {5: "dst port 8091 ∉ range 8080 8090", 6: "established ∉ packet", 8: "protocol tcp ∉ udp"}),
    # P5: return traffic of an established session to 192.0.2.99 (inside 192.0.2.0/24).
    # Lines 3-5 fail (src, dst, dst), line 6 matches -> permit.
    ("P5 established return", _pkt("203.0.113.5", "192.0.2.99", "tcp", 443, 51000, True),
     "permit", 6, [3, 4, 5, 6], {}),
    # P6: udp to 192.0.2.53 port 161. Seq 50 (line 8) is checked BEFORE seq 60 (line 7):
    # line 8 fails on dst port (161 is not domain/53). Line 7: 10.0.7.0 has last
    # octet 0, inside the non-contiguous 10.0.0.0 0.0.255.0 (= 10.0.*.0); snmp = 161
    # -> permit on line 7.
    ("P6 seq order + non-contiguous wildcard", _pkt("10.0.7.0", "192.0.2.53", "udp", 50000, 161),
     "permit", 7, [3, 4, 5, 6, 8, 7], {8: "dst port 161 ∉ eq domain"}),
    # P7: same as P6 from 10.0.7.1: last octet 1 is a fixed bit of the wildcard,
    # so line 7 fails on src. Lines 9-11 are tcp/icmp/47 -> no match -> implicit deny.
    ("P7 outside non-contiguous wildcard", _pkt("10.0.7.1", "192.0.2.53", "udp", 50000, 161),
     None, None, ORDER, {7: "src 10.0.7.1 ∉ 10.0.0.0 0.0.255.0"}),
    # P8: DNS query: lines 3-6 are tcp (protocol mismatch), line 8 (seq 50) matches -> permit.
    ("P8 DNS seq 50", _pkt("198.51.100.9", "192.0.2.53", "udp", 50000, 53),
     "permit", 8, [3, 4, 5, 6, 8], {3: "protocol udp ∉ tcp"}),
    # P9: new TCP session to 192.0.2.30:443. Line 6 fails on established, line 9
    # (neq 443) does NOT match 443, lines 10 and 11 are other protocols -> implicit deny.
    ("P9 neq edge", _pkt("203.0.113.5", "192.0.2.30", "tcp", 40000, 443),
     None, None, ORDER, {9: "dst port 443 ∉ neq 443"}),
    # P10: GRE (protocol 47) between the two hosts: every tcp/udp/icmp rule fails on
    # protocol, line 11 (permit 47 host -> host) matches -> permit.
    ("P10 protocol number", _pkt("198.51.100.1", "192.0.2.1", 47),
     "permit", 11, ORDER, {10: "protocol 47 ∉ icmp"}),
]


class TestTenPackets:
    @pytest.mark.parametrize("case", TEN_PACKETS, ids=[c[0] for c in TEN_PACKETS])
    def test_manual_reading(self, case):
        _, packet, verdict, matched, lines, reasons = case
        r = _post(EDGE_IN, trace=packet, auto_packets=False)
        assert r.status_code == 200, r.text
        t = r.json()["trace"]
        assert t["acl"] == "EDGE-IN"
        if verdict is None:
            assert (t["verdict"], t["matched_line"], t["implicit_deny"]) == ("deny", None, True)
        else:
            assert (t["verdict"], t["matched_line"], t["implicit_deny"]) == (verdict, matched, False)
        assert [p["line"] for p in t["path"]] == lines
        assert [p["matched"] for p in t["path"]] == [False] * (len(lines) - 1) + [verdict is not None]
        by_line = {p["line"]: p["reason"] for p in t["path"]}
        for line, fragment in reasons.items():
            assert fragment in by_line[line]
        assert t["unevaluated_lines"] == []

    def test_deterministic(self):
        body = {"config_text": EDGE_IN, "trace": TEN_PACKETS[3][1]}
        first = client.post(URL, json=body)
        second = client.post(URL, json=body)
        assert first.content == second.content


class TestContract:
    def test_response_shape(self):
        r = _post(EDGE_IN)
        assert r.status_code == 200
        b = r.json()
        assert set(b) == {"engine", "acls", "lint", "auto_packets", "trace"}
        assert b["engine"] == "acl-01.3"
        assert b["acls"] == [{"acl": "EDGE-IN", "type": "extended", "forms": ["named"],
                              "rules": 9, "evaluated_rules": 9}]
        assert b["lint"]["engine"] == "acl-01.2"
        assert b["trace"] is None
        assert [a["acl"] for a in b["auto_packets"]] == ["EDGE-IN"]

    def test_lint_is_the_library_result(self):
        b = _post(EDGE_IN).json()
        from services.acl_lint import lint
        assert b["lint"] == json.loads(json.dumps(lint(parse_acls(EDGE_IN))))

    def test_auto_packets_off(self):
        assert _post(EDGE_IN, auto_packets=False).json()["auto_packets"] == []

    def test_trace_without_name_on_single_acl(self):
        r = _post("access-list 10 permit 10.2.0.0 0.0.255.255\n", trace={"src": "10.2.3.4"})
        t = r.json()["trace"]
        assert (t["acl"], t["verdict"], t["matched_line"]) == ("10", "permit", 1)

    def test_not_evaluated_line_is_reported_in_trace(self):
        text = ("ip access-list extended X\n"
                " 10 permit tcp any object-group WEB eq 80\n"
                " 20 deny ip any any log\n")
        t = _post(text, trace={"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "tcp",
                               "src_port": 1, "dst_port": 80}).json()["trace"]
        assert t["unevaluated_lines"] == [2]
        assert (t["verdict"], t["matched_line"]) == ("deny", 3)

    def test_paste_without_ipv4_acl(self):
        r = _post("ipv6 access-list V6\n permit ipv6 any any\n")
        assert r.status_code == 200
        b = r.json()
        assert b["acls"] == [] and b["auto_packets"] == []
        assert len(b["lint"]["not_evaluated"]) == 2

    def test_openapi_lists_endpoint(self):
        assert URL in client.get("/openapi.json").json()["paths"]


class TestAutoPackets:
    SHADOW = ("ip access-list extended T\n"
              " 10 permit tcp 10.1.1.0 0.0.0.255 host 192.0.2.10 eq 22\n"
              " 20 deny tcp 10.1.1.0 0.0.0.255 host 192.0.2.10 eq 22\n"
              " 30 deny ip any any log\n")

    def test_edges_of_a_small_acl(self):
        # Hand-built expectation. Round 1 = hit of each rule (line 3's hit equals
        # line 2's, so no new row), then dst port +1, src outside, dst outside,
        # src last address, dst port -1. Line 4 (ip any any) has only its hit.
        rows = _post(self.SHADOW).json()["auto_packets"][0]["packets"]
        got = [(r["from_line"], r["edge"], r["packet"]["src"], r["packet"]["dst"],
                r["packet"]["dst_port"], r["verdict"], r["matched_line"]) for r in rows]
        assert got == [
            (2, "hit", "10.1.1.0", "192.0.2.10", 22, "permit", 2),
            (4, "hit", "198.51.100.10", "203.0.113.10", 443, "deny", 4),
            (2, "dst_port_above", "10.1.1.0", "192.0.2.10", 23, "deny", 4),
            (2, "src_outside", "10.1.2.0", "192.0.2.10", 22, "deny", 4),
            (2, "dst_outside", "10.1.1.0", "192.0.2.11", 22, "deny", 4),
            (2, "src_last", "10.1.1.255", "192.0.2.10", 22, "permit", 2),
            (2, "dst_port_below", "10.1.1.0", "192.0.2.10", 21, "deny", 4),
        ]

    def test_shadowed_rule_is_linked_to_the_row(self):
        # The hit packet built for line 3 is line 2's packet and lands on line 2:
        # the row says so, which shows the shadowing (L01) without reading the lint.
        rows = _post(self.SHADOW).json()["auto_packets"][0]["packets"]
        assert {"line": 3, "edge": "hit", "relation": "inside"} in rows[0]["also_built_for"]
        assert rows[0]["matched_line"] == 2

    def test_standard_acl(self):
        rows = _post("access-list 10 permit 10.2.0.0 0.0.255.255\n").json()["auto_packets"][0]["packets"]
        assert [(r["edge"], r["packet"]["src"], r["verdict"], r["implicit_deny"]) for r in rows] == [
            ("hit", "10.2.0.0", "permit", False),
            ("src_outside", "10.3.0.0", "deny", True),
            ("src_last", "10.2.255.255", "permit", False),
        ]
        assert rows[0]["packet"]["dst"] is None and rows[0]["packet"]["protocol"] is None

    def test_established_rule_gets_a_new_session_packet(self):
        text = "ip access-list extended E\n permit tcp any eq 443 any established\n"
        rows = _post(text).json()["auto_packets"][0]["packets"]
        by_edge = {r["edge"]: r for r in rows}
        assert by_edge["hit"]["packet"]["established"] is True
        assert by_edge["hit"]["packet"]["src_port"] == 443
        assert by_edge["not_established"]["packet"]["established"] is False
        assert by_edge["not_established"]["implicit_deny"] is True

    def test_at_most_ten_and_consistent_with_trace(self):
        parsed = parse_acls(EDGE_IN)
        rows = auto_packets(parsed)[0]["packets"]
        assert 5 <= len(rows) <= MAX_PACKETS_PER_ACL
        for row in rows:
            t = trace(parsed, "EDGE-IN", Packet(**row["packet"]))
            assert (row["verdict"], row["matched_line"], row["implicit_deny"]) == \
                (t["verdict"], t["matched_line"], t["implicit_deny"])
        keys = [json.dumps(r["packet"], sort_keys=True) for r in rows]
        assert len(keys) == len(set(keys))

    def test_relation_holds(self):
        # A packet marked "inside" its source rule is matched by that rule when
        # traced against that rule alone; "outside" is not.
        parsed = parse_acls(EDGE_IN)
        lines = {e.line: e for e in parsed.acls["EDGE-IN"].entries}
        for row in auto_packets(parsed)[0]["packets"]:
            single = parse_acls("ip access-list extended S\n" + " " + lines[row["from_line"]].text + "\n")
            t = trace(single, "S", Packet(**row["packet"]))
            assert (t["matched_line"] is not None) == (row["relation"] == "inside"), row


class TestLimitsAndErrors:
    def test_too_many_characters(self):
        text = "!" * (acl_router.MAX_CHARS + 1)
        r = _post(text)
        assert r.status_code == 413
        assert "!!!!" not in r.text  # the paste is not echoed back

    def test_too_many_lines(self):
        r = _post("!\n" * (acl_router.MAX_LINES + 1))
        assert r.status_code == 413
        assert r.json()["detail"] == "Paste too large: at most %d lines." % acl_router.MAX_LINES

    def test_lines_counted_like_the_parser(self):
        # \r alone also ends a line for str.splitlines(), which the parser uses.
        r = _post("access-list 1 permit 10.0.0.1\r" * (acl_router.MAX_LINES + 1))
        assert r.status_code == 413

    def test_trailing_newline_is_not_an_extra_line(self):
        text = "access-list 1 permit 10.0.0.1\n" + "!\n" * (acl_router.MAX_LINES - 1)
        assert _post(text).status_code == 200

    def test_too_many_rules(self):
        text = "".join("access-list 1 permit 10.0.%d.%d\n" % divmod(i, 250)
                       for i in range(acl_router.MAX_RULES + 1))
        r = _post(text)
        assert r.status_code == 413
        assert "at most %d" % acl_router.MAX_RULES in r.json()["detail"]

    def test_rule_cap_is_inclusive(self):
        text = "".join("access-list 1 permit 10.0.%d.%d\n" % divmod(i, 250)
                       for i in range(acl_router.MAX_RULES))
        assert _post(text).status_code == 200

    def test_empty_paste(self):
        r = _post("   \n  ")
        assert r.status_code == 422
        assert r.json() == {"detail": "Paste at least one ACL."}

    def test_trace_needs_acl_name_when_several(self):
        r = _post(EDGE_IN + "access-list 10 permit any\n", trace={"src": "10.0.0.1"})
        assert r.status_code == 422
        assert "holds 2 ACLs" in r.json()["detail"]

    def test_unknown_acl_is_not_echoed(self):
        r = _post(EDGE_IN, trace={"acl": "<script>x</script>", "src": "10.0.0.1"})
        assert r.status_code == 422
        assert "script" not in r.text

    @pytest.mark.parametrize("packet, fragment", [
        ({"src": "10.0.0.1"}, "needs a valid dst"),
        ({"src": "10.0.0.1", "dst": "10.0.0.2"}, "needs a protocol"),
        ({"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "tcp"}, "src port is required"),
        ({"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "gre"}, "must be tcp, udp, icmp"),
        ({"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "udp", "src_port": 1, "dst_port": 2,
          "established": True}, "established applies only to tcp"),
        ({"src": "999.0.0.1", "dst": "10.0.0.2", "protocol": 47}, "invalid src"),
    ])
    def test_invalid_packet(self, packet, fragment):
        r = _post(EDGE_IN, trace=dict(packet, acl="EDGE-IN"))
        assert r.status_code == 422
        detail = r.json()["detail"]
        assert detail.startswith("Invalid packet: ") and fragment in detail
        assert "Traceback" not in r.text

    def test_overlong_fields_rejected_by_schema(self):
        r = _post(EDGE_IN, trace={"acl": "A" * 65, "src": "10.0.0.1"})
        assert r.status_code == 422
        r = _post(EDGE_IN, trace={"acl": "EDGE-IN", "src": "10.0.0.1", "dst": "10.0.0.2",
                                  "protocol": "tcp", "src_port": 70000, "dst_port": 1})
        assert r.status_code == 422

    def test_hostile_text_is_data(self):
        text = ("access-list 10 permit __import__('os').system('id')\n"
                "access-list 110 permit tcp any any eq ${jndi:ldap://x}\n"
                "access-list 120 permit tcp any any eq 22 {{7*7}}\n")
        r = _post(text)
        assert r.status_code == 200
        b = r.json()
        assert b["acls"][0]["evaluated_rules"] == 0
        assert "49" not in json.dumps(b["lint"])


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class TestRateLimit:
    """@ciso W1 (2026-10-28): 10/min and 120/h per IP on top of the POST default."""

    HEADERS = {"X-Forwarded-For": "70.0.0.9, 172.71.0.1"}
    OK = {"config_text": "access-list 1 permit any\n"}

    @pytest.fixture
    def clock(self, monkeypatch):
        from api import rate_limit as rl
        c = _Clock()
        monkeypatch.setattr(rl, "ENABLED", True)
        monkeypatch.setattr(rl, "limiter", rl.SlidingWindowLimiter(clock=c))
        return c

    def test_path_limit_line(self):
        from api import rate_limit as rl
        assert rl.PATH_LIMITS[URL] == ((10, 60), (120, 3600))

    def test_eleventh_in_a_minute_is_429_other_tool_still_200(self, clock):
        from api import rate_limit as rl
        codes = [client.post(URL, json=self.OK, headers=self.HEADERS).status_code for _ in range(11)]
        assert codes == [200] * 10 + [429]
        r = client.post(URL, json=self.OK, headers=self.HEADERS)
        assert r.status_code == 429
        assert r.json() == {"detail": rl.LIMIT_MESSAGE}
        assert r.headers["retry-after"] == "60"
        # Same IP, another tool: only the ACL path is throttled.
        other = client.post("/tools/subnet/info", json={"ip_cidr": "10.0.0.0/24"}, headers=self.HEADERS)
        assert other.status_code == 200
        # Another IP is not affected.
        assert client.post(URL, json=self.OK,
                           headers={"X-Forwarded-For": "70.0.0.10, 172.71.0.1"}).status_code == 200

    def test_hourly_cap(self, clock):
        for minute in range(12):
            for _ in range(10):
                assert client.post(URL, json=self.OK, headers=self.HEADERS).status_code == 200
            clock.t += 61
        r = client.post(URL, json=self.OK, headers=self.HEADERS)
        assert r.status_code == 429
        assert r.headers["retry-after"] == "3600"


class TestConcurrency:
    """@ciso W2 (2026-10-28): at most MAX_CONCURRENT analyses at once, no queue."""

    def _blocking_parser(self, monkeypatch):
        import threading
        entered = threading.Semaphore(0)
        release = threading.Event()
        real = acl_router.parse_acls

        def slow_parse(text):
            entered.release()
            assert release.wait(10)
            return real(text)

        monkeypatch.setattr(acl_router, "parse_acls", slow_parse)
        return entered, release

    def test_third_parallel_request_is_refused(self, monkeypatch):
        import threading
        assert acl_router.MAX_CONCURRENT == 2
        entered, release = self._blocking_parser(monkeypatch)
        results = []

        def worker():
            results.append(_post("access-list 1 permit any\n").status_code)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        try:
            for _ in range(2):
                assert entered.acquire(timeout=10)  # both slots taken, both parked in the parser
            r = _post("access-list 1 permit any\n")
            assert r.status_code == 503
            assert r.json() == {"detail": acl_router.BUSY_MESSAGE}
            assert r.headers["retry-after"] == str(acl_router.BUSY_RETRY_AFTER)
        finally:
            release.set()
            for t in threads:
                t.join(10)
        assert results == [200, 200]
        assert acl_router._slots._value == acl_router.MAX_CONCURRENT
        assert _post("access-list 1 permit any\n").status_code == 200

    def test_slot_released_on_413_and_422(self):
        too_many_lines = "!\n" * (acl_router.MAX_LINES + 1)
        too_many_rules = "".join("access-list 1 permit 10.0.%d.%d\n" % divmod(i, 250)
                                 for i in range(acl_router.MAX_RULES + 1))
        for _ in range(acl_router.MAX_CONCURRENT + 1):
            assert _post(too_many_lines).status_code == 413
            assert _post(too_many_rules).status_code == 413
            assert _post("   ").status_code == 422
            assert _post(EDGE_IN, trace={"acl": "NOPE", "src": "10.0.0.1"}).status_code == 422
        assert acl_router._slots._value == acl_router.MAX_CONCURRENT
        assert _post("access-list 1 permit any\n").status_code == 200

    def test_slot_released_on_unexpected_error(self, monkeypatch):
        def boom(text):
            raise RuntimeError("x")

        monkeypatch.setattr(acl_router, "parse_acls", boom)
        for _ in range(acl_router.MAX_CONCURRENT + 1):
            with pytest.raises(RuntimeError):
                _post("access-list 1 permit any\n")
        assert acl_router._slots._value == acl_router.MAX_CONCURRENT


def _many_acls(n_acls, per, rule, name_len=3):
    out = []
    for a in range(n_acls):
        out.append("ip access-list extended %s" % (("N%02d" % a) + "X" * (name_len - 3)))
        out += [" " + rule(a, r) for r in range(per)]
    return "\n".join(out) + "\n"


# Hostile shapes measured 2026-10-28 (@ciso W3): alternating actions on overlapping
# rules maximise lint findings, `established` and ranges maximise auto-packets.
_WORST_RULES = {
    "neq_established": lambda a, r: "%s tcp any neq %d any neq %d established" % (
        "permit" if r % 2 else "deny", 5 + r, 7 + r),
    "range_overlap": lambda a, r: "%s tcp any any range %d %d established" % (
        "permit" if r % 2 else "deny", 1000 + r, 60000 - r),
    "same_host_alt": lambda a, r: "%s tcp host 10.0.0.1 eq %d any eq 22 established log" % (
        "permit" if r % 2 else "deny", 1000 + r),
    "shadow_chain": lambda a, r: "permit tcp any any established" if r == 0 else
        "permit tcp host 10.%d.%d.1 eq %d host 192.0.2.%d eq %d established log" % (
            a % 250, r % 250, 100 + r, r % 250, 2000 + r),
}


class TestResponseSize:
    """@ciso W3 (2026-10-28): MAX_ACLS next to MAX_RULES, response <= 300 KB."""

    def test_too_many_acls(self):
        text = "".join("access-list %d permit any\n" % n for n in range(1, acl_router.MAX_ACLS + 2))
        r = _post(text)
        assert r.status_code == 413
        assert r.json() == {"detail": "Too many ACLs: at most %d per request (the paste has %d)."
                                      % (acl_router.MAX_ACLS, acl_router.MAX_ACLS + 1)}

    def test_acl_cap_is_inclusive(self):
        text = "".join("access-list %d permit any\n" % n for n in range(1, acl_router.MAX_ACLS + 1))
        r = _post(text)
        assert r.status_code == 200
        assert len(r.json()["acls"]) == acl_router.MAX_ACLS

    def test_acl_cap_checked_before_lint(self, monkeypatch):
        monkeypatch.setattr(acl_router, "lint", lambda parsed: pytest.fail("lint ran"))
        text = "".join("access-list %d permit any\n" % n for n in range(1, acl_router.MAX_ACLS + 2))
        assert _post(text).status_code == 413

    @pytest.mark.parametrize("shape", sorted(_WORST_RULES))
    @pytest.mark.parametrize("layout", [(1, 500), (10, 50), (50, 10)])
    @pytest.mark.parametrize("name_len", [3, 64, 1000])
    def test_worst_paste_in_limits_stays_under_300_kb(self, shape, layout, name_len):
        n_acls, per = layout
        text = _many_acls(n_acls, per, _WORST_RULES[shape], name_len)
        if len(text) > acl_router.MAX_CHARS:
            pytest.skip("outside the character limit")
        r = _post(text)
        assert r.status_code in (200, 413)
        assert len(r.content) <= acl_router.MAX_RESPONSE_BYTES == 300_000
        if r.status_code == 413:
            assert r.json() == {"detail": "Result too large: split the paste into fewer "
                                          "ACLs or rules per request."}

    def test_ciso_example_50_long_named_established_acls(self):
        # @ciso's example: 50 ACLs with long names and `established` (was 1.09 MB at 500 ACLs).
        text = _many_acls(50, 1, lambda a, r: "permit tcp any any eq 22 established", name_len=1000)
        r = _post(text)
        assert r.status_code == 200
        assert len(r.content) <= 300_000

    def test_largest_accepted_response_is_valid_json(self):
        text = _many_acls(10, 50, _WORST_RULES["neq_established"], name_len=1000)
        r = _post(text)
        assert r.status_code == 200
        assert 200_000 < len(r.content) <= 300_000
        assert r.headers["content-type"] == "application/json"
        assert r.json()["engine"] == acl_router.ENGINE_VERSION


def _typical_acl(n_lines):
    """A realistic mix: tcp/udp with ports, ip, icmp, /24 sources, host targets, final logged deny."""
    out = ["ip access-list extended EDGE-IN"]
    for i in range(n_lines - 2):
        a, b = divmod(i, 250)
        proto = ("tcp", "udp", "ip", "icmp")[i % 4]
        port = " eq %d" % (1000 + i) if proto in ("tcp", "udp") else ""
        out.append(" %d %s %s 10.%d.%d.0 0.0.0.255 host 192.0.2.%d%s"
                   % ((i + 1) * 10, "permit" if i % 3 else "deny", proto, a, b, i % 250, port))
    out.append(" %d deny ip any any log" % ((n_lines - 1) * 10))
    return "\n".join(out) + "\n"


class TestTiming:
    def test_500_line_acl_under_200_ms(self):
        """Spec section 5: < 200 ms for an ACL of up to 500 lines (median of 5, full request)."""
        text = _typical_acl(500)
        body = {"config_text": text, "trace": {"src": "10.0.1.5", "dst": "192.0.2.9", "protocol": "tcp",
                                               "src_port": 50000, "dst_port": 1009}}
        assert client.post(URL, json=body).status_code == 200  # warm-up
        times = []
        for _ in range(5):
            start = time.perf_counter()
            r = client.post(URL, json=body)
            times.append((time.perf_counter() - start) * 1000)
            assert r.status_code == 200
        assert statistics.median(times) < 200, times
