"""
WEBSEC-01 (e), (f) and the limits around them (@ciso W9, W10, W11, W12).

(e) one small request must not hold the process: regexes on pasted text stay linear.
(f) `interface range` expansion has one budget per request.
W11: paste endpoints have their own rate limit, Config Drift caps its response.
W12: the two remaining ACL messages quote at most 20 characters.

The oracles below are the regexes as they were before the fix. Rewritten code has
to give the same answer on real output and on random lines, slow patterns included,
so inputs for them stay short.

The `show interface status` sample is written from the documented IOS format, not
copied from a device.
"""
import json
import random
import re
import time
import tracemalloc
from collections import OrderedDict

import pytest
from fastapi.testclient import TestClient

from api import body_limit as bl
from api import rate_limit as rl
from api.main import app
from api.routers import cis_audit, config_drift as cd, ip_path_tracer, port_auditor as pa
from api.routers.config_drift import DriftRequest, compare_configs
from services.acl_engine import STATUS_NOT_EVALUATED, parse_acls

client = TestClient(app)

PORT_AUDITOR = "/tools/port-auditor/analyze"
DRIFT = "/tools/config-drift/compare"
HARDENING = "/tools/hardening-audit/check"
TRACER = "/tools/ip-path-tracer/analyze"
CVE = "/analyze/cve"

# Local runs take a few hundredths of a second; the DONE from @ciso is 1 s.
FAST = 1.0


def _timed_post(path, body):
    start = time.perf_counter()
    response = client.post(path, json=body)
    return response, time.perf_counter() - start


# ----------------------------
# (e) Port Auditor
# ----------------------------

OLD_STATUS_LINE_RE = re.compile(
    r"^(\S+)\s+"
    r"(.*?)\s+"
    r"(connected|notconnect|disabled|err-disabled|inactive|monitoring)\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"(\S+)\s*"
    r"(.*)$",
    re.IGNORECASE,
)
OLD_STATUS_SIMPLE_RE = re.compile(
    r"^(\S+)\s+.*?(connected|notconnect|disabled|err-disabled|inactive)\s",
    re.IGNORECASE,
)

SHOW_INTERFACE_STATUS = """\
SW-ACCESS-01#show interface status

Port         Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1      PC-ADMIN           connected    10         a-full a-1000 10/100/1000BaseTX
Gi1/0/2                         notconnect   1            auto   auto 10/100/1000BaseTX
Gi1/0/3      Printer 2nd floor  disabled     20           auto   auto 10/100/1000BaseTX
Gi1/0/4      AP-LOBBY           err-disabled 30           auto   auto 10/100/1000BaseTX
Gi1/0/5      not connected yet  notconnect   1            auto   auto 10/100/1000BaseTX
Gi1/0/6      TRUNK-TO-CORE      connected    trunk      a-full a-1000 10/100/1000BaseTX
Gi1/0/7      SPAN               monitoring   1          a-full a-1000 10/100/1000BaseTX
Gi1/0/8                         inactive     999          auto   auto 10/100/1000BaseTX
Te1/1/1      UPLINK             connected    trunk        full    10G SFP-10GBase-LR
Po1          LAG                connected    trunk      a-full a-1000
Vl1                             notconnect   routed       auto   auto
"""


def _old_parse(text):
    """What _parse_interface_status produced before the fix, as plain dicts."""
    ports = []
    for line in text.strip().splitlines():
        line = line.rstrip()
        if not line or line.startswith("-") or line.lower().startswith("port"):
            continue
        m = OLD_STATUS_LINE_RE.match(line)
        if m:
            ports.append(pa.PortInfo(
                interface=m.group(1), status=m.group(3).lower(), description=m.group(2).strip(),
                vlan=m.group(4), duplex=m.group(5), speed=m.group(6), type=m.group(7).strip(),
            ).model_dump())
        else:
            m2 = OLD_STATUS_SIMPLE_RE.match(line)
            if m2:
                ports.append(pa.PortInfo(interface=m2.group(1), status=m2.group(2).lower()).model_dump())
    return ports


def _new_parse(text):
    return [p.model_dump() for p in pa._parse_interface_status(text)]


class TestPortAuditorSameResult:
    def test_real_output_matches_the_old_parser(self):
        assert _new_parse(SHOW_INTERFACE_STATUS) == _old_parse(SHOW_INTERFACE_STATUS)

    def test_real_output_values(self):
        ports = {p["interface"]: p for p in _new_parse(SHOW_INTERFACE_STATUS)}
        assert len(ports) == 11
        assert ports["Gi1/0/1"]["description"] == "PC-ADMIN"
        assert ports["Gi1/0/1"]["status"] == "connected"
        assert ports["Gi1/0/1"]["vlan"] == "10"
        assert ports["Gi1/0/1"]["type"] == "10/100/1000BaseTX"
        assert ports["Gi1/0/2"]["description"] == ""
        assert ports["Gi1/0/3"]["description"] == "Printer 2nd floor"
        assert ports["Gi1/0/4"]["status"] == "err-disabled"
        # Known limit, unchanged: a status word inside a description wins.
        assert ports["Gi1/0/5"]["description"] == "not"
        assert ports["Gi1/0/5"]["status"] == "connected"
        assert ports["Po1"]["type"] == ""

    def test_endpoint_on_real_output(self):
        r = client.post(PORT_AUDITOR, json={"interface_status": SHOW_INTERFACE_STATUS})
        assert r.status_code == 200
        data = r.json()
        assert data["hostname"] == "SW-ACCESS-01"
        assert data["total_ports"] == 10  # uplink Te1/1/1 excluded
        assert sorted(p["interface"] for p in data["ports"]) == [
            "Gi1/0/2", "Gi1/0/3", "Gi1/0/4", "Vl1",
        ]

    @pytest.mark.parametrize("line", [
        "Gi1 connected 1 a-full a-1000 type",              # one space: only the fallback matches
        "Gi1  connected 1 a-full a-1000 type",             # two spaces: the full form
        "Gi1   connected 1 2 3 connected 4 5 6",           # second status wins when no description
        "Gi1  desc connected 1 2 3 connected 4 5 6",       # first status wins after a description
        "Gi1  connected 1 2",                              # too few columns
        "Gi1 disconnected 1 2 3",                          # substring: the fallback finds it
        "Gi1  disconnected 1 2 3",
        "Gi1  CONNECTED 1 2 3",
        "Gi1\t\tconnected\t1\t2\t3\ttype here",
        "Gi1",
        " Gi1  connected 1 2 3",
        "Gi1  monitoring 1 2 3",
        "Gi1 monitoring 1 2",
    ])
    def test_edge_lines_match_the_old_parser(self, line):
        assert _new_parse(line) == _old_parse(line)

    def test_random_lines_match_the_old_parser(self):
        rng = random.Random(20261102)
        words = ["Gi1/0/1", "connected", "notconnect", "disabled", "err-disabled", "inactive",
                 "monitoring", "disconnected", "1", "a-full", "auto", "x", "CONNECTED", "trunk"]
        gaps = [" ", "  ", "   ", "\t", " \t "]
        for _ in range(5000):
            line = ""
            for _ in range(rng.randint(1, 9)):
                line += rng.choice(words) + rng.choice(gaps)
            if rng.random() < 0.2:
                line = rng.choice(gaps) + line
            assert _new_parse(line) == _old_parse(line), repr(line)


class TestPortAuditorIsFast:
    def test_900_kb_line_of_spaces(self):
        r, took = _timed_post(PORT_AUDITOR, {"interface_status": "a" + " " * 900_000 + "x"})
        assert r.status_code == 200
        assert took < FAST

    def test_many_lines_just_under_the_line_limit(self):
        # The line limit alone would leave this at 0.8 s per line.
        line = "a" + " " * (pa.MAX_LINE_LENGTH - 2) + "x\n"
        r, took = _timed_post(PORT_AUDITOR, {"interface_status": line * 1700})
        assert r.status_code == 200
        assert took < FAST

    def test_line_over_the_limit_is_skipped(self):
        line = "Gi1  connected 1 a-full a-1000 "
        assert len(_new_parse(line + "x" * (pa.MAX_LINE_LENGTH - len(line)))) == 1
        assert _new_parse(line + "x" * pa.MAX_LINE_LENGTH) == []
        detail = "Gi1 is down\n  Last input never" + " " * pa.MAX_LINE_LENGTH
        assert pa._parse_interface_detail(detail + "x") == {}

    def test_long_last_input_of_digits(self):
        r, took = _timed_post(PORT_AUDITOR, {
            "interface_status": "Gi1  notconnect 1 a a\n",
            "interface_detail": "Gi1 is down\nLast input " + "1" * pa.MAX_LINE_LENGTH,
        })
        assert r.status_code == 200
        assert took < FAST

    def test_last_input_real_values_unchanged(self):
        assert pa._parse_last_input_to_days("never") == 9999
        assert pa._parse_last_input_to_days("00:00:01") == 0
        assert pa._parse_last_input_to_days("2d03h") == 2
        assert pa._parse_last_input_to_days("1y2w") == 379
        assert pa._parse_last_input_to_days("26w3d") == 185
        assert pa._parse_last_input_to_days("1" * (pa.MAX_LAST_INPUT_LENGTH + 1)) is None


# ----------------------------
# (e) Config Drift, Hardening Audit, Path Tracer, CVE
# ----------------------------

class TestDriftRegexes:
    def test_trailing_comment_matches_the_old_regex(self):
        rng = random.Random(20261102)
        old = lambda s: re.sub(r"\s+!.*$", "", s).rstrip()
        for line in ["cmd  ! note", "cmd ! a ! b", "cmd!x", "!x", " !x", "cmd", "", "a\t!b", "a!b !c", "  "]:
            assert cd._strip_trailing_comment(line) == old(line), repr(line)
        for _ in range(5000):
            line = "".join(rng.choice("ab! \t") for _ in range(rng.randint(0, 12)))
            assert cd._strip_trailing_comment(line) == old(line), repr(line)

    def test_line_with_a_long_run_of_spaces(self):
        r, took = _timed_post(DRIFT, {"config_a": "a" + " " * 900_000 + "x", "config_b": "abc"})
        assert r.status_code == 200
        assert took < FAST

    def test_range_part_of_digits(self):
        r, took = _timed_post(DRIFT, {"config_a": "interface range a" + "1" * 400_000 + "\n d\n",
                                      "config_b": "abc"})
        assert r.status_code == 200
        assert took < FAST


class TestHardeningWhitespace:
    @pytest.mark.parametrize("paste", [
        "aaa new-model\naaa authentication login a " + " " * 900_000 + "x",
        "aaa new-model\naaa authentication login a" + "\n" * 400_000 + "x",
        "line vty 0 4\n transport input a" + " " * 900_000 + "x",
        "aaa new-model\naaa authentication login a" + (" " * 32 + "x") * 20_000,
    ])
    def test_stays_fast(self, paste):
        r, took = _timed_post(HARDENING, {"config_text": paste})
        assert r.status_code == 200
        assert took < FAST

    def test_short_runs_are_untouched(self):
        cfg = "hostname R1\n\n\n" + " " * 20 + "\nline vty 0 4\n transport input ssh   \n" + "a" + " " * 32 + "b"
        assert cis_audit._WHITESPACE_RUN_RE.sub(cis_audit._squeeze_whitespace_run, cfg) == cfg

    def test_long_runs_keep_the_line_structure(self):
        squeeze = lambda s: cis_audit._WHITESPACE_RUN_RE.sub(cis_audit._squeeze_whitespace_run, s)
        assert squeeze("a" + " " * 40 + "b") == "a b"
        assert squeeze("a" + "\n" * 40 + " b") == "a\n b"
        assert squeeze("a" + "\n" * 40 + " " * 40 + "b") == "a\n b"

    def test_blank_lines_do_not_end_a_vty_block(self):
        cfg = "line vty 0 4" + "\n" * 40 + " transport input telnet\n"
        r = client.post(HARDENING, json={"config_text": cfg})
        rules = [rule for category in r.json()["categories"] for rule in category["rules"]]
        telnet = [c for c in rules if "Telnet permitted" in (c.get("evidence") or "")]
        assert telnet and telnet[0]["result"] == "FAIL"

    def test_log_host_matches_the_old_regex(self):
        old = re.compile(
            r"^\s*logging\s+(?:host\s+)?(?:vrf\s+\S+\s+)?"
            r"(?P<dest>\d+\.\d+\.\d+\.\d+"
            r"|[0-9a-fA-F:]+:[0-9a-fA-F:]*"
            r"|[A-Za-z][A-Za-z0-9_.\-]*)"
            r"(?:\s+transport\s+(?:tcp|udp)(?:\s+port\s+\d+)?)?\s*$",
            re.MULTILINE,
        )
        find = lambda rx, s: [m.group("dest") for m in rx.finditer(s)]
        real = ["logging host 10.1.1.1", "logging 10.1.1.1", "logging host 2001:db8::1 transport udp port 514",
                "logging host vrf MGMT syslog.example.com", "logging ::1", "logging a:", "logging :a", "logging ::",
                "logging abc", "logging buffered 64000", "logging host fe80::1 transport tcp"]
        for text in real:
            assert find(cis_audit.LOG_HOST_RE, text) == find(old, text), text
        rng = random.Random(20261102)
        for _ in range(5000):
            text = "logging " + "".join(rng.choice("a1:: .g") for _ in range(rng.randint(0, 9)))
            assert find(cis_audit.LOG_HOST_RE, text) == find(old, text), repr(text)

    def test_log_host_on_a_long_run_of_colons(self):
        r, took = _timed_post(HARDENING, {"config_text": "logging " + ":" * 900_000 + "\x01x"})
        assert r.status_code == 200
        assert took < FAST


class TestPathTracerRtt:
    def test_matches_the_old_regex(self):
        old = re.compile(r"([\d.]+)\s*(?:ms(?:ec)?|ms)")
        rng = random.Random(20261102)
        real = [
            "192.168.1.1 (192.168.1.1)  1.234 ms  0.987 ms  1.001 ms",
            "10.0.0.1 (10.0.0.1)  5.432 ms !H  * 6.789 ms",
            "<1 ms    <1 ms    <1 ms  192.168.1.1",
            "192.168.1.1 4 msec 4 msec 4 msec",
        ]
        for text in real:
            assert ip_path_tracer.RTT_RE.findall(text) == old.findall(text)
        for _ in range(5000):
            text = "".join(rng.choice(["1", ".", " ", "ms", "msec", "x"]) for _ in range(rng.randint(0, 10)))
            assert ip_path_tracer.RTT_RE.findall(text) == old.findall(text), repr(text)

    @pytest.mark.parametrize("fill", [".", "1", "1."])
    def test_long_run(self, fill):
        r, took = _timed_post(TRACER, {"traceroute_output": "1 " + fill * (200_000 // len(fill))})
        assert r.status_code == 200
        assert took < FAST


class TestCveVersionLength:
    @pytest.mark.parametrize("fill", ["1", " "])
    def test_long_version_is_refused_without_echo(self, fill):
        r, took = _timed_post(CVE, {"platform": "IOS XE", "version": "Version " + fill * 200_000})
        assert r.status_code == 400
        assert len(r.content) < 200
        assert took < FAST

    def test_show_version_line_still_accepted(self):
        from api.routers.cve import MAX_VERSION_LENGTH
        line = "Cisco IOS XE Software, Version 17.09.04a"
        assert len(line) < MAX_VERSION_LENGTH


# ----------------------------
# (f) interface range budget
# ----------------------------

def _bomb(size=4096):
    parts, length, i = [], len("interface range \n d\n"), 0
    while True:
        part = f"G{i}/1-1024"
        if length + len(part) + 2 > size:
            break
        parts.append(part)
        length += len(part) + 2
        i += 1
    return "interface range " + ", ".join(parts) + "\n d\n"


def _old_expand(header, children):
    spec = cd.RANGE_HEADER_RE.match(header).group(1).strip()
    expanded = OrderedDict()
    for part in [p.strip() for p in spec.split(",") if p.strip()]:
        m = cd._RANGE_PART_RE.match(part)
        if m:
            prefix, start, end = m.group(1), int(m.group(2)), int(m.group(3))
            if start <= end and (end - start) <= 1024:
                for port in range(start, end + 1):
                    expanded[f"interface {prefix}{port}"] = list(children)
                continue
        expanded[f"interface {part}"] = list(children)
    return expanded


class TestRangeBudget:
    def test_bomb_is_fast_and_small(self):
        body = _bomb()
        assert len(body) <= 4096
        start = time.perf_counter()
        rep = compare_configs(DriftRequest(config_a=body, config_b="abc"))
        assert time.perf_counter() - start < FAST
        assert any("expansion stopped" in s for s in rep.summary)

        tracemalloc.start()
        compare_configs(DriftRequest(config_a=body, config_b="abc"))
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        assert peak < 50 * 1024 * 1024

    def test_bomb_through_the_endpoint(self):
        r, took = _timed_post(DRIFT, {"config_a": _bomb(), "config_b": "abc"})
        assert r.status_code == 200
        assert took < FAST

    def test_over_budget_parts_stay_one_section(self):
        budget = cd._RangeBudget()
        out = cd._expand_interface_range(_bomb().splitlines()[0], [" d"], budget)
        # 1 + 1 line for each port: 8192 ports use 16 384 of the lines.
        assert budget.exhausted
        ports = [h for h in out if not h.startswith("interface range ")]
        rest = [h for h in out if h.startswith("interface range ")]
        assert len(ports) <= cd.MAX_EXPANDED_PORTS
        assert len(rest) == 1
        assert out[rest[0]] == [" d"]

    def test_budget_is_shared_by_both_configs(self):
        def ranges(letter, count):
            return "interface range " + ", ".join(f"{letter}{i}/1-1000" for i in range(count)) + "\n d\n"

        # 3000 + 3000 ports fit, 5000 + 5000 do not, although each side alone would.
        rep = compare_configs(DriftRequest(config_a=ranges("G", 3), config_b=ranges("T", 3)))
        assert not any("expansion stopped" in s for s in rep.summary)
        rep = compare_configs(DriftRequest(config_a=ranges("G", 5), config_b=ranges("T", 5)))
        assert any("expansion stopped" in s for s in rep.summary)
        rep = compare_configs(DriftRequest(config_a=ranges("G", 5), config_b="abc"))
        assert not any("expansion stopped" in s for s in rep.summary)

    def test_children_count_against_the_budget(self):
        body = "interface range G1/1-1000\n" + "".join(f" c{i}\n" for i in range(100))
        budget = cd._RangeBudget()
        out = cd._expand_interface_range(body.splitlines()[0], body.splitlines()[1:], budget)
        assert budget.exhausted
        assert list(out) == ["interface range G1/1-1000"]

    def test_many_bad_parts_with_many_children_do_not_multiply(self):
        header = "interface range " + ",".join("a" for _ in range(50_000))
        children = [" a"] * 50_000
        out = cd._expand_interface_range(header, children)
        assert sum(len(v) for v in out.values()) <= cd.MAX_EXPANDED_LINES + len(children)

    @pytest.mark.parametrize("header,children", [
        ("interface range GigabitEthernet1/0/1 - 48", [" switchport mode access", " spanning-tree portfast"]),
        ("interface range Gi1/0/1-24, Gi2/0/1-24, Te1/1/1 - 4", [" switchport mode trunk"]),
        ("interface range GigabitEthernet1/0/1 - 3, TenGigabitEthernet1/1/1", []),
        ("interface range Gi1/0/5-1", [" description reversed"]),
        ("interface range Port-channel1", [" no shutdown"]),
        ("interface range Gi1/0/1-48, Gi2/0/1-48, Gi3/0/1-48, Gi4/0/1-48, "
         "Gi5/0/1-48, Gi6/0/1-48, Gi7/0/1-48, Gi8/0/1-48", [" c%d" % i for i in range(30)]),
    ])
    def test_real_ranges_expand_as_before(self, header, children):
        budget = cd._RangeBudget()
        assert cd._expand_interface_range(header, children, budget) == _old_expand(header, children)
        assert not budget.exhausted

    def test_real_ranges_report_nothing_about_limits(self):
        cfg_a = "interface range Gi1/0/1-48, Gi2/0/1-48\n switchport mode access\n"
        cfg_b = "".join(
            f"interface Gi{m}/0/{p}\n switchport mode access\n" for m in (1, 2) for p in range(1, 49)
        )
        rep = compare_configs(DriftRequest(config_a=cfg_a, config_b=cfg_b))
        assert rep.drift_score == 0.0
        assert rep.truncated is False
        assert rep.changes_total == rep.changes_returned == 0

    def test_merge_of_repeated_ports_keeps_order_and_drops_duplicates(self):
        sections = OrderedDict([
            (cd.GLOBAL_SECTION, []),
            ("interface G1", [" a", " b"]),
            ("interface range G1-1", [" b", " c", " c", " d"]),
        ])
        cd._expand_unmatched_ranges(sections, OrderedDict())
        assert sections["interface G1"] == [" a", " b", " c", " d"]


# ----------------------------
# Quadratic loops: bare headers in Config Drift, Last input in Port Auditor
# ----------------------------

def _old_reconcile(sections_a, sections_b):
    for first, second in ((sections_a, sections_b), (sections_b, sections_a)):
        for header in list(first.keys()):
            if header == cd.GLOBAL_SECTION or header in second:
                continue
            norm_header = cd._normalize(header)
            for gline in list(second.get(cd.GLOBAL_SECTION, [])):
                if cd._normalize(gline) == norm_header:
                    second[cd.GLOBAL_SECTION].remove(gline)
                    second[header] = []
                    break


def _at_body_limit(make):
    """make(k) for the largest k whose JSON fits under the 960 KB limit."""
    low, high = 1, 400_000
    while low < high:
        middle = (low + high + 1) // 2
        if len(json.dumps(make(middle))) <= bl.PASTE_MAX - 200:
            low = middle
        else:
            high = middle - 1
    return make(low)


class TestReconcileBareHeaders:
    def _both(self, config_a, config_b):
        old_a = cd._parse_into_sections(config_a, True)
        old_b = cd._parse_into_sections(config_b, True)
        new_a = cd._parse_into_sections(config_a, True)
        new_b = cd._parse_into_sections(config_b, True)
        _old_reconcile(old_a, old_b)
        cd._reconcile_bare_headers(new_a, new_b)
        return (old_a, old_b), (new_a, new_b)

    @pytest.mark.parametrize("config_a,config_b", [
        ("router ospf 1\n network 10.0.0.0\n", "router ospf 1\nhostname R\n"),
        ("router ospf 1\n a\n", "hostname R\nrouter ospf 1\nrouter ospf 1\nend2\n"),
        ("router  ospf 1\n a\nrouter ospf  1\n b\n", "router ospf 1\nrouter ospf 1\nrouter ospf 1\n"),
        ("line vty 0 4\n a\nip http server\n", "line vty 0 4\nip http server\n b\n"),
        ("a\n b\n", "a ! note\n"),
        ("a\n x\nb\n", "b\n y\na\n"),
    ])
    def test_real_shapes_match_the_old_code(self, config_a, config_b):
        old, new = self._both(config_a, config_b)
        assert new == old
        assert [list(s) for s in new] == [list(s) for s in old]

    def test_random_configs_match_the_old_code(self):
        rng = random.Random(20261102)
        names = ["a", "a  ", "a ! n", "b", "b c", "b  c", "c", "d", "no a", "e"]

        def config():
            lines = []
            for _ in range(rng.randint(0, 12)):
                name = rng.choice(names)
                lines.append(name)
                for _ in range(rng.choice([0, 0, 1, 2])):
                    lines.append(" " + rng.choice(names))
            return "\n".join(lines)

        for _ in range(3000):
            config_a, config_b = config(), config()
            old, new = self._both(config_a, config_b)
            assert new == old, (config_a, config_b)
            assert [list(s) for s in new] == [list(s) for s in old], (config_a, config_b)

    def test_missing_global_bucket_is_harmless(self):
        first = OrderedDict([("a", [" b"])])
        cd._reconcile_bare_headers(first, OrderedDict())
        assert first == OrderedDict([("a", [" b"])])

    @pytest.mark.parametrize("make", [
        lambda k: ("\n".join(f"h{i}\n c" for i in range(k)), "\n".join(f"h{i}x" for i in range(k))),
        lambda k: ("\n".join(f"h{i}\n c" for i in range(k)), "\n".join(f"h{i}" for i in range(k))),
        lambda k: ("\n".join(f"h{i}\n c" for i in range(k)), "\n".join("a" for i in range(k))),
    ], ids=["no-match", "all-match", "same-line"])
    def test_loop_is_fast_at_the_body_limit(self, make):
        config_a, config_b = make(40_000)
        a = cd._parse_into_sections(config_a, True)
        b = cd._parse_into_sections(config_b, True)
        start = time.perf_counter()
        cd._reconcile_bare_headers(a, b)
        assert time.perf_counter() - start < FAST


def _unused(status_lines, detail, threshold=180):
    r = client.post(PORT_AUDITOR, json={
        "interface_status": "\n".join(status_lines), "interface_detail": detail,
        "threshold_days": threshold, "exclude_uplinks": False,
    })
    assert r.status_code == 200
    return {p["interface"]: p["last_input"] for p in r.json()["ports"]}


class TestLastInputMatch:
    def test_long_name_matches_short_port(self):
        got = _unused(["Gi1/0/1  notconnect 1 a a"], "GigabitEthernet1/0/1 is down\n  Last input never, output never\n")
        assert got == {"Gi1/0/1": "never"}

    def test_exact_name_wins_over_normalized(self):
        detail = "GigabitEthernet1 is down\n  Last input 2y, x\nGi1 is down\n  Last input never, x\n"
        assert _unused(["Gi1  notconnect 1 a a"], detail) == {"Gi1": "never"}

    def test_first_entry_wins_among_normalized_names(self):
        detail = "GigabitEthernet1 is down\n  Last input never, x\nGi1 is down\n  Last input 2y, x\n"
        assert _unused(["GigabitEthernet1  notconnect 1 a a"], detail) == {"GigabitEthernet1": "never"}
        assert _unused(["Gi1  notconnect 1 a a"], detail) == {"Gi1": "2y"}

    def test_empty_exact_value_falls_back_as_before(self):
        # 'Last input  ,' parses to "": exact lookup is falsy, so the normalized one decides.
        empty_first = "Gi1 is down\n  Last input  , x\nGigabitEthernet1 is down\n  Last input 2y, x\n"
        assert _unused(["Gi1  notconnect 1 a a"], empty_first) == {"Gi1": None}
        empty_last = "GigabitEthernet1 is down\n  Last input 2y, x\nGi1 is down\n  Last input  , x\n"
        assert _unused(["Gi1  notconnect 1 a a"], empty_last) == {"Gi1": "2y"}

    def test_random_inputs_match_the_old_loop(self):
        rng = random.Random(20261102)
        names = ["Gi1", "GigabitEthernet1", "Gi2", "GigabitEthernet2", "Vl1", "Vlan1", "Po1", "Port-channel1", "X9"]
        values = ["never", "2y", "26w3d", "2d03h", "00:00:01", " "]
        for _ in range(1000):
            detail_map = {}
            detail = ""
            for name in rng.sample(names, rng.randint(0, len(names))):
                value = rng.choice(values)
                detail += f"{name} is down\n  Last input {value}, x\n"
                detail_map[name] = value.strip()
            # A status line starting with "port" is the table header to the parser.
            ports = [p for p in rng.sample(names, rng.randint(1, len(names))) if not p.lower().startswith("port")]
            if not ports:
                continue

            expected = {}
            for port in ports:
                last = detail_map.get(port)
                if not last:
                    norm = pa._normalize_interface_name(port)
                    for full, value in detail_map.items():
                        if pa._normalize_interface_name(full) == norm:
                            last = value
                            break
                days = pa._parse_last_input_to_days(last) if last else None
                if days is None or days >= 180:
                    expected[port] = last if last else None

            assert _unused([f"{p}  notconnect 1 a a" for p in ports], detail or "x") == expected, detail

    @pytest.mark.parametrize("make", [
        lambda k: {"interface_status": "\n".join(f"G{i}  notconnect 1 a a" for i in range(k)),
                   "interface_detail": "\n".join(f"H{i} is up\nLast input 1" for i in range(k))},
        lambda k: {"interface_status": "\n".join(f"Gi{i}  notconnect 1 a a" for i in range(k)),
                   "interface_detail": "\n".join(f"GigabitEthernet{i} is up\nLast input 1" for i in range(k))},
    ], ids=["no-match", "normalized-match"])
    def test_fast_at_the_body_limit(self, make):
        r, took = _timed_post(PORT_AUDITOR, _at_body_limit(make))
        assert r.status_code == 200
        assert took < 2.0


# ----------------------------
# W11 response size and rate limit
# ----------------------------

def _changes(data):
    return [c for s in data["sections"] for c in s["changes"]]


def _at_limit(fill_a, fill_b="abc"):
    """Repeat a block until the JSON body sits just under the body limit."""
    target = bl.PASTE_MAX - 2048
    unit = len(json.dumps(fill_a)) - 2
    return {"config_a": fill_a * (target // unit), "config_b": fill_b}


class TestDriftResponseLimit:
    TWO_MB = 2 * 1024 * 1024

    @pytest.mark.parametrize("body", [
        {"config_a": "".join(f"interface Ga{i}\n d\n" for i in range(20_000)),
         "config_b": "".join(f"interface Gb{i}\n d\n" for i in range(20_000))},
        {"config_a": "x\n" + " a\n" * 230_000, "config_b": "abc"},
        {"config_a": "h" * 100_000 + "\n" + " a\n" * 200_000, "config_b": "abc"},
        {"config_a": "h" * 900_000 + "\n c\n", "config_b": "abc"},
        {"config_a": "hostname " + "h" * 450_000, "config_b": "hostname " + "i" * 450_000},
        {"config_a": "x\n" + (" \u0001\n" * 100_000), "config_b": "abc"},
        {"config_a": "x\n" + "".join(f" {'q' * 200}{i}\n" for i in range(4000)), "config_b": "abc"},
    ], ids=["disjoint-sections", "many-children", "long-header", "huge-header",
            "hostnames", "control-chars", "long-lines"])
    def test_under_2_mb_at_the_body_limit(self, body):
        assert len(json.dumps(body)) <= bl.PASTE_MAX
        r = client.post(DRIFT, json=body)
        assert r.status_code == 200
        assert len(r.content) < self.TWO_MB

    def test_truncation_is_reported_and_totals_stay_true(self):
        r = client.post(DRIFT, json={"config_a": "x\n" + "".join(f" c{i}\n" for i in range(9000)),
                                     "config_b": "abc"})
        data = r.json()
        assert data["truncated"] is True
        assert data["changes_total"] == 9002  # header, 9000 children, the added "abc"
        assert data["changes_returned"] == cd.MAX_RETURNED_CHANGES == len(_changes(data))
        assert data["total_removed"] == 9001
        assert next(s for s in data["sections"] if s["title"] == "x")["removed_count"] == 9001
        assert any("Report truncated" in s and "9002" in s for s in data["summary"])

    def test_highest_risk_is_kept_first(self):
        # The critical lines come after more changes than the response can hold.
        noise = "".join(f" c{i}\n" for i in range(cd.MAX_RETURNED_CHANGES + 100))
        config = "x\n" + noise + " snmp-server community public RO\n enable secret 5 abc\n"
        rep = compare_configs(DriftRequest(config_a=config, config_b="hostname R\n"))
        assert rep.truncated
        lines = [c.line.strip() for s in rep.sections for c in s.changes]
        assert "snmp-server community public RO" in lines
        assert "enable secret 5 abc" in lines
        assert any("CRITICAL: 2" in s for s in rep.summary)

    def test_order_inside_a_section_is_kept_when_cut(self):
        config = "x\n" + "".join(f" c{i:05d}\n" for i in range(cd.MAX_RETURNED_CHANGES + 100))
        rep = compare_configs(DriftRequest(config_a=config, config_b="abc"))
        lines = [c.line for c in rep.sections[0].changes]
        assert lines == sorted(lines, key=lambda l: (not l.startswith("x"), l))

    def test_a_huge_line_does_not_hide_smaller_ones(self):
        config = "x\n " + "q" * 1_600_000 + "\n small\n"
        rep = compare_configs(DriftRequest(config_a=config, config_b="abc"))
        lines = [c.line.strip() for s in rep.sections for c in s.changes]
        assert "small" in lines
        assert rep.truncated

    def test_section_with_nothing_kept_is_left_out(self):
        rep = compare_configs(DriftRequest(config_a="h" * 1_600_000 + "\n c\n", config_b="abc"))
        assert rep.truncated
        assert all(s.changes for s in rep.sections)

    def test_normal_report_is_not_touched(self):
        a = "hostname A\ninterface G1\n description one\n"
        b = "hostname B\ninterface G1\n description two\n"
        data = client.post(DRIFT, json={"config_a": a, "config_b": b}).json()
        assert data["truncated"] is False
        assert data["changes_total"] == data["changes_returned"] == len(_changes(data)) > 0
        assert not any("truncated" in s for s in data["summary"])

    def test_long_values_are_clipped_outside_the_changes(self):
        title = "h" * 5000
        rep = compare_configs(DriftRequest(config_a=f"hostname {title}\n{title}\n c\n", config_b="abc"))
        assert len(rep.hostname_a) == cd.MAX_HOSTNAME_LENGTH
        assert all(len(s) < 2000 for s in rep.summary)


@pytest.fixture
def limited(monkeypatch):
    monkeypatch.setattr(rl, "ENABLED", True)
    monkeypatch.setattr(rl, "limiter", rl.SlidingWindowLimiter())


class TestPasteRateLimit:
    @pytest.mark.parametrize("path", sorted(bl.PASTE_PATHS))
    def test_eleventh_request_in_a_minute_is_429(self, limited, path):
        statuses = [client.post(path, json={}).status_code for _ in range(11)]
        assert statuses[:10] == [422] * 10
        assert statuses[10] == 429

    def test_same_limits_as_acl(self):
        for path in bl.PASTE_PATHS:
            assert rl.PATH_LIMITS[path] == rl.PATH_LIMITS["/tools/acl/analyze"]

    def test_other_tools_keep_the_default(self, limited):
        statuses = [client.post("/tools/subnet/info", json={"cidr": "10.0.0.0/24"}).status_code
                    for _ in range(11)]
        assert 429 not in statuses


# ----------------------------
# W12 ACL messages
# ----------------------------

class TestAclEcho:
    LONG = "Z" * 5000

    def _reason(self, rule):
        entry = parse_acls("ip access-list extended A\n %s\n" % rule).acls["A"].entries[-1]
        assert entry.status == STATUS_NOT_EVALUATED
        return entry.reason

    def test_token_echo_is_clipped(self):
        reason = self._reason("permit tcp any any " + self.LONG)
        assert "'" + "Z" * 20 + "'..." in reason
        assert "Z" * 21 not in reason

    def test_icmp_echo_is_clipped(self):
        reason = self._reason("permit icmp any any " + self.LONG)
        assert "'" + "Z" * 20 + "'..." in reason
        assert "Z" * 21 not in reason

    def test_short_values_read_as_before(self):
        assert self._reason("permit tcp any any foo") == "token 'foo' is outside the v0 grammar"
        assert self._reason("permit icmp any any echo") == "ICMP type/code 'echo' is outside v0"
