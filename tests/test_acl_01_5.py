"""
ACL-01.5 a/d/e: fixes from production dogfooding (user, 2026-10-29, LIVE v0.7.8).

5a: a line with a mistyped keyword (`10 permin <host>`) was NOT EVALUATED with no
    hint, and the header said "Findings: 0 error, 0 warn, 0 info" = looked clean.
    Now: a "not evaluated" counter in the API, the tiles and the text header,
    plus "did you mean 'permit'?" for a first word close to permit/deny/remark.
5d: "same packet from line N" said nothing about the relation; now it names
    the edge: "also the outside edge of line 5 · seq 20 (...)".
5e: "line N" is the paste line, not the ACL sequence number; every reference
    in the UI now shows both ("line 4 · seq 11"), an assigned seq is marked.

The dogfooding paste is rebuilt from the backlog description (CEO repo
projects/netdevops/backlog.md, ACL-01.5): two named standard ACLs, the first
with no entries, the second with permit <host> entries (some with log), five
remark + entry pairs on the same seq, the typo `10 permin`, `100 deny any log`
at the end. Line 7's hit packet is the outside edge of line 5's host.
"""
import json
import os
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

from api.main import app
from services.acl_engine import STATUS_NOT_EVALUATED, parse_acls, suggest_keyword
from services.acl_lint import lint
from tests.test_acl_ui import HARNESS, ROOT

client = TestClient(app)

DOGFOOD = """ip access-list standard EMPTY-ACL
ip access-list standard MGMT-HOSTS
 10 permin 10.10.10.1
 20 remark Jump host
 20 permit 10.10.10.2 log
 30 remark NMS
 30 permit 10.10.10.3
 40 remark Backup
 40 permit 10.10.10.4 log
 50 remark Monitoring
 50 permit 10.10.10.5
 60 remark Admin
 60 permit 10.10.10.6 log
 70 permit 10.10.10.7
 80 permit 10.10.10.8 log
 90 permit 10.10.10.9
 95 permit 10.10.10.10 log
 100 deny any log
"""

CLEAN = """ip access-list extended EDGE-IN
 10 permit tcp 10.1.1.0 0.0.0.255 host 192.0.2.10 eq 22
 20 deny ip any any log
"""

NUMBERED = """access-list 10 permit 10.2.0.5
access-list 10 deny any log
"""

OBJECT_GROUP = """ip access-list extended OG
 10 permit tcp object-group ADMINS any eq 22
 20 deny ip any any log
"""


def _analyze(text, **extra):
    r = client.post("/tools/acl/analyze", json=dict({"config_text": text}, **extra))
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------- 5a engine


@pytest.mark.parametrize("word,expected", [
    ("permin", "permit"),      # the dogfooding typo (substitution)
    ("pemrit", "permit"),      # swapped neighbours
    ("permt", "permit"),       # missing letter
    ("permitt", "permit"),     # extra letter
    ("dney", "deny"),
    ("deyn", "deny"),
    ("remakr", "remark"),
    ("remrk", "remark"),
    ("Permit", "permit"),      # the parser reads keywords in lower case
])
def test_suggest_keyword_typos(word, expected):
    assert suggest_keyword(word) == expected


@pytest.mark.parametrize("word", [
    "permit", "deny", "remark",                     # correct keywords: nothing to suggest
    "no", "pe", "de",                               # shorter than 3
    "key", "dns", "ddns",                           # top-level IOS words (@ciso W1)
    "dynamic", "evaluate", "default", "exit", "statistics", "end",  # real IOS words
    "object-group", "fragments", "reflect",         # known out-of-v0 keywords
    "interface", "hostname", "router", "banner", "xyzzy",
])
def test_suggest_keyword_no_false_hint(word):
    assert suggest_keyword(word) is None


def test_dogfooding_typo_line_is_an_unevaluated_rule_with_suggestion():
    acl = parse_acls(DOGFOOD).acls["MGMT-HOSTS"]
    e = next(x for x in acl.entries if x.line == 3)
    assert e.status == STATUS_NOT_EVALUATED
    assert e.kind == "rule"                 # counts as a rule of the ACL, not as "other"
    assert e.suggestion == "permit"
    assert e.seq == 10 and e.explicit_seq
    assert e.reason == "'permin' is not an ACL keyword"
    assert e.to_dict()["suggestion"] == "permit"


def test_numbered_typo_gets_suggestion_and_assigned_seq():
    acl = parse_acls("access-list 10 dney 10.1.1.1\naccess-list 10 permit any\n").acls["10"]
    e = acl.entries[0]
    assert (e.status, e.kind, e.suggestion, e.seq, e.explicit_seq) == (
        STATUS_NOT_EVALUATED, "rule", "deny", 10, False)


def test_remark_typo_is_not_a_rule():
    acl = parse_acls("ip access-list standard R\n 10 remak SSH\n 20 permit any\n").acls["R"]
    e = acl.entries[0]
    assert (e.status, e.kind, e.suggestion) == (STATUS_NOT_EVALUATED, "other", "remark")


def test_flush_left_typo_inside_named_block_is_not_dropped():
    """Without indentation a typo used to end the block and vanish into other_lines."""
    parsed = parse_acls("ip access-list standard X\npermin 10.1.1.1\n 20 permit any\n")
    assert 2 not in parsed.other_lines
    lines = [e.line for e in parsed.acls["X"].entries]
    assert lines == [2, 3]
    assert parsed.acls["X"].entries[0].suggestion == "permit"


def test_out_of_v0_line_has_no_suggestion():
    e = parse_acls(OBJECT_GROUP).acls["OG"].entries[0]
    assert e.status == STATUS_NOT_EVALUATED and e.suggestion is None


def test_trace_lists_the_typo_line_as_unevaluated():
    parsed = parse_acls(DOGFOOD)
    from services.acl_engine import Packet, trace
    t = trace(parsed, "MGMT-HOSTS", Packet(src="10.10.10.2"))
    assert t["verdict"] == "permit" and t["matched_line"] == 5
    assert t["unevaluated_lines"] == [3]


# ---------------------------------------------------------------- 5a lint + API


def test_lint_counts_not_evaluated_and_proposes_keyword():
    res = lint(parse_acls(DOGFOOD))
    assert res["totals"] == {"ERROR": 0, "WARN": 0, "INFO": 0}
    assert res["not_evaluated_count"] == 1
    ne = res["acls"][1]["not_evaluated"]
    assert [n["line"] for n in ne] == [3]
    assert ne[0]["proposal"].startswith("Did you mean 'permit'?")


def test_lint_clean_paste_counts_zero():
    res = lint(parse_acls(CLEAN))
    assert res["not_evaluated_count"] == 0
    assert all(a["not_evaluated"] == [] for a in res["acls"])


def test_lint_out_of_v0_counted_without_did_you_mean():
    res = lint(parse_acls(OBJECT_GROUP))
    assert res["not_evaluated_count"] == 1
    assert res["acls"][0]["not_evaluated"][0]["proposal"] is None


def test_lint_counts_top_level_not_evaluated_lines():
    res = lint(parse_acls("ipv6 access-list V6\n permit ipv6 any any\naccess-list 10 permit any\n"))
    assert len(res["not_evaluated"]) == 2
    assert res["not_evaluated_count"] == 2
    assert all(n["proposal"] is None for n in res["not_evaluated"])


def test_api_dogfooding_summary_and_verdicts():
    b = _analyze(DOGFOOD)
    by = {a["acl"]: a for a in b["acls"]}
    assert by["MGMT-HOSTS"]["rules"] == 11 and by["MGMT-HOSTS"]["evaluated_rules"] == 10
    assert by["EMPTY-ACL"]["rules"] == 0
    assert b["lint"]["not_evaluated_count"] == 1
    # Engine verdicts unchanged (they were correct in dogfooding): 9 permit + 1 deny.
    rows = next(g for g in b["auto_packets"] if g["acl"] == "MGMT-HOSTS")["packets"]
    verdicts = [(r["from_line"], r["verdict"], r["matched_line"]) for r in rows]
    assert [v for v in verdicts if v[1] == "permit"] == [
        (n, "permit", n) for n in (5, 7, 9, 11, 13, 14, 15, 16, 17)]
    assert [v for v in verdicts if v[1] == "deny"] == [(18, "deny", 18)]
    # Every edge packet passes the typo line first: the verdict is flagged as conditional.
    assert all(r["unevaluated_lines"] == [3] for r in rows)


# ---------------------------------------------------------------- 5e API


def test_api_lines_carry_seq_and_assigned_flag():
    b = _analyze(DOGFOOD + NUMBERED)
    by = {a["acl"]: a for a in b["acls"]}
    first = by["MGMT-HOSTS"]["lines"][:3]
    assert first == [{"line": 3, "seq": 10, "seq_assigned": False},
                     {"line": 4, "seq": 20, "seq_assigned": False},
                     {"line": 5, "seq": 20, "seq_assigned": False}]
    assert by["10"]["lines"] == [{"line": 19, "seq": 10, "seq_assigned": True},
                                 {"line": 20, "seq": 20, "seq_assigned": True}]
    assert by["EMPTY-ACL"]["lines"] == []


def test_api_remark_without_seq_has_none():
    b = _analyze("ip access-list standard R\n remark top\n permit any\n")
    assert b["acls"][0]["lines"] == [{"line": 2, "seq": None, "seq_assigned": False},
                                     {"line": 3, "seq": 10, "seq_assigned": True}]


# ---------------------------------------------------------------- 5d API data


def test_dogfooding_packet_from_line_7_is_outside_edge_of_line_5():
    rows = next(g for g in _analyze(DOGFOOD)["auto_packets"] if g["acl"] == "MGMT-HOSTS")["packets"]
    row = next(r for r in rows if r["from_line"] == 7)
    assert {"line": 5, "edge": "src_outside", "relation": "outside"} in row["also_built_for"]


# ---------------------------------------------------------------- UI (Node)


@pytest.fixture(scope="module")
def ui(tmp_path_factory):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    out = {}
    script = tmp_path_factory.mktemp("acl_015") / "harness.js"
    script.write_text(HARNESS, encoding="utf-8")
    for name, paste, extra in (
        ("dogfood", DOGFOOD, {"trace": {"acl": "MGMT-HOSTS", "src": "10.10.10.3"}}),
        ("clean", CLEAN, {}),
        ("numbered", NUMBERED, {"trace": {"src": "10.2.0.5"}}),
        ("og", OBJECT_GROUP, {}),
    ):
        data = _analyze(paste, **extra)
        proc = subprocess.run([node, str(script), os.path.join(ROOT, "web", "app-acl.js")],
                              input=json.dumps({"paste": paste, "responses": {"r": data}}),
                              capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, proc.stderr
        res = json.loads(proc.stdout)
        assert res["markupWrites"] == 0
        out[name] = {"text": "\n".join(res["r"]["text"]), "output": res["r"]["output"]}
    return out


DOT = "\u00b7"
EM_DASH = "\u2014"


class TestUi015:
    def test_5a_tile_note_and_did_you_mean(self, ui):
        t = ui["dogfood"]["text"]
        assert "NOT EVALUATED" in t
        assert "1 not evaluated: this line is not covered by the counts above" in t
        assert "Did you mean 'permit'?" in t
        out = ui["dogfood"]["output"]
        assert "Findings: 0 error, 0 warn, 0 info, 1 not evaluated (not covered by the findings, see LINT)" in out
        assert "-> Did you mean 'permit'?" in out

    def test_5a_clean_paste_counter_zero_no_alert(self, ui):
        t = ui["clean"]["text"]
        assert "not covered by the counts above" not in t
        assert "Findings: 0 error, 0 warn, 0 info, 0 not evaluated\n" in ui["clean"]["output"]

    def test_5a_out_of_v0_counted_without_did_you_mean(self, ui):
        t = ui["og"]["text"]
        assert "1 not evaluated" in t
        assert "Did you mean" not in t and "Did you mean" not in ui["og"]["output"]

    def test_5d_relation_text(self, ui):
        t = ui["dogfood"]["text"]
        assert ("also the outside edge of line 5 %s seq 20 (first src address outside)" % DOT) in t
        assert "same packet from line" not in t
        assert "same packet from line" not in ui["dogfood"]["output"]
        assert ("also the outside edge of line 5 %s seq 20" % DOT) in ui["dogfood"]["output"]

    def test_5e_line_and_seq_everywhere(self, ui):
        t = ui["dogfood"]["text"]
        ref3 = "line 3 %s seq 10" % DOT
        ref7 = "line 7 %s seq 30" % DOT
        assert ref3 in t                          # lint row (NOT EVALUATED) + trace path
        assert (ref7 + " (inside)") in t          # packet table, "Built from"
        assert (" " + ref7) in t                  # verdict node in packet table / trace head
        out = ui["dogfood"]["output"]
        assert "[NOT EVALUATED] MGMT-HOSTS " + ref3 in out
        assert "  " + ref7 + " MATCH" in out      # trace path in the text report
        assert "(from " + ref7 + "," in out       # edge packets in the text report

    def test_5e_assigned_seq_is_marked(self, ui):
        t = ui["numbered"]["text"]
        assert ("line 1 %s seq 10 (assigned)" % DOT) in t
        assert ("line 2 %s seq 20 (assigned)" % DOT) in ui["numbered"]["output"]

    def test_no_em_dash_in_new_texts(self, ui):
        for v in ui.values():
            assert EM_DASH not in v["text"] and EM_DASH not in v["output"]


# ---------------------------------------------------------------- @ciso W1 (2026-10-31)

# Probe from the @ciso review: a `show run` excerpt without `!` between sections.
CISO_W1_PROBE = """ip access-list extended B
 permit ip any any
key chain X
 key 1
  key-string cisco123
"""


def test_w1_key_chain_after_acl_is_not_pulled_in():
    b = _analyze(CISO_W1_PROBE)
    assert b["lint"]["not_evaluated_count"] == 0
    assert "key-string" not in json.dumps(b)
    acl = b["acls"][0]
    assert acl["acl"] == "B" and acl["rules"] == acl["evaluated_rules"] == 1
    assert [x["line"] for x in acl["lines"]] == [2]
    assert parse_acls(CISO_W1_PROBE).other_lines == [3, 4, 5]


@pytest.mark.parametrize("line", [
    "key chain X", "dns-server 10.0.0.1", "dns 10.0.0.1", "ddns update method X",
    "deny-list X", "pemit", "permix chain", "deni interface Gi1/0/1",
])
def test_w1_flush_left_ios_command_ends_the_block(line):
    parsed = parse_acls("ip access-list standard S\n permit any\n%s\n  key-string cisco123\n" % line)
    assert [e.line for e in parsed.acls["S"].entries] == [2]
    assert parsed.other_lines == [3, 4]
    assert lint(parsed)["not_evaluated_count"] == 0


@pytest.mark.parametrize("acl_type,line,expected", [
    ("standard", "permin host 10.1.1.1", "permit"),
    ("standard", "permin 10.1.1.1", "permit"),
    ("standard", "pemrit any", "permit"),
    ("extended", "dney tcp any any eq 22", "deny"),
    ("extended", "deyn ip any any log", "deny"),
    ("extended", "permin 6 any any", "permit"),
])
def test_w1_flush_left_rule_typo_still_gets_did_you_mean(acl_type, line, expected):
    b = _analyze("ip access-list %s T\n 10 permit %s\n%s\n" % (
        acl_type, "any" if acl_type == "standard" else "ip any any", line))
    ne = b["lint"]["acls"][0]["not_evaluated"]
    assert [n["line"] for n in ne] == [3]
    assert ne[0]["proposal"].startswith("Did you mean '%s'?" % expected)
    assert b["lint"]["not_evaluated_count"] == 1


# ---------------------------------------------------------------- 5f header typo (2026-11-05)

@pytest.mark.parametrize("word", ["acess-list", "acces-list", "access-lst", "accesslist", "ACCESS-LIST"])
def test_5f_numbered_header_typo_is_a_not_evaluated_rule_of_that_acl(word):
    parsed = parse_acls("%s 10 permit 10.1.1.1\naccess-list 10 deny any log\n" % word)
    assert parsed.other_lines == []
    acl = parsed.acls["10"]
    e = acl.entries[0]
    assert (e.line, e.status, e.kind, e.suggestion) == (1, STATUS_NOT_EVALUATED, "rule", "access-list")
    assert (e.seq, acl.entries[1].seq) == (10, 20)
    res = lint(parsed)
    assert res["not_evaluated_count"] == 1
    ne = res["acls"][0]["not_evaluated"]
    assert [n["line"] for n in ne] == [1]
    assert ne[0]["proposal"].startswith("Did you mean 'access-list'?")


def test_5f_numbered_typo_makes_the_trace_verdict_uncertain():
    from services.acl_engine import Packet, trace
    parsed = parse_acls("acess-list 10 permit 10.1.1.1\naccess-list 10 deny any log\n")
    t = trace(parsed, "10", Packet(src="10.1.1.1"))
    assert t["verdict"] == "deny" and t["unevaluated_lines"] == [1]


def test_5f_numbered_typo_alone_shows_in_the_api_as_not_clean():
    b = _analyze("acess-list 10 permit any\n")
    assert b["lint"]["not_evaluated_count"] == 1
    assert b["acls"][0]["rules"] == 1 and b["acls"][0]["evaluated_rules"] == 0


def test_5f_numbered_typo_with_a_number_outside_the_ranges_is_top_level():
    res = lint(parse_acls("acess-list 700 permit any\n"))
    assert [n["line"] for n in res["not_evaluated"]] == [1]
    assert res["not_evaluated"][0]["proposal"].startswith("Did you mean 'access-list'?")
    assert res["not_evaluated_count"] == 1


def test_5f_numbered_typo_after_a_correct_line_joins_the_same_acl():
    parsed = parse_acls("access-list 10 permit any\nacess-list 10 permit tcp any any eq 22\n")
    assert [e.line for e in parsed.acls["10"].entries] == [1, 2]
    assert lint(parsed)["not_evaluated_count"] == 1


def test_5f_remark_after_numbered_typo_is_not_a_rule():
    acl = parse_acls("acess-list 10 remark SSH\naccess-list 10 permit any\n").acls["10"]
    assert acl.entries[0].kind == "other" and acl.entries[0].status == STATUS_NOT_EVALUATED
    assert sum(1 for e in acl.entries if e.kind == "rule") == 1


@pytest.mark.parametrize("header", [
    "ip acess-list extended EDGE", "ip acces-list extended EDGE", "ip access-lst extended EDGE",
    "ip accesslist extended EDGE", "ip access list extended EDGE", "IP ACCESS-LIST EXTENDED EDGE",
    "ip acess-list extnded EDGE", "ipp access-list extended EDGE", "pi access-list extended EDGE",
])
def test_5f_named_header_typo_reports_the_header_and_every_entry(header):
    parsed = parse_acls("%s\n 10 permit tcp any any eq 22\n 20 deny ip any any log\ninterface Gi1\n" % header)
    assert parsed.acls == {}
    assert parsed.other_lines == [4]
    res = lint(parsed)
    assert [n["line"] for n in res["not_evaluated"]] == [1, 2, 3]
    assert res["not_evaluated_count"] == 3
    assert res["not_evaluated"][0]["proposal"].startswith("Did you mean 'ip access-list'?")
    assert res["not_evaluated"][1]["proposal"] is None


def test_5f_numbered_header_with_a_space_instead_of_a_hyphen():
    parsed = parse_acls("access list 10 permit any\n")
    assert parsed.acls["10"].entries[0].suggestion == "access-list"
    assert lint(parsed)["not_evaluated_count"] == 1


def test_5f_header_typo_ends_the_named_block_before_it():
    parsed = parse_acls("ip access-list standard A\n permit any\nacess-list 10 permit any\n")
    assert [e.line for e in parsed.acls["A"].entries] == [2]
    assert [e.line for e in parsed.acls["10"].entries] == [3]


def test_5f_echo_in_the_reason_is_bounded():
    # Only near-distance words reach the reason sentence, so it can never be the paste.
    res = lint(parse_acls("acess-list 10 permit any\n"))
    assert "acess-list" in res["acls"][0]["not_evaluated"][0]["reason"]
    assert len(res["acls"][0]["not_evaluated"][0]["reason"]) < 80


# False positives: real IOS commands and prose in a change file stay in other_lines.
@pytest.mark.parametrize("line", [
    "access-group 10 in", "access-class 10 in", "access-map X 10", "access-session closed",
    "ip access-group 10 in", "ip access-class 10", "ip address 10.1.1.1 255.255.255.0",
    "ip accounting output-packets", "ip route 0.0.0.0 0.0.0.0 10.1.1.1",
    "no access-list 10", "no ip access-list standard X", "show access-lists", "show ip access-lists 10",
    "sh access-list", "arp access-list X", "ipx access-list standard X", "vlan access-map X 10",
    "ip access-lists are reviewed monthly", "IP access-lists below", "Access-list changes below:",
    "access-lists 10 was reviewed", "access lists below", "access list 10 was reviewed",
    "acess-list", "acess-list 10", "acl 10 permit any", "class-map match-any X",
    "accept-lifetime 00:00:00 Jan 1 2026 infinite", "accounting-list 10 permit",
    '"access-list 10 permit any",', "-access-list 10 permit any", "+access-list 10 permit any",
    "`access-list 10 permit any`", "#access-list 10 permit any", "ip \"access-list standard X",
    "#ip access-list standard X", "//ip access-list standard X", "-ip access-list standard X",
    '"ip access-list standard X",', "assess-list reviewed", "prefix-list 10 permit any",
])
def test_5f_no_false_positive_on_real_commands_and_prose(line):
    parsed = parse_acls("%s\n" % line)
    assert parsed.acls == {}
    assert parsed.not_evaluated == []
    assert parsed.other_lines == [1]
    assert lint(parsed)["not_evaluated_count"] == 0


def test_5f_no_change_for_the_correct_headers():
    parsed = parse_acls(CLEAN)
    assert all(e.suggestion is None for a in parsed.acls.values() for e in a.entries)
    assert lint(parsed)["not_evaluated_count"] == 0


def test_5f_named_typo_through_the_api_is_not_clean_and_has_a_proposal():
    b = _analyze("ip acess-list extended EDGE\n 10 permit tcp any any eq 22\n 20 deny ip any any log\n")
    assert b["acls"] == []
    assert b["lint"]["totals"] == {"ERROR": 0, "WARN": 0, "INFO": 0}
    assert b["lint"]["not_evaluated_count"] == 3
    first = b["lint"]["not_evaluated"][0]
    assert first["proposal"].startswith("Did you mean 'ip access-list'?")
    assert set(first) == {"line", "text", "reason", "proposal"}  # contract unchanged


def test_5f_change_file_with_prose_and_real_commands_stays_clean():
    paste = """Access-list changes below:
access-lists 10 was reviewed
ip access-lists are reviewed monthly
interface Gi1/0/1
 ip access-group 10 in
line vty 0 4
 access-class 10 in
access-list 10 permit 10.1.1.1
access-list 10 deny any log
"""
    parsed = parse_acls(paste)
    assert parsed.not_evaluated == []
    assert [e.line for e in parsed.acls["10"].entries] == [8, 9]
    assert lint(parsed)["not_evaluated_count"] == 0


# ---------------------------------------------------------------- @ciso review of 5f (2026-11-05)


def test_5f_w1_indented_typo_stays_in_the_block_and_the_verdict_is_right():
    from services.acl_engine import Packet, trace
    parsed = parse_acls("ip access-list extended A\n 10 deny ip host 1.1.1.1 any\n"
                        " acess-list 10 permit any\n 20 permit ip any any\n")
    t = trace(parsed, "A", Packet(src="2.2.2.2", dst="3.3.3.3", protocol="tcp", src_port=1, dst_port=2))
    assert (t["verdict"], t["matched_line"], t["unevaluated_lines"]) == ("permit", 4, [3])
    assert parsed.other_lines == []
    assert list(parsed.acls) == ["A"]
    assert lint(parsed)["not_evaluated_count"] == 1


def test_5f_flush_left_numbered_typo_ends_the_block():
    parsed = parse_acls("ip access-list standard A\n permit any\nacess-list 10 permit any\n permit 10.1.1.1\n")
    assert [e.line for e in parsed.acls["A"].entries] == [2]
    assert [e.line for e in parsed.acls["10"].entries] == [3]
    assert parsed.other_lines == [4]


_LONG = "9" * 5000
W2_PASTES = [
    "acess-list \u00b2 permit any", "access list \u00b2 permit any", "acess-list %s permit any" % _LONG,
    "access list %s permit any" % _LONG, "access-list \u00b2 permit any", "access-list %s permit any" % _LONG,
    "ip access-list standard \u00b2", "ip access-list standard %s" % _LONG,
    "ip access-list standard A\n \u00b2 permit any", "ip access-list standard A\n %s permit any" % _LONG,
    # The same int() on a protocol and a port (found while fixing W2).
    "access-list 100 permit \u00b2 any any", "access-list 100 permit %s any any" % _LONG,
    "access-list 100 permit tcp any any eq \u00b2", "access-list 100 permit tcp any any eq %s" % _LONG,
    "access-list 100 permit tcp any eq \u00b2 any", "access-list 100 permit tcp any any range 1 %s" % _LONG,
]


@pytest.mark.parametrize("paste", W2_PASTES, ids=[str(i) for i in range(len(W2_PASTES))])
def test_5f_w2_odd_numbers_are_reported_and_never_a_500(paste):
    b = _analyze(paste + "\n")  # _analyze asserts HTTP 200
    res = b["lint"]
    assert res["not_evaluated_count"] + sum(res["totals"].values()) >= 1
    items = res["not_evaluated"] + [n for a in res["acls"] for n in a["not_evaluated"]]
    assert all(len(n["reason"]) < 200 for n in items)  # the line itself is in `text`, not in `reason`
    assert all(len(f["effect"]) < 200 for a in res["acls"] for f in a["findings"])


W2_CISO_TABLE = W2_PASTES[:10]


@pytest.mark.parametrize("paste", W2_CISO_TABLE, ids=[str(i) for i in range(len(W2_CISO_TABLE))])
def test_5f_w2_every_row_of_the_ciso_table_is_counted_as_not_evaluated(paste):
    assert _analyze(paste + "\n")["lint"]["not_evaluated_count"] >= 1


def test_5f_w2_real_numbers_still_read_as_numbers():
    parsed = parse_acls("ip access-list extended A\n 15 permit 6 any any\n 25 permit tcp any any eq 22\n")
    assert [(e.seq, e.status) for e in parsed.acls["A"].entries] == [(15, "OK"), (25, "OK")]
    assert lint(parse_acls("access-list 700 permit any\n"))["not_evaluated_count"] == 1


@pytest.mark.parametrize("word", ["acces$-list", "access<list", "access-l1st", 'access"list'])
def test_5f_w3_only_letters_hyphen_underscore_can_be_a_header_typo(word):
    parsed = parse_acls("%s 10 permit any\n" % word)
    assert parsed.acls == {} and parsed.not_evaluated == [] and parsed.other_lines == [1]


def _forbid_edit_distance(monkeypatch):
    import services.acl_engine as engine

    def boom(a, b):
        raise AssertionError("edit distance on an unbounded word")
    monkeypatch.setattr(engine, "_edit_distance", boom)
    return engine


def test_5f_w3_long_header_word_costs_no_edit_distance(monkeypatch):
    engine = _forbid_edit_distance(monkeypatch)
    assert engine._is_header_word("a" * 100_000) is False


def test_5f_w3_long_type_word_costs_no_edit_distance(monkeypatch):
    engine = _forbid_edit_distance(monkeypatch)
    assert engine._is_acl_type_word("a" * 100_000) is False


def test_5f_w3_long_first_word_before_access_list_costs_no_edit_distance(monkeypatch):
    import services.acl_engine as engine
    calls = []
    real = engine._edit_distance
    monkeypatch.setattr(engine, "_edit_distance", lambda a, b: calls.append(a) or real(a, b))
    assert engine._named_header_typo(["a" * 100_000, "access-list", "standard", "X"]) is None
    assert all(len(a) < 100 for a in calls)


def test_5f_w3_numbered_reason_does_not_repeat_the_line():
    entry = parse_acls("acess-list 10 permit any SECRET-TAIL\n").acls["10"].entries[0]
    assert entry.reason == "'acess-list' is not an ACL keyword"
    top = parse_acls("acess-list 700 permit any SECRET-TAIL\n").not_evaluated[0]
    assert top["reason"] == "'acess-list' is not an ACL keyword"


def test_5f_w3_named_reasons_do_not_repeat_the_line():
    items = parse_acls("ip acess-list extended SECRET-NAME\n 10 permit tcp any any eq 22 SECRET-TAIL\n").not_evaluated
    assert items[0]["reason"] == "'ip acess-list' is not an ACL keyword"
    assert items[1]["reason"] == "the ACL header on line 1 is mistyped, so this entry is not evaluated"
