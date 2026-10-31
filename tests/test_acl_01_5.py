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
