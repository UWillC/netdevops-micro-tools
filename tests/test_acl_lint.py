"""
ACL-01.2 lint (services/acl_lint.py) + rule containment, offline.

Acceptance (CEO repo projects/netdevops/backlog.md, ACL-01.2; spec
spec_acl-01_v0_2026-10-22.md sections 2, 3, 5; Q1/Q2/Q3 user 2026-10-26):
21/21 fixtures = 5 traps + 15 + 1 from the user's lab of 2026-10-22.

Each fixture lists the EXACT set of (finding id, line) it must produce.
Exact set equality = 100% detection (nothing expected is missing) AND
0 false alarms (nothing unexpected appears), on every fixture, not only
on the clean one.
"""

import pytest

from services.acl_engine import STATUS_NOT_EVALUATED, parse_acls
from services.acl_lint import (
    address_contains,
    address_intersects,
    lint,
    lint_json,
    ports_contain,
    rule_contains,
    rules_intersect,
)

# (name, paste, {acl: {(id, line), ...}})
FIXTURES = [
    # ---- 5 traps from the backlog (spec section 5)
    ("T1_shadow_by_wider_mask",
     "ip access-list extended T1\n"
     " 10 deny ip 10.1.0.0 0.0.255.255 any\n"
     " 20 permit tcp 10.1.1.0 0.0.0.255 any eq 443\n"
     " 30 deny ip any any log\n",
     {"T1": {("L01", 3)}}),
    ("T2_established_without_pair_2_acls",
     "ip access-list extended OUT\n"
     " 10 permit tcp 10.0.0.0 0.0.0.255 any eq 443\n"
     " 20 deny ip any any log\n"
     "ip access-list extended IN\n"
     " 10 permit tcp any eq 22 10.0.0.0 0.0.0.255 established\n"
     " 20 deny ip any any log\n",
     {"OUT": set(), "IN": {("L10", 5)}}),
    ("T3_duplicate_with_other_log",
     "ip access-list extended T3\n"
     " 10 permit tcp host 10.0.0.1 host 10.0.0.2 eq 22\n"
     " 20 permit tcp host 10.0.0.1 host 10.0.0.2 eq 22 log\n"
     " 30 deny ip any any log\n",
     {"T3": {("L03", 3)}}),
    ("T4_standard_acl_with_port",
     "access-list 10 permit 10.0.0.0 0.0.0.255 eq 22\n"
     "access-list 10 deny any log\n",
     {"10": {("P01", 1)}}),
    ("T5_no_logged_implicit_deny",
     "ip access-list extended T5\n"
     " 10 permit tcp 10.0.0.0 0.0.0.255 host 10.0.0.1 eq 22\n"
     " 20 permit udp 10.0.0.0 0.0.0.255 host 10.0.0.2 eq ntp\n",
     {"T5": {("L07", 3)}}),
    # ---- 15 more (spec section 5)
    ("F01_L02_redundant",
     "ip access-list extended F01\n"
     " 10 permit tcp 10.0.0.0 0.0.255.255 any eq 22\n"
     " 20 permit tcp 10.0.1.0 0.0.0.255 any eq 22\n"
     " 30 deny ip any any log\n",
     {"F01": {("L02", 3)}}),
    ("F02_L04_host_bits",
     "access-list 110 permit tcp 10.1.1.5 0.0.0.255 any eq 22\n"
     "access-list 110 deny ip any any log\n",
     {"110": {("L04", 1)}}),
    ("F03_L05_non_contiguous_wildcard",
     "ip access-list extended F03\n"
     " 10 permit ip 10.0.0.0 0.0.255.0 host 10.9.9.9\n"
     " 20 deny ip any any log\n",
     {"F03": {("L05", 2)}}),
    ("F04_L06_any_any_in_the_middle",
     "ip access-list extended F04\n"
     " 10 permit tcp 10.0.0.0 0.0.0.255 any eq 22\n"
     " 20 permit ip any any\n"
     " 30 deny tcp any any eq 23\n"
     " 40 deny ip any any log\n",
     {"F04": {("L06", 3), ("L01", 4), ("L01", 5)}}),
    ("F05_L08_log_on_wide_permit",
     "ip access-list extended F05\n"
     " 10 permit tcp any host 10.0.0.10 eq 443 log\n"
     " 20 deny ip any any log\n",
     {"F05": {("L08", 2)}}),
    ("F06_L09_remark_at_end",
     "ip access-list extended F06\n"
     " 10 permit tcp 10.0.0.0 0.0.0.255 host 10.0.0.1 eq 22\n"
     " 20 deny ip any any log\n"
     " 30 remark old rule removed\n",
     {"F06": {("L09", 4)}}),
    ("F07_L11_partial_overlap",
     "ip access-list extended F07\n"
     " 10 permit tcp 10.0.0.0 0.0.0.255 any\n"
     " 20 deny tcp any any eq 23\n"
     " 30 deny ip any any log\n",
     {"F07": {("L11", 3)}}),
    ("F08_named_seq_out_of_text_order",
     "ip access-list extended F08\n"
     " 30 deny ip any any log\n"
     " 10 permit tcp 10.0.0.0 0.0.0.255 host 10.0.0.10 eq 443\n"
     " 20 permit tcp 10.0.0.0 0.0.0.255 host 10.0.0.10 eq 80\n",
     {"F08": set()}),
    ("F09_neq_vs_eq_same_service",
     "ip access-list extended F09\n"
     " 10 deny tcp any host 10.0.0.1 eq telnet\n"
     " 20 permit tcp 10.0.0.0 0.0.0.255 host 10.0.0.1 neq 23\n"
     " 30 deny tcp 10.0.0.0 0.0.0.255 host 10.0.0.1 eq 22\n"
     " 40 deny ip any any log\n",
     {"F09": {("L01", 4)}}),
    ("F10_range_inside_range",
     "ip access-list extended F10\n"
     " 10 permit udp any host 10.0.0.5 range 1000 2000\n"
     " 20 deny udp any host 10.0.0.5 range 1500 1600\n"
     " 30 deny ip any any log\n",
     {"F10": {("L01", 3)}}),
    ("F11_ip_contains_tcp",
     "ip access-list extended F11\n"
     " 10 deny ip host 10.1.1.1 any\n"
     " 20 permit tcp host 10.1.1.1 any eq 80\n"
     " 30 deny ip any any log\n",
     {"F11": {("L01", 3)}}),
    ("F12_host_vs_slash32_wildcard",
     "ip access-list extended F12\n"
     " 10 permit tcp host 10.0.0.5 host 10.0.0.1 eq 22\n"
     " 20 permit tcp 10.0.0.5 0.0.0.0 host 10.0.0.1 eq 22\n"
     " 30 deny ip any any log\n",
     {"F12": {("L03", 3)}}),
    ("F13_port_name_www_vs_80",
     "ip access-list extended F13\n"
     " 10 permit tcp 10.0.0.0 0.0.0.255 host 10.0.0.10 eq www\n"
     " 20 permit tcp 10.0.0.0 0.0.0.255 host 10.0.0.10 eq 80\n"
     " 30 deny ip any any log\n",
     {"F13": {("L03", 3)}}),
    ("F14_object_group_not_evaluated",
     "ip access-list extended F14\n"
     " 10 permit tcp object-group ADMINS host 10.0.0.1 eq 22\n"
     " 20 permit tcp 10.0.0.0 0.0.0.255 host 10.0.0.1 eq 22\n"
     " 30 deny ip any any log\n",
     {"F14": set()}),
    ("F15_clean_acl",
     "ip access-list extended CLEAN-IN\n"
     " 10 remark management from the admin subnet\n"
     " 20 permit tcp 10.10.0.0 0.0.0.255 host 10.0.0.1 eq 22\n"
     " 30 permit udp 10.10.0.0 0.0.0.255 host 10.0.0.2 eq snmp\n"
     " 40 permit icmp 10.10.0.0 0.0.0.255 any\n"
     " 50 deny ip any any log\n",
     {"CLEAN-IN": set()}),
    # ---- 1 from the user's lab of 2026-10-22 (WS-C3850-48T, IOS XE 16.12.13)
    ("LAB_same_acl_99_both_forms",
     "access-list 99 permit 10.1.1.5 0.0.0.255\n"
     "!\n"
     "ip access-list standard 99\n"
     " 10 permit 10.1.1.0 0.0.0.255\n",
     {"99": {("L03", 4), ("L04", 1), ("L07", 4)}}),
]


_BY_NAME = {f[0]: f[1] for f in FIXTURES}


def _found(result):
    return {a["acl"]: {(f["id"], f["line"]) for f in a["findings"]} for a in result["acls"]}


def test_fixture_count_is_21():
    assert len(FIXTURES) == 21
    assert len({f[0] for f in FIXTURES}) == 21


@pytest.mark.parametrize("name,paste,expected", FIXTURES, ids=[f[0] for f in FIXTURES])
def test_fixture_exact_findings(name, paste, expected):
    assert _found(lint(parse_acls(paste))) == expected


def test_fixture_score_100_percent_and_zero_false_alarms():
    expected_total = detected = false_alarms = 0
    for _, paste, expected in FIXTURES:
        got = _found(lint(parse_acls(paste)))
        for acl, exp in expected.items():
            expected_total += len(exp)
            detected += len(exp & got.get(acl, set()))
            false_alarms += len(got.get(acl, set()) - exp)
    assert detected == expected_total
    assert false_alarms == 0


# ---- finding format (spec section 3: id, line(s), quote 1:1, effect, proposal)

def test_finding_format_quote_and_levels():
    res = lint(parse_acls(_BY_NAME["T1_shadow_by_wider_mask"]))
    (f,) = res["acls"][0]["findings"]
    assert f["id"] == "L01" and f["level"] == "ERROR"
    assert f["lines"] == [3, 2]
    assert f["quote"] == ["20 permit tcp 10.1.1.0 0.0.0.255 any eq 443", "10 deny ip 10.1.0.0 0.0.255.255 any"]
    assert f["effect"].endswith(".") and f["proposal"]
    assert res["totals"] == {"ERROR": 1, "WARN": 0, "INFO": 0}


def test_l03_log_message():
    (f,) = lint(parse_acls(_BY_NAME["T3_duplicate_with_other_log"]))["acls"][0]["findings"]
    assert "log on line 3 never logs" in f["effect"]


def test_l04_message_matches_lab():
    (f,) = lint(parse_acls(_BY_NAME["F02_L04_host_bits"]))["acls"][0]["findings"]
    assert "`10.1.1.0 0.0.0.255`" in f["effect"] and "IOS XE 16.12.13" in f["effect"]
    assert "host 10.1.1.5" in f["proposal"]


def test_l10_says_heuristic_and_is_info():
    res = lint(parse_acls(_BY_NAME["T2_established_without_pair_2_acls"]))
    (f,) = [x for a in res["acls"] for x in a["findings"]]
    assert f["level"] == "INFO"
    assert f["effect"].startswith("Heuristic:")
    assert "heuristic" in f["proposal"]


# ---- L10 (Q3): silent with 1 ACL, silent when the pair exists

def test_l10_silent_with_single_acl():
    paste = ("ip access-list extended IN\n"
             " 10 permit tcp any eq 22 10.0.0.0 0.0.0.255 established\n"
             " 20 deny ip any any log\n")
    assert _found(lint(parse_acls(paste))) == {"IN": set()}


def test_l10_silent_when_other_acl_has_the_port_as_dst():
    paste = _BY_NAME["T2_established_without_pair_2_acls"].replace("eq 443", "eq 22")
    assert _found(lint(parse_acls(paste))) == {"OUT": set(), "IN": set()}


def test_l10_silent_for_established_without_src_port():
    paste = _BY_NAME["T2_established_without_pair_2_acls"].replace("any eq 22 10.0.0.0", "any 10.0.0.0")
    assert _found(lint(parse_acls(paste))) == {"OUT": set(), "IN": set()}


# ---- Q2 + lab fixture: one ACL, seq 10 tie keeps paste order, L03 judged

def test_lab_fixture_is_one_acl_and_order_is_q2():
    parsed = parse_acls(_BY_NAME["LAB_same_acl_99_both_forms"])
    assert list(parsed.acls) == ["99"]
    rules = [e for e in parsed.acls["99"].entries if e.kind == "rule"]
    assert [(e.line, e.seq) for e in rules] == [(1, 10), (4, 10)]
    f = [x for x in lint(parsed)["acls"][0]["findings"] if x["id"] == "L03"][0]
    assert f["lines"] == [4, 1]


def test_object_group_line_listed_as_not_evaluated():
    res = lint(parse_acls(_BY_NAME["F14_object_group_not_evaluated"]))
    assert [n["line"] for n in res["acls"][0]["not_evaluated"]] == [2]
    assert parse_acls(_BY_NAME["F14_object_group_not_evaluated"]).acls["F14"].entries[0].status == STATUS_NOT_EVALUATED


# ---- L07 / L09 / L06 edges

def test_l07_silent_when_last_rule_is_permit_any_any():
    paste = "ip access-list extended X\n 10 deny tcp any any eq 23\n 20 permit ip any any\n"
    assert _found(lint(parse_acls(paste))) == {"X": set()}


def test_l07_on_unlogged_explicit_deny():
    paste = "ip access-list extended X\n 10 permit tcp 10.0.0.0 0.0.0.255 any eq 22\n 20 deny ip any any\n"
    res = lint(parse_acls(paste))
    assert _found(res) == {"X": {("L07", 3)}}
    assert "logs nothing" in res["acls"][0]["findings"][0]["effect"]


def test_l07_standard_uses_deny_any_log():
    res = lint(parse_acls("access-list 5 permit 10.0.0.0 0.0.0.255\n"))
    assert "`deny any log`" in res["acls"][0]["findings"][0]["proposal"]


def test_l09_remark_followed_by_remark():
    paste = ("ip access-list extended X\n remark one\n remark two\n"
             " permit tcp 10.0.0.0 0.0.0.255 any eq 22\n deny ip any any log\n")
    assert _found(lint(parse_acls(paste))) == {"X": {("L09", 2)}}


def test_l06_standard_any_not_last():
    paste = "access-list 5 permit any\naccess-list 5 deny 10.0.0.0 0.0.0.255\naccess-list 5 deny any log\n"
    assert _found(lint(parse_acls(paste))) == {"5": {("L06", 1), ("L01", 2), ("L01", 3)}}


def test_l08_standard_only_src_any_counts():
    paste = "access-list 5 permit host 10.0.0.1 log\naccess-list 5 deny any log\n"
    assert _found(lint(parse_acls(paste))) == {"5": set()}
    paste = "access-list 5 deny 10.0.0.0 0.0.0.255\naccess-list 5 permit any log\n"
    assert ("L08", 2) in _found(lint(parse_acls(paste)))["5"]


# ---- containment (spec section 2)

def _addr(text):
    return parse_acls("access-list 5 permit %s\n" % text).acls["5"].entries[0].rule.src


def test_address_containment_contiguous_and_non_contiguous():
    any_ = _addr("any")
    net16 = _addr("10.1.0.0 0.0.255.255")
    net24 = _addr("10.1.1.0 0.0.0.255")
    odd = _addr("10.0.0.0 0.0.255.0")  # 10.0.x.0
    assert address_contains(any_, net16) and address_contains(net16, net24)
    assert not address_contains(net24, net16)
    assert address_contains(odd, _addr("host 10.0.7.0"))
    assert not address_contains(odd, _addr("host 10.0.7.1"))
    assert address_contains(_addr("10.0.0.0 0.255.255.0"), odd)
    assert not address_contains(odd, _addr("10.0.0.0 0.0.255.255"))
    assert address_intersects(odd, _addr("10.0.5.0 0.0.0.255"))
    assert not address_intersects(odd, _addr("10.1.0.0 0.0.255.255"))


def test_ports_containment_with_neq_gap():
    neq80 = ((0, 79), (81, 65535))
    assert ports_contain(neq80, ((100, 200),))
    assert not ports_contain(neq80, ((70, 90),))


def _rule(line):
    return parse_acls("access-list 110 %s\n" % line).acls["110"].entries[0].rule


def test_rule_containment_dimensions():
    assert rule_contains(_rule("permit ip any any"), _rule("deny tcp host 1.1.1.1 any eq 22"))
    assert not rule_contains(_rule("permit tcp any any eq 22"), _rule("permit ip any any"))
    assert not rule_contains(_rule("permit udp any any"), _rule("permit tcp any any"))
    # established: A without the flag contains B with it, not the other way round
    plain = _rule("permit tcp any any")
    est = _rule("permit tcp any any established")
    assert rule_contains(plain, est) and not rule_contains(est, plain)
    # protocol number 6 = tcp
    assert rule_contains(_rule("permit 6 any any"), _rule("permit tcp any any eq 80"))
    assert rules_intersect(_rule("permit tcp 10.0.0.0 0.0.0.255 any"), _rule("deny tcp any any eq 23"))
    assert not rules_intersect(_rule("permit tcp any any eq 23"), _rule("deny tcp any any neq 23"))


def test_lint_deterministic_json():
    paste = "".join(f[1] for f in FIXTURES[:6])
    assert lint_json(parse_acls(paste)) == lint_json(parse_acls(paste))
