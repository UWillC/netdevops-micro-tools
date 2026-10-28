"""
ACL-01.1 parser + what-if trace engine (services/acl_engine.py), offline.

Acceptance AC1-AC9 from the ACL-01.1 backlog entry (CEO repo
projects/netdevops/backlog.md) and spec_acl-01_v0_2026-10-22.md. Golden inputs
for AC1-AC3 are the user's lab of 2026-10-22 (WS-C3850-48T, IOS XE 16.12.13):
`access-list 99 permit 10.1.1.5 0.0.0.255` was written back by IOS as
` 10 permit 10.1.1.0 0.0.0.255` under `ip access-list standard 99`, and the same
for extended `permit tcp 10.1.1.5 0.0.0.255 any eq 22`.
"""

import pytest

from services.acl_engine import (
    STATUS_NOT_EVALUATED,
    STATUS_OK,
    STATUS_P01,
    Packet,
    parse_acls,
    trace,
    trace_json,
)


def _rules(acl):
    return [e for e in acl.entries if e.kind == "rule"]


def _semantic(rule_dict):
    """Rule model without the as-written fields (AC2: identical except original)."""
    d = dict(rule_dict)
    for side in ("src", "dst"):
        d[side] = {k: v for k, v in d[side].items() if k not in ("original", "original_address")}
    for side in ("src_ports", "dst_ports"):
        if d[side] is not None:
            d[side] = {k: v for k, v in d[side].items() if k != "original"}
    return d


def _tcp(src, dst, dport, sport=50000, established=False):
    return Packet(src=src, dst=dst, protocol="tcp", src_port=sport, dst_port=dport,
                  established=established)


def _udp(src, dst, dport, sport=50000):
    return Packet(src=src, dst=dst, protocol="udp", src_port=sport, dst_port=dport)


# ---------------------------------------------------------------- AC1

AC1_TEXT = "access-list 99 permit 10.1.1.5 0.0.0.255\n"


def test_ac1_l04_std_normalized_and_original_kept():
    parsed = parse_acls(AC1_TEXT)
    acl = parsed.acls["99"]
    assert acl.acl_type == "standard"
    (entry,) = _rules(acl)
    assert entry.status == STATUS_OK
    src = entry.rule.to_dict()["src"]
    assert src["address"] == "10.1.1.0"
    assert src["wildcard"] == "0.0.0.255"
    assert src["original_address"] == "10.1.1.5"
    assert src["original"] == "10.1.1.5 0.0.0.255"


def test_ac1_l04_std_trace_permit_in_wildcard():
    parsed = parse_acls(AC1_TEXT)
    res = trace(parsed, "99", Packet(src="10.1.1.200"))
    assert res["verdict"] == "permit"
    assert res["matched_line"] == 1
    assert res["implicit_deny"] is False
    assert res["path"] == [{"line": 1, "matched": True, "reason": "match"}]


def test_ac1_l04_std_trace_implicit_deny_outside():
    parsed = parse_acls(AC1_TEXT)
    res = trace(parsed, "99", Packet(src="10.1.2.1"))
    assert res["verdict"] == "deny"
    assert res["implicit_deny"] is True
    assert res["matched_line"] is None
    assert res["path"][0]["matched"] is False
    assert res["path"][0]["reason"].startswith("src ")


# ---------------------------------------------------------------- AC2

AC2_TEXT = "ip access-list standard 99\n 10 permit 10.1.1.0 0.0.0.255\n"


def test_ac2_show_run_std_same_model_as_ac1():
    a = _rules(parse_acls(AC1_TEXT).acls["99"])[0]
    b = _rules(parse_acls(AC2_TEXT).acls["99"])[0]
    assert b.seq == 10 and b.explicit_seq
    assert parse_acls(AC2_TEXT).acls["99"].acl_type == "standard"
    assert _semantic(a.rule.to_dict()) == _semantic(b.rule.to_dict())
    assert b.rule.to_dict()["src"]["original_address"] == "10.1.1.0"


def test_ac2_show_run_std_same_trace_as_ac1():
    a, b = parse_acls(AC1_TEXT), parse_acls(AC2_TEXT)
    for src, verdict in (("10.1.1.200", "permit"), ("10.1.2.1", "deny")):
        ra, rb = trace(a, "99", Packet(src=src)), trace(b, "99", Packet(src=src))
        assert ra["verdict"] == rb["verdict"] == verdict
        assert ra["implicit_deny"] == rb["implicit_deny"]
    # line numbers differ by form (line 1 vs line 2), verdict path does not
    assert trace(b, "99", Packet(src="10.1.1.200"))["matched_line"] == 2


# ---------------------------------------------------------------- AC3

AC3_NUMBERED = "access-list 110 permit tcp 10.1.1.5 0.0.0.255 any eq 22\n"
AC3_NAMED = "ip access-list extended 110\n 10 permit tcp 10.1.1.0 0.0.0.255 any eq 22\n"


def test_ac3_l04_ext_both_forms_equivalent():
    a = _rules(parse_acls(AC3_NUMBERED).acls["110"])[0].rule.to_dict()
    b = _rules(parse_acls(AC3_NAMED).acls["110"])[0].rule.to_dict()
    assert a["src"]["address"] == "10.1.1.0" and a["src"]["original_address"] == "10.1.1.5"
    assert _semantic(a) == _semantic(b)
    assert a["dst_ports"]["intervals"] == [[22, 22]]


@pytest.mark.parametrize("text,line", [(AC3_NUMBERED, 1), (AC3_NAMED, 2)])
def test_ac3_l04_ext_trace_permit_and_dst_port_reason(text, line):
    parsed = parse_acls(text)
    ok = trace(parsed, "110", _tcp("10.1.1.9", "8.8.8.8", 22))
    assert ok["verdict"] == "permit" and ok["matched_line"] == line
    no = trace(parsed, "110", _tcp("10.1.1.9", "8.8.8.8", 23))
    assert no["verdict"] == "deny" and no["implicit_deny"] is True and no["matched_line"] is None
    assert no["path"] == [{"line": line, "matched": False, "reason": "dst port 23 ∉ eq 22"}]


# ---------------------------------------------------------------- AC4

AC4_TEXT = """\
access-list 99 permit 10.1.1.5 0.0.0.255
access-list 99 deny 192.168.0.0 0.0.255.255
!
ip access-list standard 99
 10 permit 10.1.1.0 0.0.0.255
 15 deny host 172.16.0.1
"""


def test_ac4_both_forms_one_acl_ordered_by_q2():
    parsed = parse_acls(AC4_TEXT)
    assert list(parsed.acls) == ["99"]
    acl = parsed.acls["99"]
    assert acl.forms == ["numbered", "named"]
    # Q2: seq-less lines get 10, 20 in paste order; sort by seq, ties keep paste order
    assert [(e.line, e.seq) for e in acl.entries] == [(1, 10), (5, 10), (6, 15), (2, 20)]
    # identical rules from both forms are both kept (L03 in ACL-01.2)
    assert _semantic(acl.entries[0].rule.to_dict()) == _semantic(acl.entries[1].rule.to_dict())


def test_ac4_trace_follows_merged_order():
    parsed = parse_acls(AC4_TEXT)
    res = trace(parsed, "99", Packet(src="192.168.5.5"))
    assert res["verdict"] == "deny" and res["matched_line"] == 2
    assert [p["line"] for p in res["path"]] == [1, 5, 6, 2]
    res = trace(parsed, "99", Packet(src="172.16.0.1"))
    assert res["matched_line"] == 6


def test_ac4_named_seq_out_of_text_order_sorted():
    parsed = parse_acls("ip access-list extended EDGE\n 30 deny ip any any\n 10 permit tcp any any eq 22\n")
    acl = parsed.acls["EDGE"]
    assert [e.seq for e in acl.entries] == [10, 30]
    assert trace(parsed, "EDGE", _tcp("1.1.1.1", "2.2.2.2", 22))["matched_line"] == 3


def test_ac4_remark_stays_before_its_rule():
    parsed = parse_acls("ip access-list standard R\n remark mgmt\n 20 permit host 10.0.0.1\n 10 deny any\n")
    acl = parsed.acls["R"]
    # remark has no seq of its own; it sorts in front of the rule that followed it
    assert [(e.kind, e.line) for e in acl.entries] == [("rule", 4), ("remark", 2), ("rule", 3)]
    assert acl.entries[1].seq is None
    assert acl.entries[1].remark == "mgmt"


# ---------------------------------------------------------------- AC5


def _first_rule(text, name):
    return _rules(parse_acls(text).acls[name])[0]


def test_ac5_www_equals_80_tcp():
    a = _first_rule("access-list 101 permit tcp any any eq www\n", "101").rule.to_dict()
    b = _first_rule("access-list 101 permit tcp any any eq 80\n", "101").rule.to_dict()
    assert _semantic(a) == _semantic(b)
    assert a["dst_ports"]["original"] == "eq www"


def test_ac5_udp_snmp_is_161():
    e = _first_rule("access-list 101 permit udp any any eq snmp\n", "101")
    assert e.status == STATUS_OK
    assert e.rule.dst_ports.intervals == ((161, 161),)


def test_ac5_tcp_snmp_is_p01():
    e = _first_rule("access-list 101 permit tcp any any eq snmp\n", "101")
    assert e.status == STATUS_P01 and e.line == 1
    assert "UDP name" in e.reason


def test_ac5_514_cmd_tcp_syslog_udp():
    cmd = _first_rule("access-list 101 permit tcp any any eq cmd\n", "101").rule
    syslog = _first_rule("access-list 101 permit udp any any eq syslog\n", "101").rule
    assert cmd.dst_ports.intervals == ((514, 514),) == syslog.dst_ports.intervals
    assert cmd.protocol == "tcp" and syslog.protocol == "udp"
    # and the swap is P01 both ways (Annex A pitfall 1)
    assert _first_rule("access-list 101 permit tcp any any eq syslog\n", "101").status == STATUS_P01
    assert _first_rule("access-list 101 permit udp any any eq cmd\n", "101").status == STATUS_P01


def test_ac5_neq_is_two_intervals():
    e = _first_rule("access-list 101 permit tcp any any neq 80\n", "101")
    assert e.rule.dst_ports.intervals == ((0, 79), (81, 65535))


# ---------------------------------------------------------------- AC6

P01_CASES = [
    ("port in standard", "access-list 10 permit 10.1.1.0 0.0.0.255 eq 22", "port in a standard ACL"),
    ("established on udp", "access-list 110 permit udp any any eq 53 established", "only for tcp"),
    ("port name outside table", "access-list 110 permit tcp any any eq ssh", "not in the TCP port table"),
    ("port name from other table", "access-list 110 permit udp any any eq telnet", "TCP name"),
]


@pytest.mark.parametrize("label,line,needle", P01_CASES, ids=[c[0] for c in P01_CASES])
def test_ac6_p01_with_line_number(label, line, needle):
    text = "hostname R1\n!\n" + line + "\n"
    parsed = parse_acls(text)
    (entry,) = [e for a in parsed.acls.values() for e in a.entries]
    assert entry.status == STATUS_P01
    assert entry.line == 3
    assert needle in entry.reason


def test_ac6_object_group_not_evaluated_rest_still_evaluated():
    text = (
        "ip access-list extended EDGE-IN\n"
        " 10 permit object-group WEB any any\n"
        " 20 permit tcp any host 10.0.0.1 eq 443\n"
        " 30 deny ip any any log\n"
    )
    parsed = parse_acls(text)
    acl = parsed.acls["EDGE-IN"]
    assert [e.status for e in acl.entries] == [STATUS_NOT_EVALUATED, STATUS_OK, STATUS_OK]
    assert "object-group" in acl.entries[0].reason
    res = trace(parsed, "EDGE-IN", _tcp("1.2.3.4", "10.0.0.1", 443))
    assert res["verdict"] == "permit" and res["matched_line"] == 3
    assert res["unevaluated_lines"] == [2]
    assert res["path"][0]["reason"].startswith("NOT_EVALUATED: object-group")


@pytest.mark.parametrize("line,needle", [
    ("access-list 110 permit tcp any any eq 22 time-range WORK", "time-range"),
    ("access-list 110 permit ip any any fragments", "fragments"),
    ("access-list 110 permit icmp any any echo", "ICMP"),
    ("access-list 110 permit ip any any dscp ef", "dscp"),
    ("access-list 110 permit gre any any", "protocol 'gre'"),
])
def test_out_of_v0_lines_are_not_evaluated_never_dropped(line, needle):
    parsed = parse_acls(line + "\n")
    (entry,) = parsed.acls["110"].entries
    assert entry.status == STATUS_NOT_EVALUATED and needle in entry.reason


def test_ipv6_acl_is_reported_not_dropped():
    parsed = parse_acls("ipv6 access-list V6\n permit ipv6 any any\n")
    assert parsed.acls == {}
    assert [n["line"] for n in parsed.not_evaluated] == [1, 2]


# ---------------------------------------------------------------- AC7


def test_ac7_noncontiguous_wildcard_per_spec_formula():
    """Spec section 2: match <=> (pkt & ~wc) == (addr & ~wc).

    `10.0.5.0 0.0.255.0` leaves the THIRD octet free and fixes the fourth to 0,
    so 10.0.6.0 matches and 10.0.5.7 does not. The AC7 text in the backlog says
    the opposite; that contradicts the formula and is reported as an AC defect.
    """
    parsed = parse_acls("access-list 10 permit 10.0.5.0 0.0.255.0\n")
    src = _first_rule("access-list 10 permit 10.0.5.0 0.0.255.0\n", "10").rule.to_dict()["src"]
    assert src["address"] == "10.0.0.0" and src["wildcard"] == "0.0.255.0"
    assert trace(parsed, "10", Packet(src="10.0.6.0"))["verdict"] == "permit"
    assert trace(parsed, "10", Packet(src="10.0.200.0"))["verdict"] == "permit"
    res = trace(parsed, "10", Packet(src="10.0.5.7"))
    assert res["verdict"] == "deny" and res["implicit_deny"] is True
    assert trace(parsed, "10", Packet(src="10.1.5.0"))["verdict"] == "deny"


def test_ac7_noncontiguous_wildcard_ac_sample_packets():
    """The AC7 packets (10.0.5.7 in, 10.0.6.0 out) hold for wildcard 0.255.0.255."""
    parsed = parse_acls("access-list 10 permit 10.0.5.0 0.255.0.255\n")
    assert trace(parsed, "10", Packet(src="10.0.5.7"))["verdict"] == "permit"
    assert trace(parsed, "10", Packet(src="10.77.5.1"))["verdict"] == "permit"
    res = trace(parsed, "10", Packet(src="10.0.6.0"))
    assert res["verdict"] == "deny" and res["implicit_deny"] is True


# ---------------------------------------------------------------- AC8


def test_ac8_established():
    parsed = parse_acls("access-list 120 permit tcp any 10.0.0.0 0.0.0.255 established\n")
    assert _first_rule("access-list 120 permit tcp any 10.0.0.0 0.0.0.255 established\n", "120").rule.established
    no = trace(parsed, "120", _tcp("8.8.8.8", "10.0.0.5", 51000, sport=443))
    assert no["verdict"] == "deny" and no["implicit_deny"] is True
    assert no["path"][0]["reason"].startswith("established")
    yes = trace(parsed, "120", _tcp("8.8.8.8", "10.0.0.5", 51000, sport=443, established=True))
    assert yes["verdict"] == "permit" and yes["matched_line"] == 1


# ---------------------------------------------------------------- AC9

AC9_TEXT = AC4_TEXT + AC3_NAMED + (
    "ip access-list extended EDGE-IN\n"
    " remark web\n"
    " 10 permit object-group WEB any any\n"
    " 20 permit udp any any eq snmp\n"
    " 30 deny ip any any log\n"
)


def test_ac9_deterministic_json():
    a = parse_acls(AC9_TEXT).to_json()
    b = parse_acls(AC9_TEXT).to_json()
    assert a == b
    pkt = _udp("1.1.1.1", "2.2.2.2", 161)
    assert trace_json(parse_acls(AC9_TEXT), "EDGE-IN", pkt) == trace_json(parse_acls(AC9_TEXT), "EDGE-IN", pkt)


def test_trace_contract_keys():
    res = trace(parse_acls(AC9_TEXT), "EDGE-IN", _udp("1.1.1.1", "2.2.2.2", 161))
    assert set(res) == {"acl", "verdict", "matched_line", "implicit_deny", "path", "unevaluated_lines"}
    for step in res["path"]:
        assert set(step) == {"line", "matched", "reason"}


def test_extended_trace_input_validation():
    parsed = parse_acls(AC3_NUMBERED)
    with pytest.raises(ValueError):
        trace(parsed, "110", Packet(src="10.1.1.9"))  # no dst / protocol
    with pytest.raises(ValueError):
        trace(parsed, "110", Packet(src="10.1.1.9", dst="8.8.8.8", protocol="tcp"))  # no ports
    with pytest.raises(KeyError):
        trace(parsed, "nope", Packet(src="10.1.1.9"))


def test_non_ace_subcommand_takes_no_seq_and_is_reported():
    text = "ip access-list extended 110\n permit tcp any any eq 22\n statistics per-entry\n" \
           "access-list 110 deny ip any any\n"
    acl = parse_acls(text).acls["110"]
    assert [(e.line, e.seq, e.status) for e in acl.entries] == [
        (2, 10, STATUS_OK), (3, None, STATUS_NOT_EVALUATED), (4, 20, STATUS_OK)]


def test_non_acl_config_lines_are_listed():
    parsed = parse_acls("hostname R1\ninterface Gi1\n ip access-group 10 in\n!\naccess-list 10 permit any\n")
    assert parsed.other_lines == [1, 2, 3]
    assert list(parsed.acls) == ["10"]
