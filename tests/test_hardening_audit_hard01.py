"""HARD-01: five tightened rules, two registered rules, references, de-branding.

Thresholds come from the NSA Network Infrastructure Security Guide v1.2:
  7.5  "session timeout ... five minutes or less"
  6.4  "at least two trustworthy and reliable time servers"
  4.2  central group first, "local" as the backup method
  4.4  accounting for exec sessions AND privilege-15 commands
"""
import re
from pathlib import Path

import pytest

from api.routers import cis_audit as audit

ROOT = Path(__file__).resolve().parent.parent


def _run(fn, cfg):
    result, evidence, remediation = fn(cfg)
    return result, evidence, remediation


# ---------- 1.2.5 exec-timeout ----------

@pytest.mark.parametrize("line,expected", [
    (" exec-timeout 5 0", "PASS"),
    (" exec-timeout 10 0", "PASS"),
    (" exec-timeout 15 0", "PASS"),
    (" exec-timeout 15 30", "WARNING"),
    (" exec-timeout 120 0", "WARNING"),
    (" exec-timeout 0 0", "FAIL"),
])
def test_exec_timeout_thresholds(line, expected):
    cfg = f"line vty 0 4\n{line}\n transport input ssh\n"
    assert _run(audit._check_exec_timeout, cfg)[0] == expected


def test_exec_timeout_between_nsa_and_warn_passes_but_says_so():
    result, evidence, _ = _run(audit._check_exec_timeout, "line vty 0 4\n exec-timeout 10 0\n")
    assert result == "PASS" and "NSA recommends 5 min" in evidence


def test_exec_timeout_worst_line_decides():
    cfg = "line con 0\n exec-timeout 5 0\nline vty 0 4\n exec-timeout 60 0\n"
    assert _run(audit._check_exec_timeout, cfg)[0] == "WARNING"


# ---------- 3.1.4 NTP redundancy ----------

def test_single_ntp_source_warns():
    result, evidence, fix = _run(audit._check_ntp_configured, "ntp server 10.0.0.1\n")
    assert result == "WARNING" and "single time source" in evidence and fix


def test_two_ntp_sources_pass():
    assert _run(audit._check_ntp_configured, "ntp server 10.0.0.1\nntp server 10.0.0.2\n")[0] == "PASS"


def test_same_ntp_server_twice_is_still_one_source():
    assert _run(audit._check_ntp_configured, "ntp server 10.0.0.1\nntp server 10.0.0.1 prefer\n")[0] == "WARNING"


def test_no_ntp_fails():
    assert _run(audit._check_ntp_configured, "hostname r1\n")[0] == "FAIL"


# ---------- 1.1.5 local fallback ----------

@pytest.mark.parametrize("line,expected", [
    ("aaa authentication login default group tacacs+ local", "PASS"),
    ("aaa authentication login default group MYGROUP local-case", "PASS"),
    ("aaa authentication login default group tacacs+ group radius local", "PASS"),
    ("aaa authentication login default group tacacs+", "WARNING"),
    ("aaa authentication login default group tacacs+ enable", "WARNING"),
    # a server group literally named "local" is not a fallback method
    ("aaa authentication login default group local", "WARNING"),
    ("aaa authentication login default local", "WARNING"),
])
def test_aaa_authentication_fallback(line, expected):
    assert _run(audit._check_aaa_authentication, f"aaa new-model\n{line}\n")[0] == expected


# ---------- 1.1.6 accounting ----------

def test_accounting_exec_only_warns_and_names_the_gap():
    result, evidence, fix = _run(
        audit._check_aaa_accounting,
        "aaa new-model\naaa accounting exec default start-stop group tacacs+\n")
    assert result == "WARNING" and "privilege-15 commands" in evidence and "commands 15" in fix


def test_accounting_commands_only_warns():
    result, evidence, _ = _run(
        audit._check_aaa_accounting,
        "aaa new-model\naaa accounting commands 15 default start-stop group tacacs+\n")
    assert result == "WARNING" and "exec sessions" in evidence


def test_accounting_commands_1_is_not_commands_15():
    cfg = ("aaa new-model\naaa accounting exec default start-stop group tacacs+\n"
           "aaa accounting commands 1 default start-stop group tacacs+\n")
    assert _run(audit._check_aaa_accounting, cfg)[0] == "WARNING"


def test_accounting_both_pass_none_fail():
    both = ("aaa new-model\naaa accounting exec default start-stop group tacacs+\n"
            "aaa accounting commands 15 default start-stop group tacacs+\n")
    assert _run(audit._check_aaa_accounting, both)[0] == "PASS"
    assert _run(audit._check_aaa_accounting, "aaa new-model\n")[0] == "FAIL"


# ---------- 5.1.1 community without ACL ----------

def test_community_without_acl_fails_and_says_which():
    result, evidence, fix = _run(audit._check_no_snmpv2, "snmp-server community n3tm0n RO\n")
    assert result == "FAIL" and "No ACL on: n3tm0n" in evidence and "<ACL>" in fix


def test_community_with_acl_still_fails_but_without_acl_note():
    result, evidence, _ = _run(audit._check_no_snmpv2, "snmp-server community n3tm0n RO 10\n")
    assert result == "FAIL" and "No ACL on" not in evidence


# ---------- two previously dead rules ----------

def test_dead_rules_are_registered():
    fns = {r[5] for r in audit.RULES}
    assert audit._check_rsa_key_size in fns and audit._check_no_finger in fns


def test_finger_enabled_fails():
    assert _run(audit._check_no_finger, "ip finger\n")[0] == "FAIL"
    assert _run(audit._check_no_finger, "service finger\n")[0] == "FAIL"
    assert _run(audit._check_no_finger, "no ip finger\n")[0] == "PASS"
    assert _run(audit._check_no_finger, "hostname r1\n")[0] == "PASS"


def test_rsa_key_size():
    assert _run(audit._check_rsa_key_size, "crypto key generate rsa modulus 1024\n")[0] == "FAIL"
    assert _run(audit._check_rsa_key_size, "crypto key generate rsa general-keys modulus 4096\n")[0] == "PASS"
    assert _run(audit._check_rsa_key_size, "hostname r1\n")[0] == "N/A"


def test_rule_ids_unique():
    ids = [r[0] for r in audit.RULES]
    assert len(ids) == len(set(ids))


# ---------- references ----------

def test_every_rule_has_a_primary_reference_and_nothing_else_does():
    ids = {r[0] for r in audit.RULES}
    assert set(audit.REFERENCES) == ids
    for rule_id, refs in audit.REFERENCES.items():
        assert refs, rule_id
        assert all(r.startswith(("NSA ", "Cisco")) for r in refs), (rule_id, refs)


def test_nsa_section_numbers_exist_in_the_guide():
    # top-level chapters of NISG v1.2 and how many subsections each has
    chapters = {2: 6, 3: 4, 4: 6, 5: 7, 6: 4, 7: 11, 8: 3, 9: 6, 10: 1}
    for refs in audit.REFERENCES.values():
        for ref in refs:
            m = re.search(r"§(\d+)\.(\d+) ", ref)
            if m:
                ch, sub = int(m.group(1)), int(m.group(2))
                assert ch in chapters and 1 <= sub <= chapters[ch], ref


def test_response_carries_references():
    from fastapi.testclient import TestClient
    from api.main import app
    client = TestClient(app)
    body = {"config_text": "hostname r1\nntp server 10.0.0.1\n", "level": "2"}
    new = client.post("/tools/hardening-audit/check", json=body)
    legacy = client.post("/tools/cis-audit/check", json=body)
    assert new.status_code == 200 and legacy.status_code == 200
    assert new.json() == legacy.json()
    rules = [r for c in new.json()["categories"] for r in c["rules"]]
    assert len(rules) == len(audit.RULES)
    assert all(r["references"] and r["cis_ref"] == r["references"][0] for r in rules)


# ---------- de-branding ----------

USER_FACING = ["web/index.html", "web/app-network.js", "web/app-core.js",
               "README.md", "ROADMAP.md", "api/routers/cis_audit.py", "api/main.py"]


@pytest.mark.parametrize("rel", USER_FACING)
def test_no_third_party_benchmark_mark_in_user_facing_text(rel):
    text = (ROOT / rel).read_text(encoding="utf-8")
    hits = [ln for ln in text.splitlines() if re.search(r"\bCIS\b", ln)]
    assert hits == [], hits[:3]


def test_audit_response_text_is_debranded():
    from fastapi.testclient import TestClient
    from api.main import app
    r = TestClient(app).post("/tools/hardening-audit/check",
                             json={"config_text": "hostname r1\n", "level": "2"})
    assert not re.search(r"\bCIS\b", r.text)


def test_ui_rule_counts_match_the_engine():
    html = (ROOT / "web/index.html").read_text(encoding="utf-8")
    l1 = sum(1 for r in audit.RULES if r[4] == "1")
    assert f"({l1} rules, recommended)" in html
    assert f"({len(audit.RULES)} rules, all checks)" in html
    assert f"**{len(audit.RULES)} rules**" in (ROOT / "README.md").read_text(encoding="utf-8")
