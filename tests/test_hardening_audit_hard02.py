"""HARD-02: login attack surface (VTY brute force), rule 1.2.11.

Acceptance (backlog HARD-02):
  FAIL     no `login block-for N attempts M within S`
  WARNING  block-for set, but `login on-failure log` or `login on-success log` missing
  INFO     `login delay`, `ip ssh logging events`: named in the evidence only,
           they never change the result
  Golden PASS / FAIL per platform: IOS classic (15.x) and IOS-XE (17.x), run
  through the whole audit, not just the check function.
"""
import pytest

from api.routers import cis_audit as audit
from api.routers.cis_audit import AuditRequest, cis_audit

RULE_ID = "1.2.11"

IOS_CLASSIC_HEAD = """version 15.2
service timestamps log datetime msec
hostname ISR2911-BRANCH
!
boot-start-marker
boot system flash:c2900-universalk9-mz.SPA.152-4.M11.bin
boot-end-marker
!
aaa new-model
aaa authentication login default group tacacs+ local
!
ip ssh version 2
"""

IOS_XE_HEAD = """version 17.9
service timestamps log datetime msec localtime show-timezone
platform qfp utilization monitor load 80
hostname C8300-EDGE
!
boot system bootflash:c8000be-universalk9.17.09.04a.SPA.bin
!
aaa new-model
aaa authentication login default group tacacs+ local
!
ip ssh version 2
"""

LOGIN_HARDENED = """login block-for 120 attempts 3 within 60
login delay 2
login on-failure log
login on-success log
ip ssh logging events
!
"""

IOS_CLASSIC_VTY = """line con 0
 exec-timeout 5 0
line vty 0 4
 access-class MGMT in
 exec-timeout 5 0
 transport input ssh
line vty 5 15
 access-class MGMT in
 exec-timeout 5 0
 transport input ssh
!
end
"""

IOS_XE_VTY = """line con 0
 exec-timeout 5 0
 stopbits 1
line vty 0 4
 access-class MGMT in vrf-also
 exec-timeout 5 0
 transport input ssh
line vty 5 31
 access-class MGMT in vrf-also
 exec-timeout 5 0
 transport input ssh
!
end
"""

GOLDENS = {
    "ios-classic-pass": (IOS_CLASSIC_HEAD + LOGIN_HARDENED + IOS_CLASSIC_VTY, "PASS"),
    "ios-classic-fail": (IOS_CLASSIC_HEAD + "!\n" + IOS_CLASSIC_VTY, "FAIL"),
    "ios-xe-pass": (IOS_XE_HEAD + LOGIN_HARDENED + IOS_XE_VTY, "PASS"),
    "ios-xe-fail": (IOS_XE_HEAD + "!\n" + IOS_XE_VTY, "FAIL"),
}


def _rule(cfg, level="1"):
    resp = cis_audit(AuditRequest(config_text=cfg, level=level))
    rules = [r for c in resp.categories for r in c.rules if r.rule_id == RULE_ID]
    assert len(rules) == 1
    return rules[0]


# ---------- golden PASS / FAIL per platform ----------

@pytest.mark.parametrize("name", sorted(GOLDENS))
@pytest.mark.parametrize("level", ["1", "2"])
def test_golden_per_platform(name, level):
    cfg, expected = GOLDENS[name]
    rule = _rule(cfg, level)
    assert rule.result == expected
    assert rule.category == "Access" and rule.severity == "high"
    if expected == "PASS":
        assert rule.evidence == ("login block-for 120 attempts 3 within 60; "
                                 "failed and successful logins logged.")
        assert rule.remediation == ""
    else:
        assert rule.evidence.startswith("No 'login block-for'")
        assert "login block-for 120 attempts 3 within 60" in rule.remediation
        assert "login on-failure log" in rule.remediation
        assert "login on-success log" in rule.remediation


def test_indented_paste_reads_the_same():
    cfg, _ = GOLDENS["ios-xe-pass"]
    indented = "\n".join("  " + ln for ln in cfg.splitlines())
    assert _rule(indented).result == "PASS"


# ---------- WARNING: login logging ----------

@pytest.mark.parametrize("drop,missing", [
    ("login on-failure log\n", "login on-failure log"),
    ("login on-success log\n", "login on-success log"),
])
@pytest.mark.parametrize("head,vty", [(IOS_CLASSIC_HEAD, IOS_CLASSIC_VTY), (IOS_XE_HEAD, IOS_XE_VTY)],
                         ids=["ios-classic", "ios-xe"])
def test_missing_login_logging_warns(head, vty, drop, missing):
    rule = _rule(head + LOGIN_HARDENED.replace(drop, "") + vty)
    assert rule.result == "WARNING"
    assert missing in rule.evidence
    assert rule.remediation == "Add: " + missing


def test_both_logging_lines_missing_warns_with_both():
    result, evidence, fix = audit._check_login_block_for(
        "login block-for 60 attempts 5 within 30\nline vty 0 4\n")
    assert result == "WARNING"
    assert "login block-for 60 attempts 5 within 30" in evidence
    assert fix == "Add: login on-failure log; login on-success log"


def test_logging_with_every_keyword_counts():
    cfg = ("login block-for 120 attempts 3 within 60\nlogin on-failure log every 10\n"
           "login on-success log every 5\nline vty 0 4\n")
    assert audit._check_login_block_for(cfg)[0] == "PASS"


# ---------- INFO: never changes the result ----------

def test_info_items_are_named_but_do_not_change_pass():
    cfg = ("login block-for 120 attempts 3 within 60\nlogin on-failure log\n"
           "login on-success log\nline vty 0 4\n")
    result, evidence, fix = audit._check_login_block_for(cfg)
    assert result == "PASS" and fix == ""
    assert evidence.endswith("Info: no 'login delay' (IOS applies 1 s while login block-for is set); "
                             "no 'ip ssh logging events'.")


def test_info_items_alone_do_not_rescue_a_fail():
    cfg = "login delay 2\nip ssh logging events\nline vty 0 4\n"
    result, evidence, _ = audit._check_login_block_for(cfg)
    assert result == "FAIL"
    assert "Info" not in evidence


# ---------- what does not count ----------

@pytest.mark.parametrize("line", [
    "no login block-for 120 attempts 3 within 60",
    "! login block-for 120 attempts 3 within 60",
    "login block-for 120 attempts 3",               # incomplete, rejected by IOS
    "login quiet-mode access-class MGMT",           # quiet-mode alone is not a block-for
    " login block-for 120 attempts 3 within 60",    # inside a line block = not global
])
def test_not_a_global_block_for(line):
    cfg = "hostname r\n%s\nline vty 0 4\n transport input ssh\n" % line
    assert audit._check_login_block_for(cfg)[0] == "FAIL"


def test_no_vty_lines_is_not_applicable():
    assert audit._check_login_block_for("hostname r\nlogin on-failure log\n")[0] == "N/A"


# ---------- registration ----------

def test_rule_is_registered_at_level_1_with_references():
    row = [r for r in audit.RULES if r[0] == RULE_ID]
    assert row == [(RULE_ID, "Login brute-force protection", "Access", "high", "1",
                    audit._check_login_block_for)]
    refs = audit.REFERENCES[RULE_ID]
    assert refs[0].endswith("§4.6 Limit authentication attempts")
    assert "login block-for" in refs[1]
