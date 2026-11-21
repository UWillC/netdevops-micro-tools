"""HARD-03b: closing the LOW recommendations of the @ciso HARD-03 review (19.11).

R1  every number a rule passes to int() is capped: 5000 digits -> HTTP 200, never a PASS
R2  a `version` line inside a banner does not decide the release
R5  evidence lists at most 5 tokens, then "and N more"
R7  the five S2 names marked [VERIFY] are known strong tokens
"""

import pytest
from fastapi.testclient import TestClient

from api import ssh_crypto
from api.main import app
from api.routers import cis_audit as audit
from api.routers.cis_audit import AuditRequest, cis_audit

HUGE = "9" * 5000
VTY = "line vty 0 4\n transport input ssh\n login local\n"

# (rule id, config with a 5000-digit number in that rule's numeric field)
NUMERIC_CASES = [
    ("1.2.2", f"ip ssh time-out {HUGE}\n"),
    ("1.2.3", f"ip ssh authentication-retries {HUGE}\n"),
    ("1.2.5", f"{VTY} exec-timeout {HUGE} 0\n"),
    ("1.2.5", f"{VTY} exec-timeout 5 {HUGE}\n"),
    ("1.2.10", f"crypto key generate rsa modulus {HUGE}\n"),
    ("1.2.11", f"{VTY}login block-for {HUGE} attempts 3 within 60\n"),
    ("1.2.11", f"{VTY}login block-for 120 attempts {HUGE} within 60\n"),
    ("1.2.11", f"{VTY}login block-for 120 attempts 3 within {HUGE}\n"),
    ("1.2.11", f"{VTY}aaa authentication attempts login {HUGE}\nlogin delay 2\n"),
    ("1.2.11", f"{VTY}aaa authentication attempts login 3\nlogin delay {HUGE}\n"),
    ("1.2.11", f"{VTY}ip ssh authentication-retries {HUGE}\nlogin delay 2\n"),
    ("1.2.12", f"ip ssh dh min size {HUGE}\n"),
    ("1.2.12", f"version {HUGE}.1\n"),
    ("1.2.12", f"version 17.{HUGE}\n"),
    ("3.1.1", f"logging buffered {HUGE}\n"),
    ("3.1.1", f"logging buffered 64000 {HUGE}\n"),
]


def _rule(cfg, rule_id):
    resp = cis_audit(AuditRequest(config_text="hostname r1\n" + cfg, level="2"))
    rules = [r for c in resp.categories for r in c.rules if r.rule_id == rule_id]
    assert len(rules) == 1
    return rules[0]


# ---------- R1 ----------

@pytest.mark.parametrize("rule_id,cfg", NUMERIC_CASES,
                         ids=[f"{r}-{c.replace(HUGE, 'N').strip().splitlines()[-1]}" for r, c in NUMERIC_CASES])
def test_huge_number_is_http_200_for_every_numeric_rule(rule_id, cfg):
    resp = TestClient(app).post("/tools/hardening-audit/check",
                                json={"config_text": "hostname r1\n" + cfg, "level": "2"})
    assert resp.status_code == 200
    rules = [r for c in resp.json()["categories"] for r in c["rules"] if r["rule_id"] == rule_id]
    assert len(rules) == 1
    # an invalid value never earns a PASS
    assert rules[0]["result"] != "PASS"


@pytest.mark.parametrize("cfg", [f"{VTY} exec-timeout {HUGE} 0\n", f"{VTY} exec-timeout 5 {HUGE}\n"],
                         ids=["minutes", "seconds"])
def test_huge_exec_timeout_warns_not_passes(cfg):
    r = _rule(cfg, "1.2.5")
    assert r.result == "WARNING"
    assert "not a valid IOS value" in r.evidence


@pytest.mark.parametrize("cfg,rule_id,expected", [
    ("ip ssh time-out 60\n", "1.2.2", "PASS"),
    ("ip ssh time-out 99999\n", "1.2.2", "WARNING"),
    ("ip ssh authentication-retries 3\n", "1.2.3", "PASS"),
    (f"{VTY} exec-timeout 5 0\n", "1.2.5", "PASS"),
    (f"{VTY} exec-timeout 35791 2147483\n", "1.2.5", "WARNING"),
    ("crypto key generate rsa modulus 2048\n", "1.2.10", "PASS"),
    ("crypto key generate rsa modulus 1024\n", "1.2.10", "FAIL"),
    ("logging buffered 2147483647 informational\n", "3.1.1", "PASS"),
    ("logging buffered 4096\n", "3.1.1", "WARNING"),
    (f"{VTY}login block-for 120 attempts 3 within 60\nlogin on-failure log\nlogin on-success log\n",
     "1.2.11", "PASS"),
])
def test_valid_numbers_keep_their_result(cfg, rule_id, expected):
    assert _rule(cfg, rule_id).result == expected


# ---------- R2 ----------

SSH_NO_ALGO_LINES = "ip ssh dh min size 4096\n"


def test_version_in_banner_gives_no_17_10_exemption():
    cfg = ("banner motd ^C\nversion 17.12\nAuthorized access only\n^C\n"
           "version 16.9\n" + SSH_NO_ALGO_LINES)
    result, evidence, _ = audit._check_ssh_crypto(audit._normalize_config(cfg))
    assert result == "WARNING"
    assert "17.10+" not in evidence


def test_version_in_one_line_banner_is_ignored():
    cfg = "banner login #version 17.12#\n" + SSH_NO_ALGO_LINES
    assert audit._ios_version(cfg) is None
    assert audit._check_ssh_crypto(cfg)[0] == "WARNING"


def test_version_outside_banner_still_counts():
    cfg = "version 17.12\nbanner motd ^C\nhello\n^C\n" + SSH_NO_ALGO_LINES
    assert audit._ios_version(cfg) == (17, 12)
    assert audit._check_ssh_crypto(cfg)[0] == "PASS"


def test_unterminated_banner_hides_the_rest_conservatively():
    # no closing delimiter: everything after is banner text, so no release is known
    cfg = "banner motd ^C\nversion 17.12\n" + SSH_NO_ALGO_LINES
    assert audit._ios_version(cfg) is None


# ---------- R5 ----------

def test_evidence_capped_at_five_tokens_for_10000_unknown():
    toks = " ".join(f"bogus{i}" for i in range(10000))
    cfg = (f"ip ssh server algorithm encryption {toks}\n"
           "ip ssh server algorithm mac hmac-sha2-256\n"
           "ip ssh server algorithm kex ecdh-sha2-nistp256\nip ssh dh min size 4096\n")
    result, evidence, _ = audit._check_ssh_crypto(cfg)
    assert result == "WARNING"
    assert len(evidence) < 1024
    assert "bogus0 bogus1 bogus2 bogus3 bogus4 and 9995 more" in evidence
    assert "bogus5 " not in evidence


def test_evidence_dedupes_and_caps_weak_tokens():
    weak = " ".join(["aes128-cbc"] * 50 + sorted(ssh_crypto.SSH_ENC_WEAK) * 3)
    cfg = f"ip ssh server algorithm encryption {weak}\nip ssh dh min size 4096\n"
    result, evidence, _ = audit._check_ssh_crypto(cfg)
    assert result == "FAIL"
    assert evidence.count("aes128-cbc") == 1
    assert "more" not in evidence.split("Also:")[0]  # 4 distinct weak tokens: no "and N more"


def test_six_distinct_tokens_show_and_1_more():
    toks = " ".join(f"x{i}" for i in range(6))
    cfg = f"ip ssh server algorithm encryption {toks}\nip ssh dh min size 4096\n"
    _, evidence, _ = audit._check_ssh_crypto(cfg)
    assert "x0 x1 x2 x3 x4 and 1 more" in evidence


# ---------- R7 ----------

# S2 (IOS XE 17.x, SSH Algorithms for Common Criteria), re-read 2026-11-20
S2_CONFIRMED = [
    ("encryption", "aes128-gcm"),
    ("encryption", "aes256-gcm"),
    ("encryption", "chacha20-poly1305@openssh.com"),
    ("mac", "hmac-sha2-256-etm@openssh.com"),
    ("mac", "hmac-sha2-512-etm@openssh.com"),
    ("kex", "curve25519-sha256@libssh.org"),
]


@pytest.mark.parametrize("keyword,token", S2_CONFIRMED)
def test_s2_confirmed_names_are_known_strong(keyword, token):
    assert token in ssh_crypto.SSH_STRONG_KNOWN[keyword]
    assert token not in audit.SSH_WEAK[keyword]
