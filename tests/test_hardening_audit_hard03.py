"""HARD-03: SSH server cryptography, rule 1.2.12.

Acceptance (backlog HARD-03 + @ciso correction 04.10, report 7d):
  FAIL     `ip ssh server algorithm encryption|mac|kex` names a weak algorithm
           (full token names: diffie-hellman-group14-sha1, not group14-sha1)
  FAIL     `ip ssh dh min size` < 2048
  WARNING  `ip ssh dh min size` < 4096, or not set (IOS default 2048)
  WARNING  an algorithm line is missing (defaults depend on the release)
  INFO     `ip ssh cipher|key-exchange` (ASA-like, not an IOS command): named in
           the evidence, never changes the result
  never    asks for `kex` on IOS 15.x (command needs IOS XE 16.3)
  SSOT     the rule and the Golden Config generator read one list (api/ssh_crypto.py)
"""
import pytest

from api import ssh_crypto
from api.routers import cis_audit as audit
from api.routers.cis_audit import AuditRequest, cis_audit
from api.routers.golden_config import GoldenConfigRequest, assemble_golden

RULE_ID = "1.2.12"

STRONG = """ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr
ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256
ip ssh server algorithm kex ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256
ip ssh dh min size 4096
"""

IOS_XE_HEAD = """version 17.9
hostname C8300-EDGE
!
ip ssh version 2
"""

IOS_CLASSIC_HEAD = """version 15.2
hostname ISR2911-BRANCH
!
ip ssh version 2
"""

VTY = """line vty 0 4
 transport input ssh
!
end
"""


def _run(cfg):
    return audit._check_ssh_crypto(audit._normalize_config(cfg))


def _rule(cfg, level="1"):
    resp = cis_audit(AuditRequest(config_text=cfg, level=level))
    rules = [r for c in resp.categories for r in c.rules if r.rule_id == RULE_ID]
    assert len(rules) == 1
    return rules[0]


# ---------- PASS ----------

@pytest.mark.parametrize("level", ["1", "2"])
def test_strong_config_passes_through_the_whole_audit(level):
    rule = _rule(IOS_XE_HEAD + STRONG + VTY, level)
    assert rule.result == "PASS"
    assert rule.evidence == "SSH server algorithms strong; dh min size 4096."
    assert rule.remediation == ""
    assert rule.category == "Access" and rule.severity == "high"


def test_newer_strong_algorithms_pass():
    cfg = ("ip ssh server algorithm encryption aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr\n"
           "ip ssh server algorithm mac hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com\n"
           "ip ssh server algorithm kex curve25519-sha256 diffie-hellman-group16-sha512 ecdh-sha2-nistp256\n"
           "ip ssh dh min size 4096\n")
    assert _run(cfg)[0] == "PASS"


def test_ios_classic_never_asks_for_kex():
    cfg = IOS_CLASSIC_HEAD + ("ip ssh server algorithm encryption aes256-ctr\n"
                              "ip ssh server algorithm mac hmac-sha2-256\n"
                              "ip ssh dh min size 4096\n")
    result, evidence, remediation = _run(cfg)
    assert result == "PASS"
    assert "kex" not in remediation
    assert "no kex line: the command needs IOS XE 16.3+" in evidence


def test_ios_xe_3x_reports_version_15_and_is_treated_as_classic():
    # IOS XE 3.x running-config says `version 15.x`; kex arrived in IOS XE 16.3.
    cfg = "version 15.5\nip ssh server algorithm encryption aes256-ctr\nip ssh server algorithm mac hmac-sha2-256\nip ssh dh min size 4096\n"
    assert _run(cfg)[0] == "PASS"


def test_ios_xe_17_10_plus_defaults_are_strong():
    result, evidence, _ = _run("version 17.12\nip ssh dh min size 4096\n")
    assert result == "PASS"
    for kw in ("encryption", "mac", "kex"):
        assert f"no {kw} line: IOS XE 17.10+ defaults have no weak {kw}" in evidence


def test_ios_xe_17_9_defaults_still_warn():
    result, evidence, _ = _run("version 17.9\nip ssh dh min size 4096\n")
    assert result == "WARNING"
    assert "diffie-hellman-group14-sha1" in evidence and "hmac-sha1" in evidence


# ---------- FAIL: weak algorithms (every token of the SSOT weak lists) ----------

WEAK_CASES = ([("encryption", t) for t in sorted(ssh_crypto.SSH_ENC_WEAK)]
              + [("mac", t) for t in sorted(ssh_crypto.SSH_MAC_WEAK)]
              + [("kex", t) for t in sorted(ssh_crypto.SSH_KEX_WEAK)])


@pytest.mark.parametrize("keyword,token", WEAK_CASES)
def test_each_weak_algorithm_fails(keyword, token):
    lines = {
        "encryption": "ip ssh server algorithm encryption aes256-ctr",
        "mac": "ip ssh server algorithm mac hmac-sha2-512",
        "kex": "ip ssh server algorithm kex ecdh-sha2-nistp384",
    }
    lines[keyword] += " " + token
    cfg = "\n".join(lines.values()) + "\nip ssh dh min size 4096\n"
    result, evidence, remediation = _run(cfg)
    assert result == "FAIL"
    assert f"{keyword} {token}" in evidence
    assert f"ip ssh server algorithm {keyword} " in remediation
    # the fix never re-suggests a weak algorithm
    for weak in ssh_crypto.SSH_ENC_WEAK | ssh_crypto.SSH_MAC_WEAK | ssh_crypto.SSH_KEX_WEAK:
        assert weak not in remediation.split()


@pytest.mark.parametrize("level", ["1", "2"])
def test_weak_config_fails_through_the_whole_audit(level):
    weak = ("ip ssh server algorithm encryption aes256-ctr 3des-cbc\n"
            "ip ssh server algorithm mac hmac-sha2-256\n"
            "ip ssh server algorithm kex diffie-hellman-group14-sha1 ecdh-sha2-nistp256\n"
            "ip ssh dh min size 4096\n")
    rule = _rule(IOS_XE_HEAD + weak + VTY, level)
    assert rule.result == "FAIL"
    assert rule.evidence.startswith("Weak SSH crypto allowed: encryption 3des-cbc; kex diffie-hellman-group14-sha1.")


def test_full_token_name_only():
    # AC wording "group14-sha1" is not a token; only the full name counts as weak.
    cfg = STRONG.replace("ecdh-sha2-nistp256", "ecdh-sha2-nistp256 diffie-hellman-group14-sha256")
    assert _run(cfg)[0] == "PASS"


def test_weak_token_case_insensitive():
    cfg = STRONG.replace("aes128-ctr", "AES128-CBC")
    assert _run(cfg)[0] == "FAIL"


def test_last_algorithm_line_wins():
    cfg = ("ip ssh server algorithm encryption aes128-cbc\n" + STRONG)
    assert _run(cfg)[0] == "PASS"
    cfg = (STRONG + "ip ssh server algorithm encryption aes256-ctr 3des-cbc\n")
    assert _run(cfg)[0] == "FAIL"


def test_negated_and_client_lines_do_not_count():
    cfg = STRONG + ("no ip ssh server algorithm encryption 3des-cbc\n"
                    "ip ssh client algorithm encryption 3des-cbc\n"
                    "! ip ssh server algorithm mac hmac-sha1\n")
    assert _run(cfg)[0] == "PASS"


# ---------- dh min size ----------

@pytest.mark.parametrize("size,expected", [
    (1024, "FAIL"), (2047, "FAIL"), (2048, "WARNING"), (4095, "WARNING"), (4096, "PASS"),
])
def test_dh_min_size_thresholds(size, expected):
    cfg = STRONG.replace("ip ssh dh min size 4096", f"ip ssh dh min size {size}")
    result, evidence, remediation = _run(cfg)
    assert result == expected
    if expected != "PASS":
        assert f"dh min size {size}" in evidence
        assert "ip ssh dh min size 4096" in remediation


def test_dh_min_size_missing_warns():
    cfg = STRONG.replace("ip ssh dh min size 4096\n", "")
    result, evidence, remediation = _run(cfg)
    assert result == "WARNING"
    assert "no 'ip ssh dh min size' (IOS default 2048)" in evidence
    assert remediation == "Use: ip ssh dh min size 4096"


# ---------- missing lines = WARNING ----------

@pytest.mark.parametrize("keyword", ["encryption", "mac", "kex"])
def test_missing_algorithm_line_warns(keyword):
    cfg = "\n".join(ln for ln in STRONG.splitlines()
                    if not ln.startswith(f"ip ssh server algorithm {keyword}")) + "\n"
    result, evidence, remediation = _run(cfg)
    assert result == "WARNING"
    assert f"no 'ip ssh server algorithm {keyword}'" in evidence
    assert f"ip ssh server algorithm {keyword} " in remediation


def test_empty_config_warns_with_full_fix():
    result, evidence, remediation = _run("hostname r1\n")
    assert result == "WARNING"
    for kw in ("encryption", "mac", "kex"):
        assert f"ip ssh server algorithm {kw} " in remediation
    assert "ip ssh dh min size 4096" in remediation


def test_ios_classic_without_strong_mac_warns():
    cfg = IOS_CLASSIC_HEAD + "ip ssh server algorithm encryption aes256-ctr\nip ssh dh min size 4096\n"
    result, evidence, remediation = _run(cfg)
    assert result == "WARNING"
    assert "IOS 15.x offers only hmac-sha1 / hmac-sha1-96" in evidence
    assert "kex" not in remediation


def test_weak_and_missing_both_named():
    cfg = "ip ssh server algorithm encryption aes128-cbc\n"
    result, evidence, _ = _run(cfg)
    assert result == "FAIL"
    assert "Also: no 'ip ssh server algorithm mac'" in evidence


# ---------- INFO: ASA-like lines ----------

@pytest.mark.parametrize("cfg,expected", [
    (STRONG + "ip ssh cipher aes256-ctr aes192-ctr\n", "PASS"),
    (STRONG + "ip ssh key-exchange group14-sha256\n", "PASS"),
    ("ip ssh cipher aes256-ctr\nip ssh key-exchange group14-sha256\n", "WARNING"),
])
def test_asa_like_lines_are_info_only(cfg, expected):
    result, evidence, _ = _run(cfg)
    assert result == expected
    assert "not an IOS / IOS XE command (ASA-like syntax)" in evidence


# ---------- SSOT: one list for the rule and the generator ----------

def test_rule_reads_the_ssot_lists():
    assert audit.SSH_WEAK == {"encryption": ssh_crypto.SSH_ENC_WEAK,
                              "mac": ssh_crypto.SSH_MAC_WEAK,
                              "kex": ssh_crypto.SSH_KEX_WEAK}
    assert audit.SSH_FIX["encryption"].endswith(" ".join(ssh_crypto.SSH_ENC_ALLOWED))
    assert " ".join(ssh_crypto.SSH_KEX_ALLOWED) in audit.SSH_FIX["kex"]


def test_allowed_and_weak_lists_do_not_overlap():
    allowed = set(ssh_crypto.SSH_ENC_ALLOWED) | set(ssh_crypto.SSH_KEX_ALLOWED) | set(ssh_crypto.SSH_MAC_ALLOWED)
    for _, algos, _ in ssh_crypto.SSH_NEWER:
        allowed |= set(algos)
    weak = ssh_crypto.SSH_ENC_WEAK | ssh_crypto.SSH_MAC_WEAK | ssh_crypto.SSH_KEX_WEAK
    assert not allowed & weak


@pytest.mark.parametrize("mode", ["secure", "hardened"])
@pytest.mark.parametrize("device", ["Cisco IOS XE", "Cisco IOS 15.2"])
def test_golden_config_output_never_fails_the_rule(mode, device):
    """GC-FIX-01 report 7b.4: our own generated config must not FAIL the audit.
    It is a WARNING today, honestly: the 16.3 baseline has no strong MAC (hmac-sha2
    needs 16.5.1b), so no mac line is emitted; profiles per release = GC-FIX-02."""
    text = assemble_golden(GoldenConfigRequest(mode=mode, device=device, output_format="cli"))
    result, evidence, _ = _run(text)
    assert result == "WARNING"
    assert "Weak" not in evidence
    assert "no 'ip ssh server algorithm mac'" in evidence
    assert "no 'ip ssh server algorithm encryption'" not in evidence
    if mode == "hardened":
        assert "dh min size" not in evidence
    else:
        assert "dh min size 2048 (4096 recommended" in evidence


def test_golden_config_hardened_plus_mac_line_passes():
    text = assemble_golden(GoldenConfigRequest(mode="hardened", device="Cisco IOS XE", output_format="cli"))
    text += "\nip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256\n"
    assert _run(text)[0] == "PASS"


# ---------- registration ----------

def test_registered_level_1_with_references():
    entry = [r for r in audit.RULES if r[0] == RULE_ID]
    assert len(entry) == 1
    _, title, category, severity, level, fn = entry[0]
    assert (title, category, severity, level, fn) == (
        "SSH cryptography", "Access", "high", "1", audit._check_ssh_crypto)
    refs = audit.REFERENCES[RULE_ID]
    assert any("ip ssh server algorithm" in r for r in refs)


def test_rule_counts():
    assert len(audit.RULES) == 41
    assert sum(1 for r in audit.RULES if r[4] == "1") == 25
