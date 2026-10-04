"""GC-FIX-01: Golden Config SSH lines use real IOS / IOS XE syntax.

Until v0.6.64 secure/hardened emitted `ip ssh cipher ...` and
`ip ssh key-exchange group14-sha256`: ASA-style commands that IOS / IOS XE
rejects, so the "hardened" config silently kept the device defaults.
Correct syntax: `ip ssh server algorithm encryption|mac|kex ...` (Cisco IOS
Security Command Reference D-L; report DATA/ciso-hard03-ssh-syntax-2026-10-04.md).
"""
import re

import pytest

from api import ssh_crypto
from api.routers import config_drift
from api.routers.golden_config import (
    GoldenConfigRequest,
    assemble_golden,
    generate_golden_template,
    generate_security_baseline,
)

MODES = ["standard", "secure", "hardened"]
DEVICES = ["Cisco IOS XE", "Catalyst 9300 IOS-XE 17.9", "Cisco IOS 15.2", ""]

# Algorithms accepted from IOS XE 16.3 on (S1), independent of the module under test.
ACCEPTED_FROM_16_3 = {
    "encryption": {"aes128-ctr", "aes192-ctr", "aes256-ctr"},
    "kex": {"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521"},
    "mac": set(),  # hmac-sha2 needs 16.5.1b
}

ALGO_RE = re.compile(r"^ip ssh server algorithm (encryption|mac|kex) (.+)$")


def _commands(text):
    """Non-comment command lines from a CLI or oneline output."""
    out = []
    for chunk in text.replace(" ; ", "\n").splitlines():
        line = chunk.strip()
        if line and not line.startswith("!"):
            out.append(line)
    return out


def _outputs():
    for mode in MODES:
        for device in DEVICES:
            for fmt in ("cli", "oneline"):
                for skip in (False, True):
                    req = GoldenConfigRequest(mode=mode, device=device, output_format=fmt)
                    if skip:
                        req.aaa_payload = {"mode": "local-only", "domain_name": "example.net",
                                           "local_username": "admin", "local_password": "x"}
                    yield mode, device, fmt, skip, assemble_golden(req)


ALL_OUTPUTS = list(_outputs())


@pytest.mark.parametrize("mode,device,fmt,skip,text", ALL_OUTPUTS)
def test_no_asa_style_ssh_commands(mode, device, fmt, skip, text):
    for line in _commands(text):
        assert not ssh_crypto.INVALID_IP_SSH_RE.match(line), line


@pytest.mark.parametrize("mode,device,fmt,skip,text", ALL_OUTPUTS)
def test_every_ip_ssh_line_is_allowlisted(mode, device, fmt, skip, text):
    for line in _commands(text):
        if line.startswith("ip ssh"):
            assert ssh_crypto.IP_SSH_COMMAND_RE.match(line), line


@pytest.mark.parametrize("mode,device,fmt,skip,text", ALL_OUTPUTS)
def test_algorithms_come_from_ssot_and_exist_since_16_3(mode, device, fmt, skip, text):
    ssot = {
        "encryption": set(ssh_crypto.SSH_ENC_ALLOWED),
        "kex": set(ssh_crypto.SSH_KEX_ALLOWED),
        "mac": set(ssh_crypto.SSH_MAC_ALLOWED),
    }
    for line in _commands(text):
        m = ALGO_RE.match(line)
        if not m:
            continue
        kw, algos = m.group(1), set(m.group(2).split())
        assert algos <= ssot[kw], line
        assert algos <= ACCEPTED_FROM_16_3[kw], line


@pytest.mark.parametrize("mode,device,fmt,skip,text", ALL_OUTPUTS)
def test_dh_min_size_is_a_valid_value(mode, device, fmt, skip, text):
    for line in _commands(text):
        m = re.match(r"^ip ssh dh min size (\S+)$", line)
        if m:
            # S1: "The available options are 2048, and 4096."
            assert int(m.group(1)) in (2048, 4096), line
            assert int(m.group(1)) in ssh_crypto.SSH_DH_MIN_SIZES, line


def test_ssot_lists_disjoint_from_weak():
    assert not set(ssh_crypto.SSH_ENC_ALLOWED) & ssh_crypto.SSH_ENC_WEAK
    assert not set(ssh_crypto.SSH_KEX_ALLOWED) & ssh_crypto.SSH_KEX_WEAK
    assert not set(ssh_crypto.SSH_MAC_ALLOWED) & ssh_crypto.SSH_MAC_WEAK
    for _kw, algos, _rel in ssh_crypto.SSH_NEWER:
        assert not set(algos) & (ssh_crypto.SSH_ENC_WEAK | ssh_crypto.SSH_KEX_WEAK | ssh_crypto.SSH_MAC_WEAK)


def test_secure_and_hardened_exact_lines():
    secure = _commands(generate_security_baseline("secure"))
    assert "ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr" in secure
    assert "ip ssh server algorithm kex ecdh-sha2-nistp384 ecdh-sha2-nistp256" in secure
    assert "ip ssh dh min size 2048" in secure

    hardened = _commands(generate_security_baseline("hardened"))
    assert "ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr" in hardened
    assert ("ip ssh server algorithm kex ecdh-sha2-nistp521 ecdh-sha2-nistp384 "
            "ecdh-sha2-nistp256") in hardened
    assert "ip ssh dh min size 4096" in hardened
    assert not any(l.startswith("ip ssh server algorithm mac") for l in hardened)


def test_standard_keeps_defaults():
    out = _commands(generate_security_baseline("standard"))
    assert not any(l.startswith(("ip ssh server algorithm", "ip ssh dh")) for l in out)


def test_newer_algorithms_only_in_comments_with_release():
    text = generate_security_baseline("hardened")
    commands = " ".join(_commands(text))
    comments = [l for l in text.splitlines() if l.startswith("!")]
    for kw, algos, release in ssh_crypto.SSH_NEWER:
        for a in algos:
            assert a not in commands
        assert any(release in c and all(a in c for a in algos) for c in comments), (kw, release)


def test_classic_ios_has_no_kex_line():
    out = generate_security_baseline("hardened", device="Cisco IOS 15.2")
    assert not any(l.startswith("ip ssh server algorithm kex") for l in _commands(out))
    assert "ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr" in out
    assert "17.11.1a" not in out  # kex hint is XE-only


def test_crypto_lines_emitted_even_when_aaa_provides_ssh_basics():
    out = _commands(generate_security_baseline("hardened", skip_ssh=True))
    assert "ip ssh version 2" not in out
    assert any(l.startswith("ip ssh server algorithm encryption") for l in out)


def _yaml_crypto(yaml_text):
    m = re.search(r"ssh_crypto:(.*)$", yaml_text, re.S)
    block = m.group(1)
    if block.strip().startswith("null"):
        return None

    def lst(key):
        mm = re.search(rf"{key}: \[(.*?)\]", block)
        return [x.strip().strip('"') for x in mm.group(1).split(",") if x.strip()]

    return {
        "encryption": lst("ssh_encryption"),
        "mac": lst("ssh_mac"),
        "kex": lst("ssh_kex"),
        "dh": int(re.search(r"ssh_dh_min_size: (\d+)", block).group(1)),
    }


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("device", DEVICES)
def test_yaml_matches_cli(mode, device):
    yaml_c = _yaml_crypto(generate_golden_template(
        GoldenConfigRequest(mode=mode, device=device, output_format="template")))
    cli = _commands(generate_security_baseline(mode, device=device))

    def cli_list(kw):
        for l in cli:
            m = ALGO_RE.match(l)
            if m and m.group(1) == kw:
                return m.group(2).split()
        return []

    dh = [int(l.split()[-1]) for l in cli if l.startswith("ip ssh dh min size")]
    if mode == "standard":
        assert yaml_c is None and not dh
        return
    assert yaml_c == {
        "encryption": cli_list("encryption"),
        "mac": cli_list("mac"),
        "kex": cli_list("kex"),
        "dh": dh[0],
    }


def test_yaml_has_no_asa_style_ssh():
    for mode in MODES:
        text = generate_golden_template(GoldenConfigRequest(mode=mode, output_format="template"))
        assert "ip ssh cipher" not in text and "key-exchange" not in text


def test_config_drift_treats_generated_ssh_crypto_as_protective():
    for line in _commands(generate_security_baseline("hardened")):
        if line.startswith(("ip ssh server algorithm", "ip ssh dh min size")):
            assert config_drift._security_weight(config_drift._normalize(line)) > 0, line
