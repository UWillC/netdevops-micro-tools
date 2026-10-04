"""
Single source of SSH algorithm names for Cisco IOS / IOS XE (GC-FIX-01, 2026-10-04).

Used by the Golden Config generator today; the future HARD-03 audit rule and
Config Drift should read the same lists instead of keeping their own copies.

Syntax on IOS / IOS XE is `ip ssh server algorithm encryption|mac|kex ...`.
`ip ssh cipher ...` and `ip ssh key-exchange ...` do NOT exist on IOS or IOS XE
(that is ASA-style syntax, and ASA has no `ip` prefix). Golden Config emitted
them from 2025-12-02 until v0.6.65.

Sources (Cisco, fetched 2026-10-04, report DATA/ciso-hard03-ssh-syntax-2026-10-04.md):
  S1  IOS Security Command Reference D-L (sec-cr-i3):
      - `ip ssh server algorithm encryption` aes128/192/256-ctr: IOS 15.5(2)S/T, IOS XE 3.15S
      - `ip ssh server algorithm kex` (dh-group14-sha1, ecdh-sha2-nistp256/384/521): IOS XE 16.3
      - `ip ssh server algorithm mac` hmac-sha2-256/512: IOS XE 16.5.1b
      - `ip ssh dh min size {2048|4096}`, default 2048: 12.4(20)T, 15.1(2)S
  S2  IOS XE 17.x SSH Algorithms for Common Criteria:
      - aes128/256-gcm@openssh.com: 17.9.1
      - curve25519-sha256, diffie-hellman-group14-sha256, diffie-hellman-group16-sha512: 17.11.1a
      - 17.10 removed dh-group14-sha1, hmac-sha1, hmac-sha2-256/512 from the defaults

Rule for generated config: emit only algorithms accepted from IOS XE 16.3 on.
Anything newer is printed as a `!` comment with its release, never as a command,
because one unknown token makes the parser reject the whole line.
"""

import re
from typing import Dict, List, Optional, Tuple

BASELINE_RELEASE = "IOS XE 16.3"

# --- Strong, accepted from BASELINE_RELEASE (emitted as commands) ------------
SSH_ENC_ALLOWED: Tuple[str, ...] = ("aes256-ctr", "aes192-ctr", "aes128-ctr")  # S1: 15.5(2)S / XE 3.15S
SSH_KEX_ALLOWED: Tuple[str, ...] = (                                           # S1: XE 16.3
    "ecdh-sha2-nistp521",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp256",
)
# No strong MAC exists at 16.3 (hmac-sha2 arrived in 16.5.1b), so nothing here.
SSH_MAC_ALLOWED: Tuple[str, ...] = ()

SSH_DH_MIN_SIZES: Tuple[int, ...] = (2048, 4096)  # S1: only valid values; default 2048

# --- Strong, but newer than BASELINE_RELEASE (comment only, with release) ----
# (keyword, algorithms, first release that accepts them)
SSH_NEWER: Tuple[Tuple[str, Tuple[str, ...], str], ...] = (
    ("mac", ("hmac-sha2-512", "hmac-sha2-256"), "IOS XE 16.5.1b"),                         # S1
    ("encryption", ("aes256-gcm@openssh.com", "aes128-gcm@openssh.com"), "IOS XE 17.9.1"),  # S2
    ("kex", ("curve25519-sha256", "diffie-hellman-group16-sha512"), "IOS XE 17.11.1a"),     # S2
)

# --- Weak (for the HARD-03 audit rule; never generated) ----------------------
SSH_ENC_WEAK = frozenset({"aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc"})
SSH_KEX_WEAK = frozenset({
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
})
SSH_MAC_WEAK = frozenset({"hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-md5-96"})

# Every `ip ssh ...` command the generator may emit. Anything else is a bug.
IP_SSH_COMMAND_RE = re.compile(
    r"^ip ssh (version|authentication-retries|time-out|"
    r"server algorithm (encryption|mac|kex)|dh min size|source-interface|logging events)\b"
)
# ASA-style lines that IOS / IOS XE rejects (what Golden Config used to emit).
INVALID_IP_SSH_RE = re.compile(r"^ip ssh (cipher|key-exchange)\b")

# Per Golden Config mode. `standard` leaves the device defaults alone.
SSH_PROFILES: Dict[str, Dict] = {
    "secure": {
        "encryption": SSH_ENC_ALLOWED,
        "kex": ("ecdh-sha2-nistp384", "ecdh-sha2-nistp256"),
        "mac": SSH_MAC_ALLOWED,
        "dh_min_size": 2048,
        "show_newer": False,
    },
    "hardened": {
        "encryption": SSH_ENC_ALLOWED,
        "kex": SSH_KEX_ALLOWED,
        "mac": SSH_MAC_ALLOWED,
        "dh_min_size": 4096,
        "show_newer": True,
    },
}


def is_ios_xe(device: Optional[str]) -> bool:
    """`device` is free text; anything without "XE" is treated as classic IOS 15.x,
    which has no `ip ssh server algorithm kex` (S1: introduced in IOS XE 16.3)."""
    return "xe" in (device or "").lower()


def ssh_crypto_settings(mode: str, device: Optional[str] = "Cisco IOS XE") -> Optional[Dict]:
    """Structured SSH crypto settings for a mode, or None when the mode keeps defaults.
    The CLI lines and the YAML template are both built from this dict."""
    profile = SSH_PROFILES.get(mode)
    if not profile:
        return None
    xe = is_ios_xe(device)
    notes: List[str] = []
    if not xe:
        notes.append("kex skipped: ip ssh server algorithm kex needs IOS XE 16.3+ (not in IOS 15.x)")
    if profile["dh_min_size"] == 4096:
        notes.append("dh min size 4096 can lock out older SSH clients; 2048 is the IOS default")
    if profile["show_newer"]:
        for keyword, algos, release in SSH_NEWER:
            if keyword == "kex" and not xe:
                continue
            notes.append(f"{release}+: add {' '.join(algos)} to ip ssh server algorithm {keyword}")
    return {
        "encryption": list(profile["encryption"]),
        "kex": list(profile["kex"]) if xe else [],
        "mac": list(profile["mac"]),
        "dh_min_size": profile["dh_min_size"],
        "min_release": BASELINE_RELEASE if xe else "IOS 15.5(2)S/T",
        "notes": notes,
    }


def ssh_crypto_cli_lines(mode: str, device: Optional[str] = "Cisco IOS XE") -> List[str]:
    """CLI lines (commands + `!` comments) for a mode; empty list for `standard`."""
    s = ssh_crypto_settings(mode, device)
    if not s:
        return []
    lines = [f"! SSH algorithms: valid from {s['min_release']}"]
    if s["encryption"]:
        lines.append("ip ssh server algorithm encryption " + " ".join(s["encryption"]))
    if s["mac"]:
        lines.append("ip ssh server algorithm mac " + " ".join(s["mac"]))
    if s["kex"]:
        lines.append("ip ssh server algorithm kex " + " ".join(s["kex"]))
    lines.append(f"ip ssh dh min size {s['dh_min_size']}")
    lines.extend("! " + n for n in s["notes"])
    return lines
