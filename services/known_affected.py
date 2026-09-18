"""
Exact-version matching against Cisco's Known Affected lists (MATCH-01, 2026-09-18).

The problem this solves. Records imported from PSIRT carry
`affected: {"min": "0.0.0", "max": "999.999.999"}` — a placeholder, because the
PSIRT advisory list endpoint has no version range. Such a record matches EVERY
version. On an `IOS XE 17.9.4` report that produced 104 matches, of which the
tool itself marked 100 as "coverage uncertain" and then printed all of them
anyway, including nine SNMP bugs from 2017.

Cisco does publish the answer: every advisory's `productNames` is the complete
list of affected releases ("Cisco IOS XE Software 17.9.4", "Cisco IOS
15.2(7)E8", …), median 192 entries per advisory. The importer kept the first 50
"for display" in `affected_versions_raw` and never matched on them.

Measured on that same report, the full lists settle 95 of the 100 uncertain
matches: 62 are genuinely affected (17.9.4 is listed), 33 are false positives
(not listed), and 5 advisories name no IOS XE release at all.

What a list does and does not say. It is Cisco's statement, as of the advisory's
last revision, of which releases are affected. A release that is absent is one
Cisco did not list — overwhelmingly because it carries the fix. It is not proof
about a release that shipped after the advisory was last touched; callers get
the list's as-of date so that caveat can be shown rather than hidden.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

# productNames entry -> (family key, version). Order matters: "IOS XE" first,
# so "Cisco IOS XE Software 17.9.4" is never read as IOS classic "XE".
_PATTERNS = (
    ("ios-xe", re.compile(r"^Cisco IOS XE Software\s+(\S+)\s*$")),
    ("ios", re.compile(r"^Cisco IOS\s+(\d\S*)\s*$")),
    # ISE-04: ISE releases contain spaces ("3.4 Patch 1", "3.1.0 p10",
    # "1.1.1.268 Patch1"), so the capture runs to end of line. ISE-PIC ships
    # the same release numbers and is filed under the same family.
    ("ise", re.compile(r"^Cisco Identity Services Engine Software\s+(\d.*?)\s*$")),
    ("ise", re.compile(r"^Cisco ISE Passive Identity Connector\s+(\d.*?)\s*$")),
)


def extract_known_affected(adv: Dict[str, Any]) -> Dict[str, List[str]]:
    """{family: [versions]} from a raw PSIRT advisory; empty dict if none."""
    found: Dict[str, set] = {}
    for name in adv.get("productNames") or []:
        if not isinstance(name, str):
            continue
        for family, rx in _PATTERNS:
            m = rx.match(name.strip())
            if m:
                found.setdefault(family, set()).add(m.group(1))
                break
    return {fam: sorted(vs) for fam, vs in found.items()}


def _norm(version: str) -> str:
    """Case-fold and drop zero padding: "17.09.04a" and "17.9.4A" -> "17.9.4a"."""
    v = (version or "").strip().lower()
    return re.sub(r"(?<![\d])0+(?=\d)", "", v)


def _ise_key(version: str):
    """(major, minor, maint, patch) for an ISE release, or None.

    The build number is dropped on purpose: Cisco writes the same release as
    "1.1.1.268 Patch1" in one advisory and "1.1.1 Patch 1" in another, and an
    operator types neither — they type "3.4 Patch 3".
    """
    from services.cisco_version import CiscoIseVersion
    v = (version or "").strip()
    for prefix in ("cisco ise-pic", "cisco ise", "ise-pic", "ise"):
        if v.lower().startswith(prefix + " "):
            v = v[len(prefix):].strip()
            break
    parsed = CiscoIseVersion.parse(v)
    if parsed is None:
        return None
    return (parsed.major, parsed.minor, parsed.maint, parsed.patch)


def version_is_listed(version: str, listed: Iterable[str], family: Optional[str] = None) -> bool:
    """Exact membership of `version` in a Known Affected list.

    For `family="ise"` releases are compared as parsed ISE versions, because the
    same release is spelled "3.4 Patch 1", "3.4.0 p1" and "3.4.0.608 Patch1".
    """
    if family == "ise":
        target_key = _ise_key(version)
        if target_key is None:
            return False
        return any(_ise_key(v) == target_key for v in listed)
    target = _norm(version)
    if not target:
        return False
    return any(_norm(v) == target for v in listed)


def family_for_version(version: str) -> Optional[str]:
    """Which Known Affected list a version string should be checked against.

    Used when the platform field is a device model ("ISR4451-X") that names no
    software family — the version's own shape decides.
    """
    from services.cisco_version import (
        CiscoIosClassicVersion, CiscoIosXeVersion, parse_cisco_version)
    parsed = parse_cisco_version(version or "")
    if type(parsed).__name__ == "CiscoIseVersion":
        return "ise"
    if isinstance(parsed, CiscoIosXeVersion):
        return "ios-xe"
    if isinstance(parsed, CiscoIosClassicVersion):
        return "ios"
    return None
