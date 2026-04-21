"""
Cisco version comparator (CVE-006 W19+ sprint, Phase 1).

Two families share the comparator surface:
  - Cisco IOS XE: major.minor.maint[rebuild][.sSMU]
      e.g. 17.9.4, 17.9.4a, 17.9.4.s1, 17.15.4aa
  - Cisco IOS classic: major.minor(rev)TRAIN sub
      e.g. 15.7(3)M5, 12.4(15)T10, 15.2(7)E8

Family detection is based on string pattern. Cross-family comparison returns
None (undefined ordering — different product trains).

Usage:
    from services.cisco_version import cisco_compare, parse_cisco_version

    cisco_compare("17.9.4a", "17.9.4")     # 1
    cisco_compare("17.9.4",  "17.9.4a")    # -1
    cisco_compare("17.9.4",  "17.9.4")     # 0
    cisco_compare("17.9.4a", "15.7(3)M5")  # None (cross-family)

Design rationale: services/cve_engine.py has inline _tokenize_version() with
gaps on SMU suffixes, multi-letter rebuilds, and IOS classic train letters
beyond M. This module replaces that logic standalone so Phase 4 matcher
update can route version comparisons through a single well-tested API.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Union

# IOS XE: major.minor.maint[rebuild_letters][.sSMU]
_IOS_XE_RE = re.compile(
    r"^\s*"
    r"(\d+)\.(\d+)\.(\d+)"
    r"([a-z]+)?"
    r"(?:\.s(\d+))?"
    r"\s*$",
    re.IGNORECASE,
)

# IOS classic: major.minor(rev)TRAIN sub — TRAIN ∈ {M, T, S, E}
_IOS_CLASSIC_RE = re.compile(
    r"^\s*"
    r"(\d+)\.(\d+)"
    r"\((\d+)\)"
    r"([MTSE])"
    r"(\d+)"
    r"\s*$",
    re.IGNORECASE,
)

# Train rank for ordering within IOS classic family.
# Convention per design doc: higher = more recent merge train.
# M (Maintenance) < T (Technology) < S (Service provider) < E (Enterprise edge).
_TRAIN_RANKS = {"M": 10, "T": 20, "S": 30, "E": 40}

# Prefixes stripped before parsing (Cisco's prose includes many variants).
_KNOWN_PREFIXES = (
    "Cisco IOS XE ",
    "IOS XE ",
    "IOS-XE ",
    "Cisco IOS ",
    "IOS ",
)


def _rebuild_rank(letters: Optional[str]) -> int:
    """Convert rebuild letters to integer rank (spreadsheet-column style).

    ''/None → 0,  'a' → 1,  'z' → 26,  'aa' → 27,  'ab' → 28, ...
    Returns 0 on any non-ascii-letter input (defensive).
    """
    if not letters:
        return 0
    rank = 0
    for ch in letters.lower():
        if not ("a" <= ch <= "z"):
            return 0
        rank = rank * 26 + (ord(ch) - ord("a") + 1)
    return rank


@dataclass(frozen=True, order=True)
class CiscoIosXeVersion:
    """Ordered tuple: (major, minor, maint, rebuild, smu)

    17.9.4    → (17, 9, 4, 0, 0)
    17.9.4a   → (17, 9, 4, 1, 0)
    17.9.4.s1 → (17, 9, 4, 0, 1)
    17.9.4aa  → (17, 9, 4, 27, 0)
    """

    major: int
    minor: int
    maint: int
    rebuild: int = 0
    smu: int = 0

    @classmethod
    def parse(cls, s: str) -> Optional["CiscoIosXeVersion"]:
        if not s:
            return None
        m = _IOS_XE_RE.match(s.strip())
        if not m:
            return None
        try:
            return cls(
                major=int(m.group(1)),
                minor=int(m.group(2)),
                maint=int(m.group(3)),
                rebuild=_rebuild_rank(m.group(4)),
                smu=int(m.group(5)) if m.group(5) else 0,
            )
        except (ValueError, TypeError):
            return None


@dataclass(frozen=True, order=True)
class CiscoIosClassicVersion:
    """Ordered tuple: (major, minor, rev, train_rank, sub)

    15.7(3)M5   → (15, 7, 3, 10, 5)
    12.4(15)T10 → (12, 4, 15, 20, 10)
    15.2(7)E8   → (15, 2, 7, 40, 8)
    """

    major: int
    minor: int
    rev: int
    train_rank: int
    sub: int
    # Preserved for display / debugging but not part of ordering.
    train_letter: str = field(default="", compare=False)

    @classmethod
    def parse(cls, s: str) -> Optional["CiscoIosClassicVersion"]:
        if not s:
            return None
        m = _IOS_CLASSIC_RE.match(s.strip())
        if not m:
            return None
        train = m.group(4).upper()
        try:
            return cls(
                major=int(m.group(1)),
                minor=int(m.group(2)),
                rev=int(m.group(3)),
                train_rank=_TRAIN_RANKS.get(train, 0),
                sub=int(m.group(5)),
                train_letter=train,
            )
        except (ValueError, TypeError):
            return None


CiscoVersion = Union[CiscoIosXeVersion, CiscoIosClassicVersion]


def parse_cisco_version(s: str) -> Optional[CiscoVersion]:
    """Try IOS XE first, then IOS classic. Returns None if neither matches.

    Strips common product prefixes ("IOS XE 17.9.4" → "17.9.4").
    """
    if not s:
        return None
    s = s.strip()
    upper = s.upper()
    for prefix in _KNOWN_PREFIXES:
        if upper.startswith(prefix.upper()):
            s = s[len(prefix):].strip()
            break
    parsed: Optional[CiscoVersion] = CiscoIosXeVersion.parse(s)
    if parsed is not None:
        return parsed
    return CiscoIosClassicVersion.parse(s)


def cisco_compare(a: str, b: str) -> Optional[int]:
    """Compare two Cisco version strings.

    Returns -1 if a < b, 0 if equal, 1 if a > b.
    Returns None if either is unparseable, or the two versions come from
    different families (IOS XE vs IOS classic).
    """
    pa = parse_cisco_version(a)
    pb = parse_cisco_version(b)
    if pa is None or pb is None:
        return None
    if type(pa) is not type(pb):
        return None
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0
