"""
Cisco version comparator (CVE-006 W19+ sprint, Phase 1).

Three families share the comparator surface:
  - Cisco IOS XE: major.minor.maint[rebuild][.sSMU]
      e.g. 17.9.4, 17.9.4a, 17.9.4.s1, 17.15.4aa
  - Cisco IOS classic: major.minor(rev)TRAIN sub
      e.g. 15.7(3)M5, 12.4(15)T10, 15.2(7)E8
  - Cisco ISE (ISE-01, 2026-09-18): major.minor[.maint[.build]] [Patch N]
      e.g. "3.4 Patch 7", "ISE 3.3 Patch 12", "3.4.0.608", "3.5P4"

Family detection is based on string pattern. Cross-family comparison returns
None (undefined ordering — different product trains).

Usage:
    from services.cisco_version import cisco_compare, parse_cisco_version

    cisco_compare("17.9.4a", "17.9.4")     # 1
    cisco_compare("17.9.4",  "17.9.4a")    # -1
    cisco_compare("17.9.4",  "17.9.4")     # 0
    cisco_compare("17.9.4a", "15.7(3)M5")  # None (cross-family)
    cisco_compare("ISE 3.4 Patch 7", "ISE 3.4 Patch 6")   # 1

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

# Cisco ISE: major.minor[.maint[.build]] with an optional "Patch N" suffix.
#
# Deliberately NOT a bare "3.4.0" matcher: that string is ambiguous with IOS XE
# (see _ISE_IS_UNAMBIGUOUS below). Cisco advisory tables write ISE fixes as
# "3.4 Patch 7"; the installed-image string is "3.4.0.608". Both parse here.
_ISE_RE = re.compile(
    r"^\s*"
    r"(\d+)\.(\d+)"
    r"(?:\.(\d+))?"
    r"(?:\.(\d+))?"
    r"(?:\s*[-,]?\s*(?:patch|p)\s*(\d+))?"
    r"\s*$",
    re.IGNORECASE,
)

# Prefixes stripped before parsing (Cisco's prose includes many variants).
_KNOWN_PREFIXES = (
    "Cisco IOS XE ",
    "IOS XE ",
    "IOS-XE ",
    "Cisco IOS ",
    "IOS ",
)

# ISE prefixes are tracked separately: seeing one is what makes an otherwise
# ambiguous version string ("3.4.0") unambiguously ISE.
_ISE_PREFIXES = (
    "Cisco ISE-PIC ",
    "Cisco ISE ",
    "ISE-PIC ",
    "ISE ",
    "Cisco Identity Services Engine ",
    "Identity Services Engine ",
)

# A bare "Patch N" token is the other unambiguous ISE marker — no IOS/IOS XE
# version string carries it.
_ISE_PATCH_MARKER = re.compile(r"(?:patch|(?<=\d)p)\s*\d+\s*$", re.IGNORECASE)


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


@dataclass(frozen=True, order=True)
class CiscoIseVersion:
    """Ordered tuple: (major, minor, maint, build, patch)

    Cisco ISE versions its fixes as a train plus a cumulative patch level.
    Advisory tables say "3.4 Patch 7"; `show version` says "3.4.0.608".
    Patch level is the field that actually moves when Cisco ships a fix, so
    it is the last (and most significant trailing) ordering component.

    "3.4 Patch 7"    -> (3, 4, 0, 0, 7)
    "3.4"            -> (3, 4, 0, 0, 0)
    "3.4.0.608"      -> (3, 4, 0, 608, 0)
    "3.5P4"          -> (3, 5, 0, 0, 4)

    Note on ordering: a build number and a patch level are different axes and
    Cisco never publishes both in one string, so mixed comparisons
    ("3.4.0.608" vs "3.4 Patch 7") are ordered on the fields present. Callers
    that need image-level precision should compare like for like.
    """

    major: int
    minor: int
    maint: int = 0
    build: int = 0
    patch: int = 0

    @classmethod
    def parse(cls, s: str) -> Optional["CiscoIseVersion"]:
        if not s:
            return None
        m = _ISE_RE.match(s.strip())
        if not m:
            return None
        try:
            return cls(
                major=int(m.group(1)),
                minor=int(m.group(2)),
                maint=int(m.group(3)) if m.group(3) else 0,
                build=int(m.group(4)) if m.group(4) else 0,
                patch=int(m.group(5)) if m.group(5) else 0,
            )
        except (ValueError, TypeError):
            return None


def _strip_ise_prefix(s: str) -> Optional[str]:
    """Return the version part if `s` carries an explicit ISE product prefix."""
    upper = s.upper()
    for prefix in _ISE_PREFIXES:
        if upper.startswith(prefix.upper()):
            return s[len(prefix):].strip()
    return None


CiscoVersion = Union[CiscoIosXeVersion, CiscoIosClassicVersion, CiscoIseVersion]


def parse_cisco_version(s: str) -> Optional[CiscoVersion]:
    """Try ISE (when unambiguous), then IOS XE, then IOS classic.

    Returns None if none match. Strips common product prefixes
    ("IOS XE 17.9.4" → "17.9.4", "Cisco ISE 3.4 Patch 7" → "3.4 Patch 7").

    Ambiguity rule: "3.4.0" alone parses as IOS XE, not ISE. ISE requires an
    explicit product prefix or a trailing "Patch N" token.
    """
    if not s:
        return None
    s = s.strip()
    upper = s.upper()
    for prefix in _KNOWN_PREFIXES:
        if upper.startswith(prefix.upper()):
            s = s[len(prefix):].strip()
            break
    # ISE is tried first, but ONLY when the string is unambiguously ISE:
    # either it carried an ISE product prefix, or it ends in a patch token.
    # A bare "3.4.0" stays IOS XE — guessing there would silently mis-match
    # two different product families.
    ise_body = _strip_ise_prefix(s)
    if ise_body is not None:
        parsed_ise = CiscoIseVersion.parse(ise_body)
        if parsed_ise is not None:
            return parsed_ise
        s = ise_body
    elif _ISE_PATCH_MARKER.search(s):
        parsed_ise = CiscoIseVersion.parse(s)
        if parsed_ise is not None:
            return parsed_ise

    parsed: Optional[CiscoVersion] = CiscoIosXeVersion.parse(s)
    if parsed is not None:
        return parsed
    return CiscoIosClassicVersion.parse(s)


def cisco_compare(a: str, b: str) -> Optional[int]:
    """Compare two Cisco version strings.

    Returns -1 if a < b, 0 if equal, 1 if a > b.
    Returns None if either is unparseable, or the two versions come from
    different families (IOS XE vs IOS classic vs ISE).
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
