"""
Config Drift Detection — Compare two Cisco configs and highlight differences.

Paste two running-configs (or fragments). Get a structured diff showing:
- Added lines (in config B but not A)
- Removed lines (in config A but not B)
- Modified lines (same command, changed arguments — paired into one entry)
- Changed sections (same parent, different children)
- Summary stats + heuristic security direction (hardening / degradation)

v1.1 (2026-07-28):
- Comment lines (! ...) are never sections and never generate warnings
- Single-line global commands live in one "Global Configuration" bucket
  (no more one-section-per-command inflation of the report and score)
- Removed+added lines of the same command are paired as "modified"
- Risk notes are context-aware (line vty / con / aux)
- Each change gets a direction tag: hardening / degradation / neutral
  (heuristic — NOT a risk rating)
- Multiline banners are treated as one logical line

Endpoints:
  POST /config-drift/compare — Compare two configs
"""

import re
from typing import List, Optional, Tuple, Dict
from collections import OrderedDict

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter()


# ----------------------------
# Models
# ----------------------------

class DriftRequest(BaseModel):
    config_a: str = Field(..., min_length=3, description="Baseline config (e.g. golden/backup)")
    config_b: str = Field(..., min_length=3, description="Current config (e.g. running-config)")
    ignore_order: bool = Field(default=True, description="Ignore line ordering in comparison")
    ignore_cosmetic: bool = Field(default=True, description="Ignore timestamps, version, building config lines")


class DriftLine(BaseModel):
    line: str
    old_line: Optional[str] = None  # set for change_type == "modified" (the config A variant)
    section: str = ""
    change_type: str  # "added", "removed", "modified", "context"
    risk: Optional[str] = None  # "critical", "warning", "info"
    note: Optional[str] = None
    direction: Optional[str] = None  # "hardening", "degradation", "neutral"


class DriftSection(BaseModel):
    title: str
    changes: List[DriftLine]
    added_count: int = 0
    removed_count: int = 0
    modified_count: int = 0


class DriftResponse(BaseModel):
    hostname_a: Optional[str] = None
    hostname_b: Optional[str] = None
    sections: List[DriftSection]
    total_added: int
    total_removed: int
    total_modified: int = 0
    total_unchanged: int
    drift_score: float  # 0-100: 0 = identical, 100 = completely different
    summary: List[str]


# ----------------------------
# Cosmetic / noise lines to skip
# ----------------------------

COSMETIC_PATTERNS = [
    r"^Building configuration",
    r"^Current configuration",
    r"^Last configuration change",
    r"^NVRAM config last updated",
    r"^end\s*$",
    r"^version \d",
    r"^boot-start-marker",
    r"^boot-end-marker",
]


def _is_cosmetic(line: str) -> bool:
    for pat in COSMETIC_PATTERNS:
        if re.match(pat, line.strip(), re.IGNORECASE):
            return True
    return False


def _strip_trailing_comment(line: str) -> str:
    """Drop an inline trailing comment ('cmd  ! note') for comparison purposes."""
    return re.sub(r"\s+!.*$", "", line).rstrip()


def _normalize(line: str) -> str:
    """Canonical form used for comparison: no trailing comment, collapsed whitespace."""
    return re.sub(r"\s+", " ", _strip_trailing_comment(line).strip())


# ----------------------------
# Config parsing into sections
# ----------------------------

GLOBAL_SECTION = "__global__"
BANNER_RE = re.compile(r"^banner\s+(motd|login|exec|incoming|prompt-timeout|slip-ppp)\s+(\S+)", re.IGNORECASE)


def _parse_into_sections(config_text: str, ignore_cosmetic: bool) -> OrderedDict:
    """Parse config into {section_header: [child_lines]}.

    Rules (v1.1):
    - Comment lines (starting with '!') are dropped entirely — they are not
      config state and must never appear as sections or drift lines.
    - Multiline banners are collapsed into one logical global line.
    - A non-indented line is a section header ONLY if it has indented children.
      Standalone global commands go into the GLOBAL_SECTION bucket.
    """
    raw_lines = config_text.splitlines()

    # Pass 1: build logical lines (line, is_indented), handling comments and banners
    logical: List[Tuple[str, bool]] = []
    i = 0
    n_raw = len(raw_lines)
    while i < n_raw:
        raw = raw_lines[i].rstrip()
        i += 1
        if not raw.strip():
            continue
        stripped = raw.strip()
        if stripped.startswith("!"):
            continue  # comments are never config state
        if ignore_cosmetic and _is_cosmetic(raw):
            continue

        indented = raw[0].isspace()
        if not indented:
            m = BANNER_RE.match(stripped)
            if m:
                delim = m.group(2)[0]
                # Consume banner body until closing delimiter
                content: List[str] = []
                # Anything after the delimiter on the same line?
                after = stripped[m.end():].strip()
                closed = False
                if after:
                    if delim in after:
                        pre = after.split(delim)[0].strip()
                        if pre:
                            content.append(pre)
                        closed = True
                    else:
                        content.append(after)
                while not closed and i < n_raw:
                    body = raw_lines[i].rstrip()
                    i += 1
                    if delim in body:
                        pre = body.split(delim)[0].strip()
                        if pre:
                            content.append(pre)
                        closed = True
                    else:
                        if body.strip():
                            content.append(body.strip())
                logical.append((f"banner {m.group(1).lower()} <{' / '.join(content)}>", False))
                continue
            logical.append((stripped, False))
        else:
            logical.append((raw, True))

    # Pass 2: group into sections (header = non-indented line WITH indented children)
    sections: OrderedDict = OrderedDict()
    sections[GLOBAL_SECTION] = []
    idx = 0
    n = len(logical)
    while idx < n:
        line, indented = logical[idx]
        if indented:
            # Defensive: indented line without a preceding header
            sections[GLOBAL_SECTION].append(line.strip())
            idx += 1
            continue
        if idx + 1 < n and logical[idx + 1][1]:
            header = line
            if header not in sections:
                sections[header] = []
            idx += 1
            while idx < n and logical[idx][1]:
                sections[header].append(logical[idx][0])
                idx += 1
        else:
            sections[GLOBAL_SECTION].append(line)
            idx += 1

    return sections


def _reconcile_bare_headers(sections_a: OrderedDict, sections_b: OrderedDict) -> None:
    """If a line is a section (has children) in one config but appears as a bare
    global line in the other, promote the bare line to an empty section so the
    engine compares children instead of reporting section removed + line added."""
    for first, second in ((sections_a, sections_b), (sections_b, sections_a)):
        for header in list(first.keys()):
            if header == GLOBAL_SECTION or header in second:
                continue
            norm_header = _normalize(header)
            for gline in list(second.get(GLOBAL_SECTION, [])):
                if _normalize(gline) == norm_header:
                    second[GLOBAL_SECTION].remove(gline)
                    second[header] = []
                    break


def _detect_hostname(config_text: str) -> Optional[str]:
    m = re.search(r"^hostname\s+(\S+)", config_text, re.MULTILINE)
    return m.group(1) if m else None


# ----------------------------
# Risk assessment for changed lines
# ----------------------------

RISK_PATTERNS = [
    # NTP first — must win over the generic AAA "key N" pattern below
    # (v1.1 fix: 'ntp server X key 1' / 'ntp authentication-key' were
    # misclassified as CRITICAL "AAA server/key changed")
    (r"^\s*ntp (server|authenticate|authentication-key|trusted-key|access-group)", "warning", "NTP configuration changed"),

    # Critical changes
    (r"enable secret|enable password|enable algorithm-type", "critical", "Enable password changed"),
    (r"username\s+\S+\s+(secret|password|privilege)", "critical", "User credentials modified"),
    (r"snmp-server community", "critical", "SNMP community string changed"),
    (r"tacacs.server|radius.server|^\s*key\s+\S+", "critical", "AAA server/key changed"),
    (r"crypto\s+key|crypto\s+isakmp|crypto\s+ipsec", "critical", "VPN/crypto config changed"),
    (r"aaa\s+(new-model|authentication|authorization)", "critical", "AAA policy changed"),
    (r"access-list|ip access-list|ip access-group", "warning", "ACL modified"),
    (r"no ip http secure-server|ip http server", "critical", "HTTP/HTTPS management changed"),

    # Warning changes
    (r"transport (input|output)", "warning", "Transport method changed"),
    (r"ip ssh version", "warning", "SSH version changed"),
    (r"exec-timeout", "warning", "Session timeout changed"),
    (r"logging\s+(host|\d+\.\d+)", "warning", "Logging destination changed"),
    (r"switchport mode", "warning", "Switchport mode changed"),
    (r"switchport trunk", "warning", "Trunk config changed"),
    (r"spanning-tree", "warning", "STP config changed"),
    (r"ip route", "warning", "Static route changed"),
    (r"router\s+(ospf|eigrp|bgp)", "warning", "Routing protocol changed"),
    (r"shutdown|no shutdown", "warning", "Interface state changed"),
    (r"ip address\s+\d", "warning", "IP address changed"),

    # Info
    (r"description\s+", "info", "Interface description changed"),
    (r"banner\s+(motd|login)", "info", "Banner changed"),
    (r"snmp-server (location|contact)", "info", "SNMP metadata changed"),
    (r"hostname", "info", "Hostname changed"),
]

_LINE_TYPE_LABELS = [
    (re.compile(r"^line vty", re.IGNORECASE), "VTY"),
    (re.compile(r"^line con", re.IGNORECASE), "Console"),
    (re.compile(r"^line aux", re.IGNORECASE), "AUX"),
    (re.compile(r"^line tty", re.IGNORECASE), "TTY"),
]


def _line_type_label(section_header: str) -> Optional[str]:
    for pat, label in _LINE_TYPE_LABELS:
        if pat.match(section_header.strip()):
            return label
    return None


def _assess_risk(line: str, section: str = "") -> tuple:
    """Return (risk_level, note) for a changed line. Section header gives context
    (e.g. transport change on line aux is reported as AUX, not VTY)."""
    for pattern, risk, note in RISK_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            if note == "Transport method changed":
                label = _line_type_label(section)
                if label:
                    note = f"{label} transport method changed"
            elif note == "Session timeout changed":
                label = _line_type_label(section)
                if label:
                    note = f"{label} session timeout changed"
            return risk, note
    return None, None


# ----------------------------
# Security direction heuristic (hardening vs degradation)
# ----------------------------

# Patterns matched against the NORMALIZED line (leading "no " kept).
# +1 = protective control, -1 = risky/legacy control. Unlisted = 0 (neutral).
_PROTECTIVE_PATTERNS = [
    r"^no service (pad|config)\b",
    r"^no ip source-route\b",
    r"^no ip gratuitous-arps\b",
    r"^ip dhcp bootp ignore\b",
    r"^no vstack\b",
    r"^service tcp-keepalives-(in|out)\b",
    r"algorithm-type (scrypt|sha256)",
    r"^ip ssh (dh min size|server algorithm|logging events|source-interface)",
    r"^ip ssh version 2\b",
    r"^login (block-for|quiet-mode|on-failure|on-success)\b",
    r"^aaa authorization console\b",
    r"^aaa accounting (connection|system)\b",
    r"^ip arp inspection\b",
    r"^udld (enable|port)\b",
    r"^storm-control\b",
    r"^switchport port-security\b",
    r"^spanning-tree guard root\b",
    r"^spanning-tree portfast bpduguard\b",
    r"^ip verify source\b",
    r"^no cdp (enable|run)\b",
    r"^no lldp (transmit|receive|run)\b",
    r"^access-class\b",
    r"^transport (input|output) (ssh|none)\b",
    r"^session-timeout\b",
    r"^service sequence-numbers\b",
    r"^service password-encryption\b",
    r"^snmp-server (group|user|view) .*v3\b",
    r"^snmp-server .* v3 ",
    r"^no snmp-server community\b",
    r"^ntp (authenticate|authentication-key|trusted-key)\b",
    r"^ntp server .+ key \d",
    r"^banner (login|motd)\b",
    r"^no ip http (server|secure-server)\b",
    r"^ip dhcp snooping\b",
    r"^no exec\b",
    r"^errdisable recovery\b",
    r"^archive\b",
    r"^logging enable\b",
    r"^hidekeys\b",
]

_RISKY_PATTERNS = [
    r"^ip http server\b",
    r"^snmp-server community\b",
    r"^transport (input|output) (telnet|all)\b",
    r"^no aaa\b",
    r"^no login block-for\b",
    r"^no service password-encryption\b",
    r"^no ip ssh\b",
    r"^no ip dhcp snooping\b",
    r"^no switchport port-security\b",
]

_PROTECTIVE_RE = [re.compile(p, re.IGNORECASE) for p in _PROTECTIVE_PATTERNS]
_RISKY_RE = [re.compile(p, re.IGNORECASE) for p in _RISKY_PATTERNS]


def _security_weight(norm_line: str) -> int:
    """+1 protective, -1 risky, 0 neutral. Protective checked first so explicit
    'no <risky>' entries (e.g. 'no snmp-server community') win."""
    for pat in _PROTECTIVE_RE:
        if pat.search(norm_line):
            return 1
    for pat in _RISKY_RE:
        if pat.search(norm_line):
            return -1
    return 0


def _direction(change_type: str, new_norm: str, old_norm: Optional[str] = None) -> str:
    if change_type == "added":
        w = _security_weight(new_norm)
        return "hardening" if w > 0 else ("degradation" if w < 0 else "neutral")
    if change_type == "removed":
        w = _security_weight(new_norm)
        return "degradation" if w > 0 else ("hardening" if w < 0 else "neutral")
    if change_type == "modified":
        wn = _security_weight(new_norm)
        wo = _security_weight(old_norm or "")
        if wn > wo:
            return "hardening"
        if wn < wo:
            return "degradation"
        return "neutral"
    return "neutral"


# ----------------------------
# Modified-line pairing (command keys)
# ----------------------------

# (pattern on normalized line WITHOUT leading "no ", number of tokens forming the key)
_KEY_RULES = [
    (r"^username \S+", 2),
    (r"^ntp server \S+", 3),
    (r"^logging buffered", 2),
    (r"^logging console", 2),
    (r"^snmp-server community \S+", 3),
    (r"^enable (secret|password|algorithm-type)", 1),
    (r"^exec-timeout", 1),
    (r"^session-timeout", 1),
    (r"^transport input", 2),
    (r"^transport output", 2),
    (r"^switchport trunk native vlan", 4),
    (r"^switchport trunk allowed vlan", 4),
    (r"^storm-control broadcast", 2),
    (r"^ip ssh version", 3),
    (r"^banner \S+", 2),
]

_KEY_RULES_RE = [(re.compile(p, re.IGNORECASE), n) for p, n in _KEY_RULES]


def _command_key(norm_line: str) -> str:
    """Key used to pair a removed line with an added line of the same command."""
    s = norm_line
    if s.lower().startswith("no "):
        s = s[3:]
    for pat, ntok in _KEY_RULES_RE:
        if pat.match(s):
            return " ".join(s.split()[:ntok]).lower()
    tokens = s.split()
    return " ".join(tokens[:2]).lower()


def _pair_modified(removed: List[str], added: List[str]) -> Tuple[List[Tuple[str, str]], List[str], List[str]]:
    """Pair removed/added lines that represent the same command (unambiguous 1:1 only).

    Returns (pairs [(old, new)], remaining_removed, remaining_added)."""
    removed_by_key: Dict[str, List[str]] = {}
    added_by_key: Dict[str, List[str]] = {}
    for line in removed:
        removed_by_key.setdefault(_command_key(line), []).append(line)
    for line in added:
        added_by_key.setdefault(_command_key(line), []).append(line)

    pairs: List[Tuple[str, str]] = []
    paired_removed = set()
    paired_added = set()
    for key, rem_lines in removed_by_key.items():
        add_lines = added_by_key.get(key, [])
        if len(rem_lines) == 1 and len(add_lines) == 1:
            old, new = rem_lines[0], add_lines[0]
            if old != new:
                pairs.append((old, new))
                paired_removed.add(old)
                paired_added.add(new)

    remaining_removed = [l for l in removed if l not in paired_removed]
    remaining_added = [l for l in added if l not in paired_added]
    return pairs, remaining_removed, remaining_added


# ----------------------------
# Section name prettifier
# ----------------------------

def _pretty_section(header: str) -> str:
    """Make section headers more readable."""
    if header == GLOBAL_SECTION:
        return "Global Configuration"
    if header.startswith("interface "):
        return header
    if header.startswith("router "):
        return f"Routing: {header}"
    if header.startswith("line "):
        return f"Management: {header}"
    if header.startswith("ip access-list"):
        return f"ACL: {header}"
    if header.startswith("vlan"):
        return f"VLAN: {header}"
    return header


# ----------------------------
# Comparison engine
# ----------------------------

def _make_change(line: str, section: str, change_type: str,
                 old_line: Optional[str] = None,
                 risk: Optional[str] = None, note: Optional[str] = None) -> DriftLine:
    if risk is None and note is None:
        risk, note = _assess_risk(line, section)
        if risk is None and old_line:
            risk, note = _assess_risk(old_line, section)
    direction = _direction(change_type, _normalize(line), _normalize(old_line) if old_line else None)
    return DriftLine(line=line, old_line=old_line, section=section,
                     change_type=change_type, risk=risk, note=note,
                     direction=direction)


def _compare_sections(sections_a: OrderedDict, sections_b: OrderedDict) -> List[DriftSection]:
    """Compare two parsed configs section by section."""
    all_headers = list(OrderedDict.fromkeys(list(sections_a.keys()) + list(sections_b.keys())))
    result = []

    for header in all_headers:
        in_a = header in sections_a
        in_b = header in sections_b

        # Normalized-line maps (normalized -> original) for robust comparison
        map_a = OrderedDict((_normalize(l), l) for l in sections_a.get(header, []))
        map_b = OrderedDict((_normalize(l), l) for l in sections_b.get(header, []))

        norm_a = set(map_a.keys())
        norm_b = set(map_b.keys())
        removed_norm = norm_a - norm_b
        added_norm = norm_b - norm_a

        if in_a and not in_b and header != GLOBAL_SECTION:
            # Entire section removed
            changes = [DriftLine(line=header, section=header, change_type="removed",
                                 risk="warning", note="Section removed",
                                 direction=_direction("removed", _normalize(header)))]
            for line in sections_a[header]:
                changes.append(_make_change(line, header, "removed"))
            result.append(DriftSection(
                title=_pretty_section(header), changes=changes,
                added_count=0, removed_count=len(changes), modified_count=0,
            ))
            continue

        if in_b and not in_a and header != GLOBAL_SECTION:
            # Entire section is new
            changes = [DriftLine(line=header, section=header, change_type="added",
                                 risk="info", note="New section",
                                 direction=_direction("added", _normalize(header)))]
            for line in sections_b[header]:
                changes.append(_make_change(line, header, "added"))
            result.append(DriftSection(
                title=_pretty_section(header), changes=changes,
                added_count=len(changes), removed_count=0, modified_count=0,
            ))
            continue

        if not removed_norm and not added_norm:
            continue

        # Section exists in both (or is the global bucket) and has changes
        pairs, rem_left, add_left = _pair_modified(sorted(removed_norm), sorted(added_norm))

        changes = []
        for old_n, new_n in pairs:
            changes.append(_make_change(map_b[new_n], header, "modified", old_line=map_a[old_n]))
        for norm in rem_left:
            changes.append(_make_change(map_a[norm], header, "removed"))
        for norm in add_left:
            changes.append(_make_change(map_b[norm], header, "added"))

        result.append(DriftSection(
            title=_pretty_section(header), changes=changes,
            added_count=len(add_left), removed_count=len(rem_left),
            modified_count=len(pairs),
        ))

    return result


def _generate_summary(sections: List[DriftSection], total_added: int,
                      total_removed: int, total_modified: int) -> List[str]:
    """Generate human-readable summary of drift."""
    summary = []

    if total_added == 0 and total_removed == 0 and total_modified == 0:
        summary.append("Configs are identical (no drift detected).")
        return summary

    summary.append(
        f"{total_added} line(s) added, {total_removed} line(s) removed, "
        f"{total_modified} line(s) modified across {len(sections)} logical area(s)."
    )

    # Count by risk (each change entry counts once — modified is one change)
    critical = 0
    warning = 0
    hardening = 0
    degradation = 0
    for s in sections:
        for c in s.changes:
            if c.risk == "critical":
                critical += 1
            elif c.risk == "warning":
                warning += 1
            if c.direction == "hardening":
                hardening += 1
            elif c.direction == "degradation":
                degradation += 1

    if critical > 0:
        summary.append(f"CRITICAL: {critical} high-risk change(s) detected — review immediately!")
    if warning > 0:
        summary.append(f"WARNING: {warning} change(s) require attention.")
    if hardening or degradation:
        summary.append(
            f"Direction: {hardening} hardening / {degradation} degradation "
            f"(heuristic tags, NOT a risk rating — review flagged lines yourself)."
        )

    # Highlight specific sections
    section_names = [s.title for s in sections
                     if s.added_count + s.removed_count + s.modified_count > 0]
    if len(section_names) <= 5:
        summary.append(f"Changed sections: {', '.join(section_names)}")
    else:
        summary.append(f"Changed sections: {', '.join(section_names[:5])} + {len(section_names) - 5} more")

    return summary


# ----------------------------
# Endpoint
# ----------------------------

@router.post("/config-drift/compare", response_model=DriftResponse)
def compare_configs(req: DriftRequest):
    """Compare two Cisco configs and detect drift."""

    # Parse configs
    sections_a = _parse_into_sections(req.config_a, req.ignore_cosmetic)
    sections_b = _parse_into_sections(req.config_b, req.ignore_cosmetic)
    _reconcile_bare_headers(sections_a, sections_b)

    # Detect hostnames
    hostname_a = _detect_hostname(req.config_a)
    hostname_b = _detect_hostname(req.config_b)

    # Compare
    drift_sections = _compare_sections(sections_a, sections_b)

    # Stats
    total_added = sum(s.added_count for s in drift_sections)
    total_removed = sum(s.removed_count for s in drift_sections)
    total_modified = sum(s.modified_count for s in drift_sections)

    # Count total meaningful lines for drift score (normalized)
    all_lines_a = set()
    for header, lines in sections_a.items():
        all_lines_a.update(_normalize(l) for l in lines)
        if header != GLOBAL_SECTION:
            all_lines_a.add(_normalize(header))

    all_lines_b = set()
    for header, lines in sections_b.items():
        all_lines_b.update(_normalize(l) for l in lines)
        if header != GLOBAL_SECTION:
            all_lines_b.add(_normalize(header))

    total_unique = len(all_lines_a | all_lines_b)
    # A modified pair contributes its old and new variant to the union — collapse
    # each pair to a single logical line so score reflects logical changes.
    total_unique_logical = max(total_unique - total_modified, 1)
    total_changed = total_added + total_removed + total_modified
    total_unchanged = total_unique_logical - total_changed
    if total_unchanged < 0:
        total_unchanged = 0

    drift_score = (total_changed / total_unique_logical) * 100

    summary = _generate_summary(drift_sections, total_added, total_removed, total_modified)

    return DriftResponse(
        hostname_a=hostname_a,
        hostname_b=hostname_b,
        sections=drift_sections,
        total_added=total_added,
        total_removed=total_removed,
        total_modified=total_modified,
        total_unchanged=total_unchanged,
        drift_score=round(min(drift_score, 100), 1),
        summary=summary,
    )
