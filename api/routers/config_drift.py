"""
Config Drift Detection — Compare two Cisco configs and highlight differences.

Paste two running-configs (or fragments). Get a structured diff showing:
- Added lines (in config B but not A)
- Removed lines (in config A but not B)
- Changed sections (same parent, different children)
- Summary stats

Endpoints:
  POST /config-drift/compare — Compare two configs
"""

import re
from typing import List, Optional
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
    section: str = ""
    change_type: str  # "added", "removed", "context"
    risk: Optional[str] = None  # "critical", "warning", "info"
    note: Optional[str] = None


class DriftSection(BaseModel):
    title: str
    changes: List[DriftLine]
    added_count: int = 0
    removed_count: int = 0


class DriftResponse(BaseModel):
    hostname_a: Optional[str] = None
    hostname_b: Optional[str] = None
    sections: List[DriftSection]
    total_added: int
    total_removed: int
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
    r"^!\s*$",
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


# ----------------------------
# Config parsing into sections
# ----------------------------

def _parse_into_sections(config_text: str, ignore_cosmetic: bool) -> OrderedDict:
    """Parse config into {section_header: [child_lines]} structure."""
    sections = OrderedDict()
    current_section = "__global__"
    sections[current_section] = []

    for raw_line in config_text.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        if ignore_cosmetic and _is_cosmetic(line):
            continue

        # Section headers: lines that don't start with whitespace
        if line and not line[0].isspace() and line != "!":
            current_section = line
            if current_section not in sections:
                sections[current_section] = []
        elif line.startswith(" ") or line.startswith("\t"):
            sections[current_section].append(line)

    return sections


def _detect_hostname(config_text: str) -> Optional[str]:
    m = re.search(r"^hostname\s+(\S+)", config_text, re.MULTILINE)
    return m.group(1) if m else None


# ----------------------------
# Risk assessment for changed lines
# ----------------------------

RISK_PATTERNS = [
    # Critical changes
    (r"enable secret|enable password", "critical", "Enable password changed"),
    (r"username\s+\S+\s+(secret|password|privilege)", "critical", "User credentials modified"),
    (r"snmp-server community", "critical", "SNMP community string changed"),
    (r"tacacs.server|radius.server|key\s+\d+", "critical", "AAA server/key changed"),
    (r"crypto\s+key|crypto\s+isakmp|crypto\s+ipsec", "critical", "VPN/crypto config changed"),
    (r"aaa\s+(new-model|authentication|authorization)", "critical", "AAA policy changed"),
    (r"access-list|ip access-list|ip access-group", "warning", "ACL modified"),
    (r"no ip http secure-server|ip http server", "critical", "HTTP/HTTPS management changed"),

    # Warning changes
    (r"transport input", "warning", "VTY transport method changed"),
    (r"ip ssh version", "warning", "SSH version changed"),
    (r"exec-timeout", "warning", "Session timeout changed"),
    (r"ntp server|ntp authenticate", "warning", "NTP configuration changed"),
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


def _assess_risk(line: str) -> tuple:
    """Return (risk_level, note) for a changed line."""
    for pattern, risk, note in RISK_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return risk, note
    return None, None


# ----------------------------
# Section name prettifier
# ----------------------------

def _pretty_section(header: str) -> str:
    """Make section headers more readable."""
    if header == "__global__":
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

def _compare_sections(sections_a: OrderedDict, sections_b: OrderedDict) -> List[DriftSection]:
    """Compare two parsed configs section by section."""
    all_headers = list(OrderedDict.fromkeys(list(sections_a.keys()) + list(sections_b.keys())))
    result = []

    for header in all_headers:
        lines_a = set(sections_a.get(header, []))
        lines_b = set(sections_b.get(header, []))

        in_a_only = lines_a - lines_b  # removed
        in_b_only = lines_b - lines_a  # added

        if header not in sections_a:
            # Entire section is new
            changes = []
            changes.append(DriftLine(line=header, section=header, change_type="added", risk="info", note="New section"))
            for line in sections_b[header]:
                risk, note = _assess_risk(line)
                changes.append(DriftLine(line=line, section=header, change_type="added", risk=risk, note=note))
            result.append(DriftSection(
                title=_pretty_section(header),
                changes=changes,
                added_count=len(changes),
                removed_count=0,
            ))
        elif header not in sections_b:
            # Entire section removed
            changes = []
            changes.append(DriftLine(line=header, section=header, change_type="removed", risk="warning", note="Section removed"))
            for line in sections_a[header]:
                risk, note = _assess_risk(line)
                changes.append(DriftLine(line=line, section=header, change_type="removed", risk=risk, note=note))
            result.append(DriftSection(
                title=_pretty_section(header),
                changes=changes,
                added_count=0,
                removed_count=len(changes),
            ))
        elif in_a_only or in_b_only:
            # Section exists in both but has changes
            changes = []
            # Show removed lines (sorted for consistency)
            for line in sorted(in_a_only):
                risk, note = _assess_risk(line)
                changes.append(DriftLine(line=line, section=header, change_type="removed", risk=risk, note=note))
            # Show added lines
            for line in sorted(in_b_only):
                risk, note = _assess_risk(line)
                changes.append(DriftLine(line=line, section=header, change_type="added", risk=risk, note=note))
            result.append(DriftSection(
                title=_pretty_section(header),
                changes=changes,
                added_count=len(in_b_only),
                removed_count=len(in_a_only),
            ))

    return result


def _generate_summary(sections: List[DriftSection], total_added: int, total_removed: int) -> List[str]:
    """Generate human-readable summary of drift."""
    summary = []

    if total_added == 0 and total_removed == 0:
        summary.append("Configs are identical (no drift detected).")
        return summary

    summary.append(f"{total_added} line(s) added, {total_removed} line(s) removed across {len(sections)} section(s).")

    # Count by risk
    critical = 0
    warning = 0
    for s in sections:
        for c in s.changes:
            if c.risk == "critical":
                critical += 1
            elif c.risk == "warning":
                warning += 1

    if critical > 0:
        summary.append(f"CRITICAL: {critical} high-risk change(s) detected — review immediately!")
    if warning > 0:
        summary.append(f"WARNING: {warning} change(s) require attention.")

    # Highlight specific sections
    section_names = [s.title for s in sections if s.added_count + s.removed_count > 0]
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

    # Detect hostnames
    hostname_a = _detect_hostname(req.config_a)
    hostname_b = _detect_hostname(req.config_b)

    # Compare
    drift_sections = _compare_sections(sections_a, sections_b)

    # Stats
    total_added = sum(s.added_count for s in drift_sections)
    total_removed = sum(s.removed_count for s in drift_sections)

    # Count total meaningful lines for drift score
    all_lines_a = set()
    for lines in sections_a.values():
        all_lines_a.update(lines)
    all_lines_a.update(k for k in sections_a.keys() if k != "__global__")

    all_lines_b = set()
    for lines in sections_b.values():
        all_lines_b.update(lines)
    all_lines_b.update(k for k in sections_b.keys() if k != "__global__")

    total_unique = len(all_lines_a | all_lines_b)
    total_changed = total_added + total_removed
    total_unchanged = total_unique - total_changed if total_unique > total_changed else 0

    drift_score = (total_changed / max(total_unique, 1)) * 100

    summary = _generate_summary(drift_sections, total_added, total_removed)

    return DriftResponse(
        hostname_a=hostname_a,
        hostname_b=hostname_b,
        sections=drift_sections,
        total_added=total_added,
        total_removed=total_removed,
        total_unchanged=total_unchanged,
        drift_score=round(min(drift_score, 100), 1),
        summary=summary,
    )
