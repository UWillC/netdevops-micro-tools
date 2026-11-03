"""
Unused Port Auditor — Find interfaces with no traffic for 6+ months.

Based on Przemek's original Tcl script for Cisco IOS.

Endpoints:
  POST /port-auditor/analyze   — Parse 'show interface status' + optional detail, find unused ports
"""

import re
from typing import List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter()


# ----------------------------
# Models
# ----------------------------

class PortInfo(BaseModel):
    interface: str
    status: str
    last_input: Optional[str] = None
    last_input_days: Optional[int] = None
    description: str = ""
    vlan: Optional[str] = None
    speed: Optional[str] = None
    duplex: Optional[str] = None
    type: Optional[str] = None
    unused: bool = False
    reason: str = ""


class ShutdownCommand(BaseModel):
    interface: str
    commands: List[str]


class AuditRequest(BaseModel):
    interface_status: str = Field(..., min_length=5, description="Output of 'show interface status'")
    interface_detail: Optional[str] = Field(None, description="Output of 'show interfaces' (for Last input)")
    threshold_days: int = Field(default=180, ge=30, le=730, description="Unused threshold in days")
    include_disabled: bool = Field(default=True, description="Include admin-down ports")
    exclude_uplinks: bool = Field(default=True, description="Exclude TenGig/FortyGig/HundredGig uplinks")


class AuditResponse(BaseModel):
    total_ports: int
    unused_ports: int
    notconnect_ports: int
    disabled_ports: int
    ports: List[PortInfo]
    shutdown_config: List[str]
    summary: str
    hostname: Optional[str] = None


# ----------------------------
# Parser helpers
# ----------------------------

UPLINK_PREFIXES = ("Te", "Fo", "Hu", "Tw", "FiveGig", "TwentyFiveGig", "App")

# IOS 'show interface status' fixed-width columns
# Port         Name               Status       Vlan       Duplex  Speed Type
# Gi1/0/1      PC-ADMIN           connected    10         a-full  a-1000 10/100/1000BaseTX
# Gi1/0/2                         notconnect   1            auto    auto 10/100/1000BaseTX

#
# WEBSEC-01e (@ciso W9): this used to be one regex,
#   ^(\S+)\s+(.*?)\s+(<status>)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$
# whose \s+ / .*? / \s+ overlap, so a run of spaces cost cubic time (1000 spaces
# = 6.5 s under the GIL, and every tool shares that process). _match_status_line
# finds the same match in linear time; tests/test_websec_02.py compares the two.
_IFACE_RE = re.compile(r"\S+")
_NON_SPACE_RE = re.compile(r"\S")
_STATUS_TAIL_RE = re.compile(
    r"(?<=\s)(connected|notconnect|disabled|err-disabled|inactive|monitoring)\s+"
    r"(\S+)\s+"             # vlan
    r"(\S+)\s+"             # duplex
    r"(\S+)\s*"             # speed
    r"(.*)$",               # type
    re.IGNORECASE,
)

# Fallback for wider column formats: the first status word after the interface.
_STATUS_SIMPLE_RE = re.compile(
    r"(connected|notconnect|disabled|err-disabled|inactive)\s",
    re.IGNORECASE,
)

# No real line of these commands comes near this (@ciso W9).
MAX_LINE_LENGTH = 512
# 'Last input' is a short duration; a longer value is not one.
MAX_LAST_INPUT_LENGTH = 64

# 'show interfaces' Last input parsing
LAST_INPUT_RE = re.compile(r"Last input\s+([^,]+)", re.IGNORECASE)
INTERFACE_HEADER_RE = re.compile(r"^(\S+)\s+is\s+(administratively\s+)?(up|down)", re.IGNORECASE)


def _parse_last_input_to_days(last_input: str) -> Optional[int]:
    """Convert Cisco 'Last input' string to approximate days.

    Examples: 'never', '00:00:01', '2d03h', '1y2w', '26w3d', '3w2d'
    """
    s = last_input.strip().lower()
    if not s or s == "unknown":
        return None
    if "never" in s:
        return 9999  # never = definitely unused
    if len(s) > MAX_LAST_INPUT_LENGTH:
        return None  # the searches below are quadratic on a long run of digits

    days = 0
    # Years
    m = re.search(r"(\d+)y", s)
    if m:
        days += int(m.group(1)) * 365
    # Weeks
    m = re.search(r"(\d+)w", s)
    if m:
        days += int(m.group(1)) * 7
    # Days
    m = re.search(r"(\d+)d", s)
    if m:
        days += int(m.group(1))
    # Hours (less than a day)
    m = re.search(r"(\d+)h", s)
    if m:
        if days == 0:
            return 0  # active recently
    # HH:MM:SS format (very recent)
    if re.match(r"\d+:\d+:\d+", s):
        return 0

    return days if days > 0 else 0


def _match_status_line(line: str) -> Optional[tuple]:
    """(interface, description, status, vlan, duplex, speed, type), or None.

    The description is what lies between the interface and the status word, and
    the interface and status are separated by at least two whitespace characters
    when there is no description. A status word inside a description wins over
    the one opening the description, as it always did.
    """
    head = _IFACE_RE.match(line)
    if not head or head.end() == len(line):
        return None
    after = head.end()
    first = _NON_SPACE_RE.search(line, after)
    if not first:
        return None
    start = first.start()
    m = _STATUS_TAIL_RE.search(line, start + 1)
    if not m and start >= after + 2:
        m = _STATUS_TAIL_RE.match(line, start)
    if not m:
        return None
    return (head.group(0), line[after:m.start()].strip(), m.group(1).lower(),
            m.group(2), m.group(3), m.group(4), m.group(5).strip())


def _match_status_simple(line: str) -> Optional[tuple]:
    """(interface, status) for a line _match_status_line refused, or None."""
    head = _IFACE_RE.match(line)
    if not head or head.end() == len(line):
        return None
    m = _STATUS_SIMPLE_RE.search(line, head.end() + 1)
    return (head.group(0), m.group(1).lower()) if m else None


def _parse_interface_status(text: str) -> List[PortInfo]:
    """Parse 'show interface status' output."""
    ports = []
    for line in text.strip().splitlines():
        line = line.rstrip()
        if not line or line.startswith("-") or line.lower().startswith("port"):
            continue
        if len(line) > MAX_LINE_LENGTH:
            continue

        full = _match_status_line(line)
        if full:
            iface, desc, status, vlan, duplex, speed, port_type = full
            ports.append(PortInfo(
                interface=iface,
                status=status,
                description=desc,
                vlan=vlan,
                duplex=duplex,
                speed=speed,
                type=port_type,
            ))
        else:
            # Fallback parse
            simple = _match_status_simple(line)
            if simple:
                ports.append(PortInfo(
                    interface=simple[0],
                    status=simple[1],
                ))

    return ports


def _parse_interface_detail(text: str) -> dict:
    """Parse 'show interfaces' to extract Last input per interface.

    Returns: {interface_name: last_input_string}
    """
    result = {}
    current_iface = None

    for line in text.strip().splitlines():
        if len(line) > MAX_LINE_LENGTH:
            continue

        # Interface header line
        m = INTERFACE_HEADER_RE.match(line)
        if m:
            current_iface = m.group(1)
            continue

        # Last input line
        if current_iface:
            m = LAST_INPUT_RE.search(line)
            if m:
                result[current_iface] = m.group(1).strip()

    return result


def _normalize_interface_name(name: str) -> str:
    """Normalize interface names for matching.

    e.g. 'GigabitEthernet1/0/1' -> 'Gi1/0/1'
    """
    replacements = [
        ("GigabitEthernet", "Gi"),
        ("FastEthernet", "Fa"),
        ("TenGigabitEthernet", "Te"),
        ("FortyGigabitEthernet", "Fo"),
        ("HundredGigabitEthernet", "Hu"),
        ("TwentyFiveGigE", "Twe"),
        ("Port-channel", "Po"),
        ("Loopback", "Lo"),
        ("Vlan", "Vl"),
    ]
    for long, short in replacements:
        if name.startswith(long):
            return short + name[len(long):]
    return name


def _detect_hostname(text: str) -> Optional[str]:
    """Try to detect hostname from output."""
    # Look for prompt pattern like 'ROUTER#' or 'ROUTER>'
    for line in text.strip().splitlines():
        m = re.match(r"^(\S+)[#>]", line)
        if m and not m.group(1).startswith("show"):
            return m.group(1)
    return None


# ----------------------------
# Endpoint
# ----------------------------

@router.post("/port-auditor/analyze", response_model=AuditResponse)
def analyze_unused_ports(req: AuditRequest):
    """Parse interface status output and identify unused ports."""

    hostname = _detect_hostname(req.interface_status)

    # Parse interface status table
    ports = _parse_interface_status(req.interface_status)

    if not ports:
        return AuditResponse(
            total_ports=0,
            unused_ports=0,
            notconnect_ports=0,
            disabled_ports=0,
            ports=[],
            shutdown_config=[],
            summary="Could not parse interface status output. Expected format: 'show interface status'",
            hostname=hostname,
        )

    # Parse interface detail if provided (for Last input data)
    last_input_map = {}
    if req.interface_detail:
        last_input_map = _parse_interface_detail(req.interface_detail)

    # The first entry per normalized name. An index instead of a scan per port
    # (WEBSEC-01): 200 KB cost 9.3 s.
    last_input_by_norm = {}
    for full_name, li in last_input_map.items():
        last_input_by_norm.setdefault(_normalize_interface_name(full_name), li)

    # Match Last input data to ports
    for port in ports:
        # Try exact match first, then normalized
        last_input = last_input_map.get(port.interface)
        if not last_input:
            # Try matching normalized names
            last_input = last_input_by_norm.get(_normalize_interface_name(port.interface))

        if last_input:
            port.last_input = last_input
            port.last_input_days = _parse_last_input_to_days(last_input)

    # Filter: exclude uplinks if requested
    if req.exclude_uplinks:
        ports = [p for p in ports if not any(p.interface.startswith(prefix) for prefix in UPLINK_PREFIXES)]

    # Classify unused ports
    notconnect_count = 0
    disabled_count = 0

    for port in ports:
        if port.status == "notconnect":
            notconnect_count += 1
        elif port.status in ("disabled", "err-disabled"):
            disabled_count += 1

        # Determine if unused
        if port.status == "notconnect":
            if port.last_input_days is not None and port.last_input_days >= (req.threshold_days):
                port.unused = True
                if port.last_input_days >= 9999:
                    port.reason = "Never used"
                else:
                    port.reason = f"No traffic for {port.last_input_days}+ days (Last input: {port.last_input})"
            elif port.last_input_days is None:
                # No detail data — mark as candidate based on status alone
                port.unused = True
                port.reason = f"Not connected (no 'show interfaces' data for Last input verification)"

        elif port.status in ("disabled", "err-disabled") and req.include_disabled:
            port.unused = True
            if port.status == "err-disabled":
                port.reason = "Error-disabled (port security or other violation)"
            else:
                port.reason = "Administratively disabled"

    # Sort: unused first, then by interface name
    unused_ports = [p for p in ports if p.unused]
    unused_ports.sort(key=lambda p: p.interface)

    # Generate shutdown config
    shutdown_lines = []
    if unused_ports:
        shutdown_lines.append("! Unused Port Shutdown Configuration")
        shutdown_lines.append(f"! Generated by NetDevOps Micro-Tools — Port Auditor")
        if hostname:
            shutdown_lines.append(f"! Device: {hostname}")
        shutdown_lines.append(f"! Threshold: {req.threshold_days} days")
        shutdown_lines.append(f"! Ports to shut: {len(unused_ports)}")
        shutdown_lines.append("!")
        shutdown_lines.append("configure terminal")
        for port in unused_ports:
            if port.status != "disabled":  # Skip already disabled
                shutdown_lines.append(f"interface {port.interface}")
                shutdown_lines.append(f" description UNUSED-{port.reason[:30]}")
                shutdown_lines.append(f" shutdown")
                shutdown_lines.append("!")
        shutdown_lines.append("end")
        shutdown_lines.append("write memory")

    # Summary
    summary_parts = [f"{len(ports)} total ports analyzed"]
    summary_parts.append(f"{notconnect_count} not connected")
    summary_parts.append(f"{disabled_count} disabled")
    summary_parts.append(f"{len(unused_ports)} identified as unused")
    if req.exclude_uplinks:
        summary_parts.append("uplinks excluded")

    return AuditResponse(
        total_ports=len(ports),
        unused_ports=len(unused_ports),
        notconnect_ports=notconnect_count,
        disabled_ports=disabled_count,
        ports=unused_ports,
        shutdown_config=shutdown_lines,
        summary=" | ".join(summary_parts),
        hostname=hostname,
    )
