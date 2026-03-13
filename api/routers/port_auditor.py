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

STATUS_LINE_RE = re.compile(
    r"^(\S+)\s+"            # interface
    r"(.*?)\s+"             # description (may be empty/spaces)
    r"(connected|notconnect|disabled|err-disabled|inactive|monitoring)\s+"  # status
    r"(\S+)\s+"             # vlan
    r"(\S+)\s+"             # duplex
    r"(\S+)\s*"             # speed
    r"(.*)$",               # type
    re.IGNORECASE,
)

# Fallback: simpler pattern for wider column formats
STATUS_SIMPLE_RE = re.compile(
    r"^(\S+)\s+.*?(connected|notconnect|disabled|err-disabled|inactive)\s",
    re.IGNORECASE,
)

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


def _parse_interface_status(text: str) -> List[PortInfo]:
    """Parse 'show interface status' output."""
    ports = []
    for line in text.strip().splitlines():
        line = line.rstrip()
        if not line or line.startswith("-") or line.lower().startswith("port"):
            continue

        m = STATUS_LINE_RE.match(line)
        if m:
            iface = m.group(1)
            desc = m.group(2).strip()
            status = m.group(3).lower()
            vlan = m.group(4)
            duplex = m.group(5)
            speed = m.group(6)
            port_type = m.group(7).strip()

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
            m2 = STATUS_SIMPLE_RE.match(line)
            if m2:
                ports.append(PortInfo(
                    interface=m2.group(1),
                    status=m2.group(2).lower(),
                ))

    return ports


def _parse_interface_detail(text: str) -> dict:
    """Parse 'show interfaces' to extract Last input per interface.

    Returns: {interface_name: last_input_string}
    """
    result = {}
    current_iface = None

    for line in text.strip().splitlines():
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

    # Match Last input data to ports
    for port in ports:
        # Try exact match first, then normalized
        last_input = last_input_map.get(port.interface)
        if not last_input:
            # Try matching normalized names
            norm = _normalize_interface_name(port.interface)
            for full_name, li in last_input_map.items():
                if _normalize_interface_name(full_name) == norm:
                    last_input = li
                    break

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
