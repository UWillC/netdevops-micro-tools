"""
IP Path Tracer — Traceroute analyzer + command generator.

Endpoints:
  POST /ip-path-tracer/analyze   — Parse & analyze traceroute output
  POST /ip-path-tracer/generate  — Generate traceroute commands for Cisco platforms
"""

import re
from typing import List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter()


# ----------------------------
# Models
# ----------------------------

class HopInfo(BaseModel):
    hop_number: int
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    rtt_ms: List[Optional[float]] = []
    rtt_avg_ms: Optional[float] = None
    packet_loss: bool = False
    is_private: bool = False
    is_destination: bool = False
    issues: List[str] = []


class AnalyzeRequest(BaseModel):
    traceroute_output: str = Field(..., min_length=5)
    destination_ip: Optional[str] = None


class AnalyzeResponse(BaseModel):
    hops: List[HopInfo]
    hop_count: int
    destination_reached: bool
    destination_ip: Optional[str]
    total_latency_ms: Optional[float]
    warnings: List[str]
    summary: str


class GenerateRequest(BaseModel):
    destination: str = Field(..., min_length=1)
    source_ip: Optional[str] = None
    platform: str = Field(default="ios-xe")
    max_ttl: int = Field(default=30, ge=1, le=255)
    timeout: int = Field(default=3, ge=1, le=30)
    probe_count: int = Field(default=3, ge=1, le=10)
    use_tcp: bool = False
    port: Optional[int] = None
    vrf: Optional[str] = None


class GenerateResponse(BaseModel):
    platform: str
    commands: List[str]
    notes: List[str]


# ----------------------------
# RFC1918 check
# ----------------------------

def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 169 and octets[1] == 254:
        return True
    return False


# ----------------------------
# Traceroute parser
# ----------------------------

# Matches lines like:
#  1  192.168.1.1 (192.168.1.1)  1.234 ms  0.987 ms  1.001 ms
#  2  * * *
#  3  10.0.0.1 (10.0.0.1)  5.432 ms !H  * 6.789 ms
# Also handles Windows tracert:
#  1    <1 ms    <1 ms    <1 ms  192.168.1.1
# And Cisco IOS:
#  1 192.168.1.1 4 msec 4 msec 4 msec

HOP_LINE_RE = re.compile(r"^\s*(\d+)\s+(.+)$")
IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
RTT_RE = re.compile(r"([\d.]+)\s*(?:ms(?:ec)?|ms)")
STAR_RE = re.compile(r"\*")


def _parse_traceroute(text: str) -> List[HopInfo]:
    hops = []
    for line in text.strip().splitlines():
        line = line.strip()
        m = HOP_LINE_RE.match(line)
        if not m:
            continue

        hop_num = int(m.group(1))
        rest = m.group(2)

        # Extract IP
        ip_match = IP_RE.search(rest)
        ip_addr = ip_match.group(1) if ip_match else None

        # Extract hostname (text before IP in parentheses)
        hostname = None
        hostname_match = re.match(r"^([\w\-.]+)\s+\(", rest)
        if hostname_match and hostname_match.group(1) != ip_addr:
            hostname = hostname_match.group(1)

        # Extract RTTs
        rtts = []
        for rtt_match in RTT_RE.finditer(rest):
            try:
                rtts.append(float(rtt_match.group(1)))
            except ValueError:
                pass

        # Handle <1 ms (Windows)
        for _ in re.finditer(r"<1\s*ms", rest):
            rtts.append(0.5)

        # Count stars (timeouts)
        stars = len(STAR_RE.findall(rest))
        for _ in range(stars):
            rtts.append(None)

        valid_rtts = [r for r in rtts if r is not None]
        avg_rtt = round(sum(valid_rtts) / len(valid_rtts), 2) if valid_rtts else None

        has_loss = None in rtts and len(valid_rtts) > 0
        all_timeout = len(valid_rtts) == 0 and stars > 0

        hops.append(HopInfo(
            hop_number=hop_num,
            ip_address=ip_addr if not all_timeout else None,
            hostname=hostname,
            rtt_ms=rtts,
            rtt_avg_ms=avg_rtt,
            packet_loss=has_loss or all_timeout,
            is_private=_is_private_ip(ip_addr) if ip_addr else False,
        ))

    return hops


def _analyze_hops(hops: List[HopInfo], dest_ip: Optional[str]) -> tuple:
    warnings = []
    dest_reached = False

    prev_avg = None
    for i, hop in enumerate(hops):
        # Destination check
        if dest_ip and hop.ip_address == dest_ip:
            hop.is_destination = True
            dest_reached = True

        # Last hop = likely destination
        if i == len(hops) - 1 and hop.ip_address and not hop.packet_loss:
            if not dest_reached:
                hop.is_destination = True
                dest_reached = True

        # Latency spike detection
        if hop.rtt_avg_ms is not None and prev_avg is not None:
            delta = hop.rtt_avg_ms - prev_avg
            if delta > 50:
                hop.issues.append(f"Latency spike: +{delta:.0f}ms from previous hop")
                warnings.append(f"Hop {hop.hop_number}: latency spike +{delta:.0f}ms")
            elif delta > 20:
                hop.issues.append(f"Notable latency increase: +{delta:.0f}ms")

        # High latency
        if hop.rtt_avg_ms is not None and hop.rtt_avg_ms > 200:
            hop.issues.append(f"High latency: {hop.rtt_avg_ms}ms")
            if f"Hop {hop.hop_number}" not in " ".join(warnings):
                warnings.append(f"Hop {hop.hop_number}: high latency ({hop.rtt_avg_ms}ms)")

        # Packet loss
        if hop.packet_loss and hop.ip_address:
            hop.issues.append("Partial packet loss detected")
            warnings.append(f"Hop {hop.hop_number} ({hop.ip_address}): packet loss")

        # All timeout
        if hop.packet_loss and not hop.ip_address:
            hop.issues.append("No response (filtered or rate-limited)")

        # Private → Public boundary
        if i > 0 and hop.ip_address and hops[i - 1].ip_address:
            was_private = _is_private_ip(hops[i - 1].ip_address)
            is_now_private = _is_private_ip(hop.ip_address)
            if was_private and not is_now_private:
                hop.issues.append("RFC1918 → Public boundary (likely NAT/edge)")
            elif not was_private and is_now_private:
                hop.issues.append("Public → RFC1918 boundary (carrier NAT or destination network)")

        if hop.rtt_avg_ms is not None:
            prev_avg = hop.rtt_avg_ms

    if not dest_reached:
        warnings.append("Destination may not have been reached (traceroute incomplete)")

    # Total latency
    last_valid = None
    for hop in reversed(hops):
        if hop.rtt_avg_ms is not None:
            last_valid = hop.rtt_avg_ms
            break

    # Summary
    responding = sum(1 for h in hops if h.ip_address)
    timeout_hops = sum(1 for h in hops if not h.ip_address and h.packet_loss)
    summary_parts = [f"{len(hops)} hops traced"]
    if responding:
        summary_parts.append(f"{responding} responding")
    if timeout_hops:
        summary_parts.append(f"{timeout_hops} timeout")
    if dest_reached:
        summary_parts.append("destination reached")
    if last_valid:
        summary_parts.append(f"total latency {last_valid}ms")

    return dest_reached, last_valid, warnings, " | ".join(summary_parts)


# ----------------------------
# Command generator
# ----------------------------

PLATFORMS = {
    "ios": "Cisco IOS",
    "ios-xe": "Cisco IOS-XE",
    "nxos": "Cisco NX-OS",
    "asa": "Cisco ASA",
    "linux": "Linux",
    "windows": "Windows",
}


def _generate_commands(req: GenerateRequest) -> tuple:
    commands = []
    notes = []
    p = req.platform.lower()

    if p in ("ios", "ios-xe"):
        cmd = f"traceroute {req.destination}"
        if req.source_ip:
            cmd += f" source {req.source_ip}"
        if req.max_ttl != 30:
            cmd += f" ttl 1 {req.max_ttl}"
        if req.timeout != 3:
            cmd += f" timeout {req.timeout}"
        if req.probe_count != 3:
            cmd += f" probe {req.probe_count}"
        if req.vrf:
            cmd = f"traceroute vrf {req.vrf} {req.destination}"
            if req.source_ip:
                cmd += f" source {req.source_ip}"
        commands.append(cmd)
        notes.append("Use 'traceroute' from privileged EXEC mode")
        if req.use_tcp:
            commands.append(f"traceroute {req.destination} port {req.port or 443} numeric")
            notes.append("TCP traceroute requires 'ip sla' or extended traceroute")

    elif p == "nxos":
        cmd = f"traceroute {req.destination}"
        if req.source_ip:
            cmd += f" source {req.source_ip}"
        if req.vrf:
            cmd += f" vrf {req.vrf}"
        commands.append(cmd)
        notes.append("NX-OS traceroute is similar to IOS")

    elif p == "asa":
        cmd = f"traceroute {req.destination}"
        if req.source_ip:
            notes.append(f"ASA does not support source option directly. Use: 'traceroute {req.destination}' from the interface closest to {req.source_ip}")
        if req.timeout != 3:
            cmd += f" timeout {req.timeout}"
        if req.max_ttl != 30:
            cmd += f" ttl {req.max_ttl}"
        if req.probe_count != 3:
            cmd += f" probe {req.probe_count}"
        commands.append(cmd)
        notes.append("ASA traceroute: use from correct security context")

    elif p == "linux":
        cmd = f"traceroute -m {req.max_ttl} -w {req.timeout} -q {req.probe_count}"
        if req.source_ip:
            cmd += f" -s {req.source_ip}"
        if req.use_tcp:
            cmd += f" -T -p {req.port or 443}"
        cmd += f" {req.destination}"
        commands.append(cmd)
        commands.append(f"mtr -r -c 10 {req.destination}")
        notes.append("mtr combines traceroute + ping for continuous monitoring")
        notes.append("Use -T for TCP mode (bypasses ICMP filtering)")

    elif p == "windows":
        cmd = f"tracert -d -h {req.max_ttl} -w {req.timeout * 1000} {req.destination}"
        commands.append(cmd)
        commands.append(f"pathping -n -h {req.max_ttl} {req.destination}")
        notes.append("pathping provides packet loss statistics per hop (takes ~5 min)")
        notes.append("-d flag disables DNS resolution for faster results")

    else:
        commands.append(f"traceroute {req.destination}")
        notes.append(f"Unknown platform '{req.platform}' — using generic command")

    return commands, notes


# ----------------------------
# Endpoints
# ----------------------------

@router.post("/ip-path-tracer/analyze", response_model=AnalyzeResponse)
def analyze_traceroute(req: AnalyzeRequest):
    """Parse traceroute output and analyze hops for issues."""
    hops = _parse_traceroute(req.traceroute_output)

    if not hops:
        return AnalyzeResponse(
            hops=[],
            hop_count=0,
            destination_reached=False,
            destination_ip=req.destination_ip,
            total_latency_ms=None,
            warnings=["Could not parse traceroute output. Supported formats: Linux traceroute, Windows tracert, Cisco IOS traceroute."],
            summary="No hops parsed",
        )

    # Auto-detect destination from last responding hop
    dest_ip = req.destination_ip
    if not dest_ip:
        for hop in reversed(hops):
            if hop.ip_address:
                dest_ip = hop.ip_address
                break

    dest_reached, total_latency, warnings, summary = _analyze_hops(hops, dest_ip)

    return AnalyzeResponse(
        hops=hops,
        hop_count=len(hops),
        destination_reached=dest_reached,
        destination_ip=dest_ip,
        total_latency_ms=total_latency,
        warnings=warnings,
        summary=summary,
    )


@router.post("/ip-path-tracer/generate", response_model=GenerateResponse)
def generate_traceroute_commands(req: GenerateRequest):
    """Generate platform-specific traceroute commands."""
    commands, notes = _generate_commands(req)

    return GenerateResponse(
        platform=PLATFORMS.get(req.platform.lower(), req.platform),
        commands=commands,
        notes=notes,
    )
