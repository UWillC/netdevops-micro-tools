"""
MTU Calculator Router

Calculates effective MTU for various tunnel encapsulations.
"""

from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum


router = APIRouter()


class TunnelType(str, Enum):
    NONE = "none"
    GRE = "gre"
    IPSEC_TUNNEL = "ipsec_tunnel"
    IPSEC_TRANSPORT = "ipsec_transport"
    VXLAN = "vxlan"
    GRE_OVER_IPSEC = "gre_over_ipsec"
    MPLS = "mpls"
    LISP = "lisp"


# Overhead values in bytes
OVERHEAD = {
    TunnelType.NONE: 0,
    TunnelType.GRE: 24,              # 20 (new IP) + 4 (GRE header)
    TunnelType.IPSEC_TUNNEL: 73,     # Worst case: 20 (IP) + 8 (ESP) + 16 (IV) + 2 (trailer) + 12 (auth) + 15 (padding)
    TunnelType.IPSEC_TRANSPORT: 53,  # No new IP header: 8 (ESP) + 16 (IV) + 2 (trailer) + 12 (auth) + 15 (padding)
    TunnelType.VXLAN: 50,            # 20 (outer IP) + 8 (UDP) + 8 (VXLAN) + 14 (inner Ethernet)
    TunnelType.GRE_OVER_IPSEC: 97,   # GRE (24) + IPSec tunnel (73)
    TunnelType.MPLS: 4,              # Single MPLS label (can be more with label stacking)
    TunnelType.LISP: 36,             # 20 (outer IP) + 8 (UDP) + 8 (LISP)
}

# Descriptions for overhead breakdown
OVERHEAD_DESC = {
    TunnelType.NONE: "No encapsulation",
    TunnelType.GRE: "20B (outer IP) + 4B (GRE header)",
    TunnelType.IPSEC_TUNNEL: "20B (outer IP) + 8B (ESP) + 16B (IV/AES) + 2B (trailer) + 12B (auth) + ~15B (padding)",
    TunnelType.IPSEC_TRANSPORT: "8B (ESP) + 16B (IV/AES) + 2B (trailer) + 12B (auth) + ~15B (padding)",
    TunnelType.VXLAN: "20B (outer IP) + 8B (UDP) + 8B (VXLAN) + 14B (inner Ethernet)",
    TunnelType.GRE_OVER_IPSEC: "GRE (24B) + IPSec tunnel mode (73B)",
    TunnelType.MPLS: "4B per label (single label assumed)",
    TunnelType.LISP: "20B (outer IP) + 8B (UDP) + 8B (LISP header)",
}


class MTURequest(BaseModel):
    interface_mtu: int = Field(default=1500, ge=576, le=9216, description="Physical interface MTU")
    tunnel_type: TunnelType = Field(default=TunnelType.GRE, description="Tunnel encapsulation type")
    mpls_labels: Optional[int] = Field(default=1, ge=1, le=8, description="Number of MPLS labels (if MPLS)")
    include_tcp_mss: bool = Field(default=True, description="Include TCP MSS recommendation")


class MTUResponse(BaseModel):
    interface_mtu: int
    tunnel_type: str
    overhead_bytes: int
    overhead_breakdown: str
    effective_mtu: int
    tcp_mss: Optional[int]
    warnings: List[str]
    recommendations: List[str]


@router.post("/mtu/calculate", response_model=MTUResponse)
def calculate_mtu(req: MTURequest):
    """
    Calculate effective MTU for tunnel encapsulation.

    Returns the effective MTU after subtracting tunnel overhead,
    along with TCP MSS recommendation and any warnings.
    """
    warnings = []
    recommendations = []

    # Get overhead for tunnel type
    if req.tunnel_type == TunnelType.MPLS:
        overhead = 4 * req.mpls_labels  # 4 bytes per MPLS label
        overhead_desc = f"{4 * req.mpls_labels}B ({req.mpls_labels} MPLS label(s) × 4B)"
    else:
        overhead = OVERHEAD[req.tunnel_type]
        overhead_desc = OVERHEAD_DESC[req.tunnel_type]

    # Calculate effective MTU
    effective_mtu = req.interface_mtu - overhead

    # TCP MSS = MTU - 20 (IP header) - 20 (TCP header)
    tcp_mss = effective_mtu - 40 if req.include_tcp_mss else None

    # Generate warnings
    if effective_mtu < 1280:
        warnings.append(f"Effective MTU {effective_mtu} is below IPv6 minimum (1280 bytes)")

    if effective_mtu < 576:
        warnings.append(f"Effective MTU {effective_mtu} is below IPv4 minimum (576 bytes) - will cause issues!")

    if req.interface_mtu == 1500 and req.tunnel_type != TunnelType.NONE:
        warnings.append("Using default MTU 1500 with tunneling may cause fragmentation")

    if tcp_mss and tcp_mss < 536:
        warnings.append(f"TCP MSS {tcp_mss} is very low - may impact performance")

    # Generate recommendations
    if req.tunnel_type != TunnelType.NONE:
        recommended_interface_mtu = effective_mtu + overhead + 100  # Add some headroom
        if recommended_interface_mtu <= 9000:
            recommendations.append(f"Consider jumbo frames (MTU 9000) on physical interface for better performance")

        recommendations.append(f"Set 'ip tcp adjust-mss {tcp_mss}' on tunnel interface")

        if req.tunnel_type in [TunnelType.GRE, TunnelType.GRE_OVER_IPSEC]:
            recommendations.append("Set 'tunnel path-mtu-discovery' to enable PMTUD")

        if req.tunnel_type in [TunnelType.IPSEC_TUNNEL, TunnelType.IPSEC_TRANSPORT, TunnelType.GRE_OVER_IPSEC]:
            recommendations.append("Ensure ICMP 'fragmentation needed' (type 3, code 4) is not blocked by firewalls")

    return MTUResponse(
        interface_mtu=req.interface_mtu,
        tunnel_type=req.tunnel_type.value,
        overhead_bytes=overhead,
        overhead_breakdown=overhead_desc,
        effective_mtu=effective_mtu,
        tcp_mss=tcp_mss,
        warnings=warnings,
        recommendations=recommendations,
    )


@router.get("/mtu/reference")
def mtu_reference():
    """
    Return MTU overhead reference table for all tunnel types.
    """
    reference = []
    for tunnel_type in TunnelType:
        reference.append({
            "tunnel_type": tunnel_type.value,
            "overhead_bytes": OVERHEAD[tunnel_type],
            "description": OVERHEAD_DESC[tunnel_type],
            "effective_mtu_1500": 1500 - OVERHEAD[tunnel_type],
            "tcp_mss_1500": 1500 - OVERHEAD[tunnel_type] - 40,
        })

    return {"reference_table": reference}
