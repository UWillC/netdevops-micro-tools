from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, validator
from typing import Optional, List
import ipaddress
import datetime

router = APIRouter()


# -----------------------------
# Schemas
# -----------------------------
class SubnetInfoRequest(BaseModel):
    """Request for subnet information"""
    ip_cidr: str  # e.g., "192.168.1.0/24" or "10.0.0.50/16"

    @validator("ip_cidr")
    def validate_cidr(cls, v):
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation: {e}")
        return v


class SubnetSplitRequest(BaseModel):
    """Request for subnet splitting"""
    ip_cidr: str  # e.g., "192.168.1.0/24"
    new_prefix: int  # e.g., 26 (split /24 into /26s)

    @validator("ip_cidr")
    def validate_cidr(cls, v):
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation: {e}")
        return v


class SupernetRequest(BaseModel):
    """Request for supernetting (aggregation)"""
    networks: List[str]  # e.g., ["192.168.0.0/24", "192.168.1.0/24"]


class ConvertRequest(BaseModel):
    """Request for CIDR/Netmask conversion"""
    value: str  # e.g., "/24" or "255.255.255.0" or "24"


# -----------------------------
# Helper functions
# -----------------------------
def get_subnet_info(network: ipaddress.IPv4Network) -> dict:
    """Get detailed information about a subnet"""
    # Calculate usable hosts
    total_hosts = network.num_addresses
    usable_hosts = total_hosts - 2 if total_hosts > 2 else total_hosts

    # Get host range
    hosts = list(network.hosts())
    if hosts:
        first_host = str(hosts[0])
        last_host = str(hosts[-1])
    else:
        first_host = str(network.network_address)
        last_host = str(network.network_address)

    # Wildcard mask (inverse of netmask)
    netmask_int = int(network.netmask)
    wildcard_int = netmask_int ^ 0xFFFFFFFF
    wildcard = str(ipaddress.IPv4Address(wildcard_int))

    # Binary representations
    netmask_binary = format(netmask_int, '032b')
    netmask_binary_dotted = '.'.join([netmask_binary[i:i+8] for i in range(0, 32, 8)])

    return {
        "network": str(network.network_address),
        "broadcast": str(network.broadcast_address),
        "netmask": str(network.netmask),
        "wildcard": wildcard,
        "prefix_length": network.prefixlen,
        "cidr": str(network),
        "first_host": first_host,
        "last_host": last_host,
        "total_addresses": total_hosts,
        "usable_hosts": usable_hosts,
        "network_class": get_network_class(network.network_address),
        "is_private": network.is_private,
        "netmask_binary": netmask_binary_dotted,
    }


def get_network_class(ip: ipaddress.IPv4Address) -> str:
    """Determine the traditional network class"""
    first_octet = int(str(ip).split('.')[0])
    if first_octet < 128:
        return "A"
    elif first_octet < 192:
        return "B"
    elif first_octet < 224:
        return "C"
    elif first_octet < 240:
        return "D (Multicast)"
    else:
        return "E (Reserved)"


def prefix_to_netmask(prefix: int) -> str:
    """Convert prefix length to dotted decimal netmask"""
    if not 0 <= prefix <= 32:
        raise ValueError("Prefix must be between 0 and 32")
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return str(ipaddress.IPv4Address(mask))


def netmask_to_prefix(netmask: str) -> int:
    """Convert dotted decimal netmask to prefix length"""
    try:
        mask = ipaddress.IPv4Address(netmask)
        mask_int = int(mask)
        # Count the number of 1 bits
        return bin(mask_int).count('1')
    except Exception as e:
        raise ValueError(f"Invalid netmask: {e}")


# -----------------------------
# API Endpoints
# -----------------------------
@router.post("/subnet/info")
def subnet_info(req: SubnetInfoRequest):
    """Get detailed information about a subnet"""
    try:
        network = ipaddress.ip_network(req.ip_cidr, strict=False)
        info = get_subnet_info(network)

        return {
            "input": req.ip_cidr,
            "subnet_info": info,
            "metadata": {
                "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
                "module": "IP Subnet Calculator",
                "tool": "NetDevOps Micro-Tools",
            },
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/subnet/split")
def subnet_split(req: SubnetSplitRequest):
    """Split a network into smaller subnets"""
    try:
        network = ipaddress.ip_network(req.ip_cidr, strict=False)

        if req.new_prefix <= network.prefixlen:
            raise HTTPException(
                status_code=400,
                detail=f"New prefix (/{req.new_prefix}) must be larger than original (/{network.prefixlen})"
            )

        if req.new_prefix > 32:
            raise HTTPException(status_code=400, detail="Prefix cannot exceed /32")

        # Calculate subnets
        subnets = list(network.subnets(new_prefix=req.new_prefix))

        # Limit output if too many subnets
        max_display = 64
        truncated = len(subnets) > max_display

        subnet_list = []
        for i, subnet in enumerate(subnets[:max_display]):
            info = get_subnet_info(subnet)
            subnet_list.append({
                "index": i + 1,
                "cidr": str(subnet),
                "network": info["network"],
                "broadcast": info["broadcast"],
                "first_host": info["first_host"],
                "last_host": info["last_host"],
                "usable_hosts": info["usable_hosts"],
            })

        return {
            "original_network": str(network),
            "original_prefix": network.prefixlen,
            "new_prefix": req.new_prefix,
            "total_subnets": len(subnets),
            "hosts_per_subnet": subnet_list[0]["usable_hosts"] if subnet_list else 0,
            "subnets": subnet_list,
            "truncated": truncated,
            "metadata": {
                "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
                "module": "IP Subnet Calculator",
                "tool": "NetDevOps Micro-Tools",
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/subnet/supernet")
def subnet_supernet(req: SupernetRequest):
    """Aggregate multiple networks into a supernet"""
    try:
        if len(req.networks) < 2:
            raise HTTPException(status_code=400, detail="Need at least 2 networks to aggregate")

        # Parse all networks
        networks = []
        for net_str in req.networks:
            try:
                net = ipaddress.ip_network(net_str, strict=False)
                networks.append(net)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=f"Invalid network '{net_str}': {e}")

        # Try to collapse
        collapsed = list(ipaddress.collapse_addresses(networks))

        result_networks = []
        for net in collapsed:
            info = get_subnet_info(net)
            result_networks.append({
                "cidr": str(net),
                "network": info["network"],
                "broadcast": info["broadcast"],
                "netmask": info["netmask"],
                "usable_hosts": info["usable_hosts"],
            })

        return {
            "input_networks": req.networks,
            "input_count": len(req.networks),
            "result_networks": result_networks,
            "result_count": len(result_networks),
            "aggregation_possible": len(collapsed) < len(networks),
            "metadata": {
                "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
                "module": "IP Subnet Calculator",
                "tool": "NetDevOps Micro-Tools",
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/subnet/convert")
def subnet_convert(req: ConvertRequest):
    """Convert between CIDR prefix and netmask"""
    try:
        value = req.value.strip()

        # Try to detect format
        if value.startswith('/'):
            # It's a prefix like "/24"
            prefix = int(value[1:])
            netmask = prefix_to_netmask(prefix)
            input_type = "prefix"
        elif '.' in value:
            # It's a netmask like "255.255.255.0"
            prefix = netmask_to_prefix(value)
            netmask = value
            input_type = "netmask"
        else:
            # Assume it's just a number like "24"
            prefix = int(value)
            netmask = prefix_to_netmask(prefix)
            input_type = "prefix"

        # Calculate wildcard
        netmask_int = int(ipaddress.IPv4Address(netmask))
        wildcard_int = netmask_int ^ 0xFFFFFFFF
        wildcard = str(ipaddress.IPv4Address(wildcard_int))

        # Calculate hosts
        total_hosts = 2 ** (32 - prefix)
        usable_hosts = total_hosts - 2 if total_hosts > 2 else total_hosts

        # Binary
        netmask_binary = format(netmask_int, '032b')
        netmask_binary_dotted = '.'.join([netmask_binary[i:i+8] for i in range(0, 32, 8)])

        return {
            "input": req.value,
            "input_type": input_type,
            "prefix": prefix,
            "prefix_notation": f"/{prefix}",
            "netmask": netmask,
            "wildcard": wildcard,
            "total_addresses": total_hosts,
            "usable_hosts": usable_hosts,
            "netmask_binary": netmask_binary_dotted,
            "metadata": {
                "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
                "module": "IP Subnet Calculator",
                "tool": "NetDevOps Micro-Tools",
            },
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/subnet/reference")
def subnet_reference():
    """Get a reference table of common subnets"""
    reference = []
    for prefix in range(8, 33):
        netmask = prefix_to_netmask(prefix)
        total = 2 ** (32 - prefix)
        usable = total - 2 if total > 2 else total

        # Wildcard
        netmask_int = int(ipaddress.IPv4Address(netmask))
        wildcard_int = netmask_int ^ 0xFFFFFFFF
        wildcard = str(ipaddress.IPv4Address(wildcard_int))

        reference.append({
            "prefix": f"/{prefix}",
            "netmask": netmask,
            "wildcard": wildcard,
            "total_addresses": total,
            "usable_hosts": usable,
        })

    return {
        "reference_table": reference,
        "metadata": {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "module": "IP Subnet Calculator",
            "tool": "NetDevOps Micro-Tools",
        },
    }
