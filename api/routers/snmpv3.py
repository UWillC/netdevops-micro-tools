from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, List
import datetime

router = APIRouter()


# -----------------------------
# SNMPv3 Request Schema (v2)
# -----------------------------
class SNMPv3Request(BaseModel):
    # Basic settings
    mode: str = "secure-default"  # secure-default | balanced | legacy-compatible
    device: str = "Cisco IOS XE"
    host: str
    user: str
    group: str
    auth_password: str
    priv_password: str
    output_format: str = "cli"  # cli | oneline | template

    # v2: New fields
    access_mode: str = "read-only"  # read-only | read-write
    use_acl: bool = False
    acl_hosts: Optional[str] = None  # comma-separated IPs
    source_interface: Optional[str] = None  # e.g. Loopback0, GigabitEthernet0/0

    # v2.1: Contact/Location (Cisco Best Practice)
    contact: Optional[str] = None  # e.g. "NOC Team noc@company.com"
    location: Optional[str] = None  # e.g. "DC1 Rack A5"

    # v2.2: Packet size (recommended 4096 for large tables)
    packetsize: Optional[int] = None

    # v2.3: Specific traps (if empty, generates "snmp-server enable traps" for all)
    traps: Optional[List[str]] = None  # e.g. ["syslog", "config", "envmon"]

    # v2.4: Logging section
    logging_enabled: bool = False
    logging_level: str = "informational"


# -----------------------------
# SNMPv3 Logic (API-adapted)
# -----------------------------
ALGORITHMS = {
    "secure-default": ("sha-2 256", "aes 256"),
    "sha2-384": ("sha-2 384", "aes 256"),
    "sha2-512": ("sha-2 512", "aes 256"),
    "balanced": ("sha", "aes 128"),
    "legacy-compatible": ("sha", "aes 128"),
}

# View names based on access mode
VIEW_NAMES = {
    "read-only": "SNMP-RO-VIEW",
    "read-write": "SNMP-RW-VIEW",
}


def generate_snmpv3_cli(user, group, mode, host, auth_pass, priv_pass,
                        access_mode="read-only", use_acl=False, acl_hosts=None,
                        source_interface=None, contact=None, location=None,
                        packetsize=None, traps=None, logging_enabled=False,
                        logging_level="informational"):
    auth_algo, priv_algo = ALGORITHMS.get(mode, ("sha", "aes 128"))
    view_name = VIEW_NAMES.get(access_mode, "SNMP-RO-VIEW")

    sections = []

    # Contact/Location (Cisco Best Practice)
    if contact or location:
        sys_lines = ["!", "! SNMP System Information"]
        if contact:
            sys_lines.append(f"snmp-server contact {contact}")
        if location:
            sys_lines.append(f"snmp-server location {location}")
        sections.append("\n".join(sys_lines))

    # ACL section (if enabled)
    if use_acl and acl_hosts:
        acl_lines = ["!", "! SNMP Access Control List", "ip access-list standard SNMP-ACCESS"]
        hosts = [h.strip() for h in acl_hosts.split(",") if h.strip()]
        for i, host_ip in enumerate(hosts, 1):
            acl_lines.append(f"  permit {host_ip}")
        acl_lines.append("  deny any log")
        sections.append("\n".join(acl_lines))

    # View section
    sections.append(f"!\n! SNMP View\nsnmp-server view {view_name} iso included")

    # Group section
    acl_ref = " access SNMP-ACCESS" if use_acl and acl_hosts else ""
    if access_mode == "read-write":
        group_cmd = f"snmp-server group {group} v3 priv read {view_name} write {view_name}{acl_ref}"
    else:
        group_cmd = f"snmp-server group {group} v3 priv read {view_name}{acl_ref}"
    sections.append(f"!\n! SNMP Group ({access_mode})\n{group_cmd}")

    # User section
    user_cmd = f"snmp-server user {user} {group} v3 auth {auth_algo} {auth_pass} priv {priv_algo} {priv_pass}"
    sections.append(f"!\n! SNMP User\n{user_cmd}")

    # Host section
    host_cmd = f"snmp-server host {host} version 3 priv {user}"
    sections.append(f"!\n! SNMP Host\n{host_cmd}")

    # Source interface (new syntax: separate for traps and informs)
    if source_interface:
        src_lines = ["!", "! SNMP Source Interface"]
        src_lines.append(f"snmp-server source-interface traps {source_interface}")
        src_lines.append(f"snmp-server source-interface informs {source_interface}")
        sections.append("\n".join(src_lines))

    # Packet size (for large SNMP responses)
    if packetsize:
        sections.append(f"!\n! SNMP Packet Size\nsnmp-server packetsize {packetsize}")

    # Traps (specific or all)
    trap_lines = ["!", "! SNMP Traps"]
    if traps and len(traps) > 0:
        for trap_type in traps:
            trap_lines.append(f"snmp-server enable traps {trap_type}")
    else:
        trap_lines.append("snmp-server enable traps")
    sections.append("\n".join(trap_lines))

    # Logging section (optional)
    if logging_enabled:
        log_lines = ["!", "! Logging Configuration"]
        log_lines.append(f"logging trap {logging_level}")
        log_lines.append("service timestamps debug datetime msec")
        log_lines.append("service timestamps log datetime msec")
        sections.append("\n".join(log_lines))

    return "\n".join(sections)


def generate_snmpv3_oneline(cli_text: str):
    lines = []
    for line in cli_text.splitlines():
        line = line.strip()
        if not line or line.startswith("!"):
            continue
        lines.append(line)
    return " ; ".join(lines)


def generate_snmpv3_template(user, group, mode, host, auth_pass, priv_pass, device,
                             access_mode="read-only", use_acl=False, acl_hosts=None,
                             source_interface=None, contact=None, location=None,
                             packetsize=None, traps=None, logging_enabled=False,
                             logging_level="informational"):
    """Generate YAML template for automation tools (Ansible, Netmiko, etc.)"""
    auth_algo, priv_algo = ALGORITHMS.get(mode, ("sha", "aes 128"))
    view_name = VIEW_NAMES.get(access_mode, "SNMP-RO-VIEW")
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # Parse ACL hosts
    acl_list = []
    if use_acl and acl_hosts:
        acl_list = [h.strip() for h in acl_hosts.split(",") if h.strip()]

    # Pre-compute contact/location for YAML
    contact_val = f'"{contact}"' if contact else "null"
    location_val = f'"{location}"' if location else "null"

    # Traps list for YAML
    traps_list = traps if traps and len(traps) > 0 else []

    yaml = f"""# SNMPv3 YAML config generated by NetDevOps Micro-Tools
# Mode: {mode}
# Access: {access_mode}
# Date: {now}
# Device: {device}

snmpv3_config:
  system:
    contact: {contact_val}
    location: {location_val}

  view:
    name: "{view_name}"
    oid: "iso"
    included: true

  group:
    name: "{group}"
    version: 3
    security_level: "priv"
    read_view: "{view_name}"
    write_view: {f'"{view_name}"' if access_mode == "read-write" else "null"}
    acl: {"SNMP-ACCESS" if use_acl and acl_list else "null"}

  users:
    - name: "{user}"
      group: "{group}"
      auth_algorithm: "{auth_algo}"
      auth_password: "{auth_pass}"
      priv_algorithm: "{priv_algo}"
      priv_password: "{priv_pass}"

  host:
    address: "{host}"
    version: 3
    security_level: "priv"
    user: "{user}"

  source_interface: {f'"{source_interface}"' if source_interface else "null"}

  packetsize: {packetsize if packetsize else "null"}

  acl:
    enabled: {str(use_acl and len(acl_list) > 0).lower()}
    name: "SNMP-ACCESS"
    permitted_hosts: {acl_list if acl_list else "[]"}

  traps:
    enabled: true
    specific_types: {traps_list if traps_list else "[]"}

  logging:
    enabled: {str(logging_enabled).lower()}
    level: "{logging_level}"
"""
    return yaml.strip()


# -----------------------------
# SNMPv3 API Endpoint (v2)
# -----------------------------
@router.post("/snmpv3")
def generate_snmpv3(req: SNMPv3Request):

    if req.output_format == "template":
        output = generate_snmpv3_template(
            user=req.user,
            group=req.group,
            mode=req.mode,
            host=req.host,
            auth_pass=req.auth_password,
            priv_pass=req.priv_password,
            device=req.device,
            access_mode=req.access_mode,
            use_acl=req.use_acl,
            acl_hosts=req.acl_hosts,
            source_interface=req.source_interface,
            contact=req.contact,
            location=req.location,
            packetsize=req.packetsize,
            traps=req.traps,
            logging_enabled=req.logging_enabled,
            logging_level=req.logging_level,
        )
    else:
        cli_config = generate_snmpv3_cli(
            user=req.user,
            group=req.group,
            mode=req.mode,
            host=req.host,
            auth_pass=req.auth_password,
            priv_pass=req.priv_password,
            access_mode=req.access_mode,
            use_acl=req.use_acl,
            acl_hosts=req.acl_hosts,
            source_interface=req.source_interface,
            contact=req.contact,
            location=req.location,
            packetsize=req.packetsize,
            traps=req.traps,
            logging_enabled=req.logging_enabled,
            logging_level=req.logging_level,
        )

        if req.output_format == "oneline":
            output = generate_snmpv3_oneline(cli_config)
        else:
            output = cli_config

    return {
        "mode": req.mode,
        "access_mode": req.access_mode,
        "device": req.device,
        "output_format": req.output_format,
        "config": output,
        "metadata": {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "module": "SNMPv3 Generator v2",
            "tool": "NetDevOps Micro-Tools"
        }
    }


# -----------------------------
# SNMPv3 Multiple Hosts (v3)
# -----------------------------

class SNMPv3Host(BaseModel):
    """Single SNMP host configuration"""
    name: str  # e.g. "PRIME", "WUG" - used for remark, group name
    ip_address: str
    user_name: Optional[str] = None  # Custom user name, or auto-generated as {name}-user
    access_mode: str = "read-only"  # read-only | read-write
    auth_algorithm: str = "sha-2 256"  # sha-2 256 | sha-2 384 | sha-2 512 | sha | md5
    priv_algorithm: str = "aes 256"  # aes 256 | aes 192 | aes 128 | 3des | des
    auth_password: str
    priv_password: str


class SNMPv3MultiRequest(BaseModel):
    """Request for multiple SNMP hosts configuration"""
    # Common settings
    acl_name: str = "SNMP-POLLERS"
    view_name: str = "SECUREVIEW"
    device: str = "Cisco IOS XE"
    output_format: str = "cli"  # cli | oneline | template

    # Contact/Location (optional)
    contact: Optional[str] = None
    location: Optional[str] = None

    # Source interface (optional) - used for traps and informs
    source_interface: Optional[str] = None

    # Packet size (optional, default 1500, recommended 4096 for large tables)
    packetsize: Optional[int] = None

    # Specific traps (if empty list or None, generates "snmp-server enable traps" for all)
    # If list provided, generates specific trap types
    traps: Optional[List[str]] = None  # e.g. ["syslog", "config", "envmon", "cpu", "power"]

    # Logging section (optional)
    logging_enabled: bool = False
    logging_level: str = "informational"  # emergencies|alerts|critical|errors|warnings|notifications|informational|debugging

    # List of hosts
    hosts: List[SNMPv3Host]


def generate_snmpv3_multi_cli(req: SNMPv3MultiRequest) -> str:
    """Generate CLI config for multiple SNMP hosts"""
    sections = []

    # Contact/Location
    if req.contact or req.location:
        sys_lines = ["!", "! === SNMP System Information ==="]
        if req.contact:
            sys_lines.append(f"snmp-server contact {req.contact}")
        if req.location:
            sys_lines.append(f"snmp-server location {req.location}")
        sections.append("\n".join(sys_lines))

    # ACL with remarks per host
    acl_lines = ["!", "! === SNMP Access Control List ===", f"ip access-list standard {req.acl_name}"]
    seq = 10
    for host in req.hosts:
        acl_lines.append(f" {seq} remark {host.name}")
        seq += 10
        acl_lines.append(f" {seq} permit {host.ip_address}")
        seq += 10
    acl_lines.append(f" {seq} deny any log")
    sections.append("\n".join(acl_lines))

    # View (shared)
    sections.append(f"!\n! === SNMP View ===\nsnmp-server view {req.view_name} iso included")

    # Groups per host
    group_lines = ["!", "! === SNMP Groups ==="]
    for host in req.hosts:
        if host.access_mode == "read-write":
            group_cmd = f"snmp-server group {host.name} v3 priv read {req.view_name} write {req.view_name} access {req.acl_name}"
        else:
            group_cmd = f"snmp-server group {host.name} v3 priv read {req.view_name} access {req.acl_name}"
        group_lines.append(group_cmd)
    sections.append("\n".join(group_lines))

    # Users per host
    user_lines = ["!", "! === SNMP Users ==="]
    for host in req.hosts:
        # Use custom user_name if provided, otherwise auto-generate
        user_name = host.user_name if host.user_name else f"{host.name.lower()}-user"
        user_cmd = f"snmp-server user {user_name} {host.name} v3 auth {host.auth_algorithm} {host.auth_password} priv {host.priv_algorithm} {host.priv_password}"
        user_lines.append(user_cmd)
    sections.append("\n".join(user_lines))

    # Hosts (trap destinations)
    host_lines = ["!", "! === SNMP Trap Destinations ==="]
    for host in req.hosts:
        user_name = host.user_name if host.user_name else f"{host.name.lower()}-user"
        host_cmd = f"snmp-server host {host.ip_address} version 3 priv {user_name}"
        host_lines.append(host_cmd)
    sections.append("\n".join(host_lines))

    # Source interface (new syntax: separate for traps and informs)
    if req.source_interface:
        src_lines = ["!", "! === SNMP Source Interface ==="]
        src_lines.append(f"snmp-server source-interface traps {req.source_interface}")
        src_lines.append(f"snmp-server source-interface informs {req.source_interface}")
        sections.append("\n".join(src_lines))

    # Packet size (for large SNMP responses)
    if req.packetsize:
        sections.append(f"!\n! === SNMP Packet Size ===\nsnmp-server packetsize {req.packetsize}")

    # Traps (specific or all)
    trap_lines = ["!", "! === SNMP Traps ==="]
    if req.traps and len(req.traps) > 0:
        for trap_type in req.traps:
            trap_lines.append(f"snmp-server enable traps {trap_type}")
    else:
        trap_lines.append("snmp-server enable traps")
    sections.append("\n".join(trap_lines))

    # Logging section (optional)
    if req.logging_enabled:
        log_lines = ["!", "! === Logging Configuration ==="]
        log_lines.append(f"logging trap {req.logging_level}")
        log_lines.append("service timestamps debug datetime msec")
        log_lines.append("service timestamps log datetime msec")
        sections.append("\n".join(log_lines))

    return "\n".join(sections)


def generate_snmpv3_multi_template(req: SNMPv3MultiRequest) -> str:
    """Generate YAML template for multiple SNMP hosts"""
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # Build hosts YAML section
    hosts_yaml = []
    for host in req.hosts:
        user_name = host.user_name if host.user_name else f"{host.name.lower()}-user"
        host_yaml = f"""    - name: "{host.name}"
      ip_address: "{host.ip_address}"
      access_mode: "{host.access_mode}"
      user: "{user_name}"
      auth_algorithm: "{host.auth_algorithm}"
      auth_password: "{host.auth_password}"
      priv_algorithm: "{host.priv_algorithm}"
      priv_password: "{host.priv_password}" """
        hosts_yaml.append(host_yaml)

    # Build ACL entries
    acl_entries = []
    for host in req.hosts:
        acl_entries.append(f'      - remark: "{host.name}"\n        permit: "{host.ip_address}"')

    yaml = f"""# SNMPv3 Multi-Host YAML config generated by NetDevOps Micro-Tools
# Date: {now}
# Device: {req.device}
# Hosts: {len(req.hosts)}

snmpv3_multi_config:
  system:
    contact: {f'"{req.contact}"' if req.contact else 'null'}
    location: {f'"{req.location}"' if req.location else 'null'}

  acl:
    name: "{req.acl_name}"
    entries:
{chr(10).join(acl_entries)}
      - deny: "any"
        log: true

  view:
    name: "{req.view_name}"
    oid: "iso"
    included: true

  source_interface: {f'"{req.source_interface}"' if req.source_interface else 'null'}

  hosts:
{chr(10).join(hosts_yaml)}

  traps:
    enabled: true
    specific_types: {req.traps if req.traps and len(req.traps) > 0 else "[]"}

  logging:
    enabled: {str(req.logging_enabled).lower()}
    level: "{req.logging_level}"
"""
    return yaml.strip()


@router.post("/snmpv3/multi")
def generate_snmpv3_multi(req: SNMPv3MultiRequest):
    """Generate SNMPv3 config for multiple hosts with individual settings"""

    if not req.hosts:
        return {
            "error": "At least one host is required",
            "config": None
        }

    if req.output_format == "template":
        output = generate_snmpv3_multi_template(req)
    else:
        cli_config = generate_snmpv3_multi_cli(req)
        if req.output_format == "oneline":
            lines = []
            for line in cli_config.splitlines():
                line = line.strip()
                if not line or line.startswith("!"):
                    continue
                lines.append(line)
            output = " ; ".join(lines)
        else:
            output = cli_config

    return {
        "hosts_count": len(req.hosts),
        "acl_name": req.acl_name,
        "view_name": req.view_name,
        "device": req.device,
        "output_format": req.output_format,
        "config": output,
        "metadata": {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "module": "SNMPv3 Multi-Host Generator v3",
            "tool": "NetDevOps Micro-Tools"
        }
    }
