from fastapi import APIRouter
from pydantic import BaseModel
import datetime
from typing import Optional, Dict, Any, List

# Import generator functions from other routers
from api.routers.snmpv3 import (
    generate_snmpv3_cli, generate_snmpv3_oneline, generate_snmpv3_template,
    generate_snmpv3_multi_cli, generate_snmpv3_multi_template, SNMPv3MultiRequest, SNMPv3Host
)
from api.routers.ntp import generate_ntp_cli, generate_ntp_oneline, generate_ntp_template
from api.routers.aaa import generate_aaa_local_only, generate_aaa_tacacs, generate_aaa_template, to_oneline as aaa_to_oneline, AAARequest

router = APIRouter()


# --------------------------------------------------------------------
# REQUEST SCHEMA
# --------------------------------------------------------------------
class GoldenConfigRequest(BaseModel):
    device: str = "Cisco IOS XE"
    mode: str = "standard"       # standard | secure | hardened
    snmpv3_config: Optional[str] = None
    ntp_config: Optional[str] = None
    aaa_config: Optional[str] = None
    # Payloads for re-generation (Phase C)
    snmpv3_payload: Optional[Dict[str, Any]] = None
    snmpv3_multi_payload: Optional[Dict[str, Any]] = None  # Multi-host SNMP
    ntp_payload: Optional[Dict[str, Any]] = None
    aaa_payload: Optional[Dict[str, Any]] = None
    # Baseline sections (v2 - modular)
    include_banner: bool = True
    custom_banner: Optional[str] = None
    include_logging: bool = True
    include_security: bool = True
    output_format: str = "cli"   # cli | oneline | template


# --------------------------------------------------------------------
# PAYLOAD GENERATORS (re-generate from saved payloads)
# --------------------------------------------------------------------
def generate_snmpv3_from_payload(payload: Dict[str, Any], output_format: str) -> str:
    """Generate SNMPv3 config from payload in the specified format"""
    if output_format == "template":
        return generate_snmpv3_template(
            user=payload.get("user", ""),
            group=payload.get("group", ""),
            mode=payload.get("mode", "secure-default"),
            host=payload.get("host", ""),
            auth_pass=payload.get("auth_password", ""),
            priv_pass=payload.get("priv_password", ""),
            device=payload.get("device", "Cisco IOS XE"),
            access_mode=payload.get("access_mode", "read-only"),
            use_acl=payload.get("use_acl", False),
            acl_hosts=payload.get("acl_hosts"),
            source_interface=payload.get("source_interface"),
            contact=payload.get("contact"),
            location=payload.get("location"),
            packetsize=payload.get("packetsize"),
            traps=payload.get("traps"),
            logging_enabled=payload.get("logging_enabled", False),
            logging_level=payload.get("logging_level", "informational"),
        )
    else:
        cli = generate_snmpv3_cli(
            user=payload.get("user", ""),
            group=payload.get("group", ""),
            mode=payload.get("mode", "secure-default"),
            host=payload.get("host", ""),
            auth_pass=payload.get("auth_password", ""),
            priv_pass=payload.get("priv_password", ""),
            access_mode=payload.get("access_mode", "read-only"),
            use_acl=payload.get("use_acl", False),
            acl_hosts=payload.get("acl_hosts"),
            source_interface=payload.get("source_interface"),
            contact=payload.get("contact"),
            location=payload.get("location"),
            packetsize=payload.get("packetsize"),
            traps=payload.get("traps"),
            logging_enabled=payload.get("logging_enabled", False),
            logging_level=payload.get("logging_level", "informational"),
        )
        if output_format == "oneline":
            return generate_snmpv3_oneline(cli)
        return cli


def generate_snmpv3_multi_from_payload(payload: Dict[str, Any], output_format: str) -> str:
    """Generate SNMPv3 Multi-Host config from payload in the specified format"""
    # Build hosts list
    hosts = []
    for h in payload.get("hosts", []):
        hosts.append(SNMPv3Host(
            name=h.get("name", ""),
            ip_address=h.get("ip_address", ""),
            user_name=h.get("user_name"),
            access_mode=h.get("access_mode", "read-only"),
            auth_algorithm=h.get("auth_algorithm", "sha-2 256"),
            priv_algorithm=h.get("priv_algorithm", "aes 256"),
            auth_password=h.get("auth_password", ""),
            priv_password=h.get("priv_password", ""),
        ))

    req = SNMPv3MultiRequest(
        acl_name=payload.get("acl_name", "SNMP-POLLERS"),
        view_name=payload.get("view_name", "SECUREVIEW"),
        device=payload.get("device", "Cisco IOS XE"),
        contact=payload.get("contact"),
        location=payload.get("location"),
        source_interface=payload.get("source_interface"),
        packetsize=payload.get("packetsize"),
        traps=payload.get("traps"),
        logging_enabled=payload.get("logging_enabled", False),
        logging_level=payload.get("logging_level", "informational"),
        output_format=output_format,
        hosts=hosts,
    )

    if output_format == "template":
        return generate_snmpv3_multi_template(req)
    else:
        cli = generate_snmpv3_multi_cli(req)
        if output_format == "oneline":
            lines = []
            for line in cli.splitlines():
                line = line.strip()
                if not line or line.startswith("!"):
                    continue
                lines.append(line)
            return " ; ".join(lines)
        return cli


def generate_ntp_from_payload(payload: Dict[str, Any], output_format: str) -> str:
    """Generate NTP config from payload in the specified format"""
    # Build NTPRequest-like object for template generator
    class NTPPayload:
        def __init__(self, p):
            self.device = p.get("device", "Cisco IOS XE")
            self.network_tier = p.get("network_tier", "ACCESS")
            self.timezone = p.get("timezone", "UTC")
            self.primary_server = p.get("primary_server", "")
            self.secondary_server = p.get("secondary_server")
            self.tertiary_server = p.get("tertiary_server")
            self.source_interface = p.get("source_interface")
            self.use_auth = p.get("use_auth", False)
            self.auth_algorithm = p.get("auth_algorithm", "sha1")
            self.key_id = p.get("key_id")
            self.key_value = p.get("key_value")
            self.use_logging = p.get("use_logging", True)
            self.update_calendar = p.get("update_calendar", False)
            self.use_access_control = p.get("use_access_control", False)
            self.acl_peer_hosts = p.get("acl_peer_hosts")
            self.acl_serve_network = p.get("acl_serve_network")
            self.acl_serve_wildcard = p.get("acl_serve_wildcard")

    req = NTPPayload(payload)

    if output_format == "template":
        return generate_ntp_template(req)
    else:
        cli = generate_ntp_cli(req)
        if output_format == "oneline":
            return generate_ntp_oneline(cli)
        return cli


def generate_aaa_from_payload(payload: Dict[str, Any], output_format: str) -> str:
    """Generate AAA config from payload in the specified format"""
    # Build AAARequest object
    req = AAARequest(
        device=payload.get("device", "Cisco IOS XE"),
        mode=payload.get("mode", "tacacs"),
        enable_secret=payload.get("enable_secret"),
        tacacs1_name=payload.get("tacacs1_name"),
        tacacs1_ip=payload.get("tacacs1_ip"),
        tacacs1_key=payload.get("tacacs1_key"),
        tacacs2_name=payload.get("tacacs2_name"),
        tacacs2_ip=payload.get("tacacs2_ip"),
        tacacs2_key=payload.get("tacacs2_key"),
        source_interface=payload.get("source_interface"),
        output_format=output_format,
    )

    if output_format == "template":
        return generate_aaa_template(req)
    else:
        if req.mode == "local-only":
            cli = generate_aaa_local_only(enable_secret=req.enable_secret)
        else:
            cli = generate_aaa_tacacs(req)
        if output_format == "oneline":
            return aaa_to_oneline(cli)
        return cli


# --------------------------------------------------------------------
# STATIC SECTIONS
# --------------------------------------------------------------------
DEFAULT_BANNER_TEXT = "Unauthorized access to this device is prohibited.\nAll activity is monitored."

def generate_banner(custom_text: str = None):
    text = custom_text.strip() if custom_text else DEFAULT_BANNER_TEXT
    return f"""banner login ^
{text}
^
"""


def generate_logging():
    return """
! Logging baseline
service timestamps debug datetime localtime
service timestamps log datetime localtime
logging buffered 64000 warnings
logging console warnings
"""


def generate_security_baseline(mode: str):
    base = """
! Security baseline
no ip http server
no ip http secure-server
ip ssh version 2
ip ssh authentication-retries 3
ip ssh time-out 60
"""

    if mode == "secure":
        base += """
ip ssh cipher aes256-ctr
ip ssh key-exchange group14-sha256
"""

    if mode == "hardened":
        base += """
ip ssh cipher aes256-ctr aes192-ctr aes128-ctr
ip ssh key-exchange group16-sha512
ip ssh key-exchange group14-sha256
no cdp run
no lldp run
"""

    return base


# --------------------------------------------------------------------
# YAML TEMPLATE
# --------------------------------------------------------------------
def generate_golden_template(req: GoldenConfigRequest) -> str:
    """Generate YAML template for automation tools (Ansible, Netmiko, etc.)"""
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # Generate configs from payloads if available
    snmpv3_cfg = None
    ntp_cfg = None
    aaa_cfg = None

    # SNMPv3: multi payload > single payload > config string
    if req.snmpv3_multi_payload:
        snmpv3_cfg = generate_snmpv3_multi_from_payload(req.snmpv3_multi_payload, "template")
    elif req.snmpv3_payload:
        snmpv3_cfg = generate_snmpv3_from_payload(req.snmpv3_payload, "template")
    elif req.snmpv3_config:
        snmpv3_cfg = req.snmpv3_config

    if req.ntp_payload:
        ntp_cfg = generate_ntp_from_payload(req.ntp_payload, "template")
    elif req.ntp_config:
        ntp_cfg = req.ntp_config

    if req.aaa_payload:
        aaa_cfg = generate_aaa_from_payload(req.aaa_payload, "template")
    elif req.aaa_config:
        aaa_cfg = req.aaa_config

    yaml = f"""# Golden Config YAML generated by NetDevOps Micro-Tools
# Mode: {req.mode}
# Date: {now}
# Device: {req.device}

golden_config:
  device: "{req.device}"
  mode: "{req.mode}"

  sections:
    snmpv3:
      enabled: {str(bool(snmpv3_cfg)).lower()}
      config: |
{_indent_multiline(snmpv3_cfg, 8) if snmpv3_cfg else "        # Not configured"}

    ntp:
      enabled: {str(bool(ntp_cfg)).lower()}
      config: |
{_indent_multiline(ntp_cfg, 8) if ntp_cfg else "        # Not configured"}

    aaa:
      enabled: {str(bool(aaa_cfg)).lower()}
      config: |
{_indent_multiline(aaa_cfg, 8) if aaa_cfg else "        # Not configured"}

  baseline:
    banner:
      enabled: {str(req.include_banner).lower()}
      text: "{req.custom_banner.strip() if req.custom_banner else DEFAULT_BANNER_TEXT}"

    logging:
      enabled: {str(req.include_logging).lower()}
      buffer_size: 64000
      level: "warnings"
      timestamps: true

    security:
      enabled: {str(req.include_security).lower()}
      http_server: false
      https_server: false
      ssh_version: 2
      ssh_auth_retries: 3
      ssh_timeout: 60
      cdp: {"false" if req.mode == "hardened" else "true"}
      lldp: {"false" if req.mode == "hardened" else "true"}
"""
    return yaml.strip()


def _indent_multiline(text: str, spaces: int) -> str:
    """Helper to indent multiline text for YAML"""
    if not text:
        return ""
    indent = " " * spaces
    lines = text.strip().split("\n")
    return "\n".join(indent + line for line in lines)


# --------------------------------------------------------------------
# ASSEMBLER
# --------------------------------------------------------------------
def assemble_golden(req: GoldenConfigRequest):
    sections = []

    # SNMPv3: multi payload > single payload > config string
    if req.snmpv3_multi_payload:
        snmpv3_cfg = generate_snmpv3_multi_from_payload(req.snmpv3_multi_payload, req.output_format)
        sections.append(f"! SNMPv3 (Multi-Host)\n{snmpv3_cfg}")
    elif req.snmpv3_payload:
        snmpv3_cfg = generate_snmpv3_from_payload(req.snmpv3_payload, req.output_format)
        sections.append(f"! SNMPv3\n{snmpv3_cfg}")
    elif req.snmpv3_config:
        sections.append(f"! SNMPv3\n{req.snmpv3_config}")

    # NTP: payload takes priority over config string
    if req.ntp_payload:
        ntp_cfg = generate_ntp_from_payload(req.ntp_payload, req.output_format)
        sections.append(f"! NTP\n{ntp_cfg}")
    elif req.ntp_config:
        sections.append(f"! NTP\n{req.ntp_config}")

    # AAA: payload takes priority over config string
    if req.aaa_payload:
        aaa_cfg = generate_aaa_from_payload(req.aaa_payload, req.output_format)
        sections.append(f"! AAA\n{aaa_cfg}")
    elif req.aaa_config:
        sections.append(f"! AAA\n{req.aaa_config}")

    # Built-in sections (modular - check include flags)
    if req.include_banner:
        sections.append("! Banner\n" + generate_banner(req.custom_banner))
    if req.include_logging:
        sections.append("! Logging\n" + generate_logging())
    if req.include_security:
        sections.append("! Security\n" + generate_security_baseline(req.mode))

    final = "\n\n".join(sections)

    # For oneline, only convert built-in sections (payloads already in correct format)
    if req.output_format == "oneline" and not (req.snmpv3_payload or req.ntp_payload or req.aaa_payload):
        lines = []
        for line in final.splitlines():
            line = line.strip()
            if not line or line.startswith("!"):
                continue
            lines.append(line)
        final = " ; ".join(lines)

    return final


# --------------------------------------------------------------------
# API ENDPOINT
# --------------------------------------------------------------------
@router.post("/golden-config")
def generate_golden_config(req: GoldenConfigRequest):

    if req.output_format == "template":
        final_cfg = generate_golden_template(req)
    else:
        final_cfg = assemble_golden(req)

    return {
        "device": req.device,
        "mode": req.mode,
        "output_format": req.output_format,
        "config": final_cfg,
        "metadata": {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "module": "Golden Config Builder",
            "tool": "NetDevOps Micro-Tools"
        }
    }
