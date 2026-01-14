from fastapi import APIRouter
from pydantic import BaseModel
import datetime
from typing import Optional, List

router = APIRouter()


# -----------------------------
# NTP Request Schema (v2 - Cisco Best Practices)
# -----------------------------
class NTPRequest(BaseModel):
    device: str = "Cisco IOS XE"

    # Network tier determines NTP hierarchy
    network_tier: str = "ACCESS"  # CORE / DISTRIBUTION / ACCESS

    # Time settings
    timezone: str = "UTC"

    # NTP servers
    primary_server: str
    secondary_server: Optional[str] = None
    tertiary_server: Optional[str] = None  # Cisco recommends 3 sources

    # Source interface (best practice: use Loopback)
    source_interface: Optional[str] = None

    # Authentication settings
    use_auth: bool = False
    auth_algorithm: str = "sha1"  # md5 / sha1 / sha256
    key_id: Optional[str] = None
    key_value: Optional[str] = None

    # NTP logging
    use_logging: bool = True

    # Access control
    use_access_control: bool = False
    acl_peer_hosts: Optional[str] = None      # Comma-separated IPs for peer ACL
    acl_serve_network: Optional[str] = None   # Network for serve-only ACL (e.g., 192.168.0.0)
    acl_serve_wildcard: Optional[str] = None  # Wildcard mask (e.g., 0.0.255.255)

    # Hardware clock sync
    update_calendar: bool = False

    # Output
    output_format: str = "cli"


# -----------------------------
# NTP Logic (v2 - Cisco Best Practices)
# -----------------------------
def generate_ntp_cli(req: NTPRequest) -> str:
    lines = []

    # Section: Clock settings
    lines.append("!")
    lines.append("! === Clock Settings ===")
    lines.append(f"clock timezone {req.timezone}")
    if req.update_calendar:
        lines.append("clock calendar-valid")

    # Section: NTP Authentication (if enabled)
    if req.use_auth and req.key_id and req.key_value:
        lines.append("!")
        lines.append("! === NTP Authentication ===")
        lines.append("ntp authenticate")
        lines.append(f"ntp authentication-key {req.key_id} {req.auth_algorithm} {req.key_value}")
        lines.append(f"ntp trusted-key {req.key_id}")

    # Section: NTP Source Interface
    if req.source_interface:
        lines.append("!")
        lines.append("! === NTP Source Interface ===")
        lines.append(f"ntp source {req.source_interface}")

    # Section: NTP Calendar Update
    if req.update_calendar:
        lines.append("ntp update-calendar")

    # Section: NTP Logging
    if req.use_logging:
        lines.append("!")
        lines.append("! === NTP Logging ===")
        lines.append("ntp logging")

    # Section: NTP Servers
    lines.append("!")
    if req.network_tier == "CORE":
        lines.append("! === NTP Servers (CORE - External Stratum Sources) ===")
    else:
        lines.append(f"! === NTP Servers ({req.network_tier} - Upstream CORE) ===")

    # Primary server with prefer keyword and optional key binding
    primary_cmd = f"ntp server {req.primary_server} prefer"
    if req.use_auth and req.key_id:
        primary_cmd += f" key {req.key_id}"
    lines.append(primary_cmd)

    # Secondary server
    if req.secondary_server:
        secondary_cmd = f"ntp server {req.secondary_server}"
        if req.use_auth and req.key_id:
            secondary_cmd += f" key {req.key_id}"
        lines.append(secondary_cmd)

    # Tertiary server (Cisco recommends 3 sources)
    if req.tertiary_server:
        tertiary_cmd = f"ntp server {req.tertiary_server}"
        if req.use_auth and req.key_id:
            tertiary_cmd += f" key {req.key_id}"
        lines.append(tertiary_cmd)

    # Section: Access Control Lists (if enabled)
    if req.use_access_control:
        lines.append("!")
        lines.append("! === NTP Access Control ===")

        # Peer ACL (who can sync with us)
        peer_acl_num = 10
        serve_acl_num = 20

        # Build peer ACL from comma-separated hosts
        if req.acl_peer_hosts:
            peer_hosts = [h.strip() for h in req.acl_peer_hosts.split(",") if h.strip()]
            for host in peer_hosts:
                lines.append(f"access-list {peer_acl_num} permit {host}")
            lines.append(f"ntp access-group peer {peer_acl_num}")

        # Build serve-only ACL (clients we serve time to)
        if req.acl_serve_network and req.acl_serve_wildcard:
            lines.append(f"access-list {serve_acl_num} permit {req.acl_serve_network} {req.acl_serve_wildcard}")
            lines.append(f"ntp access-group serve-only {serve_acl_num}")

    lines.append("!")

    return "\n".join(lines)


def generate_ntp_oneline(cli_text: str) -> str:
    lines = []
    for line in cli_text.splitlines():
        line = line.strip()
        if not line or line.startswith("!"):
            continue
        lines.append(line)
    return " ; ".join(lines)


# -----------------------------
# NTP API Endpoint
# -----------------------------
@router.post("/ntp")
def generate_ntp(req: NTPRequest):
    cli_config = generate_ntp_cli(req)

    if req.output_format == "oneline":
        output = generate_ntp_oneline(cli_config)
    else:
        output = cli_config

    return {
        "device": req.device,
        "output_format": req.output_format,
        "config": output,
        "metadata": {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "module": "NTP Generator",
            "tool": "Cisco Micro-Tool Generator",
        },
    }
