"""
CIS Compliance Checker — Audit Cisco IOS/IOS-XE config against CIS Benchmark rules.

Rule-based: no LLM required, zero cost, works offline.
Based on CIS Cisco IOS Benchmark v4.x key recommendations.

Endpoints:
  POST /cis-audit/check — Audit config against CIS benchmark rules
"""

import re
from typing import List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter()


# ----------------------------
# Block extractors (shared)
# ----------------------------

VTY_HEADER_RE = re.compile(r"^line vty\s+(\d+)(?:\s+(\d+))?\s*$", re.MULTILINE)
CON_HEADER_RE = re.compile(r"^line con(?:sole)?\s+(\d+)(?:\s+(\d+))?\s*$", re.MULTILINE)

def _extract_blocks(cfg: str, header_re: re.Pattern) -> List[str]:
    """Return list of block bodies. A block starts at a header line and ends at
    the next top-level line (first char not whitespace) or end of text.

    Robust to:
    - range syntax ("line vty 0 4", "line vty 5 15")
    - trailing whitespace on header
    - interleaved "!" separators and other top-level commands
    """
    blocks = []
    headers = list(header_re.finditer(cfg))
    for i, m in enumerate(headers):
        start = m.end()
        # Find next top-level line (line starts with a non-whitespace char).
        # The block body is indented (leading space/tab).
        end = len(cfg)
        pos = start
        while pos < len(cfg):
            # Find next newline
            nl = cfg.find("\n", pos)
            if nl == -1:
                break
            next_line_start = nl + 1
            if next_line_start >= len(cfg):
                break
            ch = cfg[next_line_start]
            if ch not in (" ", "\t", "\n", "\r"):
                # Top-level line — block ends here
                end = next_line_start
                break
            pos = next_line_start
        blocks.append(cfg[m.start():end])
    return blocks


# ----------------------------
# Models
# ----------------------------

class AuditRequest(BaseModel):
    config_text: str = Field(..., min_length=3, description="Cisco IOS/IOS-XE running-config")
    level: str = Field(default="1", description="CIS Level: 1 (basic) or 2 (hardened)")


class AuditRule(BaseModel):
    rule_id: str  # e.g. "1.1.1"
    title: str
    description: str
    result: str  # "PASS", "FAIL", "WARNING", "N/A"
    severity: str  # "critical", "high", "medium", "low"
    category: str
    evidence: str = ""  # what was found in config
    remediation: str = ""  # how to fix
    cis_ref: str = ""  # CIS benchmark reference


class AuditCategory(BaseModel):
    name: str
    passed: int
    failed: int
    warnings: int
    rules: List[AuditRule]


class AuditResponse(BaseModel):
    hostname: Optional[str] = None
    level: str
    categories: List[AuditCategory]
    total_rules: int
    passed: int
    failed: int
    warnings: int
    score: float  # 0-100
    grade: str  # A/B/C/D/F
    summary: List[str]


# ----------------------------
# CIS Benchmark Rules
# ----------------------------

# Each rule: (rule_id, title, category, severity, level, check_fn)
# check_fn(config_text) -> (result, evidence, remediation)

def _check_password_encryption(cfg):
    if re.search(r"^service password-encryption", cfg, re.M):
        return "PASS", "service password-encryption found", ""
    return "FAIL", "service password-encryption NOT found", "Add: service password-encryption"

def _check_enable_secret(cfg):
    if re.search(r"^enable secret\s+[89]\s+", cfg, re.M):
        return "PASS", "enable secret with Type 8/9 (strong hash)", ""
    if re.search(r"^enable secret\s+5\s+", cfg, re.M):
        return "WARNING", "enable secret Type 5 (MD5) — acceptable but Type 9 preferred", "Upgrade to: enable algorithm-type scrypt secret <password>"
    if re.search(r"^enable secret", cfg, re.M):
        return "PASS", "enable secret configured", ""
    if re.search(r"^enable password", cfg, re.M):
        return "FAIL", "enable PASSWORD used (weak Type 7 encryption)", "Replace with: enable secret <password>"
    return "FAIL", "No enable secret configured", "Add: enable secret <password>"

def _check_no_enable_password(cfg):
    if re.search(r"^enable password", cfg, re.M):
        return "FAIL", "enable password found (weak Type 7)", "Remove: no enable password\nUse: enable secret <password>"
    return "PASS", "No enable password (good)", ""

def _check_aaa_new_model(cfg):
    if re.search(r"^aaa new-model", cfg, re.M):
        return "PASS", "aaa new-model enabled", ""
    return "FAIL", "AAA not enabled", "Add: aaa new-model"

def _check_aaa_authentication(cfg):
    if not re.search(r"^aaa new-model", cfg, re.M):
        return "N/A", "AAA not enabled — skipping", ""
    if re.search(r"^aaa authentication login\s+\S+\s+.*group\s+(tacacs|radius)", cfg, re.M):
        return "PASS", "AAA authentication via TACACS+/RADIUS with fallback", ""
    if re.search(r"^aaa authentication login\s+\S+\s+local", cfg, re.M):
        return "WARNING", "AAA authentication local only (no central server)", "Consider: aaa authentication login default group tacacs+ local"
    return "FAIL", "No AAA authentication list configured", "Add: aaa authentication login default group tacacs+ local"

def _check_aaa_accounting(cfg):
    if not re.search(r"^aaa new-model", cfg, re.M):
        return "N/A", "AAA not enabled — skipping", ""
    if re.search(r"^aaa accounting\s+(exec|commands)", cfg, re.M):
        return "PASS", "AAA accounting configured", ""
    return "FAIL", "No AAA accounting — no audit trail", "Add: aaa accounting exec default start-stop group tacacs+"

def _check_ssh_version_2(cfg):
    if re.search(r"^ip ssh version 2", cfg, re.M):
        return "PASS", "SSH version 2 enforced", ""
    if re.search(r"^ip ssh version 1", cfg, re.M):
        return "FAIL", "SSH version 1 (VULNERABLE)", "Change to: ip ssh version 2"
    return "WARNING", "SSH version not explicitly set (defaults may allow v1)", "Add: ip ssh version 2"

def _check_ssh_timeout(cfg):
    m = re.search(r"^ip ssh time-out\s+(\d+)", cfg, re.M)
    if m:
        timeout = int(m.group(1))
        if timeout <= 60:
            return "PASS", f"SSH timeout: {timeout} seconds", ""
        return "WARNING", f"SSH timeout: {timeout}s (>60s recommended)", "Set: ip ssh time-out 60"
    return "WARNING", "SSH timeout not set (default 120s)", "Add: ip ssh time-out 60"

def _check_ssh_retries(cfg):
    m = re.search(r"^ip ssh authentication-retries\s+(\d+)", cfg, re.M)
    if m:
        retries = int(m.group(1))
        if retries <= 3:
            return "PASS", f"SSH retries: {retries}", ""
        return "WARNING", f"SSH retries: {retries} (3 recommended)", "Set: ip ssh authentication-retries 3"
    return "WARNING", "SSH retries not set (default 3)", ""

def _check_no_telnet(cfg):
    vty_blocks = _extract_blocks(cfg, VTY_HEADER_RE)
    if not vty_blocks:
        return "N/A", "No VTY lines configured — inbound VTY management disabled", ""
    offending = []
    missing_transport = False
    for block in vty_blocks:
        # Find transport input lines (ignoring comments)
        transport_lines = re.findall(r"^\s*transport input\s+(.+?)\s*$", block, re.M)
        if not transport_lines:
            missing_transport = True
            continue
        for ti in transport_lines:
            tokens = ti.split()
            # "transport input all" permits everything including telnet
            if "all" in tokens or "telnet" in tokens:
                offending.append(f"transport input {ti}")
    if offending:
        evidence = "; ".join(sorted(set(offending)))
        return "FAIL", f"Telnet permitted on VTY: {evidence}", "Set: transport input ssh"
    if missing_transport:
        return "WARNING", "No transport input specified on some VTY lines (telnet may be allowed by default)", "Add: transport input ssh"
    return "PASS", "VTY lines restricted to SSH only", ""

def _check_exec_timeout(cfg):
    vty_blocks = _extract_blocks(cfg, VTY_HEADER_RE)
    con_blocks = _extract_blocks(cfg, CON_HEADER_RE)
    all_blocks = vty_blocks + con_blocks
    if not all_blocks:
        return "N/A", "No VTY/console lines configured", ""
    for block in all_blocks:
        if re.search(r"^\s*exec-timeout\s+0\s+0\b", block, re.M):
            return "FAIL", "exec-timeout 0 0 found (NEVER timeout)", "Set: exec-timeout 10 0 (10 minutes)"
    # At least one block missing exec-timeout → FAIL (management line without idle timeout)
    missing = [b for b in all_blocks if not re.search(r"^\s*exec-timeout\b", b, re.M)]
    if missing:
        return "FAIL", f"exec-timeout not set on {len(missing)} of {len(all_blocks)} management line block(s)", "Add: exec-timeout 10 0"
    return "PASS", "exec-timeout configured on all management lines", ""

def _check_access_class(cfg):
    vty_blocks = _extract_blocks(cfg, VTY_HEADER_RE)
    if not vty_blocks:
        return "N/A", "No VTY lines configured", ""
    unprotected = [b for b in vty_blocks if not re.search(r"^\s*access-class\s+\S+\s+in\b", b, re.M)]
    if not unprotected:
        return "PASS", "All VTY blocks restricted by access-class ACL", ""
    if len(unprotected) == len(vty_blocks):
        return "FAIL", "No access-class on any VTY lines — anyone routable can attempt SSH", "Add: access-class <ACL> in"
    return "FAIL", f"access-class missing on {len(unprotected)} of {len(vty_blocks)} VTY block(s)", "Add: access-class <ACL> in"

def _check_no_http_server(cfg):
    if re.search(r"^no ip http server", cfg, re.M):
        return "PASS", "HTTP server disabled", ""
    if re.search(r"^ip http server", cfg, re.M):
        return "FAIL", "HTTP server enabled (unencrypted)", "Add: no ip http server"
    return "PASS", "HTTP server not configured", ""

def _check_https_server(cfg):
    if re.search(r"^ip http secure-server", cfg, re.M):
        return "PASS", "HTTPS server enabled", ""
    return "WARNING", "HTTPS server not enabled", "Consider: ip http secure-server (if web management needed)"

def _check_no_source_route(cfg):
    if re.search(r"^no ip source-route", cfg, re.M):
        return "PASS", "IP source routing disabled", ""
    return "FAIL", "IP source routing not disabled", "Add: no ip source-route"

def _check_no_finger(cfg):
    if re.search(r"^no ip finger", cfg, re.M) or re.search(r"^no service finger", cfg, re.M):
        return "PASS", "Finger service disabled", ""
    # In modern IOS, finger is off by default
    return "PASS", "Finger service not configured (off by default in modern IOS)", ""

def _check_no_cdp_global(cfg):
    if re.search(r"^no cdp run", cfg, re.M):
        return "PASS", "CDP disabled globally", ""
    return "WARNING", "CDP enabled globally (information disclosure)", "Consider: no cdp run (on untrusted interfaces)"

def _check_no_pad(cfg):
    if re.search(r"^no service pad", cfg, re.M):
        return "PASS", "PAD service disabled", ""
    return "FAIL", "PAD service not disabled", "Add: no service pad"

def _check_tcp_keepalives(cfg):
    has_in = re.search(r"^service tcp-keepalives-in", cfg, re.M)
    has_out = re.search(r"^service tcp-keepalives-out", cfg, re.M)
    if has_in and has_out:
        return "PASS", "TCP keepalives enabled (in + out)", ""
    if has_in or has_out:
        return "WARNING", "Only one direction of TCP keepalives", "Add both: service tcp-keepalives-in / service tcp-keepalives-out"
    return "FAIL", "TCP keepalives not enabled", "Add: service tcp-keepalives-in / service tcp-keepalives-out"

def _check_logging_buffered(cfg):
    if re.search(r"^logging buffered", cfg, re.M):
        return "PASS", "Logging to buffer configured", ""
    return "FAIL", "No buffered logging", "Add: logging buffered 64000 informational"

def _check_logging_remote(cfg):
    if re.search(r"^logging host\s+|^logging\s+\d+\.\d+\.\d+\.\d+", cfg, re.M):
        return "PASS", "Remote syslog configured", ""
    return "FAIL", "No remote syslog server", "Add: logging host <syslog-server-IP>"

def _check_logging_timestamps(cfg):
    if re.search(r"^service timestamps (log|debug)\s+datetime\s+msec", cfg, re.M):
        return "PASS", "Log timestamps with datetime msec", ""
    if re.search(r"^service timestamps", cfg, re.M):
        return "WARNING", "Timestamps present but may lack milliseconds", "Set: service timestamps log datetime msec localtime show-timezone"
    return "FAIL", "No service timestamps configured", "Add: service timestamps log datetime msec localtime show-timezone"

NTP_SERVER_RE = re.compile(
    r"^\s*ntp\s+server\s+(?:vrf\s+\S+\s+)?(?P<host>\S+)"
    r"(?P<modifiers>(?:\s+(?:prefer|key\s+\d+|source\s+\S+|version\s+\d+|iburst|minpoll\s+\d+|maxpoll\s+\d+))*)\s*$",
    re.MULTILINE,
)

def _check_ntp_configured(cfg):
    servers = [m.group("host") for m in NTP_SERVER_RE.finditer(cfg)]
    if servers:
        evidence = f"NTP server(s) configured: {', '.join(servers)}"
        return "PASS", evidence, ""
    return "FAIL", "No NTP server configured", "Add: ntp server <NTP-server-IP-or-FQDN>"

def _check_ntp_authentication(cfg):
    if not NTP_SERVER_RE.search(cfg):
        return "N/A", "No NTP configured — skipping", ""
    if re.search(r"^ntp authenticate\b", cfg, re.M):
        return "PASS", "NTP authentication enabled", ""
    return "WARNING", "NTP configured without authentication", "Add: ntp authenticate / ntp authentication-key / ntp trusted-key"

def _check_banner(cfg):
    if re.search(r"^banner (motd|login)", cfg, re.M):
        return "PASS", "Login banner configured", ""
    return "FAIL", "No login banner (legal/compliance requirement)", "Add: banner motd ^Unauthorized access prohibited^"

SNMP_COMMUNITY_RE = re.compile(
    r"^\s*snmp-server\s+community\s+(?P<name>\S+)"
    r"(?:\s+(?P<access>RO|RW))?"
    r"(?:\s+(?P<acl>\S+))?\s*$",
    re.MULTILINE | re.IGNORECASE,
)

DEFAULT_COMMUNITIES = {"public", "private", "cisco", "admin", "manager", "netman", "secret"}

def _check_no_snmpv2(cfg):
    matches = list(SNMP_COMMUNITY_RE.finditer(cfg))
    if not matches:
        return "PASS", "No SNMPv2c community strings", ""
    defaults = []
    rw_any = []
    all_communities = []
    for m in matches:
        name = m.group("name")
        access = (m.group("access") or "RO").upper()
        acl = m.group("acl")
        all_communities.append(f"{name} ({access}{', ACL='+acl if acl else ''})")
        if name.lower() in DEFAULT_COMMUNITIES:
            defaults.append(f"{name}/{access}")
        if access == "RW":
            rw_any.append(name)
    # Severity escalation is enforced via the rule severity at registration
    # (critical). Evidence reflects worst condition.
    if defaults and rw_any and any(n.lower() in DEFAULT_COMMUNITIES for n in rw_any):
        evidence = (
            f"DEFAULT + RW community string(s): {', '.join(defaults)}. "
            f"Equivalent to unauthenticated admin access. "
            f"All: {', '.join(all_communities)}"
        )
        remediation = (
            "IMMEDIATE: no snmp-server community " + rw_any[0] + "\n"
            "Then migrate to SNMPv3 authPriv: snmp-server group <grp> v3 priv"
        )
        return "FAIL", evidence, remediation
    if defaults:
        evidence = f"Default community string(s): {', '.join(defaults)}. All: {', '.join(all_communities)}"
        return "FAIL", evidence, "Remove default communities; migrate to SNMPv3 authPriv"
    if rw_any:
        evidence = f"SNMPv2c RW community: {', '.join(rw_any)}. All: {', '.join(all_communities)}"
        return "FAIL", evidence, "Remove RW SNMPv2c; migrate to SNMPv3 authPriv"
    evidence = f"SNMPv2c community string(s): {', '.join(all_communities)}"
    return "FAIL", evidence, "Remove SNMPv2c; migrate to SNMPv3: snmp-server group <grp> v3 priv"

def _check_snmpv3_priv(cfg):
    if re.search(r"^snmp-server group\s+\S+\s+v3\s+priv", cfg, re.M):
        return "PASS", "SNMPv3 with priv (auth+encryption)", ""
    if re.search(r"^snmp-server group\s+\S+\s+v3\s+(auth|noauth)", cfg, re.M):
        return "WARNING", "SNMPv3 without encryption", "Use: snmp-server group <name> v3 priv"
    if SNMP_COMMUNITY_RE.search(cfg):
        return "FAIL", "Using SNMPv2c instead of SNMPv3", "Migrate to SNMPv3 with priv"
    return "N/A", "SNMP not configured", ""

def _check_dhcp_snooping(cfg):
    if re.search(r"^ip dhcp snooping$", cfg, re.M):
        return "PASS", "DHCP snooping enabled", ""
    return "WARNING", "DHCP snooping not enabled", "Add: ip dhcp snooping"

def _check_arp_inspection(cfg):
    if re.search(r"^ip arp inspection vlan", cfg, re.M):
        return "PASS", "Dynamic ARP inspection enabled", ""
    return "WARNING", "Dynamic ARP inspection not enabled", "Add: ip arp inspection vlan <vlans>"

def _check_port_security(cfg):
    if re.search(r"switchport port-security", cfg, re.M):
        return "PASS", "Port security configured on some interfaces", ""
    return "WARNING", "No port security configured", "Consider: switchport port-security on access ports"

def _check_stp_bpduguard(cfg):
    if re.search(r"spanning-tree portfast bpduguard default", cfg, re.M):
        return "PASS", "BPDU Guard enabled globally for portfast ports", ""
    if re.search(r"spanning-tree bpduguard enable", cfg, re.M):
        return "WARNING", "BPDU Guard on individual ports only (not global)", "Add globally: spanning-tree portfast bpduguard default"
    return "WARNING", "BPDU Guard not configured", "Add: spanning-tree portfast bpduguard default"

def _check_stp_mode(cfg):
    if re.search(r"^spanning-tree mode rapid-pvst", cfg, re.M):
        return "PASS", "STP mode: rapid-pvst (recommended)", ""
    if re.search(r"^spanning-tree mode mst", cfg, re.M):
        return "PASS", "STP mode: MST", ""
    m = re.search(r"^spanning-tree mode\s+(\S+)", cfg, re.M)
    if m:
        return "WARNING", f"STP mode: {m.group(1)} — consider rapid-pvst", "Set: spanning-tree mode rapid-pvst"
    return "WARNING", "STP mode not explicitly set", "Add: spanning-tree mode rapid-pvst"

def _check_domain_name(cfg):
    if re.search(r"^ip domain[- ]name\s+\S+", cfg, re.M):
        return "PASS", "Domain name configured (required for SSH keys)", ""
    return "WARNING", "No domain name set (needed for SSH key generation)", "Add: ip domain-name <domain>"

def _check_rsa_key_size(cfg):
    m = re.search(r"^crypto key generate rsa.*modulus\s+(\d+)", cfg, re.M)
    if m:
        bits = int(m.group(1))
        if bits >= 2048:
            return "PASS", f"RSA key: {bits}-bit", ""
        return "FAIL", f"RSA key: {bits}-bit (weak)", "Regenerate: crypto key generate rsa modulus 2048"
    # Can't tell from running-config alone
    return "N/A", "RSA key size not visible in config (check: show crypto key mypubkey rsa)", ""

def _check_login_local(cfg):
    vty_blocks = _extract_blocks(cfg, VTY_HEADER_RE)
    if not vty_blocks:
        return "N/A", "No VTY lines configured", ""
    has_aaa = bool(re.search(r"^aaa new-model", cfg, re.M))
    any_no_login = False
    all_have_login = True
    for block in vty_blocks:
        if re.search(r"^\s*no login\b", block, re.M):
            any_no_login = True
        # "login local", "login authentication <list>" → authenticated.
        # Bare "login" on a block with "password <pwd>" is weak but present;
        # when aaa new-model is on, bare "login" inherits the default list.
        has_login_strong = bool(re.search(r"^\s*login\s+(local|authentication)\b", block, re.M))
        has_login_bare = bool(re.search(r"^\s*login\s*$", block, re.M))
        if not (has_login_strong or has_login_bare):
            all_have_login = False
    if any_no_login:
        return "FAIL", "VTY block(s) configured with 'no login' — no authentication required", "Add: login local (or login authentication <list>)"
    if all_have_login:
        if has_aaa:
            return "PASS", "VTY lines require authentication", ""
        return "PASS", "VTY lines have login configured", ""
    return "WARNING", "Login method not explicitly set on all VTY blocks", "Add: login local (or login authentication <list>)"

def _check_ip_verify_source(cfg):
    if re.search(r"ip verify source", cfg, re.M):
        return "PASS", "IP Source Guard configured on some interfaces", ""
    return "WARNING", "IP Source Guard not configured", "Consider: ip verify source on access ports"

def _check_console_password(cfg):
    con_blocks = _extract_blocks(cfg, CON_HEADER_RE)
    if not con_blocks:
        return "N/A", "No console line configured in running-config", ""
    for block in con_blocks:
        if re.search(r"^\s*login\s+(local|authentication)\b", block, re.M):
            return "PASS", "Console line requires authentication", ""
        if re.search(r"^\s*password\b", block, re.M) and re.search(r"^\s*login\s*$", block, re.M):
            return "WARNING", "Console uses line password (weak)", "Use: login local with username/secret"
    return "WARNING", "Console authentication not verified", "Ensure: login local on line con 0"

def _check_no_ip_bootp(cfg):
    if re.search(r"^no ip bootp server", cfg, re.M):
        return "PASS", "BOOTP server disabled", ""
    return "WARNING", "BOOTP server not explicitly disabled", "Add: no ip bootp server"

def _check_no_gratuitous_arps(cfg):
    if re.search(r"^no ip gratuitous-arps", cfg, re.M):
        return "PASS", "Gratuitous ARPs disabled", ""
    return "WARNING", "Gratuitous ARPs not disabled", "Add: no ip gratuitous-arps"


# ----------------------------
# Rule registry
# ----------------------------

RULES = [
    # Management Plane (1.x)
    ("1.1.1", "Enable secret", "Management Plane", "critical", "1", _check_enable_secret),
    ("1.1.2", "No enable password", "Management Plane", "critical", "1", _check_no_enable_password),
    ("1.1.3", "Password encryption", "Management Plane", "high", "1", _check_password_encryption),
    ("1.1.4", "AAA new-model", "Management Plane", "critical", "1", _check_aaa_new_model),
    ("1.1.5", "AAA authentication", "Management Plane", "high", "1", _check_aaa_authentication),
    ("1.1.6", "AAA accounting", "Management Plane", "medium", "2", _check_aaa_accounting),

    # Access (1.2.x)
    ("1.2.1", "SSH version 2", "Access", "critical", "1", _check_ssh_version_2),
    ("1.2.2", "SSH timeout", "Access", "medium", "1", _check_ssh_timeout),
    ("1.2.3", "SSH retries", "Access", "low", "2", _check_ssh_retries),
    ("1.2.4", "No telnet on VTY", "Access", "critical", "1", _check_no_telnet),
    ("1.2.5", "Exec-timeout", "Access", "high", "1", _check_exec_timeout),
    ("1.2.6", "VTY access-class", "Access", "high", "1", _check_access_class),
    ("1.2.7", "VTY login required", "Access", "critical", "1", _check_login_local),
    ("1.2.8", "Console authentication", "Access", "high", "2", _check_console_password),
    ("1.2.9", "Domain name", "Access", "low", "1", _check_domain_name),

    # Services (2.x)
    ("2.1.1", "No HTTP server", "Services", "critical", "1", _check_no_http_server),
    ("2.1.2", "HTTPS server", "Services", "medium", "2", _check_https_server),
    ("2.1.3", "No source routing", "Services", "high", "1", _check_no_source_route),
    ("2.1.4", "No PAD service", "Services", "medium", "1", _check_no_pad),
    ("2.1.5", "TCP keepalives", "Services", "medium", "1", _check_tcp_keepalives),
    ("2.1.6", "No CDP globally", "Services", "medium", "2", _check_no_cdp_global),
    ("2.1.7", "No BOOTP server", "Services", "low", "2", _check_no_ip_bootp),
    ("2.1.8", "No gratuitous ARPs", "Services", "low", "2", _check_no_gratuitous_arps),

    # Logging & NTP (3.x)
    ("3.1.1", "Logging to buffer", "Logging & NTP", "high", "1", _check_logging_buffered),
    ("3.1.2", "Remote syslog", "Logging & NTP", "high", "1", _check_logging_remote),
    ("3.1.3", "Log timestamps", "Logging & NTP", "medium", "1", _check_logging_timestamps),
    ("3.1.4", "NTP configured", "Logging & NTP", "high", "1", _check_ntp_configured),
    ("3.1.5", "NTP authentication", "Logging & NTP", "medium", "2", _check_ntp_authentication),

    # Banner (4.x)
    ("4.1.1", "Login banner", "Banner & Info", "medium", "1", _check_banner),

    # SNMP (5.x)
    ("5.1.1", "No SNMPv2c", "SNMP", "critical", "1", _check_no_snmpv2),
    ("5.1.2", "SNMPv3 with priv", "SNMP", "high", "1", _check_snmpv3_priv),

    # Layer 2 (6.x)
    ("6.1.1", "DHCP snooping", "Layer 2 Security", "high", "2", _check_dhcp_snooping),
    ("6.1.2", "ARP inspection", "Layer 2 Security", "high", "2", _check_arp_inspection),
    ("6.1.3", "Port security", "Layer 2 Security", "medium", "2", _check_port_security),
    ("6.1.4", "IP Source Guard", "Layer 2 Security", "medium", "2", _check_ip_verify_source),
    ("6.1.5", "BPDU Guard", "Layer 2 Security", "high", "2", _check_stp_bpduguard),
    ("6.1.6", "STP mode", "Layer 2 Security", "medium", "2", _check_stp_mode),
]


# ----------------------------
# Score and grade
# ----------------------------

SEVERITY_WEIGHTS = {
    "critical": 5,
    "high": 3,
    "medium": 2,
    "low": 1,
}

def _calculate_score(results: List[AuditRule]) -> tuple:
    """Calculate compliance score 0-100 and letter grade."""
    total_weight = 0
    earned_weight = 0

    for r in results:
        if r.result == "N/A":
            continue
        w = SEVERITY_WEIGHTS.get(r.severity, 1)
        total_weight += w
        if r.result == "PASS":
            earned_weight += w
        elif r.result == "WARNING":
            earned_weight += w * 0.5

    score = (earned_weight / max(total_weight, 1)) * 100

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return round(score, 1), grade


def _generate_summary(results: List[AuditRule], score: float, grade: str) -> List[str]:
    summary = []
    passed = sum(1 for r in results if r.result == "PASS")
    failed = sum(1 for r in results if r.result == "FAIL")
    warnings = sum(1 for r in results if r.result == "WARNING")

    summary.append(f"CIS Compliance Score: {score}% (Grade {grade})")
    summary.append(f"{passed} passed, {failed} failed, {warnings} warnings")

    critical_fails = [r for r in results if r.result == "FAIL" and r.severity == "critical"]
    if critical_fails:
        summary.append(f"CRITICAL failures ({len(critical_fails)}): {', '.join(r.title for r in critical_fails)}")

    if score >= 90:
        summary.append("Excellent hardening. Minor improvements possible.")
    elif score >= 75:
        summary.append("Good baseline. Address critical/high failures to improve.")
    elif score >= 60:
        summary.append("Moderate compliance. Several important gaps to fix.")
    elif score >= 40:
        summary.append("Poor compliance. Significant hardening required.")
    else:
        summary.append("Critical compliance gaps. Immediate remediation needed.")

    return summary


# ----------------------------
# Endpoint
# ----------------------------

@router.post("/cis-audit/check", response_model=AuditResponse)
def cis_audit(req: AuditRequest):
    """Audit Cisco IOS/IOS-XE config against CIS Benchmark."""

    level = req.level if req.level in ("1", "2") else "1"

    # Detect hostname
    hostname = None
    m = re.search(r"^hostname\s+(\S+)", req.config_text, re.MULTILINE)
    if m:
        hostname = m.group(1)

    # Run checks
    all_results = []
    for rule_id, title, category, severity, rule_level, check_fn in RULES:
        # Level 1 runs level 1 rules; Level 2 runs all
        if level == "1" and rule_level == "2":
            continue

        result, evidence, remediation = check_fn(req.config_text)
        all_results.append(AuditRule(
            rule_id=rule_id,
            title=title,
            description=f"CIS Benchmark {rule_id}",
            result=result,
            severity=severity,
            category=category,
            evidence=evidence,
            remediation=remediation,
            cis_ref=f"CIS Cisco IOS Benchmark {rule_id}",
        ))

    # Group by category
    cat_map = {}
    for r in all_results:
        if r.category not in cat_map:
            cat_map[r.category] = []
        cat_map[r.category].append(r)

    categories = []
    for cat_name, rules in cat_map.items():
        categories.append(AuditCategory(
            name=cat_name,
            passed=sum(1 for r in rules if r.result == "PASS"),
            failed=sum(1 for r in rules if r.result == "FAIL"),
            warnings=sum(1 for r in rules if r.result == "WARNING"),
            rules=rules,
        ))

    # Score
    score, grade = _calculate_score(all_results)

    # Stats
    passed = sum(1 for r in all_results if r.result == "PASS")
    failed = sum(1 for r in all_results if r.result == "FAIL")
    warnings = sum(1 for r in all_results if r.result == "WARNING")

    summary = _generate_summary(all_results, score, grade)

    return AuditResponse(
        hostname=hostname,
        level=level,
        categories=categories,
        total_rules=len(all_results),
        passed=passed,
        failed=failed,
        warnings=warnings,
        score=score,
        grade=grade,
        summary=summary,
    )
