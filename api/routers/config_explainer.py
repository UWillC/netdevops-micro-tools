"""
Config Explainer — Explains Cisco IOS/IOS-XE config in plain English.

Rule-based: no LLM required, zero cost, works offline.
Covers 150+ common Cisco commands with explanations, risk flags, and tips.

Endpoints:
  POST /config-explainer/explain — Parse config and explain each section
"""

import re
from typing import List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter()


# ----------------------------
# Models
# ----------------------------

class ExplainRequest(BaseModel):
    config_text: str = Field(..., min_length=3, description="Cisco config snippet or full running-config")
    mode: str = Field(default="standard", description="standard or junior")


class ExplainedLine(BaseModel):
    line: str
    explanation: str
    category: str = ""
    risk: Optional[str] = None  # "warning", "critical", "info"
    tip: Optional[str] = None


class ExplainedSection(BaseModel):
    title: str
    lines: List[ExplainedLine]
    summary: str = ""


class ExplainResponse(BaseModel):
    hostname: Optional[str] = None
    sections: List[ExplainedSection]
    security_notes: List[str]
    total_lines: int
    explained_lines: int
    coverage_pct: float
    mode: str


# ----------------------------
# Knowledge base: command → explanation
# ----------------------------

# Each entry: (regex_pattern, category, explanation_template, risk, tip)
# Use {0}, {1}, etc. for captured groups in explanation_template

COMMAND_DB = [
    # === HOSTNAME & BASICS ===
    (r"^hostname\s+(\S+)", "basics",
     "Sets the device hostname to '{0}'",
     None, "Hostname appears in CLI prompt and SNMP."),

    (r"^ip domain[- ]name\s+(\S+)", "basics",
     "Sets the DNS domain name to '{0}' — used for SSH key generation and FQDN",
     None, None),

    (r"^service timestamps (debug|log)\s+(datetime|uptime)(?:\s+(.+))?", "basics",
     "Adds {1} timestamps to {0} messages{2}",
     None, "datetime with msec and timezone is recommended for log correlation."),

    (r"^service password-encryption", "security",
     "Enables weak (Type 7) encryption for plaintext passwords in config",
     "info", "Type 7 is easily reversible. Use 'secret' commands instead for strong hashing."),

    (r"^no service pad", "security",
     "Disables PAD (Packet Assembler/Disassembler) service — removes an unnecessary attack surface",
     None, "Good practice. PAD is almost never needed."),

    (r"^no service dhcp", "basics",
     "Disables the DHCP server/relay feature on this device",
     None, None),

    (r"^service tcp-keepalives-(in|out)", "security",
     "Enables TCP keepalives for {0}bound connections — detects dead sessions",
     None, "Helps clean up stale VTY sessions."),

    # === ENABLE SECRET ===
    (r"^enable secret\s+(\d+)\s+", "security",
     "Sets the enable password using Type {0} hashing",
     None, "Type 9 (scrypt) is strongest. Type 5 (MD5) is acceptable. Type 0 is plaintext — never use!"),

    (r"^enable secret\s+(\S+)$", "security",
     "Sets the enable password (plaintext — will be hashed)",
     "warning", "This password is stored in plaintext until 'service password-encryption' is enabled."),

    (r"^enable password\s+", "security",
     "Sets enable password using WEAK encryption — use 'enable secret' instead!",
     "critical", "enable password uses Type 7 (reversible). Always use 'enable secret' with Type 5/9."),

    # === SSH / VTY ===
    (r"^crypto key generate rsa.*modulus\s+(\d+)", "security",
     "Generates RSA key pair with {0}-bit modulus for SSH",
     None if int("2048") >= 2048 else "warning",
     "Use at least 2048-bit. 4096-bit recommended for high security."),

    (r"^ip ssh version\s+(\d+)", "security",
     "Forces SSH version {0}",
     "critical" if True else None,  # will check in handler
     "Always use SSH version 2. Version 1 has known vulnerabilities."),

    (r"^ip ssh time-out\s+(\d+)", "security",
     "Sets SSH authentication timeout to {0} seconds",
     None, None),

    (r"^ip ssh authentication-retries\s+(\d+)", "security",
     "Limits SSH login attempts to {0} retries",
     None, "Helps prevent brute-force attacks."),

    (r"^transport input\s+(ssh|telnet|all|none|ssh telnet)", "security",
     "Allows {0} connections on this VTY line",
     "critical" if True else None,  # check in handler
     None),

    (r"^line vty\s+(\d+)\s+(\d+)", "access",
     "Configures VTY lines {0} through {1} (remote access sessions)",
     None, "Typically 0-4 (5 sessions) or 0-15 (16 sessions)."),

    (r"^line con\s+(\d+)", "access",
     "Configures console line {0} (physical serial access)",
     None, None),

    (r"^login local", "security",
     "Requires authentication using local username database",
     None, "Good — requires credentials. Better with AAA."),

    (r"^login authentication\s+(\S+)", "security",
     "Uses AAA authentication list '{0}' for login",
     None, None),

    (r"^exec-timeout\s+(\d+)\s+(\d+)", "security",
     "Auto-logout after {0} minutes {1} seconds of inactivity",
     None, "0 0 means NEVER timeout — security risk on VTY!"),

    (r"^access-class\s+(\S+)\s+(in|out)", "security",
     "Restricts VTY access using ACL '{0}' ({1}bound)",
     None, "Essential for limiting who can SSH/Telnet to the device."),

    (r"^logging synchronous", "basics",
     "Prevents log messages from interrupting your typing in CLI",
     None, "Quality of life. Recommended on console and VTY."),

    # === INTERFACES ===
    (r"^interface\s+(GigabitEthernet|FastEthernet|TenGigabitEthernet|FortyGigabitEthernet|Loopback|Vlan|Port-channel|Tunnel|BDI|Management)(\S*)", "interface",
     "Enters configuration mode for interface {0}{1}",
     None, None),

    (r"^\s+description\s+(.+)", "interface",
     "Interface description: '{0}'",
     None, "Always label interfaces — essential for troubleshooting."),

    (r"^\s+ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", "interface",
     "Assigns IP address {0} with subnet mask {1}",
     None, None),

    (r"^\s+ip address\s+dhcp", "interface",
     "Gets IP address via DHCP (dynamic)",
     "info", "Unusual for infrastructure devices. Normal for management interfaces."),

    (r"^\s+no ip address", "interface",
     "No IP address assigned to this interface",
     None, None),

    (r"^\s+shutdown", "interface",
     "Interface is administratively DISABLED",
     None, "Unused ports should be shut down — good security practice."),

    (r"^\s+no shutdown", "interface",
     "Interface is administratively ENABLED",
     None, None),

    (r"^\s+switchport mode\s+(access|trunk|dynamic)", "interface",
     "Sets switchport mode to {0}",
     "warning" if True else None,  # dynamic is risky
     None),

    (r"^\s+switchport access vlan\s+(\d+)", "interface",
     "Assigns port to VLAN {0}",
     None, None),

    (r"^\s+switchport trunk allowed vlan\s+(.+)", "interface",
     "Trunk allows VLANs: {0}",
     None, "Limit trunk VLANs to only what's needed — don't allow 'all'."),

    (r"^\s+switchport trunk native vlan\s+(\d+)", "interface",
     "Sets native VLAN to {0} on this trunk",
     "warning" if True else None,
     "Native VLAN should NOT be VLAN 1. Use a dedicated unused VLAN."),

    (r"^\s+spanning-tree portfast", "interface",
     "Enables PortFast — port transitions immediately to forwarding state",
     "info", "Only use on access ports (end devices). NEVER on trunk/uplink ports!"),

    (r"^\s+spanning-tree bpduguard enable", "security",
     "Enables BPDU Guard — shuts port if it receives spanning-tree BPDUs",
     None, "Good security. Protects against rogue switches."),

    (r"^\s+storm-control\s+(broadcast|multicast|unicast)\s+level\s+(\S+)", "security",
     "Limits {0} traffic to {1}% — protects against traffic storms",
     None, None),

    (r"^\s+switchport port-security", "security",
     "Enables port security on this interface",
     None, "Limits MAC addresses. Good for access ports."),

    (r"^\s+switchport port-security maximum\s+(\d+)", "security",
     "Allows maximum {0} MAC address(es) on this port",
     None, None),

    (r"^\s+switchport port-security violation\s+(\S+)", "security",
     "On security violation: {0} (restrict=drop+log, shutdown=err-disable, protect=drop)",
     None, None),

    (r"^\s+ip dhcp snooping trust", "security",
     "Marks this port as TRUSTED for DHCP snooping (DHCP server allowed here)",
     None, None),

    (r"^\s+ip verify source", "security",
     "Enables IP Source Guard — prevents IP spoofing on this port",
     None, None),

    (r"^\s+channel-group\s+(\d+)\s+mode\s+(\S+)", "interface",
     "Joins port-channel {0} in {1} mode (active=LACP, on=static, desirable/auto=PAgP)",
     None, None),

    (r"^\s+standby\s+(\d+)\s+ip\s+(\S+)", "interface",
     "HSRP group {0}: virtual IP {1} (gateway redundancy)",
     None, None),

    (r"^\s+standby\s+(\d+)\s+priority\s+(\d+)", "interface",
     "HSRP group {0}: priority {1} (higher = preferred active router)",
     None, None),

    (r"^\s+standby\s+(\d+)\s+preempt", "interface",
     "HSRP group {0}: preempt enabled (will take over if higher priority)",
     None, None),

    (r"^\s+ip helper-address\s+(\S+)", "interface",
     "Forwards DHCP/BOOTP requests to server {0} (DHCP relay)",
     None, None),

    # === SNMP ===
    (r"^snmp-server community\s+(\S+)\s+(RO|RW)", "snmp",
     "SNMPv2c community string '{0}' with {1} access",
     "critical", "SNMPv2c sends community strings in CLEARTEXT. Use SNMPv3 instead!"),

    (r"^snmp-server group\s+(\S+)\s+v3\s+(priv|auth|noauth)", "snmp",
     "SNMPv3 group '{0}' with security level: {1}",
     None if True else "warning",
     "Use 'priv' (auth+encryption). 'noauth' offers zero security."),

    (r"^snmp-server user\s+(\S+)\s+(\S+)\s+v3", "snmp",
     "SNMPv3 user '{0}' in group '{1}'",
     None, "SNMPv3 with auth+priv is the recommended approach."),

    (r"^snmp-server host\s+(\S+)(?:\s+version\s+(\S+))?", "snmp",
     "Sends SNMP traps/informs to {0}" + " (version {1})" if True else "",
     None, None),

    (r"^snmp-server location\s+(.+)", "snmp",
     "SNMP location: '{0}'",
     None, "Used by NMS tools to identify device location."),

    (r"^snmp-server contact\s+(.+)", "snmp",
     "SNMP contact: '{0}'",
     None, None),

    (r"^no snmp-server", "snmp",
     "Disables SNMP server entirely",
     None, None),

    # === NTP ===
    (r"^ntp server\s+(\S+)(?:\s+key\s+(\d+))?(?:\s+(prefer))?", "ntp",
     "NTP server: {0}" + (" with authentication key {1}" if True else "") + (" (preferred)" if True else ""),
     None, "Use at least 2 NTP servers for redundancy."),

    (r"^ntp authenticate", "ntp",
     "Enables NTP authentication — only syncs with authenticated servers",
     None, "Prevents NTP poisoning attacks. Recommended."),

    (r"^ntp trusted-key\s+(\d+)", "ntp",
     "Trusts NTP authentication key {0}",
     None, None),

    (r"^ntp source\s+(\S+)", "ntp",
     "NTP packets sourced from interface {0}",
     None, "Use Loopback interface for stability."),

    (r"^ntp master\s*(\d*)", "ntp",
     "Device acts as NTP master (stratum {0})",
     "info", "Only use if this device is the authoritative time source."),

    (r"^clock timezone\s+(\S+)\s+(-?\d+)(?:\s+(\d+))?", "ntp",
     "System clock timezone: {0} (UTC{1})",
     None, None),

    # === AAA ===
    (r"^aaa new-model", "aaa",
     "Enables AAA (Authentication, Authorization, Accounting) — centralized access control",
     None, "Required before any AAA commands work. This is the master switch."),

    (r"^aaa authentication login\s+(\S+)\s+(.+)", "aaa",
     "Login authentication list '{0}': methods = {1}",
     None, "group tacacs+ local = try TACACS first, fall back to local passwords."),

    (r"^aaa authorization\s+(exec|commands\s+\d+|network)\s+(\S+)\s+(.+)", "aaa",
     "Authorization for {0}, list '{1}': methods = {2}",
     None, "Controls what users can DO after logging in."),

    (r"^aaa accounting\s+(exec|commands\s+\d+|network)\s+(\S+)\s+(.+)", "aaa",
     "Accounting for {0}, list '{1}': {2}",
     None, "Logs who did what — essential for audit trails."),

    (r"^tacacs server\s+(\S+)", "aaa",
     "Defines TACACS+ server named '{0}'",
     None, None),

    (r"^\s+address ipv4\s+(\S+)", "aaa",
     "TACACS+ server IP: {0}",
     None, None),

    (r"^\s+key\s+(\d+)\s+", "aaa",
     "TACACS+ shared secret (encrypted Type {0})",
     None, "Keep this key synchronized with the TACACS+ server."),

    (r"^tacacs-server host\s+(\S+)", "aaa",
     "Legacy TACACS+ server: {0}",
     "info", "Use 'tacacs server <name>' syntax instead (newer format)."),

    # === USERS ===
    (r"^username\s+(\S+)\s+privilege\s+(\d+)\s+secret\s+(\d+)", "users",
     "Local user '{0}' with privilege level {1}, password hashed as Type {2}",
     None, None),

    (r"^username\s+(\S+)\s+secret\s+(\d+)", "users",
     "Local user '{0}', password hashed as Type {1}",
     None, None),

    (r"^username\s+(\S+)\s+password\s+", "users",
     "Local user '{0}' with WEAK password encryption",
     "critical", "Use 'secret' instead of 'password' for strong hashing!"),

    # === LOGGING ===
    (r"^logging buffered\s+(\d+)(?:\s+(\S+))?", "logging",
     "Stores logs in RAM buffer ({0} bytes)" + (" at level {1}" if True else ""),
     None, None),

    (r"^logging console\s+(\S+)", "logging",
     "Console logging at level: {0}",
     None, "Set to 'warnings' or higher in production to avoid console floods."),

    (r"^logging host\s+(\S+)", "logging",
     "Sends syslog messages to server {0}",
     None, "Remote logging is essential for incident response and compliance."),

    (r"^logging\s+(\d+\.\d+\.\d+\.\d+)", "logging",
     "Sends syslog messages to {0}",
     None, None),

    (r"^logging source-interface\s+(\S+)", "logging",
     "Syslog sourced from interface {0}",
     None, "Use Loopback for stability."),

    (r"^logging trap\s+(\S+)", "logging",
     "Remote syslog severity level: {0}",
     None, None),

    # === ACLs ===
    (r"^ip access-list (standard|extended)\s+(\S+)", "acl",
     "Defines {0} ACL named '{1}'",
     None, None),

    (r"^access-list\s+(\d+)\s+(permit|deny)\s+(.+)", "acl",
     "ACL {0}: {1} {2}",
     None, None),

    (r"^\s+(permit|deny)\s+(.+)", "acl",
     "{0} {1}",
     None, None),

    # === ROUTING ===
    (r"^ip route\s+(\S+)\s+(\S+)\s+(\S+)", "routing",
     "Static route: {0}/{1} via {2}",
     None, None),

    (r"^ip routing", "routing",
     "Enables IP routing (Layer 3 forwarding between VLANs/subnets)",
     None, None),

    (r"^router\s+(ospf|eigrp|bgp|rip)\s+(\S+)", "routing",
     "Enables {0} routing process {1}",
     None, None),

    (r"^\s+network\s+(\S+)\s+(area\s+\S+|\S+)", "routing",
     "Advertises network {0} {1}",
     None, None),

    # === BANNER ===
    (r"^banner (motd|login|exec)\s*\^?C?(.{0,60})", "basics",
     "Sets {0} banner (displayed to users {1})",
     None, "Legal warning banners are recommended for compliance."),

    # === SECURITY HARDENING ===
    (r"^no ip http server", "security",
     "Disables HTTP management interface (unencrypted web GUI)",
     None, "Good — HTTP is unencrypted. Use HTTPS only."),

    (r"^ip http server", "security",
     "HTTP management interface is ENABLED (unencrypted!)",
     "critical", "Disable HTTP and use 'ip http secure-server' (HTTPS) instead."),

    (r"^ip http secure-server", "security",
     "Enables HTTPS management interface (encrypted web GUI)",
     None, "Good — encrypted management. Set strong authentication."),

    (r"^no ip source-route", "security",
     "Disables IP source routing — prevents attackers from specifying packet paths",
     None, "Good hardening practice."),

    (r"^no ip finger", "security",
     "Disables finger service — removes information disclosure risk",
     None, None),

    (r"^no ip bootp server", "security",
     "Disables BOOTP server — removes unnecessary service",
     None, None),

    (r"^no ip gratuitous-arps", "security",
     "Disables gratuitous ARPs — reduces ARP spoofing risk",
     None, None),

    (r"^no cdp run", "security",
     "Disables CDP globally — hides device info from neighbors",
     "info", "Good for security. May break monitoring tools that rely on CDP."),

    (r"^\s+no cdp enable", "security",
     "Disables CDP on this specific interface",
     None, None),

    (r"^no lldp run", "security",
     "Disables LLDP globally",
     None, None),

    (r"^ip dhcp snooping", "security",
     "Enables DHCP snooping — prevents rogue DHCP servers",
     None, "Good. Mark uplink/server ports as 'trusted'."),

    (r"^ip dhcp snooping vlan\s+(.+)", "security",
     "DHCP snooping active on VLANs: {0}",
     None, None),

    (r"^ip arp inspection vlan\s+(.+)", "security",
     "Dynamic ARP Inspection active on VLANs: {0} — prevents ARP spoofing",
     None, None),

    (r"^errdisable recovery cause\s+(\S+)", "security",
     "Auto-recovery from err-disabled state caused by: {0}",
     None, None),

    (r"^errdisable recovery interval\s+(\d+)", "security",
     "Err-disable recovery interval: {0} seconds",
     None, None),

    (r"^ip access-group\s+(\S+)\s+(in|out)", "security",
     "Applies ACL '{0}' in {1}bound direction",
     None, None),

    # === VLANs ===
    (r"^vlan\s+(\d+)", "vlan",
     "Defines VLAN {0}",
     None, None),

    (r"^\s+name\s+(\S+)", "vlan",
     "VLAN name: '{0}'",
     None, "Always name VLANs — makes troubleshooting much easier."),

    # === SPANNING TREE ===
    (r"^spanning-tree mode\s+(\S+)", "stp",
     "Spanning-tree mode: {0} (rapid-pvst is recommended)",
     None, None),

    (r"^spanning-tree vlan\s+(\S+)\s+priority\s+(\d+)", "stp",
     "STP priority for VLAN {0}: {1} (lower = more likely root bridge)",
     None, "Root bridge priority should be 4096-8192. Default is 32768."),

    # === CRYPTO / VPN ===
    (r"^crypto isakmp policy\s+(\d+)", "vpn",
     "Defines IKE (Phase 1) policy {0} for VPN",
     None, None),

    (r"^crypto ipsec transform-set\s+(\S+)\s+(.+)", "vpn",
     "IPsec transform set '{0}': {1}",
     None, None),
]


# ----------------------------
# Explainer logic
# ----------------------------

def _explain_line(line: str, mode: str) -> Optional[ExplainedLine]:
    """Try to match a config line against the knowledge base."""
    stripped = line.rstrip()
    if not stripped or stripped == "!" or stripped == "end" or stripped.startswith("Building configuration"):
        return None
    if stripped.startswith("Current configuration"):
        return None
    if stripped.startswith("Last configuration change"):
        return None
    if stripped.startswith("NVRAM config last updated"):
        return None
    if stripped.startswith("version "):
        return ExplainedLine(
            line=stripped,
            explanation=f"IOS version: {stripped.split()[1]}" if len(stripped.split()) > 1 else "IOS version declaration",
            category="basics",
        )

    for pattern, category, explanation_tpl, risk, tip in COMMAND_DB:
        m = re.match(pattern, stripped, re.IGNORECASE)
        if m:
            groups = m.groups()
            # Build explanation from template
            try:
                explanation = explanation_tpl
                for i, g in enumerate(groups):
                    if g is not None:
                        explanation = explanation.replace(f"{{{i}}}", g)
                    else:
                        explanation = explanation.replace(f" {{{i}}}", "")
                        explanation = explanation.replace(f"{{{i}}}", "")
            except Exception:
                explanation = explanation_tpl

            # Dynamic risk checks
            actual_risk = risk
            actual_tip = tip

            # SSH version check
            if "SSH version" in explanation and groups:
                if groups[0] == "1":
                    actual_risk = "critical"
                    actual_tip = "SSH version 1 has KNOWN VULNERABILITIES. Upgrade to version 2 immediately!"
                else:
                    actual_risk = None

            # Transport input check
            if "transport input" in stripped.lower():
                if "telnet" in stripped.lower() and "ssh" not in stripped.lower():
                    actual_risk = "critical"
                    actual_tip = "Telnet sends credentials in CLEARTEXT. Use 'transport input ssh' only!"
                elif "all" in stripped.lower():
                    actual_risk = "warning"
                    actual_tip = "Allows ALL protocols including telnet. Use 'transport input ssh' for security."
                elif "ssh" in stripped.lower() and "telnet" not in stripped.lower():
                    actual_risk = None
                    actual_tip = "Good — SSH only. Secure configuration."

            # RSA key size check
            if "RSA key" in explanation and groups:
                try:
                    bits = int(groups[0])
                    if bits < 2048:
                        actual_risk = "warning"
                        actual_tip = f"{bits}-bit is weak. Use at least 2048-bit (4096 recommended)."
                    else:
                        actual_risk = None
                except ValueError:
                    pass

            # Switchport mode dynamic
            if "switchport mode" in stripped.lower() and "dynamic" in stripped.lower():
                actual_risk = "warning"
                actual_tip = "Dynamic mode is a security risk — port can be tricked into trunking. Use 'access' or 'trunk' explicitly."
            elif "switchport mode" in stripped.lower():
                actual_risk = None

            # Native VLAN check
            if "native vlan" in stripped.lower() and groups:
                try:
                    vlan = int(groups[0])
                    if vlan == 1:
                        actual_risk = "warning"
                        actual_tip = "VLAN 1 as native is a security risk (VLAN hopping). Use a dedicated unused VLAN."
                    else:
                        actual_risk = None
                        actual_tip = None
                except (ValueError, IndexError):
                    pass

            # Exec-timeout 0 0 check
            if "exec-timeout" in stripped.lower() and groups:
                try:
                    mins, secs = int(groups[0]), int(groups[1])
                    if mins == 0 and secs == 0:
                        actual_risk = "warning"
                        actual_tip = "0 0 = NEVER timeout. Sessions stay open forever — security risk on VTY lines!"
                except (ValueError, IndexError):
                    pass

            # SNMPv2c check
            if "snmp-server community" in stripped.lower():
                actual_risk = "critical"

            # SNMPv3 noauth check
            if "snmp-server group" in stripped.lower() and "noauth" in stripped.lower():
                actual_risk = "warning"
                actual_tip = "noauth = no authentication, no encryption. Use 'priv' for security."

            # Junior mode: add more context
            if mode == "junior":
                if actual_tip:
                    explanation += f". TIP: {actual_tip}"
                    actual_tip = None

            return ExplainedLine(
                line=stripped,
                explanation=explanation,
                category=category,
                risk=actual_risk,
                tip=actual_tip,
            )

    # No match — return as unexplained
    return ExplainedLine(
        line=stripped,
        explanation="",
        category="other",
    )


def _detect_sections(lines: List[ExplainedLine]) -> List[ExplainedSection]:
    """Group explained lines into logical sections."""
    sections = []
    current_section = None
    current_lines = []

    section_names = {
        "basics": "Device Basics",
        "security": "Security Configuration",
        "interface": "Interfaces",
        "snmp": "SNMP Configuration",
        "ntp": "NTP (Time Synchronization)",
        "aaa": "AAA (Authentication & Access Control)",
        "users": "Local Users",
        "logging": "Logging",
        "acl": "Access Control Lists",
        "routing": "Routing",
        "vlan": "VLANs",
        "stp": "Spanning Tree",
        "access": "Management Access (VTY/Console)",
        "vpn": "VPN / Crypto",
        "other": "Other Commands",
    }

    for line in lines:
        if not line.explanation and line.category == "other":
            # Skip unexplained lines in grouping, but keep them
            if current_lines:
                current_lines.append(line)
            continue

        cat = line.category
        if cat != current_section:
            # Save previous section
            if current_lines:
                explained_count = sum(1 for l in current_lines if l.explanation)
                sections.append(ExplainedSection(
                    title=section_names.get(current_section, current_section or "Other"),
                    lines=current_lines,
                    summary=f"{explained_count} command(s) explained",
                ))
            current_section = cat
            current_lines = [line]
        else:
            current_lines.append(line)

    # Last section
    if current_lines:
        explained_count = sum(1 for l in current_lines if l.explanation)
        sections.append(ExplainedSection(
            title=section_names.get(current_section, current_section or "Other"),
            lines=current_lines,
            summary=f"{explained_count} command(s) explained",
        ))

    return sections


def _generate_security_notes(lines: List[ExplainedLine]) -> List[str]:
    """Generate security observations from the config."""
    notes = []
    critical_count = sum(1 for l in lines if l.risk == "critical")
    warning_count = sum(1 for l in lines if l.risk == "warning")

    if critical_count > 0:
        notes.append(f"CRITICAL: {critical_count} critical security issue(s) found — address immediately!")
    if warning_count > 0:
        notes.append(f"WARNING: {warning_count} security warning(s) — review and fix when possible.")

    # Check for missing best practices
    all_text = "\n".join(l.line for l in lines)
    if "snmp-server community" in all_text.lower() and "snmp-server user" not in all_text.lower():
        notes.append("Using SNMPv2c without SNMPv3 — community strings sent in cleartext.")
    if "aaa new-model" not in all_text.lower():
        notes.append("AAA not enabled — consider 'aaa new-model' for centralized authentication.")
    if "no ip http server" not in all_text.lower() and "ip http server" in all_text.lower():
        notes.append("HTTP server enabled — disable it and use HTTPS only.")
    if "ntp server" not in all_text.lower() and "ntp" not in all_text.lower():
        notes.append("No NTP configured — time sync is critical for log correlation and certificates.")
    if "logging" not in all_text.lower():
        notes.append("No logging configured — essential for troubleshooting and security auditing.")
    if "service password-encryption" not in all_text.lower():
        notes.append("'service password-encryption' not found — passwords may be stored in cleartext.")
    if "banner" not in all_text.lower():
        notes.append("No login banner — legal/compliance may require a warning banner.")

    if not notes:
        notes.append("No critical security issues detected. Good baseline configuration.")

    return notes


# ----------------------------
# Endpoint
# ----------------------------

@router.post("/config-explainer/explain", response_model=ExplainResponse)
def explain_config(req: ExplainRequest):
    """Explain Cisco IOS/IOS-XE configuration in plain English."""

    mode = req.mode.lower() if req.mode else "standard"
    if mode not in ("standard", "junior"):
        mode = "standard"

    # Detect hostname
    hostname = None
    hostname_match = re.search(r"^hostname\s+(\S+)", req.config_text, re.MULTILINE)
    if hostname_match:
        hostname = hostname_match.group(1)

    # Explain each line
    explained_lines = []
    total = 0
    explained = 0

    for raw_line in req.config_text.splitlines():
        stripped = raw_line.rstrip()
        if not stripped or stripped == "!" or stripped == "end":
            continue
        if stripped.startswith("Building configuration") or stripped.startswith("Current configuration"):
            continue
        if stripped.startswith("Last configuration change") or stripped.startswith("NVRAM config"):
            continue

        total += 1
        result = _explain_line(raw_line, mode)
        if result:
            if result.explanation:
                explained += 1
            explained_lines.append(result)

    # Group into sections
    sections = _detect_sections(explained_lines)

    # Security notes
    security_notes = _generate_security_notes(explained_lines)

    coverage = (explained / total * 100) if total > 0 else 0.0

    return ExplainResponse(
        hostname=hostname,
        sections=sections,
        security_notes=security_notes,
        total_lines=total,
        explained_lines=explained,
        coverage_pct=round(coverage, 1),
        mode=mode,
    )
