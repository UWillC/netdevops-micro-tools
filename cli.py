#!/usr/bin/env python3
"""
NetDevOps Micro-Tools CLI
Command-line interface for network engineers.

Usage:
    netdevops snmpv3 --user monitoring --auth-pass secret123 --priv-pass secret456
    netdevops ntp --servers 10.0.0.1,10.0.0.2 --tier campus
    netdevops subnet info 192.168.1.0/24
    netdevops mtu --tunnel gre --interface-mtu 1500
    netdevops cve CVE-2023-20198

Environment:
    NETDEVOPS_API_URL - API base URL (default: https://netdevops-tools.thebackroom.ai)
"""

import click
import requests
import json
import os
import sys

# Default API URL (can be overridden with env var)
DEFAULT_API_URL = "https://netdevops-tools.thebackroom.ai"
API_URL = os.environ.get("NETDEVOPS_API_URL", DEFAULT_API_URL)


def api_request(method, endpoint, data=None, params=None):
    """Make API request and handle errors."""
    url = f"{API_URL}{endpoint}"
    try:
        if method == "GET":
            resp = requests.get(url, params=params, timeout=30)
        else:
            resp = requests.post(url, json=data, timeout=30)

        if resp.status_code == 200:
            return resp.json()
        else:
            click.echo(f"Error: API returned {resp.status_code}", err=True)
            click.echo(resp.text, err=True)
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        click.echo(f"Error: Cannot connect to API at {API_URL}", err=True)
        click.echo("Make sure the API is running or set NETDEVOPS_API_URL", err=True)
        sys.exit(1)
    except requests.exceptions.Timeout:
        click.echo("Error: API request timed out", err=True)
        sys.exit(1)


@click.group()
@click.version_option(version="0.4.2", prog_name="netdevops")
@click.option("--api-url", envvar="NETDEVOPS_API_URL", default=DEFAULT_API_URL,
              help="API base URL")
@click.pass_context
def cli(ctx, api_url):
    """NetDevOps Micro-Tools CLI - Generate Cisco configs from terminal."""
    global API_URL
    API_URL = api_url
    ctx.ensure_object(dict)


# ============================================
# SNMPv3 Command
# ============================================
@cli.command()
@click.option("--host", "-h", required=True, help="SNMP manager/server IP or hostname")
@click.option("--user", "-u", required=True, help="SNMPv3 username")
@click.option("--group", "-g", default="ADMIN", help="SNMPv3 group name")
@click.option("--auth-pass", required=True, help="Authentication password")
@click.option("--priv-pass", required=True, help="Privacy password")
@click.option("--mode", "-m", default="secure-default",
              type=click.Choice(["secure-default", "balanced", "legacy-compatible"]),
              help="Security mode")
@click.option("--format", "-f", "output_format", default="cli",
              type=click.Choice(["cli", "oneline", "template"]), help="Output format")
@click.option("--location", default="", help="Device location")
@click.option("--contact", default="", help="Contact info")
def snmpv3(host, user, group, auth_pass, priv_pass, mode, output_format, location, contact):
    """Generate SNMPv3 configuration."""
    data = {
        "host": host,
        "user": user,
        "group": group,
        "auth_password": auth_pass,
        "priv_password": priv_pass,
        "mode": mode,
        "output_format": output_format,
    }
    if location:
        data["location"] = location
    if contact:
        data["contact"] = contact

    result = api_request("POST", "/generate/snmpv3", data)
    click.echo(result.get("config", ""))


# ============================================
# NTP Command
# ============================================
@cli.command()
@click.option("--servers", "-s", required=True, help="NTP servers (comma-separated)")
@click.option("--tier", default="campus",
              type=click.Choice(["datacenter", "campus", "branch", "edge"]),
              help="Network tier")
@click.option("--auth/--no-auth", default=False, help="Enable NTP authentication")
@click.option("--key-id", default=1, help="NTP key ID")
@click.option("--key-value", default="", help="NTP key value")
@click.option("--source", default="", help="Source interface")
def ntp(servers, tier, auth, key_id, key_value, source):
    """Generate NTP configuration."""
    server_list = [s.strip() for s in servers.split(",")]
    data = {
        "ntp_servers": server_list,
        "network_tier": tier,
        "enable_auth": auth,
        "key_id": key_id,
        "key_value": key_value,
        "source_interface": source
    }
    result = api_request("POST", "/generate/ntp", data)
    click.echo(result.get("config", ""))


# ============================================
# AAA Command
# ============================================
@cli.command()
@click.option("--tacacs-servers", "-t", required=True, help="TACACS+ servers (comma-separated)")
@click.option("--tacacs-key", "-k", required=True, help="TACACS+ shared key")
@click.option("--local-user", default="admin", help="Local fallback username")
@click.option("--local-pass", default="", help="Local fallback password")
@click.option("--local-priv", default=15, help="Local user privilege level")
def aaa(tacacs_servers, tacacs_key, local_user, local_pass, local_priv):
    """Generate AAA/TACACS+ configuration."""
    server_list = [s.strip() for s in tacacs_servers.split(",")]
    data = {
        "tacacs_servers": server_list,
        "tacacs_key": tacacs_key,
        "local_username": local_user,
        "local_password": local_pass,
        "local_privilege": local_priv
    }
    result = api_request("POST", "/generate/aaa", data)
    click.echo(result.get("config", ""))


# ============================================
# Golden Config Command
# ============================================
@cli.command()
@click.option("--hostname", "-h", required=True, help="Device hostname")
@click.option("--domain", "-d", default="", help="Domain name")
@click.option("--security-mode", default="secure",
              type=click.Choice(["secure", "balanced", "legacy"]),
              help="Security mode")
@click.option("--enable-secret", default="", help="Enable secret")
@click.option("--banner", default="", help="MOTD banner text")
def golden(hostname, domain, security_mode, enable_secret, banner):
    """Generate Golden Config (baseline)."""
    data = {
        "hostname": hostname,
        "domain_name": domain,
        "security_mode": security_mode,
        "enable_secret": enable_secret,
        "banner_motd": banner
    }
    result = api_request("POST", "/generate/golden-config", data)
    click.echo(result.get("config", ""))


# ============================================
# Subnet Calculator Command
# ============================================
@cli.group()
def subnet():
    """IP Subnet Calculator commands."""
    pass


@subnet.command("info")
@click.argument("cidr")
def subnet_info(cidr):
    """Get subnet information for CIDR notation."""
    result = api_request("POST", "/tools/subnet/info", {"ip_cidr": cidr})
    info = result.get("subnet_info", {})
    click.echo(f"Network:    {info.get('network')}/{info.get('prefix_length')}")
    click.echo(f"Broadcast:  {info.get('broadcast')}")
    click.echo(f"Netmask:    {info.get('netmask')}")
    click.echo(f"Wildcard:   {info.get('wildcard')}")
    click.echo(f"Hosts:      {info.get('usable_hosts')} usable / {info.get('total_addresses')} total")
    click.echo(f"Range:      {info.get('first_host')} - {info.get('last_host')}")
    click.echo(f"Class:      {info.get('network_class')}")
    click.echo(f"Private:    {'Yes' if info.get('is_private') else 'No'}")


@subnet.command("split")
@click.argument("cidr")
@click.option("--prefix", "-p", required=True, type=int, help="New prefix length")
def subnet_split(cidr, prefix):
    """Split subnet into smaller subnets."""
    result = api_request("POST", "/tools/subnet/split",
                        {"ip_cidr": cidr, "new_prefix": prefix})
    click.echo(f"Splitting {cidr} into /{prefix} subnets:\n")
    for sub in result.get("subnets", []):
        click.echo(f"  {sub}")
    click.echo(f"\nTotal: {result.get('subnet_count')} subnets")


# ============================================
# MTU Calculator Command
# ============================================
@cli.command()
@click.option("--interface-mtu", "-m", default=1500, type=int, help="Interface MTU")
@click.option("--tunnel", "-t", default="gre",
              type=click.Choice(["none", "gre", "ipsec_tunnel", "ipsec_transport",
                                "vxlan", "gre_over_ipsec", "mpls", "lisp"]),
              help="Tunnel type")
@click.option("--mpls-labels", default=1, type=int, help="MPLS label count (for MPLS)")
@click.option("--no-mss", is_flag=True, help="Don't include TCP MSS recommendation")
def mtu(interface_mtu, tunnel, mpls_labels, no_mss):
    """Calculate effective MTU for tunnel encapsulation."""
    data = {
        "interface_mtu": interface_mtu,
        "tunnel_type": tunnel,
        "mpls_labels": mpls_labels,
        "include_tcp_mss": not no_mss
    }
    result = api_request("POST", "/tools/mtu/calculate", data)

    click.echo(f"Interface MTU:  {result.get('interface_mtu')} bytes")
    click.echo(f"Tunnel Type:    {result.get('tunnel_type')}")
    click.echo(f"Overhead:       {result.get('overhead_bytes')} bytes")
    click.echo(f"                ({result.get('overhead_breakdown')})")
    click.echo(f"Effective MTU:  {result.get('effective_mtu')} bytes")

    if result.get('tcp_mss'):
        click.echo(f"TCP MSS:        {result.get('tcp_mss')} bytes")

    if result.get('warnings'):
        click.echo("\nWarnings:")
        for w in result['warnings']:
            click.echo(f"  ! {w}")

    if result.get('recommendations'):
        click.echo("\nRecommendations:")
        for r in result['recommendations']:
            click.echo(f"  * {r}")


# ============================================
# CVE Analyzer Command
# ============================================
@cli.command()
@click.argument("cve_id")
@click.option("--json", "-j", "as_json", is_flag=True, help="Output as JSON")
def cve(cve_id, as_json):
    """Analyze CVE and get details from NVD."""
    result = api_request("GET", f"/analyze/cve/{cve_id}")

    if as_json:
        click.echo(json.dumps(result, indent=2))
        return

    click.echo(f"CVE ID:      {result.get('cve_id')}")
    click.echo(f"Severity:    {result.get('severity', 'Unknown').upper()}")
    click.echo(f"CVSS Score:  {result.get('cvss_score', 'N/A')}")
    click.echo(f"Description: {result.get('description', 'N/A')[:200]}...")

    if result.get('affected_versions'):
        click.echo(f"\nAffected Versions:")
        for v in result['affected_versions'][:5]:
            click.echo(f"  - {v}")

    if result.get('mitigation'):
        click.echo(f"\nMitigation:\n{result.get('mitigation')}")


# ============================================
# Config Parser Command
# ============================================
@cli.command("parse")
@click.argument("config_file", type=click.File("r"))
@click.option("--summary", "-s", is_flag=True, help="Show summary only")
@click.option("--json", "-j", "as_json", is_flag=True, help="Output as JSON")
def parse_config(config_file, summary, as_json):
    """Parse Cisco running-config file."""
    config_text = config_file.read()

    endpoint = "/tools/config/parse/summary" if summary else "/tools/config/parse"
    result = api_request("POST", endpoint, {"config_text": config_text})

    if as_json:
        click.echo(json.dumps(result, indent=2))
        return

    if summary:
        click.echo(f"Hostname:         {result.get('hostname', 'N/A')}")
        s = result.get('summary', {})
        click.echo(f"Interfaces:       {s.get('total_interfaces', 0)} total, {s.get('active_interfaces', 0)} active")
        click.echo(f"SNMP Communities: {s.get('snmp_communities', 0)}")
        click.echo(f"SNMPv3 Users:     {s.get('snmp_v3_users', 0)}")
        click.echo(f"NTP Servers:      {s.get('ntp_servers', 0)}")
        click.echo(f"AAA Enabled:      {'Yes' if s.get('aaa_enabled') else 'No'}")
        click.echo(f"Local Users:      {s.get('local_users', 0)}")
    else:
        click.echo(json.dumps(result, indent=2))


# ============================================
# Health Check Command
# ============================================
@cli.command()
def health():
    """Check API health status."""
    result = api_request("GET", "/health")
    if result.get("status") == "ok":
        click.echo(f"API Status: OK")
        click.echo(f"API URL:    {API_URL}")

        # Get version info
        meta = api_request("GET", "/meta/version")
        click.echo(f"Version:    {meta.get('version')}")
        click.echo(f"Features:   {', '.join(meta.get('feature_flags', []))}")
    else:
        click.echo("API Status: ERROR", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
