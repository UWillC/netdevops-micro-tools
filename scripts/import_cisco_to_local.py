#!/usr/bin/env python3
"""
Import Cisco PSIRT cached advisories into local CVE data + mitigation templates.

Usage:
    python3 scripts/import_cisco_to_local.py [--dry-run] [--force]

Reads from:  cache/cisco/iosxe.json (cached PSIRT advisories)
Writes to:   cve_data/ios_xe/cve-XXXX-XXXXX.json  (CVE matching data)
             cve_mitigations/CVE-XXXX-XXXXX.json   (mitigation templates)

Skips CVEs that already exist locally unless --force is given.
"""

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
CACHE_FILE = os.path.join(PROJECT_DIR, "cache", "cisco", "iosxe.json")
CVE_DATA_DIR = os.path.join(PROJECT_DIR, "cve_data", "ios_xe")
MITIGATION_DIR = os.path.join(PROJECT_DIR, "cve_mitigations")

# Regex to extract IOS XE version from productNames
XE_VERSION_RE = re.compile(r"Cisco IOS XE Software\s+(\d[\d.]+)")


def extract_xe_version_range(product_names: List[str]) -> Tuple[str, str]:
    """Extract min/max IOS XE version from productNames list."""
    versions = []
    for name in product_names:
        m = XE_VERSION_RE.match(name.strip())
        if m:
            versions.append(m.group(1))

    if not versions:
        return ("0.0.0", "999.999.999")

    def version_key(v: str):
        parts = []
        for p in v.split("."):
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        while len(parts) < 4:
            parts.append(0)
        return tuple(parts)

    versions.sort(key=version_key)
    return (versions[0], versions[-1])


def parse_severity(sir: str) -> str:
    return {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(
        sir.lower(), "medium"
    )


def strip_html(text: str) -> str:
    clean = re.sub(r"<[^>]+>", "", text).strip()
    # Collapse whitespace
    clean = re.sub(r"\s+", " ", clean)
    return clean


def classify_vuln_type(title: str, summary: str) -> str:
    """Classify vulnerability type from title/summary for mitigation templates."""
    text = (title + " " + summary).lower()
    if "snmp" in text:
        return "snmp"
    if "web" in text or "http" in text or "webui" in text or "web ui" in text:
        return "webui"
    if "ssh" in text:
        return "ssh"
    if "bgp" in text:
        return "bgp"
    if "ospf" in text:
        return "ospf"
    if "dhcp" in text:
        return "dhcp"
    if "dns" in text:
        return "dns"
    if "ipsec" in text or "ikev" in text or "vpn" in text:
        return "vpn"
    if "aaa" in text or "tacacs" in text or "radius" in text:
        return "aaa"
    if "privilege" in text or "escalat" in text or "bypass" in text or "authent" in text:
        return "auth"
    if "denial" in text or "dos" in text or "crash" in text or "reload" in text:
        return "dos"
    if "buffer" in text or "overflow" in text or "code exec" in text or "rce" in text:
        return "rce"
    if "xss" in text or "cross-site" in text or "inject" in text:
        return "injection"
    if "information" in text and "disclos" in text:
        return "info-disclosure"
    return "generic"


# Mitigation templates per vulnerability type
MITIGATION_TEMPLATES = {
    "snmp": {
        "workaround_steps": [
            {
                "order": 1,
                "description": "Check if SNMP is enabled",
                "commands": ["show snmp", "show snmp community", "show snmp user"],
                "platform_notes": "If SNMP is not required, disable it entirely.",
            },
            {
                "order": 2,
                "description": "Restrict SNMP access via ACL",
                "commands": [
                    "configure terminal",
                    "ip access-list standard SNMP-RESTRICT",
                    " permit <NMS_IP>",
                    " deny any log",
                    "exit",
                    "snmp-server community <STRING> RO SNMP-RESTRICT",
                    "end",
                    "write memory",
                ],
                "platform_notes": "Replace <NMS_IP> with your NMS server IPs.",
            },
            {
                "order": 3,
                "description": "Upgrade to patched version",
                "commands": ["show version", "copy tftp: flash:", "write memory", "reload"],
                "platform_notes": "Check Cisco advisory for specific fixed release.",
            },
        ],
        "acl_mitigation": {
            "description": "Restrict SNMP access to trusted hosts",
            "acl_name": "SNMP-RESTRICT",
            "commands": [
                "ip access-list standard SNMP-RESTRICT",
                " permit <NMS_IP>",
                " deny any log",
            ],
            "apply_to": "snmp-server community <STRING> RO SNMP-RESTRICT",
        },
        "detection_commands": ["show snmp", "show snmp community", "show logging | include SNMP"],
    },
    "webui": {
        "workaround_steps": [
            {
                "order": 1,
                "description": "Check if HTTP/HTTPS server is enabled",
                "commands": [
                    "show running-config | include ip http",
                    "show ip http server status",
                ],
                "platform_notes": "If web UI is not required, disable it.",
            },
            {
                "order": 2,
                "description": "Disable HTTP/HTTPS server if not needed",
                "commands": [
                    "configure terminal",
                    "no ip http server",
                    "no ip http secure-server",
                    "end",
                    "write memory",
                ],
                "platform_notes": "WARNING: This disables Web UI management. Use CLI/SSH instead.",
            },
            {
                "order": 3,
                "description": "Restrict HTTP access via ACL",
                "commands": [
                    "configure terminal",
                    "ip access-list standard HTTP-RESTRICT",
                    " permit <MGMT_SUBNET>",
                    " deny any log",
                    "exit",
                    "ip http access-class HTTP-RESTRICT",
                    "end",
                    "write memory",
                ],
                "platform_notes": "Limit web access to management subnet only.",
            },
        ],
        "acl_mitigation": {
            "description": "Restrict HTTP/HTTPS to management subnet",
            "acl_name": "HTTP-RESTRICT",
            "commands": [
                "ip access-list standard HTTP-RESTRICT",
                " permit <MGMT_SUBNET>",
                " deny any log",
            ],
            "apply_to": "ip http access-class HTTP-RESTRICT",
        },
        "detection_commands": [
            "show ip http server status",
            "show logging | include HTTP",
            "show users",
        ],
    },
    "dos": {
        "workaround_steps": [
            {
                "order": 1,
                "description": "Check current software version",
                "commands": ["show version"],
                "platform_notes": "Check Cisco advisory for affected versions.",
            },
            {
                "order": 2,
                "description": "Apply Control Plane Policing (CoPP)",
                "commands": [
                    "show policy-map control-plane",
                ],
                "platform_notes": "Ensure CoPP policy is active to protect the control plane from DoS.",
            },
            {
                "order": 3,
                "description": "Upgrade to patched version",
                "commands": ["show version", "copy tftp: flash:", "write memory", "reload"],
                "platform_notes": "Check Cisco advisory for specific fixed release.",
            },
        ],
        "acl_mitigation": None,
        "detection_commands": [
            "show version",
            "show logging | include restart|reload|crash",
            "show processes cpu history",
        ],
    },
    "generic": {
        "workaround_steps": [
            {
                "order": 1,
                "description": "Check current software version",
                "commands": ["show version"],
                "platform_notes": "Check Cisco advisory for affected versions and workarounds.",
            },
            {
                "order": 2,
                "description": "Review advisory for specific workarounds",
                "commands": [],
                "platform_notes": "See the Cisco PSIRT advisory URL for detailed workaround steps.",
            },
            {
                "order": 3,
                "description": "Upgrade to patched version",
                "commands": ["show version", "copy tftp: flash:", "write memory", "reload"],
                "platform_notes": "Check Cisco advisory for specific fixed release.",
            },
        ],
        "acl_mitigation": None,
        "detection_commands": ["show version", "show logging"],
    },
}

# Add aliases
for alias, target in [
    ("rce", "generic"),
    ("auth", "webui"),
    ("ssh", "generic"),
    ("bgp", "dos"),
    ("ospf", "dos"),
    ("dhcp", "dos"),
    ("dns", "dos"),
    ("vpn", "generic"),
    ("aaa", "auth"),
    ("injection", "webui"),
    ("info-disclosure", "generic"),
]:
    if alias not in MITIGATION_TEMPLATES:
        MITIGATION_TEMPLATES[alias] = MITIGATION_TEMPLATES[target]


def build_cve_data(cve_id: str, adv: Dict[str, Any], ver_min: str, ver_max: str) -> Dict[str, Any]:
    """Build local CVE data JSON from advisory."""
    sir = adv.get("sir", "Medium")
    severity = parse_severity(sir)

    cvss = None
    try:
        cvss = float(adv.get("cvssBaseScore", 0))
        if cvss == 0:
            cvss = None
    except (ValueError, TypeError):
        cvss = None

    title = adv.get("advisoryTitle", "")
    summary = strip_html(adv.get("summary", ""))
    if len(summary) > 500:
        summary = summary[:497] + "..."

    advisory_url = adv.get("publicationUrl", "")
    published = adv.get("firstPublished", "")
    if published and "T" in published:
        published = published.split("T")[0]
    last_modified = adv.get("lastUpdated", "")
    if last_modified and "T" in last_modified:
        last_modified = last_modified.split("T")[0]

    cwe_list = adv.get("cwe", [])
    cwe = cwe_list[0] if cwe_list and cwe_list != ["NA"] else None

    tags = ["cisco-psirt"]
    if severity == "critical":
        tags.append("critical")

    vuln_type = classify_vuln_type(title, summary)
    if vuln_type != "generic":
        tags.append(vuln_type)

    platforms = ["IOS XE"]
    # Check if also affects IOS
    for pn in adv.get("productNames", []):
        if "Cisco IOS " in pn and "IOS XE" not in pn and "IOS XR" not in pn:
            if "IOS" not in platforms:
                platforms.append("IOS")
            break

    return {
        "cve_id": cve_id,
        "title": title,
        "severity": severity,
        "platforms": platforms,
        "affected": {"min": ver_min, "max": ver_max},
        "fixed_in": None,
        "tags": tags,
        "description": summary,
        "workaround": "See Cisco advisory for details.",
        "advisory_url": advisory_url,
        "confidence": "cisco-psirt",
        "source": "cisco-psirt-import",
        "cvss_score": cvss,
        "cvss_vector": None,
        "cwe": cwe,
        "published": published,
        "last_modified": last_modified,
        "references": [advisory_url] if advisory_url else [],
    }


def build_mitigation(cve_id: str, adv: Dict[str, Any], cve_data: Dict[str, Any]) -> Dict[str, Any]:
    """Build mitigation template from advisory data."""
    title = adv.get("advisoryTitle", "")
    summary = strip_html(adv.get("summary", ""))
    advisory_url = adv.get("publicationUrl", "")

    vuln_type = classify_vuln_type(title, summary)
    template = MITIGATION_TEMPLATES.get(vuln_type, MITIGATION_TEMPLATES["generic"])

    risk_summary = summary[:300] if len(summary) > 300 else summary

    mitigation = {
        "cve_id": cve_id,
        "risk_summary": risk_summary,
        "attack_vector": f"See advisory: {advisory_url}",
        "workaround_steps": template["workaround_steps"],
        "acl_mitigation": template.get("acl_mitigation"),
        "recommended_fix": f"Upgrade to patched IOS XE version. Check {advisory_url} for details.",
        "upgrade_path": "Check Cisco advisory for platform-specific fixed versions.",
        "detection": {
            "description": "Check if device is running a vulnerable version",
            "commands": template.get("detection_commands", ["show version"]),
            "vulnerable_if": f"Running affected IOS XE version. See {advisory_url}",
        },
        "verification": {
            "description": "Confirm device is patched",
            "commands": ["show version"],
            "expected_output": "IOS XE version at or above the fixed release.",
        },
        "cisco_psirt": advisory_url,
        "field_notice": None,
        "cisa_alert": None,
        "tags": cve_data.get("tags", ["cisco-psirt"]),
        "last_updated": cve_data.get("published", ""),
    }
    return mitigation


def main():
    dry_run = "--dry-run" in sys.argv
    force = "--force" in sys.argv

    if not os.path.exists(CACHE_FILE):
        print(f"ERROR: Cache file not found: {CACHE_FILE}")
        print("Run with CVE_CISCO_PSIRT=1 to fetch data first.")
        sys.exit(1)

    with open(CACHE_FILE, "r") as f:
        cache = json.load(f)

    advisories = cache.get("advisories", [])
    print(f"Loaded {len(advisories)} cached advisories")

    os.makedirs(CVE_DATA_DIR, exist_ok=True)
    os.makedirs(MITIGATION_DIR, exist_ok=True)

    # Track existing local CVEs
    existing_data = set(f.replace(".json", "").upper() for f in os.listdir(CVE_DATA_DIR) if f.endswith(".json"))
    existing_mit = set(f.replace(".json", "").upper() for f in os.listdir(MITIGATION_DIR) if f.endswith(".json"))

    stats = {"cve_created": 0, "cve_skipped": 0, "mit_created": 0, "mit_skipped": 0}

    for adv in advisories:
        cves = adv.get("cves", [])
        if not cves or cves == ["NA"]:
            continue

        # Extract version range from productNames
        ver_min, ver_max = extract_xe_version_range(adv.get("productNames", []))

        for cve_id in cves:
            if not cve_id.startswith("CVE-"):
                continue

            cve_upper = cve_id.upper()
            cve_lower = cve_id.lower()

            # --- CVE Data ---
            cve_path = os.path.join(CVE_DATA_DIR, f"{cve_lower}.json")
            if cve_upper in existing_data and not force:
                stats["cve_skipped"] += 1
            else:
                cve_data = build_cve_data(cve_id, adv, ver_min, ver_max)
                if dry_run:
                    print(f"  [DRY] Would create: {cve_path}")
                else:
                    with open(cve_path, "w", encoding="utf-8") as f:
                        json.dump(cve_data, f, indent=2, ensure_ascii=False)
                stats["cve_created"] += 1

            # --- Mitigation ---
            mit_path = os.path.join(MITIGATION_DIR, f"{cve_upper}.json")
            if cve_upper in existing_mit and not force:
                stats["mit_skipped"] += 1
            else:
                cve_data_for_mit = build_cve_data(cve_id, adv, ver_min, ver_max)
                mit_data = build_mitigation(cve_id, adv, cve_data_for_mit)
                if dry_run:
                    print(f"  [DRY] Would create: {mit_path}")
                else:
                    with open(mit_path, "w", encoding="utf-8") as f:
                        json.dump(mit_data, f, indent=2, ensure_ascii=False)
                stats["mit_created"] += 1

    print(f"\n{'[DRY RUN] ' if dry_run else ''}Results:")
    print(f"  CVE data:   {stats['cve_created']} created, {stats['cve_skipped']} skipped (already exist)")
    print(f"  Mitigations: {stats['mit_created']} created, {stats['mit_skipped']} skipped (already exist)")

    if not dry_run:
        total_cve = len([f for f in os.listdir(CVE_DATA_DIR) if f.endswith(".json")])
        total_mit = len([f for f in os.listdir(MITIGATION_DIR) if f.endswith(".json")])
        print(f"\n  Total local CVEs:       {total_cve}")
        print(f"  Total mitigations:      {total_mit}")


if __name__ == "__main__":
    main()
