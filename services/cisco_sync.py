"""
Auto-sync: import NEW Cisco PSIRT CVEs into local data + mitigations.

Called by CVEEngine after load_all() when Cisco provider is active.
Only creates files for CVEs that don't exist locally yet.
"""

import json
import os
import re
from typing import Any, Dict, List, Tuple

from models.cve_model import CVEEntry

PROJECT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
CVE_DATA_DIR = os.path.join(PROJECT_DIR, "cve_data", "ios_xe")
MITIGATION_DIR = os.path.join(PROJECT_DIR, "cve_mitigations")

XE_VERSION_RE = re.compile(r"Cisco IOS XE Software\s+(\d[\d.]+)")


def _version_key(v: str):
    parts = []
    for p in v.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts)


def _extract_xe_version_range(product_names: List[str]) -> Tuple[str, str]:
    versions = []
    for name in product_names:
        m = XE_VERSION_RE.match(name.strip())
        if m:
            versions.append(m.group(1))
    if not versions:
        return ("0.0.0", "999.999.999")
    versions.sort(key=_version_key)
    return (versions[0], versions[-1])


def _strip_html(text: str) -> str:
    clean = re.sub(r"<[^>]+>", "", text).strip()
    return re.sub(r"\s+", " ", clean)


def _classify_vuln(title: str, summary: str) -> str:
    text = (title + " " + summary).lower()
    for keyword, vtype in [
        ("snmp", "snmp"), ("web", "webui"), ("http", "webui"),
        ("ssh", "ssh"), ("bgp", "bgp"), ("ospf", "ospf"),
        ("dhcp", "dhcp"), ("dns", "dns"), ("ipsec", "vpn"),
        ("vpn", "vpn"), ("aaa", "aaa"), ("tacacs", "aaa"),
        ("radius", "aaa"), ("privilege", "auth"), ("escalat", "auth"),
        ("bypass", "auth"), ("denial", "dos"), ("dos", "dos"),
        ("crash", "dos"), ("reload", "dos"), ("buffer", "rce"),
        ("overflow", "rce"), ("code exec", "rce"),
    ]:
        if keyword in text:
            return vtype
    return "generic"


# Mitigation templates keyed by vuln type
_MIT_TEMPLATES = {
    "snmp": {
        "steps": [
            {"order": 1, "description": "Check if SNMP is enabled",
             "commands": ["show snmp", "show snmp community", "show snmp user"],
             "platform_notes": "If SNMP is not required, disable it entirely."},
            {"order": 2, "description": "Restrict SNMP access via ACL",
             "commands": ["configure terminal", "ip access-list standard SNMP-RESTRICT",
                          " permit <NMS_IP>", " deny any log", "exit",
                          "snmp-server community <STRING> RO SNMP-RESTRICT", "end", "write memory"],
             "platform_notes": "Replace <NMS_IP> with your NMS server IPs."},
            {"order": 3, "description": "Upgrade to patched version",
             "commands": ["show version", "copy tftp: flash:", "write memory", "reload"],
             "platform_notes": "Check Cisco advisory for specific fixed release."},
        ],
        "acl": {"description": "Restrict SNMP to trusted hosts", "acl_name": "SNMP-RESTRICT",
                "commands": ["ip access-list standard SNMP-RESTRICT", " permit <NMS_IP>", " deny any log"],
                "apply_to": "snmp-server community <STRING> RO SNMP-RESTRICT"},
        "detect": ["show snmp", "show snmp community", "show logging | include SNMP"],
    },
    "webui": {
        "steps": [
            {"order": 1, "description": "Check if HTTP/HTTPS server is enabled",
             "commands": ["show running-config | include ip http", "show ip http server status"],
             "platform_notes": "If web UI is not required, disable it."},
            {"order": 2, "description": "Disable HTTP/HTTPS server if not needed",
             "commands": ["configure terminal", "no ip http server", "no ip http secure-server", "end", "write memory"],
             "platform_notes": "WARNING: Disables Web UI. Use CLI/SSH instead."},
            {"order": 3, "description": "Restrict HTTP access via ACL",
             "commands": ["configure terminal", "ip access-list standard HTTP-RESTRICT",
                          " permit <MGMT_SUBNET>", " deny any log", "exit",
                          "ip http access-class HTTP-RESTRICT", "end", "write memory"],
             "platform_notes": "Limit web access to management subnet only."},
        ],
        "acl": {"description": "Restrict HTTP/HTTPS to management subnet", "acl_name": "HTTP-RESTRICT",
                "commands": ["ip access-list standard HTTP-RESTRICT", " permit <MGMT_SUBNET>", " deny any log"],
                "apply_to": "ip http access-class HTTP-RESTRICT"},
        "detect": ["show ip http server status", "show logging | include HTTP", "show users"],
    },
    "dos": {
        "steps": [
            {"order": 1, "description": "Check current software version",
             "commands": ["show version"], "platform_notes": "Check advisory for affected versions."},
            {"order": 2, "description": "Apply Control Plane Policing (CoPP)",
             "commands": ["show policy-map control-plane"],
             "platform_notes": "Ensure CoPP protects control plane from DoS."},
            {"order": 3, "description": "Upgrade to patched version",
             "commands": ["show version", "copy tftp: flash:", "write memory", "reload"],
             "platform_notes": "Check Cisco advisory for specific fixed release."},
        ],
        "acl": None,
        "detect": ["show version", "show logging | include restart|reload|crash", "show processes cpu history"],
    },
    "generic": {
        "steps": [
            {"order": 1, "description": "Check current software version",
             "commands": ["show version"], "platform_notes": "Check advisory for affected versions."},
            {"order": 2, "description": "Review advisory for specific workarounds",
             "commands": [], "platform_notes": "See Cisco PSIRT advisory for detailed workaround steps."},
            {"order": 3, "description": "Upgrade to patched version",
             "commands": ["show version", "copy tftp: flash:", "write memory", "reload"],
             "platform_notes": "Check Cisco advisory for specific fixed release."},
        ],
        "acl": None,
        "detect": ["show version", "show logging"],
    },
}

# Aliases
for _alias, _target in [("rce", "generic"), ("auth", "webui"), ("ssh", "generic"),
                         ("bgp", "dos"), ("ospf", "dos"), ("dhcp", "dos"),
                         ("dns", "dos"), ("vpn", "generic"), ("aaa", "webui")]:
    if _alias not in _MIT_TEMPLATES:
        _MIT_TEMPLATES[_alias] = _MIT_TEMPLATES[_target]


def _build_cve_json(cve_id: str, adv: Dict[str, Any], ver_min: str, ver_max: str) -> Dict[str, Any]:
    sir = adv.get("sir", "Medium").lower()
    severity = {"critical": "critical", "high": "high", "medium": "medium"}.get(sir, "medium")

    cvss = None
    try:
        cvss = float(adv.get("cvssBaseScore", 0))
        if cvss == 0:
            cvss = None
    except (ValueError, TypeError):
        pass

    title = adv.get("advisoryTitle", "")
    summary = _strip_html(adv.get("summary", ""))
    if len(summary) > 500:
        summary = summary[:497] + "..."

    advisory_url = adv.get("publicationUrl", "")
    published = adv.get("firstPublished", "").split("T")[0] if adv.get("firstPublished") else ""
    last_modified = adv.get("lastUpdated", "").split("T")[0] if adv.get("lastUpdated") else ""

    cwe_list = adv.get("cwe", [])
    cwe = cwe_list[0] if cwe_list and cwe_list != ["NA"] else None

    vtype = _classify_vuln(title, summary)
    tags = ["cisco-psirt"]
    if severity == "critical":
        tags.append("critical")
    if vtype != "generic":
        tags.append(vtype)

    platforms = ["IOS XE"]
    for pn in adv.get("productNames", []):
        if "Cisco IOS " in pn and "IOS XE" not in pn and "IOS XR" not in pn:
            if "IOS" not in platforms:
                platforms.append("IOS")
            break

    return {
        "cve_id": cve_id, "title": title, "severity": severity,
        "platforms": platforms, "affected": {"min": ver_min, "max": ver_max},
        "fixed_in": None, "tags": tags, "description": summary,
        "workaround": "See Cisco advisory for details.",
        "advisory_url": advisory_url, "confidence": "cisco-psirt",
        "source": "cisco-psirt-import", "cvss_score": cvss, "cvss_vector": None,
        "cwe": cwe, "published": published, "last_modified": last_modified,
        "references": [advisory_url] if advisory_url else [],
    }


def _build_mitigation(cve_id: str, adv: Dict[str, Any], tags: list) -> Dict[str, Any]:
    title = adv.get("advisoryTitle", "")
    summary = _strip_html(adv.get("summary", ""))
    advisory_url = adv.get("publicationUrl", "")
    published = adv.get("firstPublished", "").split("T")[0] if adv.get("firstPublished") else ""

    vtype = _classify_vuln(title, summary)
    tmpl = _MIT_TEMPLATES.get(vtype, _MIT_TEMPLATES["generic"])

    return {
        "cve_id": cve_id,
        "risk_summary": summary[:300] if len(summary) > 300 else summary,
        "attack_vector": f"See advisory: {advisory_url}",
        "workaround_steps": tmpl["steps"],
        "acl_mitigation": tmpl.get("acl"),
        "recommended_fix": f"Upgrade to patched IOS XE version. Check {advisory_url} for details.",
        "upgrade_path": "Check Cisco advisory for platform-specific fixed versions.",
        "detection": {
            "description": "Check if device is running a vulnerable version",
            "commands": tmpl.get("detect", ["show version"]),
            "vulnerable_if": f"Running affected IOS XE version. See {advisory_url}",
        },
        "verification": {
            "description": "Confirm device is patched",
            "commands": ["show version"],
            "expected_output": "IOS XE version at or above the fixed release.",
        },
        "cisco_psirt": advisory_url, "field_notice": None, "cisa_alert": None,
        "tags": tags, "last_updated": published,
    }


def auto_sync_new_cves(cached_advisories: List[Dict[str, Any]]) -> int:
    """
    Import NEW Cisco PSIRT CVEs to local files. Returns count of new CVEs imported.

    Called automatically by CVEEngine after Cisco provider loads data.
    Skips CVEs that already exist locally (preserves curated data).
    """
    if not cached_advisories:
        return 0

    os.makedirs(CVE_DATA_DIR, exist_ok=True)
    os.makedirs(MITIGATION_DIR, exist_ok=True)

    existing_cve = set(
        f.replace(".json", "").upper()
        for f in os.listdir(CVE_DATA_DIR) if f.endswith(".json")
    )
    existing_mit = set(
        f.replace(".json", "").upper()
        for f in os.listdir(MITIGATION_DIR) if f.endswith(".json")
    )

    imported = 0

    for adv in cached_advisories:
        cves = adv.get("cves", [])
        if not cves or cves == ["NA"]:
            continue

        ver_min, ver_max = _extract_xe_version_range(adv.get("productNames", []))

        for cve_id in cves:
            if not cve_id.startswith("CVE-"):
                continue

            cve_upper = cve_id.upper()
            cve_lower = cve_id.lower()

            # CVE data file
            if cve_upper not in existing_cve:
                cve_data = _build_cve_json(cve_id, adv, ver_min, ver_max)
                cve_path = os.path.join(CVE_DATA_DIR, f"{cve_lower}.json")
                with open(cve_path, "w", encoding="utf-8") as f:
                    json.dump(cve_data, f, indent=2, ensure_ascii=False)
                existing_cve.add(cve_upper)
                imported += 1

            # Mitigation file
            if cve_upper not in existing_mit:
                tags = ["cisco-psirt"]
                vtype = _classify_vuln(adv.get("advisoryTitle", ""), adv.get("summary", ""))
                if vtype != "generic":
                    tags.append(vtype)
                mit_data = _build_mitigation(cve_id, adv, tags)
                mit_path = os.path.join(MITIGATION_DIR, f"{cve_upper}.json")
                with open(mit_path, "w", encoding="utf-8") as f:
                    json.dump(mit_data, f, indent=2, ensure_ascii=False)
                existing_mit.add(cve_upper)

    if imported > 0:
        print(f"[SYNC] Auto-imported {imported} new CVEs from Cisco PSIRT to local database")

    return imported
