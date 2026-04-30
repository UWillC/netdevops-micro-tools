"""
Auto-sync: import NEW Cisco PSIRT CVEs into local data + mitigations.

Called by CVEEngine after load_all() when Cisco provider is active.
Only creates files for CVEs that don't exist locally yet.

CVE-006 Phase 4a (added 2026-04-30): one-time migration helper to enrich
legacy `source=cisco-psirt-import` records with `first_fixed_version` +
`product_families` + `affected_versions_raw` from PSIRT advisory detail
endpoint.
"""

import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

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


# =============================================================================
# CVE-006 Phase 4a: one-time migration of legacy cisco-psirt-import records
# =============================================================================

# Advisory URL pattern, e.g.
#   https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-csrf-ycUYxkKO
# advisoryId is the trailing path segment.
_ADVISORY_ID_FROM_URL_RE = re.compile(r"/CiscoSecurityAdvisory/(cisco-sa-[^/?#]+)")


def _extract_advisory_id(advisory_url: Optional[str]) -> Optional[str]:
    """Extract Cisco advisoryId from an advisory_url string. Returns None if not found."""
    if not advisory_url:
        return None
    m = _ADVISORY_ID_FROM_URL_RE.search(advisory_url)
    return m.group(1) if m else None


def _atomic_write_json(path: str, data: Dict[str, Any]) -> None:
    """Write JSON via temp file + rename to avoid partial writes on crash."""
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path)


def enrich_legacy_psirt_records(
    provider,
    cve_data_dir: str = CVE_DATA_DIR,
    rate_limit_sleep: float = 2.0,
    max_records: Optional[int] = None,
    dry_run: bool = False,
) -> Dict[str, int]:
    """One-time migration: enrich legacy cisco-psirt-import records via PSIRT detail.

    CVE-006 Phase 4a. Walks `cve_data_dir`, finds records where:
      - source == "cisco-psirt-import"
      - first_fixed_version is None / missing
      - has advisory_url pointing to a Cisco advisory

    For each, calls provider._fetch_advisory_detail(advisoryId), extracts
    first-fixed map and product families, and patches the JSON file in place
    via atomic write.

    Idempotent: records already carrying first_fixed_version are skipped.

    Rate limit: sleeps `rate_limit_sleep` seconds between API calls. Cisco
    PSIRT global limit is 30 calls/min — default 2.0s leaves margin and
    keeps 129 records under ~5 min wall clock.

    Args:
        provider: CiscoAdvisoryProvider instance (already authenticated/credentialed)
        cve_data_dir: directory to scan (default: cve_data/ios_xe/)
        rate_limit_sleep: sleep between successful API fetches (skipped on cache hit)
        max_records: cap on records processed this run (None = all)
        dry_run: if True, do not write changes (only count what would change)

    Returns:
        Counts dict with keys:
          scanned, skipped_curated, skipped_already_enriched, skipped_no_url,
          fetched, enriched, failed
    """
    from services.platform_taxonomy import (
        ProductFamily,
        normalize_cisco_product_names,
    )

    counts = {
        "scanned": 0,
        "skipped_curated": 0,
        "skipped_already_enriched": 0,
        "skipped_no_url": 0,
        "fetched": 0,
        "enriched": 0,
        "failed": 0,
    }

    if not os.path.isdir(cve_data_dir):
        return counts

    files = sorted(
        f for f in os.listdir(cve_data_dir)
        if f.endswith(".json") and not f.startswith("_")
    )

    for fname in files:
        if max_records is not None and counts["enriched"] >= max_records:
            break

        path = os.path.join(cve_data_dir, fname)
        counts["scanned"] += 1

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            counts["failed"] += 1
            continue

        # Skip curated records (preserve hand-entered fixed_in / first_fixed_version).
        if data.get("source") != "cisco-psirt-import":
            counts["skipped_curated"] += 1
            continue

        # Idempotent: skip records already carrying first_fixed_version.
        if data.get("first_fixed_version"):
            counts["skipped_already_enriched"] += 1
            continue

        advisory_id = _extract_advisory_id(data.get("advisory_url"))
        if not advisory_id:
            counts["skipped_no_url"] += 1
            continue

        # Fetch detail (cache-aware via provider). On miss this triggers an API call.
        cache_was_warm = provider._read_detail_cache(advisory_id) is not None
        detail = provider._fetch_advisory_detail(advisory_id)

        if detail is None:
            counts["failed"] += 1
            # Rate-limit sleep on actual API miss, even if we got None back
            if not cache_was_warm:
                time.sleep(rate_limit_sleep)
            continue

        if not cache_was_warm:
            counts["fetched"] += 1

        # Extract enrichment from detail.
        fix_map = provider._extract_fix_versions(detail)
        product_names = detail.get("productNames", [])
        if isinstance(product_names, list) and product_names:
            families = normalize_cisco_product_names(product_names)
            product_families_str = sorted(
                f.value for f in families if f != ProductFamily.UNKNOWN
            )
            affected_versions_raw = [
                n for n in product_names if isinstance(n, str) and n
            ][:50]
        else:
            product_families_str = []
            affected_versions_raw = []

        # Patch in-place. Only touch the new fields - keep everything else identical.
        if fix_map:
            data["first_fixed_version"] = {"fixes": fix_map}
        if product_families_str and not data.get("product_families"):
            data["product_families"] = product_families_str
        if affected_versions_raw and not data.get("affected_versions_raw"):
            data["affected_versions_raw"] = affected_versions_raw

        if not dry_run:
            try:
                _atomic_write_json(path, data)
            except Exception:
                counts["failed"] += 1
                if not cache_was_warm:
                    time.sleep(rate_limit_sleep)
                continue

        counts["enriched"] += 1

        # Throttle only on actual API miss (cache hits are zero-cost).
        if not cache_was_warm:
            time.sleep(rate_limit_sleep)

    print(
        f"[MIGRATE] Phase 4a scanned={counts['scanned']} enriched={counts['enriched']} "
        f"fetched={counts['fetched']} skipped_curated={counts['skipped_curated']} "
        f"skipped_already_enriched={counts['skipped_already_enriched']} "
        f"skipped_no_url={counts['skipped_no_url']} failed={counts['failed']}"
    )

    return counts
