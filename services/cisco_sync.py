"""
Auto-sync: import NEW Cisco PSIRT CVEs into local data + mitigations.

Called by CVEEngine after load_all() when Cisco provider is active.
Only creates files for CVEs that don't exist locally yet.

CVE-006 Phase 4a (added 2026-04-30): one-time migration helper to enrich
legacy `source=cisco-psirt-import` records with `first_fixed_version` +
`product_families` + `affected_versions_raw` from PSIRT advisory detail
endpoint.
"""

import datetime
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from models.cve_model import CVEEntry
from services.advisory_text import clean_advisory_text, summarize_advisory_text
from services.hardening_release import bundled_info_from_advisory
from services.known_affected import extract_known_affected
from services import cisco_workaround

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
    # HTML-01: shared cleaner — also decodes entities (&nbsp; and friends).
    clean = clean_advisory_text(text)
    return re.sub(r"\s+", " ", clean)


# Matched on word boundaries. FEATURES name where the bug lives; EFFECTS name what
# it does. A feature always beats an effect, in the title or in the first sentence:
# "SD-Access Fabric Edge Node Denial of Service" is a DHCP snooping bug, and the
# title alone would file it under "dos".
_VULN_FEATURES = [
    (r"snmp(v[123]c?)?|simple network management protocol", "snmp"),
    (r"web ui|webui|web-based|web services|https? server|http api|lobby ambassador", "webui"),
    (r"ssh|secure shell|scp|secure copy", "ssh"),
    (r"bgp|border gateway protocol", "bgp"), (r"ospf(v3)?|open shortest path first", "ospf"),
    (r"dhcp(v6)?|dynamic host configuration protocol|bootp", "dhcp"),
    (r"m?dns|domain name system", "dns"),
    (r"ipsec|ikev?[12]?|internet key exchange|vpn(?! routing)", "vpn"),
    (r"aaa|tacacs\+?|radius", "aaa"),
]
_VULN_EFFECTS = [
    (r"secure boot bypass", "secure-boot"),
    (r"privilege escalation", "privesc"),
    (r"authentication bypass|authorization bypass", "auth-bypass"),
    (r"denial of service|dos", "dos"),
    (r"remote code execution|code execution|buffer overflow|command injection", "rce"),
]
_VULN_KEYWORDS = _VULN_FEATURES + _VULN_EFFECTS
_URL_RE = re.compile(r"https?://\S+")


def _classify_vuln(title: str, summary: str) -> str:
    """Name the feature a CVE lives in. Drives the tag AND the mitigation template.

    The title decides. The summary is only a fallback, reduced to its first
    sentence with URLs removed: Cisco closes every summary with "This advisory
    is available at the following link:https://..." and a substring search for
    "http" over that text filed 87 unrelated CVEs (Ethernet frames, IKEv1, ARP)
    under web UI, each with "no ip http server" as its workaround.
    """
    def first_hit(text: str, table) -> str:
        text = _URL_RE.sub(" ", text.lower())
        for pattern, vtype in table:
            if re.search(r"(?<![a-z0-9])(?:" + pattern + r")(?![a-z0-9])", text):
                return vtype
        return ""

    first_sentence = re.split(r"(?<=[.!?])\s", _URL_RE.sub(" ", summary or ""), maxsplit=1)[0]
    return (first_hit(title or "", _VULN_FEATURES) or first_hit(first_sentence, _VULN_FEATURES)
            or first_hit(title or "", _VULN_EFFECTS) or first_hit(first_sentence, _VULN_EFFECTS)
            or "generic")


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
for _alias, _target in [("rce", "generic"), ("auth", "generic"), ("privesc", "generic"),
                         ("auth-bypass", "generic"), ("secure-boot", "generic"), ("ssh", "generic"),
                         ("bgp", "dos"), ("ospf", "dos"), ("dhcp", "dos"),
                         ("dns", "dos"), ("vpn", "generic"), ("aaa", "generic")]:
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
    # Whole sentences, Cisco boilerplate removed. The old cut at 497 characters
    # ended records mid-word ("due to improper valida...").
    summary = summarize_advisory_text(_strip_html(adv.get("summary", "")))

    advisory_url = adv.get("publicationUrl", "")
    published = adv.get("firstPublished", "").split("T")[0] if adv.get("firstPublished") else ""
    last_modified = adv.get("lastUpdated", "").split("T")[0] if adv.get("lastUpdated") else ""

    cwe_list = adv.get("cwe", [])
    cwe = cwe_list[0] if cwe_list and cwe_list != ["NA"] else None

    # CVE-007: same rule as the other two importers (see
    # services/hardening_release.py). This is the importer that actually runs in
    # production — auto_sync_new_cves() is called on every PSIRT refresh — and
    # it was missed in v0.6.34, which patched _parse_advisory and
    # scripts/import_cisco_to_local.py only.
    bundled_info = bundled_info_from_advisory(adv)
    if bundled_info is not None:
        cwe = None

    vtype = _classify_vuln(title, summary)
    tags = ["cisco-psirt"]
    if bundled_info is not None:
        tags.extend(["hardening-release", "bundled-cve"])
    if severity == "critical":
        tags.append("critical")
    if vtype != "generic":
        tags.append(vtype)

    # Platforms come from what the advisory names. An advisory that lists only
    # classic IOS releases must not be filed as IOS XE (it used to be: the list
    # started as ["IOS XE"] unconditionally, which was harmless only while the
    # "ios" platform query returned nothing at all).
    names = adv.get("productNames", []) or []
    has_xe = any("IOS XE" in pn for pn in names)
    has_ios = any("Cisco IOS " in pn and "IOS XE" not in pn and "IOS XR" not in pn for pn in names)
    platforms = (["IOS XE"] if has_xe or not has_ios else []) + (["IOS"] if has_ios else [])

    return {
        "cve_id": cve_id, "title": title, "severity": severity,
        "platforms": platforms, "affected": {"min": ver_min, "max": ver_max},
        "fixed_in": None, "tags": tags, "description": summary,
        "workaround": "See Cisco advisory for details.",
        "advisory_url": advisory_url, "confidence": "cisco-psirt",
        "source": "cisco-psirt-import", "cvss_score": cvss, "cvss_vector": None,
        "cwe": cwe, "published": published, "last_modified": last_modified,
        "references": [advisory_url] if advisory_url else [],
        "bundled": bundled_info.model_dump() if bundled_info is not None else None,
        # MATCH-01: the full Known Affected list, not the first-50 display slice.
        "known_affected": extract_known_affected(adv),
        "known_affected_as_of": datetime.date.today().isoformat(),
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


def auto_sync_new_cves(cached_advisories: List[Dict[str, Any]], platform: str = "iosxe") -> int:
    """
    Import NEW Cisco PSIRT CVEs to local files. Returns count of new CVEs imported.

    Called automatically by CVEEngine after Cisco provider loads data.
    Skips CVEs that already exist locally (preserves curated data).

    `platform` selects the dataset. ISE has its own importer (ISE-04): different
    directory, different record shape, and a stricter admission rule.
    """
    if not cached_advisories:
        return 0
    if platform == "ise":
        return auto_sync_ise(cached_advisories)
    if platform == "nxos":
        return auto_sync_nxos(cached_advisories)

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
    refreshed = 0

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
            cve_path = os.path.join(CVE_DATA_DIR, f"{cve_lower}.json")
            if cve_upper not in existing_cve:
                cve_data = _build_cve_json(cve_id, adv, ver_min, ver_max)
                with open(cve_path, "w", encoding="utf-8") as f:
                    json.dump(cve_data, f, indent=2, ensure_ascii=False)
                existing_cve.add(cve_upper)
                imported += 1
            else:
                # LISTS-01: an existing record is otherwise left alone, but its
                # Known Affected list must follow Cisco's revisions.
                refreshed += refresh_known_affected(cve_path, adv)

            # Mitigation file
            if cve_upper not in existing_mit:
                tags = ["cisco-psirt"]
                vtype = _classify_vuln(adv.get("advisoryTitle", ""), adv.get("summary", ""))
                if vtype != "generic":
                    tags.append(vtype)
                mit_data = _build_mitigation(cve_id, adv, tags)
                wa = cisco_workaround.fetch(mit_data.get("cisco_psirt"))
                if wa:
                    mit_data["cisco_workaround"] = wa
                mit_path = os.path.join(MITIGATION_DIR, f"{cve_upper}.json")
                with open(mit_path, "w", encoding="utf-8") as f:
                    json.dump(mit_data, f, indent=2, ensure_ascii=False)
                existing_mit.add(cve_upper)

    if imported > 0:
        print(f"[SYNC] Auto-imported {imported} new CVEs from Cisco PSIRT to local database")
    if refreshed > 0:
        print(f"[SYNC] Refreshed Known Affected lists on {refreshed} existing CVE record(s)")

    return imported


ISE_DATA_DIR = os.path.join(PROJECT_DIR, "cve_data", "ise")


def _train_bounds(versions: List[str]) -> Tuple[str, str]:
    """Lowest and highest ISE train on a Known Affected list, e.g. ("3.1", "3.5")."""
    from services.known_affected import _ise_key
    trains = sorted({k[:2] for k in (_ise_key(v) for v in versions) if k})
    if not trains:
        return "0.0", "99.0"
    return "%d.%d" % trains[0], "%d.%d" % trains[-1]


def build_ise_record(cve_id: str, adv: Dict[str, Any], details: Dict[str, Any]) -> Dict[str, Any]:
    """One cve_data/ise record from a PSIRT advisory plus its CVRF details.

    Per-CVE title, CVSS and vector come from CVRF. PSIRT's `cvssBaseScore` is
    the ADVISORY maximum — right for a single-CVE advisory, wrong for the rest —
    so it is used only as a last resort and the record is tagged when it is.
    """
    listed = extract_known_affected(adv).get("ise") or []
    amin, amax = _train_bounds(listed)
    per_cve = (details.get("vulnerabilities") or {}).get(cve_id.upper(), {})
    cves = [c for c in (adv.get("cves") or []) if isinstance(c, str) and c.startswith("CVE-")]
    single = len(cves) == 1

    tags = ["cisco-psirt", "ise", "identity"]
    cvss = per_cve.get("cvss")
    if cvss is None:
        try:
            cvss = float(adv.get("cvssBaseScore") or 0) or None
        except (ValueError, TypeError):
            cvss = None
        if cvss is not None and not single:
            tags.append("cvss-advisory-level")

    from services.cve_engine import cvss_rating_from_score
    sir = (adv.get("sir") or "").strip()
    severity = cvss_rating_from_score(cvss).lower() if cvss is not None else (sir.lower() or "medium")

    bundled_info = bundled_info_from_advisory(adv)
    if bundled_info is not None:
        tags.extend(["hardening-release", "bundled-cve"])
    if details.get("exploited"):
        tags.append("actively-exploited")

    cwe_list = [c for c in (adv.get("cwe") or []) if isinstance(c, str) and c.startswith("CWE-")]
    cwe = cwe_list[0] if (single and cwe_list) else None   # per-CVE CWE is not in PSIRT or CVRF

    url = adv.get("publicationUrl") or ""
    published = (adv.get("firstPublished") or "").split("T")[0]
    return {
        "cve_id": cve_id.upper(),
        "title": per_cve.get("title") or clean_advisory_text(adv.get("advisoryTitle") or ""),
        "severity": severity,
        "platforms": ["ISE", "ISE-PIC"],
        "affected": {"min": amin, "max": amax},
        "fixed_in": None,
        "tags": tags,
        "description": clean_advisory_text(adv.get("summary") or "")[:1500],
        "workaround": "See Cisco advisory for details.",
        "advisory_url": url,
        "confidence": "cisco-psirt",
        "source": "cisco-psirt-import",
        "cvss_score": cvss,
        "cvss_vector": per_cve.get("vector"),
        "cwe": cwe,
        "published": published,
        "last_modified": (adv.get("lastUpdated") or "").split("T")[0] or published,
        "references": [u for u in (url, "https://nvd.nist.gov/vuln/detail/" + cve_id.upper()) if u],
        "cisco_sir": sir or None,
        "bundle": None,
        "product_families": ["ise"],
        "affected_versions_raw": ["Cisco ISE " + v for v in listed[:50]],
        "first_fixed_version": {"fixes": details.get("fixes") or {}} if details.get("fixes") else None,
        "bundled": bundled_info.model_dump() if bundled_info is not None else None,
        "known_affected": {"ise": listed},
        "known_affected_as_of": datetime.date.today().isoformat(),
    }


def auto_sync_ise(cached_advisories: List[Dict[str, Any]], fetch_details=None) -> int:
    """Import new ISE CVEs and refresh lists on existing ones. Returns new count.

    ADMISSION RULE: an advisory is imported only when it carries a Known Affected
    release list for ISE. Measured 2026-09-18: all 25 ISE advisories published
    in 2026 have one; none of the 168 from 2013–2025 do — they name the product
    with no release. Importing those would mean a 0.0–99.0 placeholder range
    that matches every deployment, i.e. re-creating for ISE the "100 of 104
    matches are guesses" problem MATCH-01 removed from IOS XE. What cannot be
    verified is left out and the report says so (see `ise_coverage_note`).

    No mitigation templates are generated: the templates in this module are IOS
    configuration snippets and would be wrong on an ISE node.
    """
    if fetch_details is None:
        from services.ise_fixed_table import fetch_cvrf, ise_advisory_details

        def fetch_details(adv):  # one CVRF request per advisory that has a NEW cve
            return ise_advisory_details(fetch_cvrf(adv.get("cvrfUrl")))

    os.makedirs(ISE_DATA_DIR, exist_ok=True)
    existing = {f[:-5].upper() for f in os.listdir(ISE_DATA_DIR) if f.endswith(".json")}
    imported = refreshed = skipped_no_list = 0

    for adv in cached_advisories:
        if not extract_known_affected(adv).get("ise"):
            skipped_no_list += 1
            continue
        details = None
        for cve_id in adv.get("cves") or []:
            if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
                continue
            path = os.path.join(ISE_DATA_DIR, cve_id.lower() + ".json")
            if cve_id.upper() in existing:
                refreshed += refresh_known_affected(path, adv)
                continue
            if details is None:
                try:
                    details = fetch_details(adv) or {}
                except Exception:
                    details = {}
            with open(path, "w", encoding="utf-8") as f:
                json.dump(build_ise_record(cve_id, adv, details), f, indent=2, ensure_ascii=False)
                f.write("\n")
            existing.add(cve_id.upper())
            imported += 1

    if imported or refreshed:
        print(f"[SYNC] ISE: imported {imported} new CVE(s), refreshed {refreshed} list(s); "
              f"{skipped_no_list} advisory(ies) without a release list left out")
    return imported


# ---------------------------------------------------------------------------
# NX-OS-01 (2026-09-18) — NX-OS as its own auto-synced dataset
# ---------------------------------------------------------------------------
# Same design as ISE-04, for the same reason: an NX-OS release has the shape of
# a classic IOS release ("10.2(6)"), so without its own dataset an NX-OS query
# was answered from IOS lists of the 1990s. Measured on PSIRT the day this was
# written: 246 NX-OS advisories, 222 of them with an NX-OS release list, 288 CVEs.
#
# Admission rule: an advisory enters only if Cisco enumerates standalone NX-OS
# releases for it. No list, no record — every match must be checkable.
# What Cisco does NOT give for NX-OS: a first fixed release (the advisories
# defer to Software Checker). `fixed_in` therefore stays empty and the report
# says so, instead of recommending a version nobody read.
NXOS_DATA_DIR = os.path.join(PROJECT_DIR, "cve_data", "nx_os")


def _nxos_train_bounds(versions: List[str]) -> Tuple[str, str]:
    trains = []
    for v in versions:
        m = re.match(r"^(\d+)\.(\d+)", v)
        if m:
            trains.append((int(m.group(1)), int(m.group(2))))
    if not trains:
        return "0.0", "99.0"
    return "%d.%d" % min(trains), "%d.%d" % max(trains)


def build_nxos_record(cve_id: str, adv: Dict[str, Any], details: Dict[str, Any]) -> Dict[str, Any]:
    """One cve_data/nx_os record. Per-CVE title/CVSS from CVRF when present."""
    lists = extract_known_affected(adv)
    listed = lists.get("nx-os") or []
    amin, amax = _nxos_train_bounds(listed)
    per_cve = (details.get("vulnerabilities") or {}).get(cve_id.upper(), {})
    cves = [c for c in (adv.get("cves") or []) if isinstance(c, str) and c.startswith("CVE-")]
    single = len(cves) == 1

    tags = ["cisco-psirt", "nx-os"]
    cvss = per_cve.get("cvss")
    if cvss is None:
        try:
            cvss = float(adv.get("cvssBaseScore") or 0) or None
        except (ValueError, TypeError):
            cvss = None
        if cvss is not None and not single:
            tags.append("cvss-advisory-level")

    from services.cve_engine import cvss_rating_from_score
    sir = (adv.get("sir") or "").strip()
    severity = cvss_rating_from_score(cvss).lower() if cvss is not None else (sir.lower() or "medium")
    if severity not in ("critical", "high", "medium", "low"):
        severity = "medium"
    if details.get("exploited"):
        tags.append("actively-exploited")

    cwe_list = [c for c in (adv.get("cwe") or []) if isinstance(c, str) and c.startswith("CWE-")]
    url = adv.get("publicationUrl") or ""
    published = (adv.get("firstPublished") or "").split("T")[0]
    known = {"nx-os": listed}
    if lists.get("nx-os-aci"):
        known["nx-os-aci"] = lists["nx-os-aci"]
    return {
        "cve_id": cve_id.upper(),
        "title": per_cve.get("title") or clean_advisory_text(adv.get("advisoryTitle") or ""),
        "severity": severity,
        "platforms": ["NX-OS"],
        "affected": {"min": amin, "max": amax},
        "fixed_in": None,
        "tags": tags,
        "description": summarize_advisory_text(adv.get("summary") or ""),
        "workaround": "See Cisco advisory for details.",
        "advisory_url": url,
        "confidence": "cisco-psirt",
        "source": "cisco-psirt-import",
        "cvss_score": cvss,
        "cvss_vector": per_cve.get("vector"),
        "cwe": cwe_list[0] if (single and cwe_list) else None,
        "published": published,
        "last_modified": (adv.get("lastUpdated") or "").split("T")[0] or published,
        "references": [u for u in (url, "https://nvd.nist.gov/vuln/detail/" + cve_id.upper()) if u],
        "cisco_sir": sir or None,
        "bundle": None,
        "product_families": ["nx-os"],
        "affected_versions_raw": ["Cisco NX-OS Software " + v for v in listed[:50]],
        "first_fixed_version": None,
        "bundled": None,
        "known_affected": known,
        "known_affected_as_of": datetime.date.today().isoformat(),
    }


def auto_sync_nxos(cached_advisories: List[Dict[str, Any]], fetch_details=None) -> int:
    """Import NEW NX-OS CVEs, refresh the lists of existing ones. Returns imports."""
    if fetch_details is None:
        from services.ise_fixed_table import (
            exploitation_confirmed_in_cvrf, fetch_cvrf, vulnerabilities_from_cvrf)

        def fetch_details(adv):  # one CVRF request per advisory that has a NEW cve
            xml = fetch_cvrf(adv.get("cvrfUrl"))
            if not xml:
                return {}
            return {"vulnerabilities": vulnerabilities_from_cvrf(xml),
                    "exploited": exploitation_confirmed_in_cvrf(xml)}

    os.makedirs(NXOS_DATA_DIR, exist_ok=True)
    existing = {f[:-5].upper() for f in os.listdir(NXOS_DATA_DIR) if f.endswith(".json")}
    imported = refreshed = skipped_no_list = 0

    for adv in cached_advisories:
        if not extract_known_affected(adv).get("nx-os"):
            skipped_no_list += 1
            continue
        details = None
        for cve_id in adv.get("cves") or []:
            if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
                continue
            path = os.path.join(NXOS_DATA_DIR, cve_id.lower() + ".json")
            if cve_id.upper() in existing:
                refreshed += refresh_known_affected(path, adv)
                continue
            if details is None:
                try:
                    details = fetch_details(adv) or {}
                except Exception:
                    details = {}
            with open(path, "w", encoding="utf-8") as f:
                json.dump(build_nxos_record(cve_id, adv, details), f, indent=2, ensure_ascii=False)
                f.write("\n")
            existing.add(cve_id.upper())
            imported += 1

    if imported or refreshed:
        print(f"[SYNC] NX-OS: imported {imported} new CVE(s), refreshed {refreshed} list(s); "
              f"{skipped_no_list} advisory(ies) without a release list left out")
    return imported


def refresh_known_affected(cve_path: str, adv: Dict[str, Any]) -> int:
    """Bring one existing record's Known Affected list up to date. Returns 0/1.

    LISTS-01 (2026-09-18). auto_sync_new_cves() skips CVEs that already exist
    locally, to protect curated data. Since MATCH-01 the Known Affected list
    decides whether a release matches at all, so a list frozen at import time
    goes quietly wrong the day Cisco revises the advisory — and nothing would
    have noticed. The previous answer was "remember to run the migration
    script", which is how the IOS XE platform cache reached 189 days.

    Rules, each one a way this could otherwise corrupt a record:
      - Only `known_affected` and `known_affected_as_of` are ever written.
        Curated fields (affected, fixed_in, severity, tags, text) are untouched.
      - Only when this advisory is the record's own advisory. A CVE can appear
        in several advisories with different release lists; without this check
        the list would flip between them on every sync.
      - Per family, a list is never replaced by an empty one. "Cisco named the
        product without releases" means we were not told, not "nothing is
        affected".
      - Nothing is written when the content is unchanged, so the as-of date
        means "last time the list actually changed or was confirmed at import",
        and an idle sync does not dirty the dataset.
    """
    new_lists = extract_known_affected(adv)
    if not new_lists:
        return 0
    try:
        with open(cve_path, "r", encoding="utf-8") as f:
            rec = json.load(f)
    except Exception:
        return 0

    m = _ADVISORY_ID_FROM_URL_RE.search(rec.get("advisory_url") or "")
    if not m or m.group(1) != (adv.get("advisoryId") or ""):
        return 0

    current = rec.get("known_affected") or {}
    merged = dict(current)
    for family, versions in new_lists.items():
        if versions:
            merged[family] = versions
    if merged == current:
        return 0

    rec["known_affected"] = merged
    rec["known_affected_as_of"] = datetime.date.today().isoformat()
    try:
        with open(cve_path, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except Exception:
        return 0
    return 1


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
