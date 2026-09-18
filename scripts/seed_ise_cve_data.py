#!/usr/bin/env python3
"""seed_ise_cve_data.py — ISE-01 seed for cve_data/ise/ (2026-09-18).

Why a script and not hand-written JSON: every field below was read from a
primary source on 2026-09-18 and the provenance is recorded here, so the
dataset can be regenerated and diffed rather than trusted.

Sources (all fetched 2026-09-18):
  - CISA KEV JSON, catalogVersion 2026.09.16 (dateReleased 2026-09-16T18:47:50Z)
  - Cisco CVRF XML per advisory:
      cisco-sa-ISE-ABP-VNSW7Tn5      (CVE-2026-76460)
      cisco-sa-hardening-ise-XU5EwX5T (CVE-2026-20130/20192/20194/20234/20237/20287)
      cisco-sa-ise-RADIUS-dos-wR3hYPMw (CVE-2026-20352)
  - NVD API 2.0 for CVSS base scores (source psirt@cisco.com)

Run:  python3 scripts/seed_ise_cve_data.py [--check]
      --check exits non-zero if on-disk files differ from what we would write.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(HERE)
OUT_DIR = os.path.join(PROJECT_DIR, "cve_data", "ise")

ADV = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"

# Fixed Software table, cisco-sa-hardening-ise-XU5EwX5T and
# cisco-sa-ISE-ABP-VNSW7Tn5 (identical): 3.0 and earlier -> migrate.
FIXES_FULL = {
    "ise-3.1": "3.1 Patch 12",
    "ise-3.2": "3.2 Patch 11",
    "ise-3.3": "3.3 Patch 12",
    "ise-3.4": "3.4 Patch 7",
    "ise-3.5": "3.5 Patch 4",
}
# cisco-sa-ise-RADIUS-dos-wR3hYPMw: "3.1 and earlier — Not vulnerable".
FIXES_RADIUS = {
    "ise-3.2": "3.2 Patch 11",
    "ise-3.3": "3.3 Patch 12",
    "ise-3.4": "3.4 Patch 7",
    "ise-3.5": "3.5 Patch 4",
}

EOSM_NOTE = (
    "Cisco ISE Software Release 3.0 has reached End of Software Maintenance; "
    "there is no fixed release on that train, customers must migrate. "
    "Releases 3.1 and 3.2 are in Software Maintenance and receive Critical SIR "
    "fixes only. ISE-PIC has reached end-of-sale; 3.4 is its last supported release."
)

HARDENING_DESC = (
    "Bundled hardening CVE from the Cisco ISE Hardening Release: September 2026. "
    "Under Cisco's risk-based disclosure model (twice-monthly, 1st and 3rd Wednesday), "
    "hardening releases do not assign one CVE per bug: a single CVE covers multiple "
    "fixes within one CWE category. Treat this record as a class of defects with a "
    "common fixed release, not as a single exploit path."
)


def rec(cve_id, title, sev, sir, cvss, cwe, desc, fixes, amin, amax,
        adv_slug, tags, workaround, exploited=False, kev=None):
    r = {
        "cve_id": cve_id,
        "title": title,
        "severity": sev,
        "platforms": ["ISE", "ISE-PIC"],
        "affected": {"min": amin, "max": amax},
        "fixed_in": None,
        "tags": tags,
        "description": desc,
        "workaround": workaround,
        "advisory_url": ADV + adv_slug,
        "confidence": "cisco-psirt",
        "source": "cisco-psirt-cvrf",
        "cvss_score": cvss,
        "cvss_vector": None,
        "cwe": cwe,
        "published": "2026-09-16",
        "last_modified": "2026-09-18",
        "references": [ADV + adv_slug, "https://nvd.nist.gov/vuln/detail/" + cve_id],
        "cisco_sir": sir,
        "bundle": "2026-09",
        "product_families": ["ise"],
        "affected_versions_raw": [
            "Cisco ISE 3.1", "Cisco ISE 3.2", "Cisco ISE 3.3",
            "Cisco ISE 3.4", "Cisco ISE 3.5",
        ],
        "first_fixed_version": {"fixes": fixes},
    }
    if exploited:
        r["references"].append(
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=" + cve_id
        )
        r["kev"] = kev
    return r


RECORDS = [
    rec(
        "CVE-2026-76460",
        "Cisco Identity Services Engine Authentication Bypass Vulnerability",
        "critical", "Critical", 10.0, "CWE-648",
        "A vulnerability in an API of Cisco Identity Services Engine (ISE) could allow an "
        "unauthenticated, remote attacker to bypass authentication. This vulnerability is due to "
        "insufficient authentication control on an API endpoint. An attacker could exploit this "
        "vulnerability by sending a crafted request to an affected API endpoint. A successful "
        "exploit could allow the attacker to gain unauthorized access to the affected device by "
        "bypassing the web-based management interface. Cisco PSIRT is aware of ACTIVE EXPLOITATION. "
        + EOSM_NOTE,
        FIXES_FULL, "3.0", "3.5", "cisco-sa-ISE-ABP-VNSW7Tn5",
        ["cisco-psirt", "ise", "identity", "auth-bypass", "kev", "actively-exploited",
         "bundle-2026-09"],
        "No workarounds address this vulnerability. Mitigation only: use infrastructure ACLs "
        "(iACLs) to permit only required management and control plane traffic destined to the "
        "affected device.",
        exploited=True,
        kev={"date_added": "2026-09-16", "due_date": "2026-09-19",
             "catalog_version": "2026.09.16", "directive": "BOD 26-04"},
    ),
    rec("CVE-2026-20192",
        "Cisco ISE Hardening Release - Access Control Vulnerabilities",
        "critical", "Critical", 10.0, "CWE-284",
        HARDENING_DESC + " Category: Access Control. " + EOSM_NOTE,
        FIXES_FULL, "3.0", "3.5", "cisco-sa-hardening-ise-XU5EwX5T",
        ["cisco-psirt", "ise", "identity", "hardening-release", "bundled-cve", "bundle-2026-09"],
        "No workarounds. Upgrade to the hardened release for your train."),
    rec("CVE-2026-20130",
        "Cisco ISE Hardening Release - Improper Neutralization Vulnerabilities",
        "critical", "Critical", 10.0, "CWE-707",
        HARDENING_DESC + " Category: Improper Neutralization. " + EOSM_NOTE,
        FIXES_FULL, "3.0", "3.5", "cisco-sa-hardening-ise-XU5EwX5T",
        ["cisco-psirt", "ise", "identity", "hardening-release", "bundled-cve", "bundle-2026-09"],
        "No workarounds. Upgrade to the hardened release for your train."),
    rec("CVE-2026-20234",
        "Cisco ISE Hardening Release - Insufficiently Protected Credential Vulnerabilities",
        "critical", "Critical", 9.9, "CWE-522",
        HARDENING_DESC + " Category: Insufficiently Protected Credentials. " + EOSM_NOTE,
        FIXES_FULL, "3.0", "3.5", "cisco-sa-hardening-ise-XU5EwX5T",
        ["cisco-psirt", "ise", "identity", "hardening-release", "bundled-cve", "bundle-2026-09"],
        "No workarounds. Upgrade to the hardened release for your train."),
    rec("CVE-2026-20237",
        "Cisco ISE Hardening Release - Input Validation Vulnerabilities",
        "critical", "Critical", 9.1, "CWE-20",
        HARDENING_DESC + " Category: Input Validation. " + EOSM_NOTE,
        FIXES_FULL, "3.0", "3.5", "cisco-sa-hardening-ise-XU5EwX5T",
        ["cisco-psirt", "ise", "identity", "hardening-release", "bundled-cve", "bundle-2026-09"],
        "No workarounds. Upgrade to the hardened release for your train."),
    rec("CVE-2026-20194",
        "Cisco ISE Hardening Release - Incorrect Resource Transfer Vulnerabilities",
        "critical", "Critical", 9.1, "CWE-669",
        HARDENING_DESC + " Category: Incorrect Resource Transfer. " + EOSM_NOTE,
        FIXES_FULL, "3.0", "3.5", "cisco-sa-hardening-ise-XU5EwX5T",
        ["cisco-psirt", "ise", "identity", "hardening-release", "bundled-cve", "bundle-2026-09"],
        "No workarounds. Upgrade to the hardened release for your train."),
    rec("CVE-2026-20287",
        "Cisco ISE Hardening Release - Improper Privilege Management Vulnerabilities",
        "medium", "Critical", 6.5, "CWE-269",
        HARDENING_DESC + " Category: Improper Privilege Management. "
        "NOTE: CVSS base score (6.5) and the advisory-level Cisco SIR (Critical) disagree here "
        "because the SIR applies to the hardening release as a whole. " + EOSM_NOTE,
        FIXES_FULL, "3.0", "3.5", "cisco-sa-hardening-ise-XU5EwX5T",
        ["cisco-psirt", "ise", "identity", "hardening-release", "bundled-cve", "bundle-2026-09",
         "sir-cvss-divergence"],
        "No workarounds. Upgrade to the hardened release for your train."),
    rec("CVE-2026-20352",
        "Cisco Identity Services Engine RADIUS Denial of Service Vulnerability",
        "high", "High", 8.6, None,
        "A vulnerability in the RADIUS feature of Cisco Identity Services Engine (ISE) could allow "
        "an unauthenticated, remote attacker to cause a denial of service condition. "
        "Releases 3.1 and earlier are NOT vulnerable, which is why the affected range starts at 3.2.",
        FIXES_RADIUS, "3.2", "3.5", "cisco-sa-ise-RADIUS-dos-wR3hYPMw",
        ["cisco-psirt", "ise", "identity", "radius", "dos", "bundle-2026-09"],
        "See Cisco advisory for details."),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if on-disk files differ (CI drift guard)")
    args = ap.parse_args()
    os.makedirs(OUT_DIR, exist_ok=True)
    drift = []
    for r in RECORDS:
        path = os.path.join(OUT_DIR, r["cve_id"].lower() + ".json")
        payload = json.dumps(r, indent=2, ensure_ascii=False) + "\n"
        if args.check:
            existing = open(path, encoding="utf-8").read() if os.path.exists(path) else None
            if existing != payload:
                drift.append(os.path.basename(path))
            continue
        with open(path, "w", encoding="utf-8") as f:
            f.write(payload)
        print("wrote", os.path.relpath(path, PROJECT_DIR))
    if args.check:
        if drift:
            print("DRIFT:", ", ".join(drift))
            return 1
        print("cve_data/ise/ matches seed (%d records)" % len(RECORDS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
