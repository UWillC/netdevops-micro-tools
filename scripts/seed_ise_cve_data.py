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
# cisco-sa-hardening-ise-XU5EwX5T only: "3.0 and earlier — Migrate to fixed
# release". Stored as an explicit "migrate" so that "Cisco says there is no fix
# here" is distinguishable from "we have no table for this CVE" (ISE-04). The
# authentication-bypass table has no 3.0 row, so FIXES_FULL stays without one.
FIXES_HARDENING = dict(FIXES_FULL)
FIXES_HARDENING.update({"ise-3.0": "migrate", "ise-<3.0": "migrate"})

# cisco-sa-ise-RADIUS-dos-wR3hYPMw: "3.1 and earlier — Not vulnerable".
FIXES_RADIUS = {
    "ise-3.2": "3.2 Patch 11",
    "ise-3.3": "3.3 Patch 12",
    "ise-3.4": "3.4 Patch 7",
    "ise-3.5": "3.5 Patch 4",
}

# The `bundled` block shared by the six hardening-release CVEs. Category list
# and sibling list are copied from the PSIRT advisory (len(cves) == len(cwe)).
HARDENING_BUNDLE = {
    "advisory_id": "cisco-sa-hardening-ise-XU5EwX5T",
    "cwe_categories": ["CWE-20", "CWE-269", "CWE-284", "CWE-522", "CWE-669", "CWE-74"],
    "sibling_cves": ["CVE-2026-20130", "CVE-2026-20192", "CVE-2026-20194",
                     "CVE-2026-20234", "CVE-2026-20237", "CVE-2026-20287"],
    "one_cve_per_cwe": True,
}

# Lower bound of the affected range. The hardening advisory's Fixed Software
# table reads "3.0 and earlier — Migrate to fixed release", i.e. unbounded below.
# v0.6.31 used "3.0", which made ISE 2.x come out as "not affected". The
# authentication-bypass advisory (CVE-2026-76460) lists 3.1–3.5 plus a footnote
# on 3.0 only, so its bound stays at 3.0: nothing there speaks about 2.x.
HARDENING_MIN = "0.0"

# CVSS 3.1 vectors, NVD API 2.0, source psirt@cisco.com, read 2026-09-18.
V_10 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
V_99 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
V_91 = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"
V_65 = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N"
V_86 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H"

# Cisco's scheduled disclosure of 2026-09-16 (advance notice
# cisco-sa-notice-jfxK98ZP): 16 ISE advisories published together.
SCHEDULED_DROP = "cisco-drop-2026-09-16"

# The ISE software-lifecycle caveat (3.0 End of Software Maintenance, 3.1/3.2
# Critical-only, ISE-PIC end-of-sale) used to be pasted into every description
# here. It now lives in services.cve_engine.ise_lifecycle_note() and is shown
# once per report, only when it applies to the caller's train (EOSM-01).

HARDENING_DESC = (
    "Bundled hardening CVE from the Cisco ISE Hardening Release: September 2026. "
    "Under Cisco's risk-based disclosure model (twice-monthly, 1st and 3rd Wednesday), "
    "hardening releases do not assign one CVE per bug: a single CVE covers multiple "
    "fixes within one CWE category. Treat this record as a class of defects with a "
    "common fixed release, not as a single exploit path."
)


def rec(cve_id, title, sev, sir, cvss, cwe, desc, fixes, amin, amax,
        adv_slug, tags, workaround, exploited=False, kev=None, vector=None,
        bundled=False):
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
        "cvss_vector": vector,
        "cwe": cwe,
        "published": "2026-09-16",
        "last_modified": "2026-09-18",
        "references": [ADV + adv_slug, "https://nvd.nist.gov/vuln/detail/" + cve_id],
        "cisco_sir": sir,
        # `bundle` (CVE-010) means Cisco's SEMI-ANNUAL IOS / IOS XE bundled
        # publication (March and September). The ISE advisories of 2026-09-16
        # are a scheduled twice-monthly disclosure, not that bundle, so the
        # field stays empty. v0.6.31 set it to "2026-09" and the analyzer then
        # reported "In Cisco bundle: 8 CVE(s)" about something that is not one.
        # The shared publication date lives in the SCHEDULED_DROP tag instead.
        "bundle": None,
        "product_families": ["ise"],
        "affected_versions_raw": [
            "Cisco ISE 3.1", "Cisco ISE 3.2", "Cisco ISE 3.3",
            "Cisco ISE 3.4", "Cisco ISE 3.5",
        ],
        "first_fixed_version": {"fixes": fixes},
        "bundled": dict(HARDENING_BUNDLE) if bundled else None,
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
        "bypassing the web-based management interface. Cisco PSIRT is aware of ACTIVE EXPLOITATION.",
        FIXES_FULL, "3.0", "3.5", "cisco-sa-ISE-ABP-VNSW7Tn5",
        ["cisco-psirt", "ise", "identity", "auth-bypass", "kev", "actively-exploited",
         SCHEDULED_DROP],
        "No workarounds address this vulnerability. Mitigation only: use infrastructure ACLs "
        "(iACLs) to permit only required management and control plane traffic destined to the "
        "affected device.",
        exploited=True,
        kev={"date_added": "2026-09-16", "due_date": "2026-09-19",
             "catalog_version": "2026.09.16", "directive": "BOD 26-04"},
        vector=V_10,
    ),
    rec("CVE-2026-20192",
        "Cisco ISE Hardening Release - Access Control Vulnerabilities",
        "critical", "Critical", 10.0, "CWE-284",
        HARDENING_DESC + " Category: Access Control.",
        FIXES_HARDENING, HARDENING_MIN, "3.5", "cisco-sa-hardening-ise-XU5EwX5T",
        ["cisco-psirt", "ise", "identity", "hardening-release", "bundled-cve", SCHEDULED_DROP],
        "No workarounds. Upgrade to the hardened release for your train.",
        vector=V_10, bundled=True),
    rec("CVE-2026-20130",
        "Cisco ISE Hardening Release - Improper Neutralization Vulnerabilities",
        "critical", "Critical", 10.0, "CWE-74",
        HARDENING_DESC + " Category: Improper Neutralization.",
        FIXES_HARDENING, HARDENING_MIN, "3.5", "cisco-sa-hardening-ise-XU5EwX5T",
        ["cisco-psirt", "ise", "identity", "hardening-release", "bundled-cve", SCHEDULED_DROP],
        "No workarounds. Upgrade to the hardened release for your train.",
        vector=V_10, bundled=True),
    rec("CVE-2026-20234",
        "Cisco ISE Hardening Release - Insufficiently Protected Credential Vulnerabilities",
        "critical", "Critical", 9.9, "CWE-522",
        HARDENING_DESC + " Category: Insufficiently Protected Credentials.",
        FIXES_HARDENING, HARDENING_MIN, "3.5", "cisco-sa-hardening-ise-XU5EwX5T",
        ["cisco-psirt", "ise", "identity", "hardening-release", "bundled-cve", SCHEDULED_DROP],
        "No workarounds. Upgrade to the hardened release for your train.",
        vector=V_99, bundled=True),
    rec("CVE-2026-20237",
        "Cisco ISE Hardening Release - Input Validation Vulnerabilities",
        "critical", "Critical", 9.1, "CWE-20",
        HARDENING_DESC + " Category: Input Validation.",
        FIXES_HARDENING, HARDENING_MIN, "3.5", "cisco-sa-hardening-ise-XU5EwX5T",
        ["cisco-psirt", "ise", "identity", "hardening-release", "bundled-cve", SCHEDULED_DROP],
        "No workarounds. Upgrade to the hardened release for your train.",
        vector=V_91, bundled=True),
    rec("CVE-2026-20194",
        "Cisco ISE Hardening Release - Incorrect Resource Transfer Vulnerabilities",
        "critical", "Critical", 9.1, "CWE-669",
        HARDENING_DESC + " Category: Incorrect Resource Transfer.",
        FIXES_HARDENING, HARDENING_MIN, "3.5", "cisco-sa-hardening-ise-XU5EwX5T",
        ["cisco-psirt", "ise", "identity", "hardening-release", "bundled-cve", SCHEDULED_DROP],
        "No workarounds. Upgrade to the hardened release for your train.",
        vector=V_91, bundled=True),
    rec("CVE-2026-20287",
        "Cisco ISE Hardening Release - Improper Privilege Management Vulnerabilities",
        "medium", "Critical", 6.5, "CWE-269",
        HARDENING_DESC + " Category: Improper Privilege Management. "
        "NOTE: CVSS base score (6.5) and the advisory-level Cisco SIR (Critical) disagree here "
        "because the SIR applies to the hardening release as a whole.",
        FIXES_HARDENING, HARDENING_MIN, "3.5", "cisco-sa-hardening-ise-XU5EwX5T",
        ["cisco-psirt", "ise", "identity", "hardening-release", "bundled-cve", SCHEDULED_DROP,
         "sir-cvss-divergence"],
        "No workarounds. Upgrade to the hardened release for your train.",
        vector=V_65, bundled=True),
    rec("CVE-2026-20352",
        "Cisco Identity Services Engine RADIUS Denial of Service Vulnerability",
        "high", "High", 8.6, "CWE-119",
        "A vulnerability in the RADIUS feature of Cisco Identity Services Engine (ISE) could allow "
        "an unauthenticated, remote attacker to cause a denial of service condition. "
        "Releases 3.1 and earlier are NOT vulnerable, which is why the affected range starts at 3.2.",
        FIXES_RADIUS, "3.2", "3.5", "cisco-sa-ise-RADIUS-dos-wR3hYPMw",
        ["cisco-psirt", "ise", "identity", "radius", "dos", SCHEDULED_DROP],
        "See Cisco advisory for details.",
        vector=V_86),
]


# Fields this script does NOT own. The PSIRT sync maintains Cisco's Known
# Affected lists on every record, curated ones included (LISTS-01 / ISE-04).
# Rewriting a record must carry them over, and --check must not call a list
# refresh "drift".
SYNC_OWNED = ("known_affected", "known_affected_as_of")


def _merged_with_disk(record, path):
    """The seeded record plus whatever sync-owned fields are already on disk."""
    out = dict(record)
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                on_disk = json.load(f)
        except Exception:
            on_disk = {}
        for key in SYNC_OWNED:
            if key in on_disk:
                out[key] = on_disk[key]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the curated fields on disk differ (CI drift guard)")
    args = ap.parse_args()
    os.makedirs(OUT_DIR, exist_ok=True)
    drift = []
    for r in RECORDS:
        path = os.path.join(OUT_DIR, r["cve_id"].lower() + ".json")
        payload = json.dumps(_merged_with_disk(r, path), indent=2, ensure_ascii=False) + "\n"
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
        print("cve_data/ise/: %d curated records match the seed" % len(RECORDS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
