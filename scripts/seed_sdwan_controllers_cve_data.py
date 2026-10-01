#!/usr/bin/env python3
"""seed_sdwan_controllers_cve_data.py - SDWAN-02.1 seed for cve_data/sdwan_controllers/ (2026-10-01).

First batch of the Catalyst SD-WAN control-component dataset (Manager / Controller /
Validator, formerly vManage / vSmart / vBond). Admission rule for this batch: the CVE
is in CISA KEV AND Cisco rates the advisory Critical. Every field below was read from a
primary source on 2026-10-01; the provenance is recorded here so the dataset can be
regenerated and diffed rather than trusted.

Sources (all fetched 2026-10-01):
  - CISA KEV JSON, catalogVersion 2026.09.30 (dateReleased 2026-09-30T16:59:23Z):
    dateAdded, dueDate, CWE, directive.
  - Cisco CSAF 2.0 per advisory (Fixed Software table, CVSS 3.1 vector, revision):
      cisco-sa-sdwan-webauth-xr8beuuU  rev 1.0.0, 2026-09-30  (CVE-2026-76504)
      cisco-sa-sdwan-rpa-EHchtZk       rev 2.0.0, 2026-06-16  (CVE-2026-20127)
      cisco-sa-sdwan-rpa2-v69WY2SW     rev 2.0.0, 2026-06-16  (CVE-2026-20182)
  - Cisco PSIRT openVuln API v2 /advisory/<id>: Security Impact Rating (all three
    "Critical"), CWE.

Why the Fixed Software table and NOT the CSAF known_affected list decides:
the CSAF product lists for these advisories contradict their own tables. Releases
the list names as affected although the table names them as fixed (computed from
the CSAF known_affected product ids, all components together, 2026-10-01):
  CVE-2026-20182: 20.9.9.2, 20.12.5.4, 20.12.7.2, 20.15.4.5, 20.15.5.2, 20.15.5.3,
                  20.18.2.2, 20.18.3; plus the "_LI_Images" variants of 20.9.9.1,
                  20.12.5.4, 20.12.7.1, 20.15.4.4, 20.15.5.2, 20.18.2.2, 20.18.3,
                  and build 20.12.401
  CVE-2026-20127: 20.9.9; plus build 20.12.401
  CVE-2026-76504: only builds and variants: 20.9.10.1.01, 20.12.8.2.01,
                  20.15.6.1.01, 20.18.4.1.01, 26.1.2.1.01, 20.12.401, and the
                  "_LI_Images" variants of 20.15.6.1 and 26.1.2.1
The lists also omit ordinary releases (CVE-2026-76504: 20.12.6, 20.12.7.1 appear
only as "_LI_Images" variants). Every advisory states that PSIRT validates "the
affected and fixed release information that is documented in this advisory" (the
table), so the table is the matcher's input and the lists are not stored whole.
They are used for two things:
  - a train the table does not name (e.g. 20.10 for CVE-2026-76504) is recorded
    as "migrate" only when the list shows releases of that train as affected;
  - csaf_listed_past_fix: the plain releases above (no "_LI_Images", no ".01" /
    "401" builds, which are backlog item N1). A query for one of them is not
    reported as a match but in cisco_source_conflicts with "verify in Cisco
    Software Checker" (SDWAN-02.1 fix S1), never silently clean.

Key format in first_fixed_version.fixes (matcher: services.cve_engine.match_sdwan_record):
  sd-wan-controllers-<maj.min>        first fixed release for the whole train
                                      (may sit on a later train = migrate there)
  sd-wan-controllers-<maj.min.maint>  earlier maintenance line on the same train
                                      that Cisco fixed separately (table cells with
                                      several releases, e.g. "20.12.5.4 / 20.12.6.2 /
                                      20.12.7.1")
  sd-wan-controllers-<<maj.min>       "Earlier than X - Migrate to a fixed release"
  value "migrate"                     no fixed release on this train

Run:  python3 scripts/seed_sdwan_controllers_cve_data.py [--check]
      --check exits non-zero if on-disk files differ from what we would write.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(HERE)
OUT_DIR = os.path.join(PROJECT_DIR, "cve_data", "sdwan_controllers")

FAMILY = "sd-wan-controllers"
ADV = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
CSAF = "https://sec.cloudapps.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/%s/csaf/%s.json"
KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve="
KEV_CATALOG = "2026.09.30"

MANAGER = "Catalyst SD-WAN Manager"
CONTROLLER = "Catalyst SD-WAN Controller"
VALIDATOR = "Catalyst SD-WAN Validator"


def fixes(table):
    return {FAMILY + "-" + k: v for k, v in table.items()}


# cisco-sa-sdwan-webauth-xr8beuuU, Fixed Software (rev 1.0.0):
#   Earlier than 20.9 -> Migrate; 20.9 -> 20.9.10.1; 20.12 -> 20.12.8.2;
#   20.15 -> 20.15.6.1; 20.18 -> 20.18.4.1; 26.1 -> 26.1.2.1; 26.2 -> 26.2.1
# Not in the table, but listed as affected in the CSAF product list:
#   20.10 (20.10.1...), 20.11 (20.11.1.1...), 20.13 (20.13.1), 20.14 (20.14.1),
#   20.16 (20.16.1) -> no fixed release on those trains.
# Cloud: fixed in Cisco SD-WAN Cloud (Cisco Managed) 20.15.605, no user action.
FIX_76504 = fixes({
    "<20.9": "migrate",
    "20.9": "20.9.10.1",
    "20.10": "migrate",
    "20.11": "migrate",
    "20.12": "20.12.8.2",
    "20.13": "migrate",
    "20.14": "migrate",
    "20.15": "20.15.6.1",
    "20.16": "migrate",
    "20.18": "20.18.4.1",
    "26.1": "26.1.2.1",
    "26.2": "26.2.1",
})

# cisco-sa-sdwan-rpa-EHchtZk, Fixed Software (rev 2.0.0):
#   Earlier than 20.9 -> Migrate; 20.9 -> 20.9.8.2; 20.11 -> 20.12.6.1;
#   20.12 -> 20.12.5.3 / 20.12.6.1; 20.13 -> 20.15.4.2; 20.14 -> 20.15.4.2;
#   20.15 -> 20.15.4.2; 20.16 -> 20.18.2.1; 20.18 -> 20.18.2.1
# 20.10 is not in the table but the CSAF list shows 20.10.1, 20.10.1.1, 20.10.1.2
# as affected -> migrate. No 26.x row and no 26.x release in the list.
FIX_20127 = fixes({
    "<20.9": "migrate",
    "20.9": "20.9.8.2",
    "20.10": "migrate",
    "20.11": "20.12.6.1",
    "20.12.5": "20.12.5.3",
    "20.12": "20.12.6.1",
    "20.13": "20.15.4.2",
    "20.14": "20.15.4.2",
    "20.15": "20.15.4.2",
    "20.16": "20.18.2.1",
    "20.18": "20.18.2.1",
})

# cisco-sa-sdwan-rpa2-v69WY2SW, Fixed Software (rev 2.0.0):
#   Earlier than 20.9 -> Migrate; 20.9 -> 20.9.9.1; 20.10 -> 20.12.7.1;
#   20.11 -> 20.12.7.1; 20.12 -> 20.12.5.4 / 20.12.6.2 / 20.12.7.1;
#   20.13 -> 20.15.5.2; 20.14 -> 20.15.5.2; 20.15 -> 20.15.4.4 / 20.15.5.2;
#   20.16 -> 20.18.2.2; 20.18 -> 20.18.2.2; 26.1 -> 26.1.1.1
# Cloud: fixed in Cisco SD-WAN Cloud (Cisco Managed) 20.15.506, no user action.
FIX_20182 = fixes({
    "<20.9": "migrate",
    "20.9": "20.9.9.1",
    "20.10": "20.12.7.1",
    "20.11": "20.12.7.1",
    "20.12.5": "20.12.5.4",
    "20.12.6": "20.12.6.2",
    "20.12": "20.12.7.1",
    "20.13": "20.15.5.2",
    "20.14": "20.15.5.2",
    "20.15.4": "20.15.4.4",
    "20.15": "20.15.5.2",
    "20.16": "20.18.2.2",
    "20.18": "20.18.2.2",
    "26.1": "26.1.1.1",
})

HARDENING_MITIGATION = (
    "No workarounds address this vulnerability (Cisco advisory). Mitigation only, for "
    "On-Prem deployments: restrict access to the control components from untrusted "
    "networks such as the internet, place them behind a filtering device and permit only "
    "known, trusted hosts (Cisco Catalyst SD-WAN Hardening Guide). For Cisco Catalyst "
    "SD-WAN Cloud Hosted environments Cisco states this mitigation is already deployed. "
    "Upgrade to the first fixed release for your train; see first_fixed_version."
)

# S1: releases the CSAF list names as affected although the table names them
# as fixed (plain releases only; see the module docstring).
LISTED_PAST_FIX_20182 = ["20.9.9.2", "20.12.5.4", "20.12.7.2", "20.15.4.5", "20.15.5.2",
                         "20.15.5.3", "20.18.2.2", "20.18.3"]
LISTED_PAST_FIX_20127 = ["20.9.9"]


def rec(cve_id, title, cvss, vector, cwe, desc, fix_table, platforms, adv_slug,
        published, last_modified, tags, kev, workaround, bug_id, listed_past_fix=()):
    return {
        "cve_id": cve_id,
        "title": title,
        "severity": "critical",
        "platforms": platforms,
        # The range is informational; the per-train table in first_fixed_version
        # decides (match_sdwan_record). min = oldest release in the CSAF product list (17.2.4, all three), max =
        # newest train the table names.
        "affected": {"min": "17.2.4", "max": max_train(fix_table)},
        "fixed_in": None,
        "tags": tags,
        "description": desc,
        "workaround": workaround,
        "advisory_url": ADV + adv_slug,
        "confidence": "cisco-psirt",
        "source": "cisco-csaf",
        "cvss_score": cvss,
        "cvss_vector": vector,
        "cwe": cwe,
        "published": published,
        "last_modified": last_modified,
        "references": [
            ADV + adv_slug,
            CSAF % (adv_slug, adv_slug),
            "https://nvd.nist.gov/vuln/detail/" + cve_id,
            KEV_URL + cve_id,
        ],
        "cisco_sir": "Critical",
        "bundle": None,
        "product_families": [FAMILY],
        "affected_versions_raw": ["Cisco Bug ID " + bug_id],
        "first_fixed_version": {"fixes": fix_table},
        "kev": kev,
        "bundled": None,
        "csaf_listed_past_fix": list(listed_past_fix),
    }


def max_train(fix_table):
    trains = []
    for key in fix_table:
        t = key[len(FAMILY) + 1:]
        if t.startswith("<"):
            continue
        parts = t.split(".")
        trains.append((int(parts[0]), int(parts[1])))
    hi = max(trains)
    return "%d.%d" % hi


RECORDS = [
    rec(
        "CVE-2026-76504",
        "Cisco Catalyst SD-WAN Manager API Authentication Bypass Vulnerability",
        9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-177",
        "A vulnerability in the API session-based authentication management of Cisco "
        "Catalyst SD-WAN Manager could allow an unauthenticated, remote attacker to access an "
        "affected system with privileges of the admin user. This vulnerability is due to "
        "improper handling of URI encoding in an HTTP request, which allows the request to "
        "bypass an authentication rule that is intended to restrict access to a specific API "
        "endpoint. Affects Cisco Catalyst SD-WAN Manager regardless of system configuration. "
        "In September 2026 Cisco PSIRT became aware of ACTIVE EXPLOITATION. Cisco SD-WAN Cloud "
        "(Cisco Managed) is fixed in release 20.15.605 with no user action required.",
        FIX_76504, [MANAGER, "SD-WAN Manager", "vManage"], "cisco-sa-sdwan-webauth-xr8beuuU",
        "2026-09-30", "2026-09-30",
        ["cisco-psirt", "sd-wan", "sd-wan-manager", "auth-bypass", "kev", "actively-exploited"],
        {"date_added": "2026-09-30", "due_date": "2026-10-03",
         "catalog_version": KEV_CATALOG, "directive": "BOD 26-04"},
        HARDENING_MITIGATION, "CSCww79570",
    ),
    rec(
        "CVE-2026-20127",
        "Cisco Catalyst SD-WAN Controller Authentication Bypass Vulnerability",
        10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-287",
        "A vulnerability in the peering authentication in Cisco Catalyst SD-WAN Controller "
        "(formerly vSmart), Cisco Catalyst SD-WAN Manager (formerly vManage) and Cisco Catalyst "
        "SD-WAN Validator (formerly vBond) could allow an unauthenticated, remote attacker to "
        "bypass authentication and obtain administrative privileges on an affected system. "
        "A successful exploit could allow the attacker to log in as an internal, "
        "high-privileged, non-root user account and access NETCONF, which would allow the "
        "attacker to manipulate network configuration for the SD-WAN fabric. Affects all three "
        "control components regardless of device configuration. Cisco PSIRT is aware of "
        "limited exploitation.",
        FIX_20127, [MANAGER, CONTROLLER, VALIDATOR, "SD-WAN Manager", "vManage", "vSmart", "vBond"],
        "cisco-sa-sdwan-rpa-EHchtZk", "2026-02-25", "2026-06-16",
        ["cisco-psirt", "sd-wan", "sd-wan-manager", "sd-wan-controller", "sd-wan-validator",
         "auth-bypass", "kev", "actively-exploited"],
        {"date_added": "2026-02-25", "due_date": "2026-02-27",
         "catalog_version": KEV_CATALOG, "directive": "ED 26-03"},
        "No workarounds address this vulnerability (Cisco advisory). Mitigation only, for "
        "customers who host their own deployment: add ACLs, security group rules and/or "
        "firewall rules that restrict the traffic to port 22 and port 830 to allow only known "
        "controller IPs and other known IPs, and allow IP traffic to the Control Components only "
        "from hosts or devices that require access. Upgrade to the first fixed release for your "
        "train; see first_fixed_version.",
        "CSCws52722", LISTED_PAST_FIX_20127,
    ),
    rec(
        "CVE-2026-20182",
        "Cisco Catalyst SD-WAN Controller Authentication Bypass Vulnerability",
        10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-287",
        "A vulnerability in the peering authentication (control connection handshaking) in "
        "Cisco Catalyst SD-WAN Controller (formerly vSmart), Cisco Catalyst SD-WAN Manager "
        "(formerly vManage) and Cisco Catalyst SD-WAN Validator (formerly vBond) could allow an "
        "unauthenticated, remote attacker to bypass authentication and obtain administrative "
        "privileges on an affected system. Discovered and fixed after CVE-2026-20127. Inference "
        "from comparing the two advisories' Fixed Software tables (not a Cisco statement): a "
        "release that fixes CVE-2026-20127 is not necessarily fixed for this one. Affects all deployment "
        "types. Cisco PSIRT is aware of limited exploitation. Collect 'request admin-tech' from "
        "each control component before upgrading to preserve indicators of compromise. Cisco "
        "SD-WAN Cloud (Cisco Managed) is fixed in release 20.15.506 with no user action required.",
        FIX_20182, [MANAGER, CONTROLLER, VALIDATOR, "SD-WAN Manager", "vManage", "vSmart", "vBond"],
        "cisco-sa-sdwan-rpa2-v69WY2SW", "2026-05-14", "2026-06-16",
        ["cisco-psirt", "sd-wan", "sd-wan-manager", "sd-wan-controller", "sd-wan-validator",
         "auth-bypass", "kev", "actively-exploited"],
        {"date_added": "2026-05-14", "due_date": "2026-05-17",
         "catalog_version": KEV_CATALOG, "directive": "ED 26-03"},
        "No workarounds address this vulnerability (Cisco advisory). Upgrade to the first fixed "
        "release for your train; see first_fixed_version.",
        "CSCwt50498", LISTED_PAST_FIX_20182,
    ),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the records on disk differ (CI drift guard)")
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
        print("cve_data/sdwan_controllers/: %d records match the seed" % len(RECORDS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
