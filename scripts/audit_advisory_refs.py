#!/usr/bin/env python3
"""audit_advisory_refs.py — does every record point at an advisory Cisco actually has?

Found 2026-09-18: seven hand-curated records carried advisory ids that never
existed ("cisco-sa-radius-blast", "cisco-sa-fmc-auth-bypass", ...). One of them,
CVE-2025-20188, consequently never received Cisco's Known Affected list and was
reported as a CVSS 10.0 match for IOS XE 17.12.4 — a release Cisco does not list.
An eighth, CVE-2026-28775, is a real CVE for a satellite receiver from another
vendor, filed here as a Cisco IOS XE vulnerability.

For each record this asks PSIRT "which advisories carry this CVE?" and fails if
the record's advisory id is not among them, or if PSIRT does not know the CVE.
Records whose advisory_url is not a Cisco advisory at all are reported too.

Usage:
    python3 scripts/audit_advisory_refs.py                 # records without a Known Affected list
    python3 scripts/audit_advisory_refs.py --all           # every record (slow: 1 request / 2 s)
Exit codes: 0 clean, 1 findings, 2 could not look (no credentials).
"""
import argparse
import glob
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(HERE)
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from services.cve_sources import CiscoAdvisoryProvider  # noqa: E402

_ADV_RE = re.compile(r"CiscoSecurityAdvisory/([^/?#\s]+)")
DATASETS = ("cve_data/ios_xe", "cve_data/ise", "cve_data/nx_os")


def classify(record, psirt_advisory_ids):
    """Returns None when fine, else a one-line finding. Pure: testable offline."""
    m = _ADV_RE.search(record.get("advisory_url") or "")
    ours = m.group(1) if m else None
    if psirt_advisory_ids is None:
        return "PSIRT does not know this CVE (wrong vendor, or not a Cisco CVE at all?)"
    if ours is None:
        return f"advisory_url is not a Cisco advisory; PSIRT has: {', '.join(psirt_advisory_ids)}"
    if ours not in psirt_advisory_ids:
        return f"advisory id '{ours}' does not exist for this CVE; PSIRT has: {', '.join(psirt_advisory_ids)}"
    return None


def classify_facts(record, advisory):
    """Hand-written records only: do the facts we state about Cisco match Cisco?

    Added after CVE-2025-20352 showed "Cisco SIR: CRITICAL" (Cisco: High) and a
    CVSS 8.8 that existed in no source. Returns a list of findings.
    """
    out = []
    sir = (advisory.get("sir") or "").strip()
    if sir in ("Critical", "High", "Medium", "Low") and record.get("cisco_sir") != sir:
        out.append(f"cisco_sir is {record.get('cisco_sir')!r}, Cisco says {sir!r}")
    cves = [c for c in advisory.get("cves") or [] if isinstance(c, str) and c.startswith("CVE-")]
    cwes = [c for c in advisory.get("cwe") or [] if isinstance(c, str) and c.startswith("CWE-")]
    if len(cves) == 1 and len(cwes) == 1 and record.get("cwe") and record["cwe"] != cwes[0]:
        out.append(f"cwe is {record['cwe']}, Cisco says {cwes[0]}")
    return out


def main(argv=None, lookup=None, sleep=2.1):
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args(argv)

    fetch_advisory = None
    if lookup is None:
        provider = CiscoAdvisoryProvider(platform="iosxe")
        creds = provider._load_credentials()
        if not creds:
            print("No PSIRT credentials — could not look.")
            return 2
        base = creds.get("api_base", "https://apix.cisco.com/security/advisories/v2")

        def lookup(cve_id):
            data = provider._api_get(f"{base}/cve/{cve_id}")
            time.sleep(sleep)
            advs = (data or {}).get("advisories") or []
            return [a["advisoryId"] for a in advs] or None

        def fetch_advisory(advisory_id):
            data = provider._api_get(f"{base}/advisory/{advisory_id}")
            time.sleep(sleep)
            return ((data or {}).get("advisories") or [None])[0]

    findings = checked = 0
    for dataset in DATASETS:
        for path in sorted(glob.glob(os.path.join(PROJECT_DIR, dataset, "cve-*.json"))):
            with open(path, encoding="utf-8") as f:
                rec = json.load(f)
            if (not args.all and rec.get("source") != "local-json"
                    and any((rec.get("known_affected") or {}).values())):
                continue  # a list could only attach through a matching advisory id
            checked += 1
            problem = classify(rec, lookup(rec["cve_id"]))
            if problem:
                findings += 1
                print(f"FINDING {rec['cve_id']} ({dataset}): {problem}")
            elif rec.get("source") == "local-json" and fetch_advisory is not None:
                m = _ADV_RE.search(rec.get("advisory_url") or "")
                adv = fetch_advisory(m.group(1)) if m else None
                for fact in classify_facts(rec, adv or {}):
                    findings += 1
                    print(f"FINDING {rec['cve_id']} ({dataset}): {fact}")
    print(f"checked {checked} record(s), {findings} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
