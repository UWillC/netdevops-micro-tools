#!/usr/bin/env python3
"""MITIG-REVIEW auto (2026-09-27): patch-only steps where Cisco says there is no workaround.

Why: the import template never read the advisory's Workarounds section and filled every
record with the same "version / generic CoPP or 'review advisory for workarounds' /
tftp+reload" steps. MITIG-REVIEW 1/7 found that where Cisco writes "There are no
workarounds that address this vulnerability", the honest record is patch-only.

This script handles only the undisputed case, for files without `steps_reviewed`:
  NO_WORKAROUND  cisco_workaround.text is exactly Cisco's "no workarounds" sentence
                 (nothing else, status "none")    -> steps rewritten to patch-only
  HAS_WORKAROUND anything else (incl. "no workarounds ... However, a mitigation")
                                                   -> untouched, listed for manual review
  UNKNOWN        missing / empty Cisco text, or the advisory's CSAF does not list this
                 CVE (Cisco's text then belongs to another CVE)  -> untouched, listed

The CVE check matters: on 2026-09-27 three hand-written records (CVE-2020-3452,
CVE-2024-20291, CVE-2024-20356) pointed at an advisory for a different CVE, so their
"no workarounds" text was not Cisco's statement about that CVE.

Product wording stays neutral ("the affected Cisco software"); the summary is truncated,
so naming a family from it could drop products Cisco lists. Exposure checks are NOT
generated: the file does not carry Cisco's "determine whether ... affected" command, so the
patch-only record is upgrade + advisory reference.

Usage: python3 scripts/mitig_patch_only.py [--dry-run]
"""
import argparse
import glob
import html
import json
import os
import re
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIT_DIR = os.path.join(ROOT, "cve_mitigations")
REVIEW_DATE = "2026-09-27"
REVIEW_METHOD = "auto-patch-only"

NO_WORKAROUND, HAS_WORKAROUND, UNKNOWN = "NO_WORKAROUND", "HAS_WORKAROUND", "UNKNOWN"

# Cisco's exact sentences (the only two variants found in the 150 records, 2026-09-27).
_NO_WA_RE = re.compile(
    r"^there are no workarounds that address (?:this vulnerability|these vulnerabilities)\.?$")
_SA_RE = re.compile(r"(cisco-sa-[A-Za-z0-9-]+)")

NOTE = ("Not a Cisco workaround (Cisco: no workarounds). "
        "Only an upgrade to a fixed release closes this vulnerability.")


def _norm(text):
    return " ".join(html.unescape(text or "").split()).lower()


CSAF_URL = ("https://sec.cloudapps.cisco.com/security/center/contentjson/"
            "CiscoSecurityAdvisory/{sa}/csaf/{sa}.json")


def csaf_cves(sa, timeout=30):
    """CVE ids the advisory's CSAF lists; None on any failure (caller treats as UNKNOWN)."""
    try:
        with urllib.request.urlopen(CSAF_URL.format(sa=sa), timeout=timeout) as r:
            doc = json.load(r)
        return {v.get("cve") for v in doc.get("vulnerabilities") or [] if v.get("cve")}
    except Exception:
        return None


def classify(cisco_workaround):
    """NO_WORKAROUND only for Cisco's bare 'no workarounds' sentence; else HAS/UNKNOWN."""
    if not cisco_workaround or not (cisco_workaround.get("text") or "").strip():
        return UNKNOWN
    t = _norm(cisco_workaround["text"])
    if _NO_WA_RE.match(t) and cisco_workaround.get("status") == "none":
        return NO_WORKAROUND
    return HAS_WORKAROUND


def family(risk_summary):
    """(label, has_show_version) from the product named in the summary; neutral if unsure."""
    t = " ".join(html.unescape(risk_summary or "").split())
    ios = re.search(r"\bIOS(?! X[ER])\b", t)
    xe = "IOS XE" in t
    xr = "IOS XR" in t
    asa = "ASA" in t or "Adaptive Security Appliance" in t
    ftd = "FTD" in t or "Firepower Threat Defense" in t
    nx = "NX-OS" in t
    exotic = re.search(r"Smart Software|Smart Licensing|Unified Communications|IMC\b|"
                       r"Integrated Management Controller|Nexus Dashboard|Access Point|"
                       r"Firepower Management Center|\bFMC\b|Identity Services", t)
    parts = []
    if asa:
        parts.append("ASA")
    if ftd:
        parts.append("FTD")
    if ios:
        parts.append("IOS")
    if xe:
        parts.append("IOS XE")
    if xr:
        parts.append("IOS XR")
    if nx:
        parts.append("NX-OS")
    if exotic or not parts:
        return None, False
    return "Cisco " + " / ".join(parts), True


def patch_only(data):
    """Return a new record with patch-only steps (Cisco text, ids and metadata untouched)."""
    d = dict(data)
    sa = _SA_RE.search(d["cisco_workaround"]["source"]).group(1)
    url = d.get("cisco_psirt") or (
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/" + sa)
    # The product list comes from the advisory, not from our (truncated) summary: the family
    # only decides whether 'show version' is a valid CLI command, never the wording.
    _, show_ver = family(d.get("risk_summary"))
    product = "the affected Cisco software"
    check_cmds = (["show version"] if show_ver else
                  ["! Read the running release on the product (see its admin guide)"])
    d["workaround_steps"] = [
        {
            "order": 1,
            "description": "Check the running release against the Cisco Software Checker",
            "commands": list(check_cmds),
            "platform_notes": (NOTE + " First fixed release differs per train: use the Cisco "
                               "Software Checker or the advisory's Fixed Software section. "
                               "Exposure conditions (feature/config) are in the advisory's "
                               "Vulnerable Products section. Advisory: " + sa + "."),
        },
        {
            "order": 2,
            "description": "Upgrade " + product + " to a first fixed release (Cisco's remediation)",
            "commands": ["! Upgrade per your platform's upgrade guide"],
            "platform_notes": NOTE,
        },
    ]
    d["acl_mitigation"] = None
    d["recommended_fix"] = ("Upgrade " + product + " to a first fixed release for your train "
                            "(Cisco Software Checker, " + sa + "). Cisco: no workarounds.")
    d["upgrade_path"] = "Fixed releases differ per train; check " + url + "."
    d["detection"] = {
        "description": "Check the running release",
        "commands": list(check_cmds),
        "vulnerable_if": ("Running a release the Cisco Software Checker lists as affected for "
                          + sa + ", with the feature/configuration named in the advisory's "
                          "Vulnerable Products section."),
    }
    d["verification"] = {
        "description": "Confirm the device runs a fixed release",
        "commands": list(check_cmds),
        "expected_output": ("A release listed as fixed for your train in " + sa +
                            " (Cisco Software Checker)."),
    }
    d["steps_reviewed"] = REVIEW_DATE
    d["review_method"] = REVIEW_METHOD
    return d


def run(mit_dir=MIT_DIR, dry_run=False, cve_lookup=csaf_cves):
    """Classify every unreviewed file; rewrite NO_WORKAROUND ones unless dry_run.

    cve_lookup(sa) -> set of CVE ids in the advisory (None = could not check). A
    NO_WORKAROUND file is only rewritten when its advisory lists its CVE.
    """
    res = {NO_WORKAROUND: [], HAS_WORKAROUND: [], UNKNOWN: [], "changed": [], "reviewed": []}
    cache = {}
    for path in sorted(glob.glob(os.path.join(mit_dir, "CVE-*.json"))):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        cve = data.get("cve_id") or os.path.basename(path)[:-5]
        if data.get("steps_reviewed"):
            res["reviewed"].append(cve)
            continue
        wa = data.get("cisco_workaround") or {}
        cls, why = classify(wa), ""
        if cls == NO_WORKAROUND:
            sa = _SA_RE.search(wa.get("source") or "")
            sa = sa.group(1) if sa else None
            if sa and sa not in cache:
                cache[sa] = cve_lookup(sa)
            listed = cache.get(sa)
            if listed is None:
                cls, why = UNKNOWN, "advisory CVE list not checked"
            elif cve not in listed:
                cls, why = UNKNOWN, f"{sa} does not list {cve} (lists {', '.join(sorted(listed))})"
        res[cls].append((cve, wa.get("status"), why))
        if cls != NO_WORKAROUND or dry_run:
            continue
        new = patch_only(data)
        if new != data:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(new, f, indent=2, ensure_ascii=False)
                f.write("\n")
            res["changed"].append(cve)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="classify and list only")
    a = ap.parse_args()
    r = run(dry_run=a.dry_run)
    print(f"already reviewed: {len(r['reviewed'])}")
    for k in (NO_WORKAROUND, HAS_WORKAROUND, UNKNOWN):
        print(f"{k}: {len(r[k])}")
        for cve, status, why in r[k]:
            print(f"  {cve}  (cisco status: {status}){'  ' + why if why else ''}")
    print(f"changed: {len(r['changed'])}{' (dry run)' if a.dry_run else ''}")


if __name__ == "__main__":
    main()
