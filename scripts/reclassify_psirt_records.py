#!/usr/bin/env python3
"""Re-run the feature classifier over imported IOS XE records and their mitigations.

Why this exists: until v0.6.54 the classifier searched the whole advisory summary
for substrings, and every summary ends with an https:// link, so "http" filed
unrelated CVEs under web UI. 87 auto-generated mitigation files told the reader
to run "no ip http server" for bugs in Ethernet frame handling, IKEv1 or ARP.

Touches ONLY machine-made content:
  * cve_data/ios_xe/*.json with source == "cisco-psirt-import": the feature tag
  * cve_mitigations/*.json that still carry the importer's boilerplate upgrade_path:
    workaround_steps, acl_mitigation, detection.commands, tags
Hand-written records and mitigations are left alone.

Usage: python3 scripts/reclassify_psirt_records.py [--dry-run]
"""
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from services.cisco_sync import _MIT_TEMPLATES, _VULN_KEYWORDS, _classify_vuln  # noqa: E402

FEATURE_TAGS = {vtype for _, vtype in _VULN_KEYWORDS}
AUTO_MARKER = "Check Cisco advisory for platform-specific fixed versions."


def main(dry_run: bool) -> int:
    retagged = rebuilt = 0
    vtypes = {}
    for path in sorted(glob.glob(os.path.join(ROOT, "cve_data", "ios_xe", "*.json"))):
        with open(path, encoding="utf-8") as f:
            rec = json.load(f)
        if not isinstance(rec, dict) or rec.get("source") != "cisco-psirt-import":
            continue
        vtype = _classify_vuln(rec.get("title", ""), rec.get("description", ""))
        vtypes[rec["cve_id"].upper()] = vtype
        tags = [t for t in rec.get("tags", []) if t not in FEATURE_TAGS]
        if vtype != "generic":
            tags.append(vtype)
        if tags != rec.get("tags", []):
            retagged += 1
            if not dry_run:
                rec["tags"] = tags
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(rec, f, indent=2, ensure_ascii=False)

    for path in sorted(glob.glob(os.path.join(ROOT, "cve_mitigations", "*.json"))):
        with open(path, encoding="utf-8") as f:
            mit = json.load(f)
        if not isinstance(mit, dict) or mit.get("upgrade_path") != AUTO_MARKER:
            continue
        vtype = vtypes.get(str(mit.get("cve_id", "")).upper())
        if vtype is None:
            continue
        tmpl = _MIT_TEMPLATES.get(vtype, _MIT_TEMPLATES["generic"])
        new = dict(mit)
        new["workaround_steps"] = tmpl["steps"]
        new["acl_mitigation"] = tmpl.get("acl")
        new["detection"] = dict(mit.get("detection") or {}, commands=tmpl.get("detect", ["show version"]))
        new["tags"] = ["cisco-psirt"] + ([vtype] if vtype != "generic" else [])
        if new != mit:
            rebuilt += 1
            if not dry_run:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(new, f, indent=2, ensure_ascii=False)

    print(f"records retagged: {retagged} | mitigations rebuilt: {rebuilt}" + (" (dry run)" if dry_run else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main("--dry-run" in sys.argv))
