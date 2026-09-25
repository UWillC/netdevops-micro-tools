#!/usr/bin/env python3
"""Backfill cve_mitigations/*.json with Cisco's verbatim Workarounds section (C1, 2026-09-25).

Usage: python3 scripts/fetch_cisco_workarounds.py [--only-missing] [--dry-run]
One CSAF request per advisory (cached across CVEs that share an advisory).
"""
import argparse
import glob
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from services import cisco_workaround as cw  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only-missing", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    cache, stats = {}, {"written": 0, "skipped": 0, "failed": 0}
    status_count = {}
    for path in sorted(glob.glob(os.path.join(ROOT, "cve_mitigations", "CVE-*.json"))):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if a.only_missing and data.get("cisco_workaround"):
            stats["skipped"] += 1
            continue
        sa = cw.advisory_id(data.get("cisco_psirt"))
        if sa not in cache:
            cache[sa] = cw.fetch(sa)
            time.sleep(0.3)
        wa = cache[sa]
        if not wa:
            stats["failed"] += 1
            print(f"  no Cisco text: {os.path.basename(path)} ({sa})")
            continue
        status_count[wa["status"]] = status_count.get(wa["status"], 0) + 1
        data["cisco_workaround"] = wa
        if not a.dry_run:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.write("\n")
        stats["written"] += 1
    print(f"{'[DRY] ' if a.dry_run else ''}{stats} statuses={status_count} advisories={len(cache)}")


if __name__ == "__main__":
    main()
