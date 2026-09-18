#!/usr/bin/env python3
"""refresh_known_affected.py — keep the REPO copy of Known Affected lists current.

Production refreshes these lists on every PSIRT sync (LISTS-01), but Render's
disk is rebuilt from this repository on each deploy, so whatever is committed
here is what production starts from — and what anyone running the tool locally
or offline gets, permanently. Until now the repo copy only moved when somebody
remembered to run a migration by hand.

What it does, per platform in AUTO_SYNC_PLATFORMS:
  1. asks the Cisco PSIRT API for today's advisories (never the 24 h cache);
  2. for every CVE that ALREADY has a record, calls the same
     services.cisco_sync.refresh_known_affected() production uses.

What it deliberately does not do: create records, touch curated fields, or
write mitigations. Importing new CVEs into the repo is a review decision
(the seed scripts), not something a cron job should do unattended.

Usage:
    python3 scripts/refresh_known_affected.py            # apply
    python3 scripts/refresh_known_affected.py --dry-run  # report only

Exit codes: 0 = ran (changed or not), 2 = no credentials / API returned nothing
for every platform (so a scheduler can tell "nothing to do" from "could not look").
"""
import argparse
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(HERE)
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from services.cisco_sync import CVE_DATA_DIR, ISE_DATA_DIR, refresh_known_affected  # noqa: E402
from services.cve_sources import AUTO_SYNC_PLATFORMS, CiscoAdvisoryProvider  # noqa: E402

DATA_DIR_FOR = {"iosxe": CVE_DATA_DIR, "ios": CVE_DATA_DIR, "ise": ISE_DATA_DIR}


def refresh_platform(platform, advisories, data_dir, dry_run=False):
    """Returns (records_seen, records_changed). Never creates a file."""
    seen = changed = 0
    for adv in advisories:
        for cve_id in adv.get("cves") or []:
            if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
                continue
            path = os.path.join(data_dir, cve_id.lower() + ".json")
            if not os.path.isfile(path):
                continue
            seen += 1
            if dry_run:
                # run against a throwaway copy so the report is exact, not guessed
                with tempfile.TemporaryDirectory() as tmp:
                    probe = os.path.join(tmp, os.path.basename(path))
                    shutil.copyfile(path, probe)
                    changed += refresh_known_affected(probe, adv)
            else:
                changed += refresh_known_affected(path, adv)
    return seen, changed


def main(argv=None, fetch=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    if fetch is None:
        def fetch(platform):
            return CiscoAdvisoryProvider(platform=platform).fetch_advisories(use_cache=False)

    got_any = False
    total_changed = 0
    for platform in AUTO_SYNC_PLATFORMS:
        advisories = fetch(platform)
        if not advisories:
            print(f"[{platform}] no advisories (no credentials, or API returned nothing)")
            continue
        got_any = True
        seen, changed = refresh_platform(platform, advisories, DATA_DIR_FOR[platform], args.dry_run)
        total_changed += changed
        verb = "would change" if args.dry_run else "changed"
        print(f"[{platform}] {len(advisories)} advisories, {seen} existing records checked, {changed} {verb}")

    if not got_any:
        print("Nothing fetched for any platform — could not look. Not a clean bill of health.")
        return 2
    print(f"TOTAL {'would change' if args.dry_run else 'changed'}: {total_changed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
