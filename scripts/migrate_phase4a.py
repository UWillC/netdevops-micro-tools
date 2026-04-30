#!/usr/bin/env python3
"""
CVE-006 Phase 4a: one-time migration of legacy cisco-psirt-import records.

Backfills first_fixed_version + product_families + affected_versions_raw
on existing cve_data/<platform>/cve-*.json files via PSIRT advisory-detail
endpoint.

Usage:
    # Dry run (no writes, shows counts of what WOULD change):
    CVE_CISCO_DETAIL_FETCH=1 python3 scripts/migrate_phase4a.py --dry-run

    # Real migration (writes patches in place, atomic):
    CVE_CISCO_DETAIL_FETCH=1 python3 scripts/migrate_phase4a.py

    # Limited migration (process only N records, useful for incremental rollout):
    CVE_CISCO_DETAIL_FETCH=1 python3 scripts/migrate_phase4a.py --max 10

    # Custom rate-limit pause (default 2.0s between API calls):
    CVE_CISCO_DETAIL_FETCH=1 python3 scripts/migrate_phase4a.py --sleep 1.5

    # Custom platform / data dir (default: iosxe + cve_data/ios_xe):
    CVE_CISCO_DETAIL_FETCH=1 python3 scripts/migrate_phase4a.py --platform iosxe --data-dir cve_data/ios_xe

Idempotent: re-run only fetches advisories whose records still need
enrichment (first_fixed_version is null/missing). Curated records
(source != cisco-psirt-import) are NEVER touched.

Estimated runtime: ~5 minutes on 129 records at default rate-limit pause
(2.0s × 129 ≈ 4 min wall clock + cache warm-up). Cache hits are
near-instantaneous.

Requires Cisco PSIRT credentials at one of:
  - ~/.config/cisco-psirt/credentials.json
  - $CISCO_CLIENT_ID + $CISCO_CLIENT_SECRET env vars

Acceptance criteria after run (per design doc):
  AR-1: >=90% of source=cisco-psirt-import records carry first_fixed_version
  AR-2: query "IOS XE 17.9.4" matched list does NOT include CVE-2017-6736..6744
  AR-7: coverage_uncertain bucket non-empty but small (<15 CVEs)
  AR-8: Migration completes in <10 min on 129 records
  AR-9: Re-run is idempotent (only refetches stale advisories)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

# Allow `python3 scripts/migrate_phase4a.py` from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.cve_sources import CiscoAdvisoryProvider
from services.cisco_sync import enrich_legacy_psirt_records


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="CVE-006 Phase 4a: enrich legacy cisco-psirt-import records",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Show what would change without writing files",
    )
    p.add_argument(
        "--max", type=int, default=None, metavar="N",
        help="Process at most N records this run (useful for incremental rollout)",
    )
    p.add_argument(
        "--sleep", type=float, default=2.0, metavar="SECONDS",
        help="Sleep between actual API fetches (cache hits skip sleep). Default: 2.0",
    )
    p.add_argument(
        "--platform", default="iosxe",
        help="PSIRT platform identifier (default: iosxe)",
    )
    p.add_argument(
        "--data-dir", default=None,
        help="Override CVE data directory (default: services.cisco_sync.CVE_DATA_DIR)",
    )
    p.add_argument(
        "--no-flag-check", action="store_true",
        help="Skip CVE_CISCO_DETAIL_FETCH env var check (advanced)",
    )
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    if not args.no_flag_check and os.getenv("CVE_CISCO_DETAIL_FETCH", "0") != "1":
        print(
            "ERROR: CVE_CISCO_DETAIL_FETCH=1 not set in environment.\n"
            "  Phase 4 enrichment is gated for safety. Set the flag to opt in:\n"
            "    CVE_CISCO_DETAIL_FETCH=1 python3 scripts/migrate_phase4a.py [args]\n"
            "  Or use --no-flag-check to bypass this guard (advanced).",
            file=sys.stderr,
        )
        return 2

    # Import the data dir constant lazily so --data-dir can override before service-side default applies
    from services.cisco_sync import CVE_DATA_DIR as DEFAULT_DATA_DIR
    data_dir = args.data_dir or DEFAULT_DATA_DIR

    if not os.path.isdir(data_dir):
        print(f"ERROR: data dir not found: {data_dir}", file=sys.stderr)
        return 2

    print("=" * 72)
    print("CVE-006 Phase 4a Migration")
    print("=" * 72)
    print(f"  Platform:        {args.platform}")
    print(f"  Data dir:        {data_dir}")
    print(f"  Rate-limit pause: {args.sleep}s between API calls")
    print(f"  Max records:     {args.max or 'unlimited'}")
    print(f"  Mode:            {'DRY RUN' if args.dry_run else 'REAL'}")
    print("=" * 72)

    provider = CiscoAdvisoryProvider(platform=args.platform)

    start_ts = time.time()
    counts = enrich_legacy_psirt_records(
        provider,
        cve_data_dir=data_dir,
        rate_limit_sleep=args.sleep,
        max_records=args.max,
        dry_run=args.dry_run,
    )
    elapsed = time.time() - start_ts

    print("=" * 72)
    print("RESULTS")
    print("=" * 72)
    print(f"  Scanned:                  {counts['scanned']}")
    print(f"  Enriched:                 {counts['enriched']}")
    print(f"  Fetched (API):            {counts['fetched']}")
    print(f"  Skipped (curated):        {counts['skipped_curated']}")
    print(f"  Skipped (already done):   {counts['skipped_already_enriched']}")
    print(f"  Skipped (no URL):         {counts['skipped_no_url']}")
    print(f"  Failed:                   {counts['failed']}")
    print(f"  Elapsed:                  {elapsed:.1f}s")
    print("=" * 72)

    if args.dry_run:
        print("DRY RUN: no files modified. Re-run without --dry-run to apply.")
    elif counts["enriched"] > 0:
        print(f"Migration applied to {counts['enriched']} record(s).")
        print("Verification suggested:")
        print("  1. Spot-check that CVE-2017-6736..6744 (SNMP RCE) no longer match IOS XE 17.9.4")
        print("  2. Check /api/cve_analyzer with platform='IOS XE' version='17.9.4'")
        print("  3. Confirm coverage_uncertain bucket is non-empty but small (<15 entries)")

    if counts["failed"] > 0:
        print(f"WARNING: {counts['failed']} record(s) failed (rate limit, 404, or network)")
        print("  Re-run later — idempotent: only failed/missing records get retried.")

    return 0 if counts["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
