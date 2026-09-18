#!/usr/bin/env python3
"""migrate_known_affected.py — MATCH-01 + HTML-01 (2026-09-18).

One pass over cve_data/ios_xe/cve-*.json that does two independent things:

1. MATCH-01: fills `known_affected` / `known_affected_as_of` from the PSIRT
   platform cache (cache/cisco/*.json). The cache holds each advisory's full
   `productNames`; the record only ever kept the first 50 for display. Records
   whose advisory is not in the cache, or whose advisory enumerates no release
   for IOS / IOS XE, are left exactly as they were — "we do not know" stays
   "we do not know".

2. HTML-01: decodes HTML entities in `title` / `description`. The importers
   stripped tags but never unescaped, so reports read "Protocol&nbsp;(SNMP)".

Idempotent. Never edits curated fields (affected, fixed_in, severity, tags).

Usage:
    python3 scripts/migrate_known_affected.py            # apply
    python3 scripts/migrate_known_affected.py --dry-run  # report only
"""
import argparse
import datetime
import glob
import html
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(HERE)
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from services.advisory_text import clean_advisory_text  # noqa: E402
from services.known_affected import extract_known_affected  # noqa: E402

DATA_DIR = os.path.join(PROJECT_DIR, "cve_data", "ios_xe")
CACHE_DIR = os.path.join(PROJECT_DIR, "cache", "cisco")
_ADV_RE = re.compile(r"(cisco-sa-[A-Za-z0-9-]+)")


def clean_text(text):
    """Decode entities; leaves text without entities byte-identical."""
    if not isinstance(text, str) or "&" not in text:
        return text
    return clean_advisory_text(text)


def load_advisories():
    """{advisoryId: (advisory, as_of_date)} — newest cache wins."""
    found = {}
    for path in sorted(glob.glob(os.path.join(CACHE_DIR, "*.json"))):
        try:
            with open(path, encoding="utf-8") as f:
                blob = json.load(f)
        except Exception:
            continue
        ts = blob.get("cached_at") or 0
        as_of = datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d") if ts else None
        for adv in blob.get("advisories") or []:
            aid = adv.get("advisoryId")
            if aid and (aid not in found or ts > found[aid][2]):
                found[aid] = (adv, as_of, ts)
    return {k: (v[0], v[1]) for k, v in found.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    advisories = load_advisories()
    stats = {"records": 0, "lists_set": 0, "no_advisory": 0, "no_versions": 0,
             "text_cleaned": 0, "written": 0}

    for path in sorted(glob.glob(os.path.join(DATA_DIR, "cve-*.json"))):
        with open(path, encoding="utf-8") as f:
            original = f.read()
        rec = json.loads(original)
        stats["records"] += 1

        for key in ("title", "description"):
            cleaned = clean_text(rec.get(key))
            if cleaned != rec.get(key):
                rec[key] = cleaned
                stats["text_cleaned"] += 1

        m = _ADV_RE.search(rec.get("advisory_url") or "")
        hit = advisories.get(m.group(1)) if m else None
        if hit is None:
            stats["no_advisory"] += 1
        else:
            adv, as_of = hit
            lists = extract_known_affected(adv)
            if lists:
                rec["known_affected"] = lists
                rec["known_affected_as_of"] = as_of
                stats["lists_set"] += 1
            else:
                stats["no_versions"] += 1

        # Compare CONTENT, not bytes: several curated records use compact inline
        # arrays, and re-serialising them would produce a formatting-only diff in
        # files this script has no business touching.
        if rec == json.loads(original):
            continue
        payload = json.dumps(rec, indent=2, ensure_ascii=False)
        if original.endswith("\n"):
            payload += "\n"
        if True:
            stats["written"] += 1
            if not args.dry_run:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(payload)

    for k, v in stats.items():
        print("%-14s %d" % (k, v))
    return 0


if __name__ == "__main__":
    sys.exit(main())
