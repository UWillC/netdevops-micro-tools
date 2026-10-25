"""Rebuild tests/fixtures/match03/iosxe_synced_17_9_4.json (MATCH-03 golden numbers).

Offline by design: no PSIRT call, no workaround fetch, no API key. Needs the
local PSIRT cache cache/cisco/iosxe.json (gitignored; written by a normal sync).

    .venv/bin/python tests/fixtures/match03/build_fixture.py

Method (same as the 2026-10-24 @cto/@pm analysis "71 -> 93 -> 188"):
  1. copy cve_data/ios_xe to a temp dir,
  2. run cisco_sync.auto_sync_new_cves() on the cached advisories into it,
     with cisco_workaround.fetch_checked stubbed out,
  3. match "IOS XE 17.9.4" on the result and keep ONLY the matched records.

Size: the full synced dataset is ~680 records / ~9 MB and the matched ones
still carry ~1 MB of release lists. Matching is per record, so the records
that do not match 17.9.4 cannot change its numbers; and a list can be cut to
the entries that matter without changing membership:
  ios-xe -> entries equal to 17.9.4,
  other  -> entries equal to the classic-IOS anchor 15.0(1)M, or the first
            entry when the list has none (the list stays non-empty).
The fixture therefore answers 17.9.4 (and the 15.0(1)M classic-IOS check)
only. Regenerating it changes the golden numbers on purpose; eyeball the diff.
"""

import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from services import cisco_sync, cisco_workaround  # noqa: E402
from services.cve_engine import CVEEngine, CVEEngineConfig  # noqa: E402
from services.known_affected import _norm  # noqa: E402

TARGET = "17.9.4"
IOS_ANCHOR = "15.0(1)M"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "iosxe_synced_17_9_4.json")


def _trim(known_affected):
    out = {}
    for fam, listed in (known_affected or {}).items():
        if not listed:
            out[fam] = listed
            continue
        anchor = TARGET if fam == "ios-xe" else IOS_ANCHOR
        keep = [v for v in listed if _norm(v) == _norm(anchor)]
        out[fam] = keep or listed[:1]
    return out


def main():
    cisco_workaround.fetch_checked = lambda *a, **k: (None, False)   # no network
    with open(os.path.join(ROOT, "cache", "cisco", "iosxe.json"), encoding="utf-8") as f:
        cache = json.load(f)
    with tempfile.TemporaryDirectory() as tmp:
        data_dir = os.path.join(tmp, "ios_xe")
        shutil.copytree(os.path.join(ROOT, "cve_data", "ios_xe"), data_dir)
        cisco_sync.CVE_DATA_DIR = data_dir
        cisco_sync.MITIGATION_DIR = os.path.join(tmp, "mitigations")
        cisco_sync.auto_sync_new_cves(cache["advisories"], platform="iosxe")
        total_records = len([n for n in os.listdir(data_dir) if n.endswith(".json")])

        engine = CVEEngine(config=CVEEngineConfig(engine_version="0.3.7", data_dir=data_dir))
        engine.load_all()
        ids = sorted(c.cve_id for c in engine.match("IOS XE", TARGET))
        records = []
        for cve_id in ids:
            with open(os.path.join(data_dir, f"{cve_id.lower()}.json"), encoding="utf-8") as f:
                rec = json.load(f)
            rec["known_affected"] = _trim(rec.get("known_affected"))
            records.append(rec)

    meta = {
        "what": f"IOS XE dataset after a full offline PSIRT sync, records matching {TARGET} only",
        "built_by": "tests/fixtures/match03/build_fixture.py",
        "psirt_cache_advisories": len(cache["advisories"]),
        "synced_dataset_records": total_records,
        "records_kept": len(records),
        "known_affected_lists": f"trimmed to {TARGET} (ios-xe) / {IOS_ANCHOR} or first entry (other)",
    }
    with open(OUT, "w", encoding="utf-8") as f:
        f.write('{"_meta": ' + json.dumps(meta, ensure_ascii=False) + ',\n "records": [\n')
        f.write(",\n".join(json.dumps(r, ensure_ascii=False, sort_keys=True) for r in records))
        f.write("\n]}\n")
    print(f"{len(records)} of {total_records} records -> {OUT}")


if __name__ == "__main__":
    main()
