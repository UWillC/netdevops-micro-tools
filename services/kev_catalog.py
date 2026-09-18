"""
CISA Known Exploited Vulnerabilities catalog lookup (KEV-X, 2026-09-18).

Why this exists: the threat feed showed a KEV badge only for CVEs we had curated
locally, because the Cisco PSIRT API does not expose KEV status. On production
that put a badge on CVE-2026-76460 and none on CVE-2026-76461, which had been in
KEV for four days. A badge that appears on some exploited CVEs and not others is
worse than no badge: its absence reads as "not exploited".

Design constraints, in order of importance:

1. Never make a request slower or break it. The catalog is fetched at most once
   per TTL, under a short timeout; any failure falls back to the last good copy
   on disk, then to an empty catalog. Failures are negatively cached so an
   outage does not add a timeout to every page load.
2. Never reach the network from a test. `KEV_CATALOG_OFFLINE=1` disables the
   fetch outright; tests/conftest.py sets it for the whole suite.
3. Say how fresh the answer is. Every lookup result carries the catalog version
   it came from, so a badge can never silently outlive its evidence.

The catalog is the only source used here. `dueDate` is the US federal
remediation deadline for FCEB agencies; it is not a vendor deadline and binds
nobody else, but it is the sharpest public signal that a CVE is being exploited.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, Optional

from services.http_client import http_get_json

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
KEV_CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", "cache", "kev")
KEV_CACHE_PATH = os.path.join(KEV_CACHE_DIR, "catalog.json")

KEV_TTL_SECONDS = 6 * 3600          # same cadence as the PSIRT "latest" cache
KEV_FETCH_TIMEOUT_SECONDS = 5       # page loads wait on this at most once per TTL
KEV_FAILURE_BACKOFF_SECONDS = 600   # after a failed fetch, do not retry for 10 min

_DIRECTIVE_RE = re.compile(r"\bBOD\s+\d{2}-\d{2}\b")

# Module-level memo: {"loaded_at": float, "index": {...}, "version": str}
_memo: Optional[Dict[str, Any]] = None
_last_failure_at: float = 0.0


def _offline() -> bool:
    return os.getenv("KEV_CATALOG_OFFLINE", "").strip().lower() in ("1", "true", "yes", "on")


def _build_index(raw: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """cve_id -> compact KEV record."""
    index: Dict[str, Dict[str, Any]] = {}
    version = raw.get("catalogVersion")
    for v in raw.get("vulnerabilities") or []:
        cve_id = (v.get("cveID") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        m = _DIRECTIVE_RE.search(v.get("notes") or "")
        index[cve_id] = {
            "cve_id": cve_id,
            "date_added": v.get("dateAdded"),
            "due_date": v.get("dueDate"),
            "catalog_version": version,
            "directive": m.group(0) if m else None,
            "ransomware": (v.get("knownRansomwareCampaignUse") or "").strip() or None,
        }
    return index


def _read_disk() -> Optional[Dict[str, Any]]:
    try:
        with open(KEV_CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _write_disk(raw: Dict[str, Any]) -> None:
    try:
        os.makedirs(KEV_CACHE_DIR, exist_ok=True)
        with open(KEV_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump({"cached_at": time.time(), "catalog": raw}, f)
    except Exception:
        pass  # a read-only filesystem must not break the feed


def _memoize(raw: Dict[str, Any], loaded_at: float) -> Dict[str, Any]:
    global _memo
    _memo = {
        "loaded_at": loaded_at,
        "index": _build_index(raw),
        "version": raw.get("catalogVersion"),
    }
    return _memo


def load_kev_index(force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
    """Return {cve_id: kev_record}. Empty dict when no catalog is obtainable."""
    global _last_failure_at
    now = time.time()

    if _memo is not None and not force_refresh and now - _memo["loaded_at"] < KEV_TTL_SECONDS:
        return _memo["index"]

    disk = _read_disk()
    if disk and not force_refresh and now - disk.get("cached_at", 0) < KEV_TTL_SECONDS:
        return _memoize(disk.get("catalog") or {}, disk.get("cached_at", now))["index"]

    can_fetch = not _offline() and (force_refresh or now - _last_failure_at > KEV_FAILURE_BACKOFF_SECONDS)
    if can_fetch:
        try:
            raw = http_get_json(KEV_FEED_URL, timeout_seconds=KEV_FETCH_TIMEOUT_SECONDS)
            if isinstance(raw, dict) and raw.get("vulnerabilities"):
                _write_disk(raw)
                return _memoize(raw, now)["index"]
            _last_failure_at = now
        except Exception as e:
            _last_failure_at = now
            print(f"[WARN] CISA KEV fetch failed, using last good copy: {e}")

    # Stale beats empty: an old KEV entry is still a true statement.
    if disk:
        return _memoize(disk.get("catalog") or {}, now - KEV_TTL_SECONDS + KEV_FAILURE_BACKOFF_SECONDS)["index"]
    if _memo is not None:
        return _memo["index"]
    return {}


def catalog_version() -> Optional[str]:
    """catalogVersion of whatever load_kev_index() last served, or None."""
    return _memo["version"] if _memo else None


def kev_status(cve_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """KEV record for one CVE, or None if it is not in the catalog."""
    if not cve_id:
        return None
    return load_kev_index().get(cve_id.strip().upper())


def first_kev_hit(cve_ids) -> Optional[Dict[str, Any]]:
    """Earliest-due KEV record among `cve_ids`, or None.

    A PSIRT feed row stands for a whole advisory but is labelled with cves[0].
    The exploited CVE can be any of them, so every id has to be checked; when
    several are in KEV the one with the nearest federal deadline wins.
    """
    index = load_kev_index()
    hits = [index[c.strip().upper()] for c in (cve_ids or [])
            if isinstance(c, str) and c.strip().upper() in index]
    if not hits:
        return None
    return sorted(hits, key=lambda h: (h.get("due_date") or "9999", h["cve_id"]))[0]


def reset_for_tests() -> None:
    """Drop the in-process memo and failure backoff."""
    global _memo, _last_failure_at
    _memo = None
    _last_failure_at = 0.0
