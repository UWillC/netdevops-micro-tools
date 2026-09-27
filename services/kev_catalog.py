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
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

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
_URL_RE = re.compile(r"https?://[^\s;,<>\"']+")
# Hosts in `notes` that are not the vendor's advisory: CISA's own directives and
# mitigation pages, and NVD (KEV Watch links NVD separately for every CVE).
_NON_ADVISORY_HOSTS = ("cisa.gov", "nvd.nist.gov")

# KEV Watch (KW-01): vendors whose new KEV listings we report. Matched
# case-insensitively against the catalog's `vendorProject`. KEV_WATCH_VENDORS
# (comma-separated) replaces the default, e.g. "Cisco,Fortinet,Palo Alto Networks".
DEFAULT_WATCH_VENDORS = ("Cisco",)

# Module-level memo: {"loaded_at": float, "index": {...}, "version": str}
_memo: Optional[Dict[str, Any]] = None
_last_failure_at: float = 0.0


def _offline() -> bool:
    return os.getenv("KEV_CATALOG_OFFLINE", "").strip().lower() in ("1", "true", "yes", "on")


def _notes_urls(notes: Any) -> List[str]:
    """Every http(s) URL in a KEV `notes` field, in order, without duplicates.

    CISA separates entries with " ; " and sometimes wraps a URL in parentheses
    or ends it with a full stop, so trailing punctuation is trimmed.
    """
    urls: List[str] = []
    for m in _URL_RE.finditer(str(notes or "")):
        url = m.group(0).rstrip(").,]")
        if url not in urls:
            urls.append(url)
    return urls


def _advisory_url(urls: Iterable[str]) -> Optional[str]:
    """First URL that is not a CISA or NVD page, i.e. the vendor advisory.

    The first URL in `notes` is often CISA's mitigation page or the NVD entry,
    so "first URL" alone would label those as the vendor's advisory.
    """
    for url in urls:
        host = re.sub(r"^https?://", "", url).split("/", 1)[0].split(":", 1)[0].lower()
        if not any(host == h or host.endswith("." + h) for h in _NON_ADVISORY_HOSTS):
            return url
    return None


def _build_index(raw: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """cve_id -> compact KEV record."""
    index: Dict[str, Dict[str, Any]] = {}
    version = raw.get("catalogVersion")
    for v in raw.get("vulnerabilities") or []:
        cve_id = (v.get("cveID") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        m = _DIRECTIVE_RE.search(v.get("notes") or "")
        urls = _notes_urls(v.get("notes"))
        index[cve_id] = {
            "cve_id": cve_id,
            "date_added": v.get("dateAdded"),
            "due_date": v.get("dueDate"),
            "catalog_version": version,
            "directive": m.group(0) if m else None,
            "ransomware": (v.get("knownRansomwareCampaignUse") or "").strip() or None,
            "vendor_project": (v.get("vendorProject") or "").strip() or None,
            "product": (v.get("product") or "").strip() or None,
            "short_description": (v.get("shortDescription") or "").strip() or None,
            # KW-01.3: links from `notes`; advisory_url = first non-CISA/NVD one.
            "notes_urls": urls,
            "advisory_url": _advisory_url(urls),
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


def _memoize(raw: Dict[str, Any], loaded_at: float,
             fetched_at: Optional[float] = None, source: str = "cache") -> Dict[str, Any]:
    global _memo
    _memo = {
        "loaded_at": loaded_at,
        "index": _build_index(raw),
        "version": raw.get("catalogVersion"),
        "date_released": raw.get("dateReleased"),
        # When the copy was fetched from CISA. Differs from loaded_at on the
        # stale-disk path, where loaded_at is shifted to drive the retry backoff.
        "fetched_at": loaded_at if fetched_at is None else fetched_at,
        # "live" = fetched from CISA by this process; "cache" = read from disk.
        "source": source,
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
                return _memoize(raw, now, source="live")["index"]
            _last_failure_at = now
        except Exception as e:
            _last_failure_at = now
            print(f"[WARN] CISA KEV fetch failed, using last good copy: {e}")

    # Stale beats empty: an old KEV entry is still a true statement.
    if disk:
        return _memoize(disk.get("catalog") or {}, now - KEV_TTL_SECONDS + KEV_FAILURE_BACKOFF_SECONDS,
                        fetched_at=disk.get("cached_at"))["index"]
    if _memo is not None:
        return _memo["index"]
    return {}


def catalog_version() -> Optional[str]:
    """catalogVersion of whatever load_kev_index() last served, or None."""
    return _memo["version"] if _memo else None


def catalog_meta() -> Dict[str, Any]:
    """Provenance of the catalog last served: version, CISA release, fetch time.

    `fetched_at` is ISO-8601 UTC, or None when no catalog has been loaded or the
    disk copy carries no timestamp.
    """
    if not _memo:
        return {"catalog_version": None, "date_released": None, "fetched_at": None}
    ts = _memo.get("fetched_at")
    return {
        "catalog_version": _memo.get("version"),
        "date_released": _memo.get("date_released"),
        "fetched_at": (datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                       if isinstance(ts, (int, float)) else None),
    }


def catalog_status(now: Optional[float] = None) -> Dict[str, Any]:
    """catalog_meta() plus where the copy came from and whether it is stale.

    `source` is "live" (fetched from CISA by this process) or "cache" (read from
    disk), None when nothing is loaded. `stale` is True when the copy is older
    than KEV_TTL_SECONDS, i.e. a refresh was due and did not happen (CISA down,
    offline mode, backoff), or when its fetch time is unknown. KEV Watch (KW-01)
    shows it so an old copy is never read as "no new listings".
    """
    meta = catalog_meta()
    if not _memo:
        meta.update({"source": None, "stale": True})
        return meta
    ts = _memo.get("fetched_at")
    now = time.time() if now is None else now
    meta["source"] = _memo.get("source") or "cache"
    meta["stale"] = not isinstance(ts, (int, float)) or now - ts > KEV_TTL_SECONDS
    return meta


def watch_vendors() -> List[str]:
    """Vendors KEV Watch reports on: KEV_WATCH_VENDORS if set, else the default."""
    env = os.getenv("KEV_WATCH_VENDORS", "")
    configured = [v.strip() for v in env.split(",") if v.strip()]
    return configured or list(DEFAULT_WATCH_VENDORS)


def _parse_date(value: Any) -> Optional[date]:
    try:
        return datetime.strptime(str(value).strip()[:10], "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


def recent_additions(days: int, vendors: Optional[Iterable[str]] = None,
                     today: Optional[date] = None) -> List[Dict[str, Any]]:
    """KEV records added in the last `days` days for the given vendors.

    The window is inclusive at both ends: with today=2026-09-27 and days=7 a
    listing dated 2026-09-20 is included. Listings dated after `today` are kept
    (CISA dates are US-based; a server clock behind them must not hide one).
    `vendors=None` means watch_vendors(); an empty iterable matches nothing.
    Vendor match is case-insensitive and exact on `vendorProject`. Records with
    no parseable dateAdded or no vendor are skipped, never raised on.

    Sorted by date_added descending, then cve_id ascending, so the order is
    stable for the same catalog. Each record carries its catalog_version; use
    catalog_meta() for the fetch time.
    """
    if days < 0:
        raise ValueError("days must be >= 0")
    wanted = {v.strip().lower() for v in (watch_vendors() if vendors is None else vendors)
              if isinstance(v, str) and v.strip()}
    if not wanted:
        return []
    cutoff = (today or date.today()) - timedelta(days=days)
    hits = []
    for rec in load_kev_index().values():
        vendor = (rec.get("vendor_project") or "").strip().lower()
        added = _parse_date(rec.get("date_added"))
        if vendor in wanted and added is not None and added >= cutoff:
            hits.append(dict(rec))
    hits.sort(key=lambda r: r.get("cve_id") or "")
    hits.sort(key=lambda r: str(r.get("date_added"))[:10], reverse=True)
    return hits


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
