"""
Provenance / audit-trail metadata — XCUT-002.

Every CVE Analyzer report carries a footer that answers four questions an
auditor or risk committee will ask:

    Where did this finding come from?
    When was that source last refreshed?
    What version of the tool produced this report?
    What was the dataset version at report time?

Without this, the tool's output is not usable as compliance evidence —
no chain of custody.

The functions here gather the metadata at request time. They are
deliberately filesystem-based: cache file mtimes for refresh dates,
directory listing for ruleset versioning. No external dependencies.
"""
from __future__ import annotations

import datetime
import os
from typing import Dict, List, Optional

# Resolve project root once. This file lives in services/, so go up one level.
_PROJECT_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def _project_path(*parts: str) -> str:
    return os.path.join(_PROJECT_ROOT, *parts)


def _iso_utc(ts: float) -> str:
    """ISO-8601 UTC string from a unix timestamp."""
    return datetime.datetime.utcfromtimestamp(ts).isoformat() + "Z"


def _hours_since(ts: float) -> float:
    age = max(0.0, datetime.datetime.utcnow().timestamp() - ts)
    return round(age / 3600.0, 1)


def _newest_mtime(path: str) -> Optional[float]:
    """Recursively find the newest mtime under `path`. Returns None if path
    doesn't exist or is empty."""
    if not os.path.exists(path):
        return None
    newest: Optional[float] = None
    if os.path.isfile(path):
        return os.path.getmtime(path)
    for root, _dirs, files in os.walk(path):
        for fname in files:
            try:
                m = os.path.getmtime(os.path.join(root, fname))
            except OSError:
                continue
            if newest is None or m > newest:
                newest = m
    return newest


def _file_count(path: str) -> int:
    if not os.path.exists(path):
        return 0
    if os.path.isfile(path):
        return 1
    n = 0
    for _root, _dirs, files in os.walk(path):
        n += len(files)
    return n


def _source_block(name: str, path: str, description: str) -> Dict:
    """Build a per-source provenance block with last_refreshed (ISO) and
    age_hours. Returns a uniform shape even when the path is empty."""
    mtime = _newest_mtime(path)
    files = _file_count(path)
    if mtime is None:
        return {
            "name": name,
            "description": description,
            "available": False,
            "last_refreshed": None,
            "age_hours": None,
            "file_count": 0,
        }
    return {
        "name": name,
        "description": description,
        "available": True,
        "last_refreshed": _iso_utc(mtime),
        "age_hours": _hours_since(mtime),
        "file_count": files,
    }


def cve_provenance(
    tool_version: str,
    cve_engine_version: str,
    matched_cves: List,
) -> Dict:
    """Return the provenance metadata block for a CVE Analyzer response.

    Args:
        tool_version: from /meta/version (api/main.py).
        cve_engine_version: CVEEngineConfig.engine_version.
        matched_cves: list of CVEEntry returned by engine.match().

    Returns:
        dict ready to attach to CVEAnalyzeResponse.provenance.
    """
    sources = []

    # Local JSON dataset — primary source of truth, curated entries.
    local_path = _project_path("cve_data", "ios_xe")
    sources.append(
        _source_block(
            name="local-json",
            path=local_path,
            description="Curated local CVE dataset (cve_data/ios_xe/*.json)",
        )
    )

    # Cisco PSIRT API cache (advisories pulled via API).
    cisco_path = _project_path("cache", "cisco")
    sources.append(
        _source_block(
            name="cisco-psirt-import",
            path=cisco_path,
            description="Cisco PSIRT API cache (advisories fetched on demand)",
        )
    )

    # NVD per-CVE enrichment cache.
    nvd_path = _project_path("cache", "nvd")
    sources.append(
        _source_block(
            name="nvd-enrichment",
            path=nvd_path,
            description="NVD CVSS / CWE enrichment cache (24h TTL per CVE)",
        )
    )

    # Per-CVE source distribution (which provider supplied each match).
    source_counts: Dict[str, int] = {}
    for cve in matched_cves:
        src = getattr(cve, "source", None) or "unknown"
        source_counts[src] = source_counts.get(src, 0) + 1

    # Ruleset version: derive a deterministic identifier from the local-json
    # mtime (ISO date only). Tells the reader "the curated dataset I matched
    # against was last touched on this day". Stable enough to cite, granular
    # enough to detect drift.
    ruleset_version = "unknown"
    local_mtime = _newest_mtime(local_path)
    if local_mtime is not None:
        ruleset_version = datetime.datetime.utcfromtimestamp(local_mtime).strftime(
            "local-json-%Y%m%d"
        )

    return {
        "tool_version": tool_version,
        "cve_engine_version": cve_engine_version,
        "ruleset_version": ruleset_version,
        "report_generated": _iso_utc(datetime.datetime.utcnow().timestamp()),
        "sources": sources,
        "source_distribution": source_counts,
        "policy_note": (
            "Per-CVE 'source' field on each finding identifies which provider "
            "supplied that record. 'advisory_url' (when present) is the "
            "canonical Cisco advisory page. This footer establishes chain of "
            "custody for audit / compliance use."
        ),
    }
