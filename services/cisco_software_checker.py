"""
Cisco's own first-fixed path for IOS XE / IOS releases (UPG-02, 2026-10-22).

Why this exists. The analyzer's recommended target is max(fixed_in) over our
curated records, and records imported from PSIRT carry no fixed_in. On
production that made IOS XE 17.9.4 -> 17.15.4a the recommendation while
17.15.4a still sat on Cisco's Known Affected list for the August 2026 hardening
release and four other High/Critical advisories (UPG-01 target check, 22.10).

The openVuln per-release query (/OSType/{iosxe|ios}?version=V) answers
for one release: which advisories apply, and per advisory `firstFixed` on that
release's train. Walking it — query, take the highest first fixed on the train,
query that release, repeat — gives the release where Cisco lists no
Critical/High advisory, which is what an engineer means by "safe upgrade
path". Measured 22.10: 17.9.4 (35 Critical/High) -> 17.9.10 (one Medium).

An advisory with an empty `firstFixed` (the hardening release on 17.9.4) does
not stop the walk: the next release is queried, and if the advisory is still
listed there with no fix, the path says so instead of naming a target.

Network: every call has a timeout, results are cached for 6 h, a failure is
cached for 10 min, and CISCO_CHECKER_OFFLINE=1 (set suite-wide in tests)
turns the lookup off. Offline or failed = None, and the report keeps the
dataset-only answer.
"""

from __future__ import annotations

import os
import time
import urllib.parse
from typing import Callable, Dict, List, Optional, Tuple

API_BASE = "https://apix.cisco.com/security/advisories/v2/OSType"
SOURCE = "Cisco PSIRT openVuln API, per-release query"
CACHE_TTL = 6 * 3600
FAILURE_TTL = 10 * 60
MAX_STEPS = 4
TIME_BUDGET = 12.0   # seconds for the whole walk; the analyzer waits on it
SEVERE = ("Critical", "High")

_cache: Dict[Tuple[str, str], Tuple[float, List[dict]]] = {}
_failed_at: Optional[float] = None
_provider = None

Fetch = Callable[[str, str], Optional[List[dict]]]


def reset_for_tests() -> None:
    global _failed_at
    _cache.clear()
    _failed_at = None


UNKNOWN_RELEASE = "unknown-release"   # openVuln 404: Cisco has no data for it


def _live_fetch(ostype: str, release: str):
    """Advisories for one release; UNKNOWN_RELEASE on 404; None on failure."""
    global _provider
    import json
    import urllib.error
    import urllib.request
    try:
        if _provider is None:
            from services.cve_sources import CiscoAdvisoryProvider
            _provider = CiscoAdvisoryProvider()
        token = _provider._get_token()
        if not token:
            return None
        url = f"{API_BASE}/{ostype}?version={urllib.parse.quote(release)}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}",
                                                   "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return UNKNOWN_RELEASE if e.code == 404 else None
    except Exception:
        return None
    if "advisories" not in data:
        return UNKNOWN_RELEASE if data.get("errorCode") == "NO_DATA_FOUND" else None
    return data.get("advisories") or []


def _advisories(ostype: str, release: str, fetch: Fetch) -> Optional[List[dict]]:
    global _failed_at
    key = (ostype, release)
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < CACHE_TTL:
        return hit[1]
    if _failed_at and time.time() - _failed_at < FAILURE_TTL:
        return None
    result = fetch(ostype, release)
    if result is None:
        _failed_at = time.time()
        return None
    _cache[key] = (time.time(), result)
    return result


def _train(release: str) -> Tuple[int, ...]:
    from services.cve_engine import _tokenize_version
    return tuple(_tokenize_version(release)[:2])


def _key(release: str):
    from services.cve_engine import _tokenize_version
    return (_tokenize_version(release), release)


def first_fixed_path(ostype: str, release: str,
                     fetch: Optional[Fetch] = None) -> Optional[dict]:
    """Walk Cisco's first-fixed releases until no Critical/High is listed.

    Returns None when the lookup is off or failed; otherwise a dict with the
    target (None when Cisco names no fix on the train), the steps taken, what
    stays listed at the target, and one statement for the report.
    """
    if os.environ.get("CISCO_CHECKER_OFFLINE") == "1" and fetch is None:
        return None
    fetch = fetch or _live_fetch
    train = _train(release)
    current = release
    steps: List[str] = [release]
    started = time.time()
    for _ in range(MAX_STEPS):
        if time.time() - started > TIME_BUDGET:
            return None   # too slow today: the dataset answer stands alone
        advisories = _advisories(ostype, current, fetch)
        if advisories is None:
            return None
        if advisories == UNKNOWN_RELEASE:
            if current == release:
                return None   # Cisco does not know the caller's release
            return _unknown_step(release, current)
        severe = [a for a in advisories if a.get("sir") in SEVERE]
        if not severe:
            if current == release:
                return None   # nothing to fix: no path to give
            return _done(release, current, steps, advisories)
        fixes = [f for a in severe for f in (a.get("firstFixed") or []) if _train(f) == train]
        nxt = max(fixes, key=_key) if fixes else None
        if nxt is None or _key(nxt) <= _key(current):
            return _stuck(release, current, severe)
        current = nxt
        steps.append(current)
    return None   # did not converge within MAX_STEPS: say nothing rather than guess


def _ids(advisories: List[dict], limit: int = 3) -> str:
    names = [a.get("advisoryId", "?") for a in advisories]
    more = f" and {len(names) - limit} more" if len(names) > limit else ""
    return ", ".join(names[:limit]) + more


def _done(release: str, target: str, steps: List[str], left: List[dict]) -> dict:
    if left:
        by_sir: Dict[str, int] = {}
        for a in left:
            by_sir[a.get("sir") or "Unknown"] = by_sir.get(a.get("sir") or "Unknown", 0) + 1
        counts = ", ".join(f"{n} {s}" for s, n in sorted(by_sir.items()))
        tail = f"Still listed for {target}: {counts} ({_ids(left)})."
    else:
        tail = f"Cisco lists no advisory for {target}."
    return {
        "source": SOURCE,
        "target": target,
        "same_train": _train(target) == _train(release),
        "steps": steps,
        "remaining": [{"advisoryId": a.get("advisoryId"), "sir": a.get("sir"),
                       "cves": a.get("cves") or []} for a in left],
        "statement": (f"Safe upgrade path (Cisco): {release} → {target}, same train. "
                      f"Cisco lists no Critical/High advisory for {target}. {tail} "
                      f"Source: {SOURCE}."),
    }


def _unknown_step(release: str, at: str) -> dict:
    return {
        "source": SOURCE,
        "target": None,
        "same_train": True,
        "steps": [release, at],
        "remaining": [],
        "statement": (f"Safe upgrade path (Cisco): Cisco names {at} as the first fixed release "
                      f"on your train, but its API has no data for {at} yet, so it cannot be "
                      f"checked here. Confirm {at} in Cisco Software Checker. Source: {SOURCE}."),
    }


def _stuck(release: str, at: str, severe: List[dict]) -> dict:
    t = ".".join(str(p) for p in _train(release))
    return {
        "source": SOURCE,
        "target": None,
        "same_train": None,
        "steps": [release] if at == release else [release, at],
        "remaining": [{"advisoryId": a.get("advisoryId"), "sir": a.get("sir"),
                       "cves": a.get("cves") or []} for a in severe],
        "statement": (f"Safe upgrade path (Cisco): no release on the {t} train clears every "
                      f"Critical/High advisory; at {at} Cisco names no fix for "
                      f"{_ids(severe)}. Plan a train change and check the target in Cisco "
                      f"Software Checker. Source: {SOURCE}."),
    }
