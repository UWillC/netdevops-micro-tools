import datetime
import json
import os
import re
import time
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services.cve_engine import CVEEngine, CVEEngineConfig
from services.cve_sources import NvdEnricherProvider, CiscoAdvisoryProvider, CISCO_CACHE_DIR
from models.cve_model import CVEEntry


router = APIRouter()


class CVEAnalyzeRequest(BaseModel):
    platform: str
    version: str
    include_suggestions: bool = True


class CVEAnalyzeResponse(BaseModel):
    platform: str
    version: str
    matched: List[CVEEntry]
    summary: dict
    recommended_upgrade: Optional[str]
    timestamp: str


class CVECheckResponse(BaseModel):
    cve_id: str
    found: bool
    entry: Optional[CVEEntry]
    timestamp: str


class FeedItem(BaseModel):
    cve_id: str
    title: str
    severity: str
    cvss: Optional[float]
    published: Optional[str]
    updated: Optional[str]
    url: Optional[str]
    platforms: List[str]


class CriticalFeedResponse(BaseModel):
    items: List[FeedItem]
    total_advisories: int
    cache_age_hours: Optional[float]
    timestamp: str


def _env_true(name: str) -> bool:
    v = os.getenv(name, "").strip().lower()
    return v in ("1", "true", "yes", "on")


@router.post("/cve", response_model=CVEAnalyzeResponse)
def analyze_cve(req: CVEAnalyzeRequest):
    # 1) Base run (local JSON only) to find which CVE IDs apply
    base_engine = CVEEngine(config=CVEEngineConfig(engine_version="0.3.3"))
    base_engine.load_all()
    matched_base = base_engine.match(req.platform, req.version)

    # 2) Optional enrichment from NVD for ONLY those CVEs (fast + cheap + avoids scanning the whole world)
    if _env_true("CVE_NVD_ENRICH") and matched_base:
        ids = [c.cve_id for c in matched_base]
        # Build a new engine with local + NVD enricher (IDs)
        enriched_engine = CVEEngine(
            config=CVEEngineConfig(engine_version="0.3.3", enable_nvd_enrichment=True),
            providers=[
                # Keep local base provider first (created internally)
                *base_engine.providers[:1],
                NvdEnricherProvider(cve_ids=ids),
            ],
        )
        enriched_engine.load_all()
        matched = enriched_engine.match(req.platform, req.version)
        summary = enriched_engine.summary(matched)
        recommendation = enriched_engine.recommended_upgrade(matched) if req.include_suggestions else None
    else:
        matched = matched_base
        summary = base_engine.summary(matched)
        recommendation = base_engine.recommended_upgrade(matched) if req.include_suggestions else None

    return CVEAnalyzeResponse(
        platform=req.platform,
        version=req.version,
        matched=matched,
        summary=summary,
        recommended_upgrade=recommendation,
        timestamp=datetime.datetime.utcnow().isoformat() + "Z",
    )


@router.get("/cve/{cve_id}", response_model=CVECheckResponse)
def check_cve(cve_id: str):
    """
    Check if a specific CVE exists in the database.
    If not found locally, tries Cisco PSIRT API (auto-imports to local).
    Optionally enriches with NVD data if CVE_NVD_ENRICH=1.
    """
    # Normalize CVE ID format
    cve_id_upper = cve_id.upper()
    if not cve_id_upper.startswith("CVE-"):
        cve_id_upper = f"CVE-{cve_id_upper}"

    # Load CVE database (local only first — fast)
    engine = CVEEngine(config=CVEEngineConfig(engine_version="0.3.3"))
    engine.load_all()

    # Find the CVE by ID
    entry = None
    for cve in engine.cves:
        if cve.cve_id.upper() == cve_id_upper:
            entry = cve
            break

    # Not found locally? Try Cisco PSIRT API (fallback lookup)
    if entry is None:
        try:
            cisco = CiscoAdvisoryProvider()
            creds = cisco._load_credentials()
            if creds:
                api_base = creds.get("api_base", "https://apix.cisco.com/security/advisories/v2")
                url = f"{api_base}/cve/{cve_id_upper}"
                data = cisco._api_get(url)
                if data:
                    advisories = data.get("advisories", [])
                    if advisories:
                        # Auto-sync this advisory to local files
                        try:
                            from services.cisco_sync import auto_sync_new_cves
                            auto_sync_new_cves(advisories)
                        except Exception:
                            pass
                        # Parse and return
                        for adv in advisories:
                            parsed = cisco._parse_advisory(adv)
                            for p in parsed:
                                if p.cve_id.upper() == cve_id_upper:
                                    entry = p
                                    break
                            if entry:
                                break
        except Exception as e:
            print(f"[WARN] Cisco PSIRT fallback lookup failed: {e}")

    # Optional NVD enrichment for this specific CVE
    if entry and _env_true("CVE_NVD_ENRICH"):
        enriched_engine = CVEEngine(
            config=CVEEngineConfig(engine_version="0.3.3", enable_nvd_enrichment=True),
            providers=[
                *engine.providers[:1],
                NvdEnricherProvider(cve_ids=[cve_id_upper]),
            ],
        )
        enriched_engine.load_all()
        for cve in enriched_engine.cves:
            if cve.cve_id.upper() == cve_id_upper:
                entry = cve
                break

    return CVECheckResponse(
        cve_id=cve_id_upper,
        found=entry is not None,
        entry=entry,
        timestamp=datetime.datetime.utcnow().isoformat() + "Z",
    )


LATEST_CACHE_PATH = os.path.join(CISCO_CACHE_DIR, "latest.json")
LATEST_CACHE_TTL = 6 * 3600  # 6 hours


def _load_latest_cache() -> tuple:
    """Load latest advisories cache. Returns (advisories, cache_age_hours)."""
    if not os.path.exists(LATEST_CACHE_PATH):
        return [], None
    try:
        with open(LATEST_CACHE_PATH, "r", encoding="utf-8") as f:
            cached = json.load(f)
        age = time.time() - cached.get("cached_at", 0)
        if age > LATEST_CACHE_TTL:
            return [], None  # expired
        return cached.get("advisories", []), round(age / 3600, 1)
    except Exception:
        return [], None


def _fetch_latest_advisories() -> list:
    """Fetch latest 50 advisories from Cisco PSIRT API (all platforms)."""
    provider = CiscoAdvisoryProvider()
    creds = provider._load_credentials()
    if not creds:
        return []

    api_base = creds.get("api_base", "https://apix.cisco.com/security/advisories/v2")
    url = f"{api_base}/latest/50"
    data = provider._api_get(url)
    if not data:
        return []

    advisories = data.get("advisories", [])

    # Cache it
    os.makedirs(CISCO_CACHE_DIR, exist_ok=True)
    try:
        with open(LATEST_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump({"cached_at": time.time(), "advisories": advisories}, f)
    except Exception:
        pass

    return advisories


def _advisories_to_feed(advisories: list, platform_filter: str = "all") -> list:
    """Convert raw advisories to FeedItem list with optional platform filter."""
    html_tag_re = re.compile(r"<[^>]+>")
    feed_items = []

    for adv in advisories:
        sir = (adv.get("sir") or "").lower()
        if sir not in ("critical", "high", "medium"):
            continue

        # Platform filter
        products = adv.get("productNames") or []
        if platform_filter != "all":
            product_text = " ".join(products).lower()
            if platform_filter == "iosxe" and "ios xe" not in product_text:
                continue
            elif platform_filter == "ios" and ("ios" not in product_text or "ios xe" in product_text):
                continue
            elif platform_filter == "nxos" and "nx-os" not in product_text:
                continue
            elif platform_filter == "asa" and "asa" not in product_text and "adaptive security" not in product_text:
                continue
            elif platform_filter == "ftd" and "firepower" not in product_text and "ftd" not in product_text:
                continue

        cves = adv.get("cves") or []
        cve_id = cves[0] if cves else adv.get("advisoryId", "N/A")

        cvss = None
        cvss_raw = adv.get("cvssBaseScore")
        if cvss_raw:
            try:
                cvss = float(cvss_raw)
            except (ValueError, TypeError):
                pass

        feed_items.append(FeedItem(
            cve_id=cve_id,
            title=adv.get("advisoryTitle", ""),
            severity=sir,
            cvss=cvss,
            published=adv.get("firstPublished"),
            updated=adv.get("lastUpdated"),
            url=adv.get("publicationUrl"),
            platforms=products[:3],
        ))

    # Sort: newest first, then severity, then CVSS
    feed_items.sort(
        key=lambda x: (x.updated or "0", 0 if x.severity == "critical" else -1, x.cvss or 0),
        reverse=True,
    )
    return feed_items


def _load_platform_cache(platform: str) -> list:
    """Load platform-specific cache (e.g. iosxe.json) if available."""
    cache_path = os.path.join(CISCO_CACHE_DIR, f"{platform}.json")
    if not os.path.exists(cache_path):
        return []
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            cached = json.load(f)
        # Accept even if expired — better stale data than none for platform filter
        return cached.get("advisories", [])
    except Exception:
        return []


def _merge_advisories(*sources: list) -> list:
    """Merge multiple advisory lists, deduplicate by advisoryId."""
    seen = set()
    merged = []
    for src in sources:
        for adv in src:
            aid = adv.get("advisoryId", "")
            if aid and aid not in seen:
                seen.add(aid)
                merged.append(adv)
    return merged


@router.get("/critical-feed", response_model=CriticalFeedResponse)
def get_critical_feed(platform: str = "all"):
    """
    Returns latest CVEs from Cisco PSIRT (all platforms).
    Optional filter: ?platform=iosxe|ios|nxos|asa|ftd|all
    Auto-fetches from API on first call.
    """
    advisories, cache_age_hours = _load_latest_cache()

    # No cache? Fetch from API
    if not advisories:
        try:
            advisories = _fetch_latest_advisories()
            if advisories:
                cache_age_hours = 0.0
        except Exception as e:
            print(f"[WARN] Auto-fetch for critical feed failed: {e}")

    # When filtering by platform, also include platform-specific cache
    # (latest/50 may not contain that platform's advisories)
    if platform != "all":
        platform_advisories = _load_platform_cache(platform)
        if not platform_advisories:
            # No platform cache — try fetching it
            try:
                provider = CiscoAdvisoryProvider(platform=platform)
                creds = provider._load_credentials()
                if creds:
                    provider.load()  # fetches + writes platform cache
                    platform_advisories = _load_platform_cache(platform)
            except Exception:
                pass
        if platform_advisories:
            advisories = _merge_advisories(advisories, platform_advisories)

    feed_items = _advisories_to_feed(advisories, platform)

    return CriticalFeedResponse(
        items=feed_items[:10],
        total_advisories=len(advisories),
        cache_age_hours=cache_age_hours,
        timestamp=datetime.datetime.utcnow().isoformat() + "Z",
    )
