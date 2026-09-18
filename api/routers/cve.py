import datetime
import json
import os
import re
import threading
import time
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services.cve_engine import CVEEngine, CVEEngineConfig, data_dir_for_platform, is_bundled_cve, severity_info, detect_bundle, data_confidence, coverage_uncertain_ids, published_date_demoted_ids
from services.eol_registry import detect_eol
from services.provenance import cve_provenance


# Read once at module load so the response footer matches the running build.
def _read_app_version() -> str:
    """Read app version from api/main.py without importing it (avoids
    circular import). Picks the LAST `version="..."` literal — that's the
    canonical /meta/version value, after the FastAPI(version=...) declaration."""
    try:
        main_path = os.path.join(os.path.dirname(__file__), "..", "main.py")
        last = None
        with open(main_path, "r") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith("version=\""):
                    last = stripped.split("\"")[1]
        return last or "unknown"
    except Exception:
        return "unknown"


_APP_VERSION = _read_app_version()
from services.cve_sources import NvdEnricherProvider, CiscoAdvisoryProvider, CISCO_CACHE_DIR
from services.hardening_release import bundled_info_from_advisory
from services import kev_catalog
from services.platform_taxonomy import ProductFamily, detect_all_families, is_cve_in_scope_for_query
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
    # v0.6.21: when the engine returns an "upgrade to X" suggestion but the
    # platform is EoL, recommended_upgrade is rewritten to "hardware
    # replacement required". This field preserves the original engine
    # suggestion so an operator can see what the patch path WOULD have been
    # if the hardware were still supported.
    original_engine_recommendation: Optional[str] = None
    # v0.3.6 P1.3 severity transparency: per-CVE details including CVSS rating
    # derived from score, effective label, and escalation reason (KEV / actively
    # exploited) when the displayed label differs from the raw CVSS rating.
    # v0.6.16 CVE-007: adds cisco_sir + primary_severity fields. Primary is
    # CVSS v3.x NVD bucket when score is known; Cisco SIR is secondary.
    # Keyed by CVE ID; empty {} if no matches.
    severity_details: dict = {}
    # v0.6.16 CVE-010: per-CVE bundled-publication identifier
    # (e.g. "2025-09" for Cisco's September 2025 semi-annual bundle).
    # Keyed by CVE ID; value None if CVE is not part of a bundle.
    bundles: dict = {}
    # v0.6.23 CVE-006 transparency: per-CVE data quality annotation.
    # Values: "verified" / "max-bound" / "uncertain". Keyed by CVE ID.
    # Shows operators which records have a concrete fix version (verified)
    # vs. PSIRT-import records matched only by `affected.max` (less
    # reliable, may show false positives on post-fix versions). Pending
    # full CVE-006 closure in W19+ sprint.
    data_quality: dict = {}
    # v0.6.24 CVE-006 Phase 5: CVE IDs whose coverage is uncertain —
    # matched by PSIRT max-bound only (no verified fix version). UI may
    # render these in a collapsed secondary section. IDs are a SUBSET of
    # `matched`; `matched` still contains the full list for backward
    # compat with existing clients. Empty list when all matches are
    # verified (local-json path with curated fix_version).
    coverage_uncertain: List[str] = []
    # CVE-007 (2026-09-18): IDs of matched CVEs that are Cisco hardening-release
    # CVEs — one CVE per CWE category, i.e. a class of defects rather than a
    # single bug. SUBSET of `matched`. The UI marks these so nobody reads a
    # category as one patchable vulnerability.
    bundled_cves: List[str] = []
    # v0.6.18 CVE-009: end-of-life status for the queried platform.
    # When non-null, the UI renders a top-banner above the CVE list:
    # "no patches available; replace the hardware". The recommendation
    # engine output below is informational on EoL platforms.
    eol_status: Optional[dict] = None
    # v0.6.19 XCUT-002: provenance / audit-trail metadata. Carries tool +
    # engine + ruleset versions, per-source freshness (ISO + age_hours),
    # and the source distribution across matched CVEs. Rendered as a
    # collapsible footer in the UI; required for compliance evidence use.
    provenance: dict = {}
    # Policy note for the report footer.
    severity_policy: str = (
        "Primary severity uses the NVD CVSS v3.x qualitative scale "
        "(None/Low/Medium/High/Critical). When Cisco's Security Impact Rating "
        "(SIR) differs from the CVSS bucket, it is shown as a secondary tag. "
        "CISA KEV / actively-exploited flags are surfaced separately, not as "
        "severity escalations."
    )
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
    # ISE-02 (2026-09-18) — where this row came from. "psirt" = live Cisco
    # PSIRT API (needs credentials), "local" = curated cve_data/ record. The
    # UI labels local rows so a stale dataset is never mistaken for a live feed.
    source: str = "psirt"
    # ISE-02 — CISA KEV status, surfaced SEPARATELY from severity per the
    # policy in CVEAnalyzeResponse.severity_policy: being in KEV is evidence
    # of exploitation, not a higher CVSS. None = not in KEV as of last import.
    kev: Optional[dict] = None
    # CVE-007 — set on rows that are a Cisco hardening release. The row is
    # labelled with one CVE id (PSIRT rows use cves[0]) but stands for
    # `cve_count` CVEs, each of which is a CWE category rather than one defect.
    # Without this the feed shows "CVE-2026-20130 10.0" and reads as one bug.
    bundled: Optional[dict] = None


class CriticalFeedResponse(BaseModel):
    items: List[FeedItem]
    total_advisories: int
    cache_age_hours: Optional[float]
    timestamp: str
    # KEV-X: which CISA KEV catalog the badges were checked against. None means
    # no catalog was obtainable, so a missing badge proves nothing.
    kev_catalog_version: Optional[str] = None
    # CACHE-01: age of the platform-specific cache behind a filtered view, and
    # whether a background refresh was started for it. None on the "all" view.
    # The UI warns when this is old instead of presenting it as current.
    platform_cache_age_hours: Optional[float] = None
    platform_cache_refreshing: bool = False


def _env_true(name: str) -> bool:
    v = os.getenv(name, "").strip().lower()
    return v in ("1", "true", "yes", "on")


def _apply_kev_catalog(entries: list) -> list:
    """Set `kev` on matched CVEs from the live catalog, then re-rank.

    The catalog wins on dates; a curated local block keeps its `directive` when
    the catalog note names none. Entries absent from the catalog keep whatever
    they had — a local KEV block is never erased by a lookup miss, since a miss
    can also mean "no catalog was obtainable".
    """
    from models.cve_model import CVEKevStatus

    for entry in entries:
        hit = kev_catalog.kev_status(entry.cve_id)
        if hit is None:
            continue
        local_directive = entry.kev.directive if entry.kev is not None else None
        entry.kev = CVEKevStatus(
            date_added=hit.get("date_added") or "",
            due_date=hit.get("due_date") or "",
            catalog_version=hit.get("catalog_version"),
            directive=hit.get("directive") or local_directive,
        )
    return CVEEngine._sort_matched(entries)


@router.post("/cve", response_model=CVEAnalyzeResponse)
def analyze_cve(req: CVEAnalyzeRequest):
    # 1) Base run (local JSON only) to find which CVE IDs apply.
    # ISE-03: the dataset directory follows the queried product family —
    # an ISE query must read cve_data/ise, not the IOS XE default.
    base_engine = CVEEngine(config=CVEEngineConfig(
        engine_version="0.3.7", data_dir=data_dir_for_platform(req.platform)))
    base_engine.load_all()
    matched_base = base_engine.match(req.platform, req.version)

    # KEV-X: stamp live CISA KEV status on the matches. Done on the base run so
    # it applies whether or not NVD enrichment is enabled.
    _apply_kev_catalog(matched_base)

    # 2) Optional enrichment from NVD for ONLY those CVEs (fast + cheap + avoids scanning the whole world)
    if _env_true("CVE_NVD_ENRICH") and matched_base:
        ids = [c.cve_id for c in matched_base]
        # Build a new engine with local + NVD enricher (IDs)
        enriched_engine = CVEEngine(
            config=CVEEngineConfig(engine_version="0.3.7", enable_nvd_enrichment=True),
            providers=[
                # Keep local base provider first (created internally)
                *base_engine.providers[:1],
                NvdEnricherProvider(cve_ids=ids),
            ],
        )
        enriched_engine.load_all()
        matched = _apply_kev_catalog(enriched_engine.match(req.platform, req.version))
        summary = enriched_engine.summary(matched)
        recommendation = enriched_engine.recommended_upgrade(matched, req.platform, req.version) if req.include_suggestions else None
    else:
        matched = matched_base
        summary = base_engine.summary(matched)
        recommendation = base_engine.recommended_upgrade(matched, req.platform, req.version) if req.include_suggestions else None

    # v0.3.6 P1.3 + v0.6.16 CVE-007: per-CVE severity transparency map.
    severity_details = {cve.cve_id: severity_info(cve) for cve in matched}
    # v0.6.16 CVE-010: bundled-publication lookup per CVE.
    bundles = {cve.cve_id: detect_bundle(cve) for cve in matched}
    # v0.6.23: per-CVE data-quality confidence (verified/max-bound/uncertain).
    data_quality = {cve.cve_id: data_confidence(cve) for cve in matched}
    # v0.6.24 CVE-006 Phase 5: flag subset of CVE IDs with uncertain coverage
    # (anything NOT "verified"). Pure post-process, additive, zero impact on
    # `matched` semantics.
    # v0.6.24 CVE-006 Phase 6: union with published-date heuristic — CVEs
    # published >3 years before the target version release date AND without
    # a per-family fix are likely patched in intermediate releases. Flag them
    # as uncertain so the UI can render informationally.
    _base_uncertain = coverage_uncertain_ids(matched)
    _stale_ids = published_date_demoted_ids(matched, req.platform, req.version)
    # Dedupe while preserving order: base list first, then stale IDs not
    # already present. Deterministic for snapshot tests.
    _seen = set(_base_uncertain)
    coverage_uncertain_list = list(_base_uncertain)
    for cid in _stale_ids:
        if cid not in _seen:
            coverage_uncertain_list.append(cid)
            _seen.add(cid)
    # v0.6.18 CVE-009: EoL platform check (independent of CVE matches —
    # populated even when matched is empty).
    eol_status = detect_eol(req.platform, req.version)

    # v0.6.21: when the platform is EoL, the engine's "upgrade to X" output
    # is misleading — there is no patch path. Override the displayed
    # recommendation with a hardware-replacement message but preserve the
    # engine's original suggestion in a separate field for context.
    original_recommendation = recommendation
    if eol_status and eol_status.get("is_eol"):
        replacement_hint = ""
        hw = eol_status.get("hardware") or {}
        if hw.get("replacement_suggestion"):
            replacement_hint = f" Suggested replacement: {hw['replacement_suggestion']}."
        recommendation = (
            f"Hardware replacement required — platform is past "
            f"end-of-vulnerability-security-support. Software upgrade is not a "
            f"remediation path on this device.{replacement_hint}"
        )

    # v0.6.19 XCUT-002: provenance footer.
    provenance = cve_provenance(
        tool_version=_APP_VERSION,
        cve_engine_version="0.3.7",
        matched_cves=matched,
    )

    return CVEAnalyzeResponse(
        platform=req.platform,
        version=req.version,
        matched=matched,
        summary=summary,
        recommended_upgrade=recommendation,
        original_engine_recommendation=original_recommendation,
        severity_details=severity_details,
        bundles=bundles,
        data_quality=data_quality,
        coverage_uncertain=coverage_uncertain_list,
        bundled_cves=[c.cve_id for c in matched if is_bundled_cve(c)],
        eol_status=eol_status,
        provenance=provenance,
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
    engine = CVEEngine(config=CVEEngineConfig(engine_version="0.3.7"))
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
            config=CVEEngineConfig(engine_version="0.3.7", enable_nvd_enrichment=True),
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


def _kev_block(hit: Optional[dict], local: Optional[dict] = None) -> Optional[dict]:
    """Merge a live catalog hit with a curated local KEV block.

    KEV-X: the catalog is authoritative for dates (it is live, the local record
    is a snapshot). The local block only fills what the catalog does not carry —
    today that is `directive`, when the catalog note names none.
    """
    if hit is None and local is None:
        return None
    if hit is None:
        return dict(local)
    block = {
        "cve_id": hit.get("cve_id"),
        "date_added": hit.get("date_added"),
        "due_date": hit.get("due_date"),
        "catalog_version": hit.get("catalog_version"),
        "directive": hit.get("directive") or (local or {}).get("directive"),
        "ransomware": hit.get("ransomware"),
    }
    return block


# KEV-X: how long a KEV listing keeps its place at the top of the feed.
KEV_PRIORITY_WINDOW_DAYS = 30


def _today() -> datetime.date:
    """Indirection so tests can freeze the clock (see tests/conftest.py)."""
    return datetime.date.today()


def _kev_is_fresh(kev: Optional[dict], today: Optional[datetime.date] = None) -> bool:
    """True while a KEV listing is recent enough to outrank newer advisories.

    With the whole catalog in play, "KEV first" without a time limit would put
    2023 entries above this week's advisories and turn "Latest Threats" into a
    historical list. A KEV badge is a permanent fact and always shown; the
    ranking boost is news, and news expires. Unparseable dates get no boost.
    """
    if not kev:
        return False
    today = today or _today()
    try:
        added = datetime.date.fromisoformat((kev.get("date_added") or "")[:10])
    except ValueError:
        return False
    return (today - added).days <= KEV_PRIORITY_WINDOW_DAYS


def _sort_feed_items(feed_items: list) -> None:
    """Order the threat feed in place: fresh KEV first, then newest, severity, CVSS.

    Putting CISA KEV entries on top is triage ordering, not a severity
    escalation — the row keeps its own CVSS and severity, exactly as required
    by CVEAnalyzeResponse.severity_policy. What changes is position: a
    vulnerability under active exploitation with a federal deadline is the one
    an operator needs to see first, regardless of how it scored.
    """
    feed_items.sort(
        key=lambda x: (
            1 if _kev_is_fresh(getattr(x, "kev", None)) else 0,
            x.updated or "0",
            0 if x.severity == "critical" else -1,
            x.cvss or 0,
        ),
        reverse=True,
    )


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
            elif platform_filter == "ise" and (
                "identity services engine" not in product_text and "ise" not in product_text.split()
            ):
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

        # KEV-X: a row is labelled with cves[0] but stands for the whole
        # advisory, and the exploited CVE can be any of them.
        kev_block = _kev_block(kev_catalog.first_kev_hit(cves))

        binfo = bundled_info_from_advisory(adv)
        bundled_block = None
        if binfo is not None:
            bundled_block = {
                "cve_count": len(binfo.sibling_cves),
                "cwe_categories": binfo.cwe_categories,
                "one_cve_per_cwe": binfo.one_cve_per_cwe,
            }

        feed_items.append(FeedItem(
            cve_id=cve_id,
            title=adv.get("advisoryTitle", ""),
            severity=sir,
            cvss=cvss,
            published=adv.get("firstPublished"),
            updated=adv.get("lastUpdated"),
            url=adv.get("publicationUrl"),
            platforms=products[:3],
            kev=kev_block,
            bundled=bundled_block,
        ))

    _sort_feed_items(feed_items)
    return feed_items


# ISE-02 (2026-09-18) — local dataset fallback for the threat feed.
#
# The feed was PSIRT-only: without Cisco API credentials it rendered "No threat
# data available" forever. Curated records in cve_data/<dir>/ are a real source
# with real provenance (advisory CVRF + NVD + KEV), so they now feed the widget
# too. PSIRT still wins on conflict — it is live, the local set is a snapshot.
_LOCAL_DATA_DIRS = {
    "ise": "ise",
    "iosxe": "ios_xe",
}

# CACHE-01: product family each local directory is supposed to contain. The IOS
# XE directory also holds records the PSIRT importer mislabelled (RV320 routers,
# ASA, CUCM, FMC, SSM On-Prem, AP software). The engine drops those with the
# taxonomy at match time; the feed read the directory raw and showed them under
# the "IOS XE" filter.
_LOCAL_DATA_FAMILIES = {
    "ise": ProductFamily.ISE,
    "iosxe": ProductFamily.IOS_XE,
}

# What a record's own `platforms` field must say for it to belong to a view.
# Curated records for other products (FMC, SD-WAN Controller) sit in the IOS XE
# directory with correct `platforms`; the taxonomy cannot always name them from
# the title alone, but the record itself already does.
_LOCAL_PLATFORM_TOKENS = {
    "ise": ("ise", "ise-pic"),
    "iosxe": ("ios xe", "ios-xe", "iosxe"),
}


def _record_belongs_to(platform: str, entry) -> bool:
    """Record-level platform check for the local feed fallback."""
    family = _LOCAL_DATA_FAMILIES.get(platform)
    if family is not None and family.value in (entry.product_families or []):
        return True
    tokens = _LOCAL_PLATFORM_TOKENS.get(platform)
    if not tokens:
        return True
    declared = [(p or "").strip().lower() for p in (entry.platforms or [])]
    return any(d in tokens for d in declared)


# Platform label shown on locally-sourced rows.
_LOCAL_PLATFORM_LABELS = {
    "ise": ["ISE", "ISE-PIC"],
    "iosxe": ["IOS XE"],
}


def _local_records_to_feed(platform: str) -> list:
    """Build FeedItems from curated cve_data/<platform>/ records.

    Returns [] for platforms with no local directory. Records that fail to
    parse are skipped rather than raising: a malformed file must not take the
    whole home page down.
    """
    subdir = _LOCAL_DATA_DIRS.get(platform)
    if not subdir:
        return []
    data_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "cve_data", subdir
    )
    data_dir = os.path.normpath(data_dir)
    if not os.path.isdir(data_dir):
        return []

    items = []
    for name in sorted(os.listdir(data_dir)):
        if not name.endswith(".json") or name.startswith("_"):
            continue
        try:
            with open(os.path.join(data_dir, name), "r", encoding="utf-8") as f:
                raw = json.load(f)
            entry = CVEEntry(**raw)
        except Exception:
            continue

        if not _record_belongs_to(platform, entry):
            continue

        # Same scope rule the engine applies in CVEEngine.match().
        family = _LOCAL_DATA_FAMILIES.get(platform)
        if family is not None:
            detected = detect_all_families(entry.title or "", entry.description or "")
            if not is_cve_in_scope_for_query(family, detected):
                continue

        local_kev = None
        if entry.kev is not None:
            local_kev = {
                "cve_id": entry.cve_id,
                "date_added": entry.kev.date_added,
                "due_date": entry.kev.due_date,
                "catalog_version": entry.kev.catalog_version,
                "directive": entry.kev.directive,
            }
        kev_block = _kev_block(kev_catalog.kev_status(entry.cve_id), local_kev)

        items.append(FeedItem(
            cve_id=entry.cve_id,
            title=entry.title,
            severity=(entry.severity or "").lower(),
            cvss=entry.cvss_score,
            published=entry.published,
            updated=entry.last_modified or entry.published,
            url=entry.advisory_url,
            platforms=(entry.platforms or _LOCAL_PLATFORM_LABELS.get(platform, []))[:3],
            source="local",
            kev=kev_block,
            bundled=(
                {
                    "cve_count": len(entry.bundled.sibling_cves),
                    "cwe_categories": entry.bundled.cwe_categories,
                    "one_cve_per_cwe": entry.bundled.one_cve_per_cwe,
                } if entry.bundled is not None else None
            ),
        ))
    return items


def _merge_feed_items(psirt_items: list, local_items: list) -> list:
    """Merge PSIRT and local rows into one advisory-granular list.

    Two different granularities meet here. A PSIRT row represents an *advisory*
    (`_advisories_to_feed` labels it with `cves[0]`), while a local record is
    one *CVE*. Merging on CVE id alone let a single advisory occupy six of the
    ten slots: the Cisco ISE hardening release carries six CVEs, and each one
    is its own file in cve_data/. So dedup happens on both keys — CVE id, and
    advisory URL.

    Precedence: PSIRT wins (live data beats a snapshot). But a local row that
    carries KEV status donates it to whichever row represents that advisory —
    the PSIRT API does not expose KEV, and dropping an active-exploitation flag
    during a merge would silently remove the most important signal on the page.
    """
    by_id = {}
    by_url = {}
    order = []

    for item in psirt_items:
        if item.cve_id in by_id:
            continue
        by_id[item.cve_id] = item
        if item.url:
            by_url.setdefault(item.url, item)
        order.append(item.cve_id)

    for item in local_items:
        existing = by_id.get(item.cve_id) or (by_url.get(item.url) if item.url else None)
        if existing is not None:
            # Same CVE, or a different CVE from an advisory already on the list.
            if existing.kev is None and item.kev is not None:
                existing.kev = item.kev
            continue
        by_id[item.cve_id] = item
        if item.url:
            by_url.setdefault(item.url, item)
        order.append(item.cve_id)

    return [by_id[i] for i in order]


PLATFORM_CACHE_TTL = 6 * 3600           # matches the provider's own TTL
PLATFORM_REFRESH_BACKOFF = 15 * 60      # after a failed refresh, wait 15 min

# platform -> epoch of the last refresh attempt that did not produce data
_platform_refresh_failed_at: dict = {}
# platforms with a refresh currently running
_platform_refresh_running: set = set()
_platform_refresh_lock = threading.Lock()


def _load_platform_cache(platform: str) -> list:
    """Load platform-specific cache (e.g. iosxe.json) if available.

    Expired data is still returned — better stale than empty for a platform
    filter — but see _platform_cache_age_hours(): the feed no longer keeps
    serving it forever without saying so or trying to replace it.
    """
    cache_path = os.path.join(CISCO_CACHE_DIR, f"{platform}.json")
    if not os.path.exists(cache_path):
        return []
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            cached = json.load(f)
        return cached.get("advisories", [])
    except Exception:
        return []


def _platform_cache_age_hours(platform: str) -> Optional[float]:
    """Age of the platform cache in hours, or None when there is none."""
    cache_path = os.path.join(CISCO_CACHE_DIR, f"{platform}.json")
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            cached_at = json.load(f).get("cached_at", 0)
        return round((time.time() - cached_at) / 3600, 1)
    except Exception:
        return None


def _refresh_platform_cache(platform: str) -> None:
    """Fetch a platform's advisories through the provider. Runs off-request."""
    try:
        provider = CiscoAdvisoryProvider(platform=platform)
        if not provider._load_credentials():
            _platform_refresh_failed_at[platform] = time.time()
            return
        provider.load()  # honours the provider TTL, writes <platform>.json
        age = _platform_cache_age_hours(platform)
        if age is None or age * 3600 > PLATFORM_CACHE_TTL:
            _platform_refresh_failed_at[platform] = time.time()
    except Exception as e:
        _platform_refresh_failed_at[platform] = time.time()
        print(f"[WARN] Platform cache refresh failed for {platform}: {e}")
    finally:
        with _platform_refresh_lock:
            _platform_refresh_running.discard(platform)


def _spawn(target, *args) -> None:
    """Indirection so tests can run or suppress background work."""
    threading.Thread(target=target, args=args, daemon=True).start()


def _refresh_platform_cache_in_background(platform: str) -> bool:
    """Start a refresh unless one is running or one just failed. True if started.

    CACHE-01: stale-while-revalidate. A full platform pull is up to five PSIRT
    pages with a 2 s pause between them; the home page must never wait on that.
    The request is answered from whatever is on disk and the next one benefits.
    """
    now = time.time()
    with _platform_refresh_lock:
        if platform in _platform_refresh_running:
            return False
        if now - _platform_refresh_failed_at.get(platform, 0) < PLATFORM_REFRESH_BACKOFF:
            return False
        _platform_refresh_running.add(platform)
    _spawn(_refresh_platform_cache, platform)
    return True


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


def _get_advisories_feed(platform: str = "all"):
    """Shared implementation for advisories endpoints."""
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
    platform_age_hours = None
    platform_refreshing = False
    if platform != "all":
        platform_advisories = _load_platform_cache(platform)
        platform_age_hours = _platform_cache_age_hours(platform)
        # CACHE-01: missing or expired -> refresh off-request, answer from what
        # is on disk. Previously an existing file was used forever (the IOS XE
        # cache reached 189 days) and a missing one blocked the page on a
        # multi-page PSIRT pull.
        if platform_age_hours is None or platform_age_hours * 3600 > PLATFORM_CACHE_TTL:
            platform_refreshing = _refresh_platform_cache_in_background(platform)
        if platform_advisories:
            advisories = _merge_advisories(advisories, platform_advisories)

    feed_items = _advisories_to_feed(advisories, platform)

    # ISE-02: fold in curated local records. For "all" we pull every local
    # directory, so a platform with no PSIRT coverage (ISE before credentials
    # are configured) is still visible on the default view.
    local_platforms = [platform] if platform != "all" else list(_LOCAL_DATA_DIRS)
    local_items = []
    for lp in local_platforms:
        local_items.extend(_local_records_to_feed(lp))
    if local_items:
        feed_items = _merge_feed_items(feed_items, local_items)
        _sort_feed_items(feed_items)

    return CriticalFeedResponse(
        items=feed_items[:10],
        total_advisories=len(advisories) + len(local_items),
        cache_age_hours=cache_age_hours,
        timestamp=datetime.datetime.utcnow().isoformat() + "Z",
        kev_catalog_version=kev_catalog.catalog_version(),
        platform_cache_age_hours=platform_age_hours,
        platform_cache_refreshing=platform_refreshing,
    )


# v0.6.6 (2026-04-19) — route rename to avoid ad-blocker false positive.
# Arc / Brave / uBlock Origin heuristics flagged "/analyze/critical-feed"
# because the "critical-feed" suffix pattern matches ad/tracking feed naming
# conventions. The new route uses neutral "advisories" language. The old
# route is kept as an alias for any cached browser clients.
@router.get("/advisories", response_model=CriticalFeedResponse)
def get_advisories(platform: str = "all"):
    """
    Returns latest Cisco PSIRT security advisories.
    Optional filter: ?platform=iosxe|ios|nxos|asa|ftd|all
    """
    return _get_advisories_feed(platform)


@router.get("/critical-feed", response_model=CriticalFeedResponse, deprecated=True)
def get_critical_feed_alias(platform: str = "all"):
    """DEPRECATED: use /advisories instead. Kept for backward compat."""
    return _get_advisories_feed(platform)
