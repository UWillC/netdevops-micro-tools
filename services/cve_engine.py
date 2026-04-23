import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from models.cve_model import CVEEntry
from services.cve_sources import (
    CVEProvider,
    LocalJsonProvider,
    NvdEnricherProvider,
    CiscoAdvisoryProvider,
    TenableProvider,
)
from services.platform_taxonomy import (
    ProductFamily,
    detect_all_families,
    normalize_user_platform,
    is_cve_in_scope_for_query,
)


# -----------------------------
# Version parsing & comparison (v0.3+)
# -----------------------------
# Sentinels for unbounded ranges: min=all → (-inf), max=all → (+inf)
_MIN_SENTINEL: Tuple[int, ...] = (-1,)
_MAX_SENTINEL: Tuple[int, ...] = (10**9,)

# Regex family for version extraction.
# - IOS classic: "15.7(3)M5" → (15, 7, 3, 0, 5) where 4th position is M-train indicator
# - Dotted generic: "17.15.4a", "1.4.2.19", "9.8.1" → variable length + optional rebuild letter
_IOS_CLASSIC_RE = re.compile(r"(\d+)\.(\d+)\((\d+)\)[Mm](\d+)")
_DOTTED_VERSION_RE = re.compile(r"(\d+(?:\.\d+)+)([a-z])?")


def _extract_version(text: str) -> Optional[Tuple[int, ...]]:
    """
    Extract the first version-like token from free text. Returns tuple or None.

    v0.3.5 (2026-04-19 evening): fixed regex to handle arbitrary-depth dotted
    versions. Previously truncated "1.4.2.19" → (1, 4, 2, 0), losing the .19
    component. Now parses all dot-separated numeric parts preserving order.
    """
    if not text:
        return None

    # IOS classic format: "15.7(3)M5" style
    m = _IOS_CLASSIC_RE.search(text)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0, int(m.group(4)))

    # Generic dotted format: any number of .-separated integers + optional rebuild letter
    m = _DOTTED_VERSION_RE.search(text)
    if m:
        dotted = m.group(1)
        letter = m.group(2)
        try:
            parts = [int(p) for p in dotted.split(".")]
        except ValueError:
            return None
        if letter:
            # rebuild letter → small tiebreaker (a=1, b=2, ...)
            parts.append(ord(letter.lower()) - ord("a") + 1)
        return tuple(parts)

    return None


def _tokenize_version(v: str) -> Tuple[int, ...]:
    """Parse a plain version string (best-effort). Used for target versions."""
    v = (v or "").strip()
    if not v:
        return (0,)

    # First try the regex extractor (handles "17.15.4a" cleanly).
    extracted = _extract_version(v)
    if extracted:
        return extracted

    # Fallback: strip to digits + dots only.
    cleaned = []
    for ch in v:
        if ch.isdigit() or ch == ".":
            cleaned.append(ch)
        else:
            break

    s = "".join(cleaned).strip(".")
    if not s:
        return (0,)

    parts = s.split(".")
    nums: List[int] = []
    for p in parts:
        try:
            nums.append(int(p))
        except ValueError:
            nums.append(0)

    while len(nums) < 3:
        nums.append(0)

    return tuple(nums)


def _cmp_tuples(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    """Compare two version tuples, padding with zeros."""
    max_len = max(len(a), len(b))
    pa = a + (0,) * (max_len - len(a))
    pb = b + (0,) * (max_len - len(b))
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


def compare_versions(a: str, b: str) -> int:
    return _cmp_tuples(_tokenize_version(a), _tokenize_version(b))


# v0.3.5 (2026-04-19) — P2.1 placeholder detection
_PROSE_FIXED_IN_MARKERS = (
    "migrate to", "upgrade to a supported", "remove default",
    "disable ", "do not use", "consult ", "see cisco advisory",
    "n/a", "not applicable", "eol", "end of life",
)


def _is_prose_not_version(fixed_in: str) -> bool:
    """
    Detect placeholder fixed_in values that are advisory prose rather than
    actual version strings. Used to skip CVEs that aren't true applicability
    findings (e.g. CVE-2026-28775 with fixed_in="Migrate to SNMPv3...").
    """
    if not fixed_in:
        return False
    low = fixed_in.strip().lower()
    if len(low) < 3:
        return False
    # If the string contains no digits at all, it's almost certainly prose.
    if not any(ch.isdigit() for ch in low):
        return True
    # If it starts with prose markers, treat as hardening rule.
    for marker in _PROSE_FIXED_IN_MARKERS:
        if marker in low:
            return True
    return False


# v0.3.6 (2026-04-19) — P1.3 severity transparency helpers
def cvss_rating_from_score(score: Optional[float]) -> str:
    """
    Return NVD CVSS v3.x qualitative severity rating for a given score.
    Reference: https://nvd.nist.gov/vuln-metrics/cvss
    """
    if score is None:
        return "UNKNOWN"
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


_ESCALATION_TAGS = {
    "kev": "Listed in CISA KEV catalog",
    "actively-exploited": "Actively exploited in the wild",
    "zero-day": "Zero-day (exploited before patch)",
    "exploited-in-wild": "Actively exploited in the wild",
}


def _escalation_reason(tags: Optional[List[str]]) -> Optional[str]:
    """
    Return human-readable escalation reason if the CVE has any risk-escalation
    tags (KEV / actively-exploited / zero-day). Returns None for normal CVEs.
    """
    if not tags:
        return None
    low = [t.lower() for t in tags]
    reasons = []
    for tag, reason in _ESCALATION_TAGS.items():
        if tag in low and reason not in reasons:
            reasons.append(reason)
    if not reasons:
        return None
    return " + ".join(reasons)


def severity_info(cve: "CVEEntry") -> Dict[str, Optional[str]]:
    """
    Compute severity transparency info for a CVE entry.

    Severity policy (CVE-007, v0.6.16):
    - Primary severity = NVD CVSS v3.x bucket derived from `cvss_score`.
    - Cisco SIR = Cisco's Security Impact Rating, distinct scale (stored in
      `cisco_sir` if different from the primary).
    - KEV / actively-exploited / zero-day flags are shown as additional tags,
      not as severity escalations (operators should see the raw CVSS and
      judge escalation themselves).

    Returns dict with:
      cvss_score (float)          — raw CVSS base score
      cvss_rating (str)           — NVD qualitative rating (primary severity)
      cisco_sir (str|None)        — Cisco SIR if distinct from CVSS bucket
      effective_label (str)       — what the tool currently displays (legacy)
      escalation_reason (str|None)— KEV / actively-exploited marker if any
      label_matches_cvss (bool)   — True if current label == CVSS bucket
      primary_severity (str)      — canonical severity the UI should render
                                     (= cvss_rating when score is known,
                                        else effective_label)
    """
    score = getattr(cve, "cvss_score", None)
    tags = getattr(cve, "tags", None) or []
    cvss = cvss_rating_from_score(score)
    label = (getattr(cve, "severity", "") or "").upper()
    explicit_sir = getattr(cve, "cisco_sir", None)
    reason = _escalation_reason(tags)

    # Determine what the UI should treat as primary severity.
    if score is not None:
        primary = cvss
    else:
        primary = label or "UNKNOWN"

    # Determine secondary Cisco SIR tag.
    # - If cisco_sir is explicitly set on the entry, trust it.
    # - Else, if the curated `severity` label differs from the CVSS bucket,
    #   treat the curated label as the effective Cisco SIR source.
    if explicit_sir:
        sir_display: Optional[str] = explicit_sir.upper()
    elif score is not None and label and label != cvss:
        sir_display = label
    else:
        sir_display = None

    info: Dict[str, Optional[str]] = {
        "cvss_score": score,
        "cvss_rating": cvss,
        "cisco_sir": sir_display,
        "effective_label": label,
        "escalation_reason": reason,
        "label_matches_cvss": (label == cvss) if score is not None else None,
        "primary_severity": primary,
    }
    return info


# -----------------------------
# CVE-010 — Bundled-publication detection
# -----------------------------

# Cisco publishes semi-annual IOS + IOS XE advisory bundles in March and
# September. Matching by title keeps us independent of published-date quirks
# (republished advisories carry the original publication date).
_BUNDLE_TITLE_RE = re.compile(
    r"semi?annual.*cisco.*ios(?:\s+xe)?\s+software\s+security\s+advisory\s+bundled\s+publication",
    re.IGNORECASE,
)


def data_confidence(cve: "CVEEntry") -> Dict[str, Optional[str]]:
    """Return per-CVE data-quality annotation (v0.6.23 CVE-006 transparency).

    Indicates how reliable the version-range matching is for this record,
    pending the full CVE-006 PSIRT closure in the W19+ sprint.

    Levels (highest to lowest confidence):
      verified   — EITHER `first_fixed_version.fixes` carries per-family fix
                   versions from PSIRT advisory-detail (v0.6.24 CVE-006 path),
                   OR scalar `fixed_in` is populated with a concrete version
                   (curated local-JSON records with human-entered fix).
                   Match logic uses exact-version comparison.
      max-bound  — fix version missing but `affected.max` populated. This
                   is the PSIRT-import case: matching uses `max` as last
                   tested vulnerable version, not a guaranteed fix point.
                   May show false positives on versions released well
                   after the real fix. Full fix in CVE-006 sprint.
      uncertain  — neither fix version nor bounded `affected.max`. Match
                   is range-unbounded — essentially "CVE touches this
                   platform family at some point in history". Lowest
                   confidence; treat as informational only.
    """
    # v0.6.24 (CVE-006 Phase 3) — strongest signal: per-family fixes from
    # PSIRT advisory-detail fetch. Richer than scalar fixed_in because it
    # preserves multi-family nuance (e.g. different fix per ASA vs IOS XE).
    ff = getattr(cve, "first_fixed_version", None)
    if ff is not None:
        fixes = getattr(ff, "fixes", None) or {}
        if fixes:
            families = ", ".join(sorted(fixes.keys()))
            return {
                "confidence": "verified",
                "rationale": (
                    f"Per-family fix versions from PSIRT advisory-detail "
                    f"({families}); exact-version comparison per platform path."
                ),
            }

    fix = (getattr(cve, "fixed_in", None) or "").strip()
    if fix and not _is_prose_not_version(fix):
        return {
            "confidence": "verified",
            "rationale": f"Fix version '{fix}' populated; target-version comparison is exact.",
        }

    aff = getattr(cve, "affected", None)
    mx = (getattr(aff, "max", "") or "").strip().lower() if aff else ""
    if mx and mx not in ("all", "any", "none", "*", ""):
        return {
            "confidence": "max-bound",
            "rationale": (
                "Fix version not in record. Matching uses `affected.max` "
                "as last tested vulnerable version (PSIRT-import default). "
                "May show false positives on versions released after the "
                "real fix. Full correction in CVE-006 W19+ sprint."
            ),
        }

    return {
        "confidence": "uncertain",
        "rationale": (
            "Neither fix version nor bounded version range in record. "
            "Treat as informational only; manual review against Cisco "
            "PSIRT advisory recommended."
        ),
    }


def coverage_uncertain_ids(matched: List["CVEEntry"]) -> List[str]:
    """CVE-006 Phase 5: return CVE IDs whose coverage is uncertain.

    A CVE is "uncertain" when its data_confidence classification is anything
    other than "verified" — i.e. matched via PSIRT `affected.max` only (no
    curated or per-family fix version).

    The returned IDs are a SUBSET of the input `matched` list. Callers keep
    the full `matched` list for backward compat; this helper just flags
    which subset deserves lower confidence in the UI.

    Order preserved from input (deterministic for snapshot tests).
    """
    out: List[str] = []
    for cve in matched:
        dq = data_confidence(cve)
        if dq.get("confidence") != "verified":
            out.append(cve.cve_id)
    return out


# -----------------------------
# CVE-006 Phase 6 — Published-date safety heuristic
# -----------------------------

# Loaded lazily on first use. Module-level cache (immutable dict after load).
_VERSION_RELEASE_DATES: Optional[Dict[str, Dict[str, str]]] = None

# Family name → key in the release-dates JSON. We translate user platform
# strings through the existing ProductFamily taxonomy where possible.
_FAMILY_TO_DATES_KEY = {
    "ios-xe": "IOS_XE",
    "ios": "IOS",
}

# How old a CVE must be (relative to target-version release) to trigger the
# heuristic. 3 years matches the design doc.
_STALE_CVE_YEARS = 3


def _load_version_release_dates() -> Dict[str, Dict[str, str]]:
    """Load cve_data/_version_release_dates.json once, cache module-level.

    Returns empty dict on IO/parse error — heuristic silently degrades to
    no-op. Safe to call repeatedly.
    """
    global _VERSION_RELEASE_DATES
    if _VERSION_RELEASE_DATES is not None:
        return _VERSION_RELEASE_DATES

    import json
    from pathlib import Path

    path = Path(__file__).parent.parent / "cve_data" / "_version_release_dates.json"
    try:
        with path.open() as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        _VERSION_RELEASE_DATES = {}
        return _VERSION_RELEASE_DATES

    # Drop _meta, keep only family data
    _VERSION_RELEASE_DATES = {
        k: v for k, v in raw.items() if not k.startswith("_") and isinstance(v, dict)
    }
    return _VERSION_RELEASE_DATES


def _query_version_release_date(family_key: str, version: str) -> Optional[str]:
    """Look up major.minor release date for a target version. Returns ISO date
    string (YYYY-MM-DD) or None if not found."""
    dates = _load_version_release_dates().get(family_key, {})
    # Reduce "17.9.4a" → "17.9" for lookup. Robust to prefixes like "IOS XE 17.9".
    import re
    m = re.search(r"(\d+)\.(\d+)", version or "")
    if not m:
        return None
    key = f"{m.group(1)}.{m.group(2)}"
    return dates.get(key)


def _cve_published_is_stale(
    cve_published: Optional[str],
    target_release_date: Optional[str],
    years: int = _STALE_CVE_YEARS,
) -> bool:
    """True if CVE was published more than `years` before the target version
    was released. Returns False on missing/malformed dates (heuristic never
    raises — it's a best-effort safety layer)."""
    if not cve_published or not target_release_date:
        return False
    try:
        import datetime
        # Both are ISO YYYY-MM-DD (cve.published may have time suffix stripped
        # by _parse_advisory; normalize defensively).
        pub = datetime.date.fromisoformat(cve_published[:10])
        rel = datetime.date.fromisoformat(target_release_date[:10])
    except (ValueError, TypeError):
        return False
    # 3-year threshold: roughly 365*3 = 1095 days, use date diff.
    return (rel - pub).days > years * 365


def published_date_demoted_ids(
    matched: List["CVEEntry"],
    query_platform: str,
    query_version: str,
) -> List[str]:
    """CVE-006 Phase 6: flag CVEs that are VERY OLD relative to the queried
    version AND lack a per-family fix version. These are almost certainly
    patched in some intermediate release — showing as high-confidence match
    is misleading.

    Rules:
      - Heuristic only fires when `first_fixed_version` is None/empty
        (verified per-family fix is trusted over the heuristic).
      - Requires both CVE.published AND target version release date to be
        known — missing data disables the check (fail-open).
      - 3-year threshold per design doc.

    Returns list of CVE IDs, order preserved from input. Safe to combine
    with coverage_uncertain_ids() via set union to build the final bucket.
    """
    from services.platform_taxonomy import normalize_user_platform

    # Map query platform to the dates-file key via existing taxonomy.
    family = normalize_user_platform(query_platform)
    if family is None:
        return []
    family_key = _FAMILY_TO_DATES_KEY.get(family.value)
    if family_key is None:
        return []

    target_release = _query_version_release_date(family_key, query_version)
    if not target_release:
        return []

    out: List[str] = []
    for cve in matched:
        # Skip if already has per-family fix — verified is verified.
        ff = getattr(cve, "first_fixed_version", None)
        if ff is not None and getattr(ff, "fixes", None):
            continue
        if _cve_published_is_stale(getattr(cve, "published", None), target_release):
            out.append(cve.cve_id)
    return out


def detect_bundle(cve: "CVEEntry") -> Optional[str]:
    """
    Return a canonical bundle identifier (e.g. "2025-09") if the CVE is part
    of a Cisco semi-annual bundled publication. Returns None otherwise.

    Detection strategy (first match wins):
    1. If entry already has `bundle` populated → trust it.
    2. If `title` matches the Cisco semi-annual bundle template → derive the
       bundle ID from `published` date (YYYY-MM prefix), defaulting to
       "unknown" if no date.
    3. Otherwise: None.
    """
    explicit = getattr(cve, "bundle", None)
    if explicit:
        return explicit
    title = getattr(cve, "title", "") or ""
    if not _BUNDLE_TITLE_RE.search(title):
        return None
    published = (getattr(cve, "published", "") or "")[:7]  # YYYY-MM
    return published if published else "unknown"


def parse_affected_range(
    affected_min: str, affected_max: str, fixed_in: Optional[str] = None
) -> Tuple[Tuple[int, ...], Tuple[int, ...], bool]:
    """
    Parse CVE affected.{min,max} free-text into (min_ver, max_ver, inclusive_max).

    Rules:
    - min = "all" / "any" / "" → unbounded below (MIN_SENTINEL).
    - max = "all" / "any" / "" → bounded by fixed_in (exclusive) if present, else unbounded above.
    - max containing "before <X>" → (X, inclusive_max=False).
    - max containing "<X> and earlier" / "through <X>" / "up to <X>" → (X, inclusive_max=True).
    - max with only a version token → parse as inclusive upper.
    - Any other non-parseable max → fall back to fixed_in (exclusive) if present, else unbounded.
    """
    # --- min ---
    mn = (affected_min or "").strip().lower()
    if not mn or mn in ("all", "any", "none", "*"):
        min_ver = _MIN_SENTINEL
    else:
        extracted = _extract_version(affected_min)
        min_ver = extracted if extracted else _MIN_SENTINEL

    # --- max ---
    mx = (affected_max or "").strip()
    mx_low = mx.lower()

    max_ver: Optional[Tuple[int, ...]] = None
    inclusive_max = True

    if not mx or mx_low in ("all", "any", "none", "*"):
        # Use fixed_in as exclusive upper bound if present
        fix_ver = _extract_version(fixed_in or "")
        if fix_ver:
            max_ver = fix_ver
            inclusive_max = False
        else:
            max_ver = _MAX_SENTINEL
    elif "before" in mx_low:
        # "all versions before 17.15.4a ..." → exclusive upper = 17.15.4a
        # Extract version AFTER "before"
        idx = mx_low.find("before")
        tail = mx[idx + len("before"):]
        ver = _extract_version(tail)
        if ver is None:
            # Fall back to fixed_in
            fix_ver = _extract_version(fixed_in or "")
            max_ver = fix_ver if fix_ver else _MAX_SENTINEL
            inclusive_max = fix_ver is None
        else:
            max_ver = ver
            inclusive_max = False
    elif any(k in mx_low for k in ("earlier", "through", "up to", "prior to")):
        ver = _extract_version(mx)
        if ver is None:
            fix_ver = _extract_version(fixed_in or "")
            max_ver = fix_ver if fix_ver else _MAX_SENTINEL
            inclusive_max = "prior to" in mx_low  # "prior to X" = exclusive
        else:
            max_ver = ver
            inclusive_max = "prior to" not in mx_low
    else:
        # Try plain version parse
        ver = _extract_version(mx)
        if ver:
            max_ver = ver
            inclusive_max = True
        else:
            # Unparseable → fall back to fixed_in (exclusive) or unbounded
            fix_ver = _extract_version(fixed_in or "")
            if fix_ver:
                max_ver = fix_ver
                inclusive_max = False
            else:
                max_ver = _MAX_SENTINEL

    return min_ver, max_ver, inclusive_max


# -----------------------------
# Platform normalization (v0.3+)
# -----------------------------
def normalize_platform(p: str) -> str:
    return (p or "").strip().lower()


def platform_matches(query_platform: str, cve_platforms: List[str]) -> bool:
    qp = normalize_platform(query_platform)
    if not qp:
        return False

    norm_list = [normalize_platform(x) for x in (cve_platforms or [])]

    if "ios xe" in qp:
        return True
    if "ios xe" in norm_list:
        return True

    for cp in norm_list:
        if not cp:
            continue
        if qp == cp:
            return True
        if qp in cp:
            return True
        if cp in qp:
            return True

    return False


# -----------------------------
# Engine configuration
# -----------------------------
@dataclass(frozen=True)
class CVEEngineConfig:
    engine_version: str = "0.3.7"
    data_dir: str = "cve_data/ios_xe"

    # External enrichers/providers are OFF by default
    enable_nvd_enrichment: bool = False
    enable_cisco_provider: bool = False
    enable_tenable_provider: bool = False


def _env_true(name: str) -> bool:
    v = os.getenv(name, "").strip().lower()
    return v in ("1", "true", "yes", "on")


class CVEEngine:
    """
    CVE Engine v0.3.5

    v0.3.5 (2026-04-19 evening) — CTO memo 3-platform fixes:
    - Product-family taxonomy: match() strict-filters CVEs whose titles
      explicitly identify a different family (SSM On-Prem, CUCM, Webex,
      Meraki etc. mislabeled as "IOS XE" by PSIRT importer).
    - Placeholder detection: fixed_in="Migrate to SNMPv3..." style entries
      are treated as hardening rules, not applicable CVEs.
    - ASA 9.8.1 test: 74 → 13 matches (61 cross-contamination false
      positives eliminated). IOS XE 17.9.1 test: 110 → 104 (only real
      positives). RV Series 1.4.2.22: 8 → 4 (feed gap still present).
    - Partial fix for CTO memo P0.1/P0.3 pending full PSIRT importer
      refactor (W19+).

    v0.3.4 (2026-04-19) — defect report fixes:
    - parse_affected_range(): handle "all" / "all versions before X" / "X and
      earlier" / "prior to X" / empty strings; fall back to fixed_in when max
      field is not a version. Fixes CVE-001 (CVE-2025-20352 excluded).
    - recommended_upgrade(): returns max(fix_versions) not min; annotates
      driver CVE + KEV flag. Fixes CVE-002 (dangerous 17.15.2 rec).
    - _tokenize_version(): parses rebuild letters ("17.15.4a" != "17.15.4").
    - match(): KEV / actively-exploited / zero-day CVEs sorted first.

    v0.3.3 focus:
    - Real external integration (read-only) WITHOUT breaking deterministic matching.
    - Approach: Local JSON dataset is the base of truth.
    - External providers act as "enrichers" (by CVE ID), not primary match sources.

    Enable:
      - NVD enrichment:      CVE_NVD_ENRICH=1
      - Cisco PSIRT provider: CVE_CISCO_PSIRT=1
      - Tenable provider stub:CVE_TENABLE_PROVIDER=1
    """

    def __init__(
        self,
        config: Optional[CVEEngineConfig] = None,
        providers: Optional[List[CVEProvider]] = None,
    ):
        self.config = config or CVEEngineConfig()

        enable_nvd = self.config.enable_nvd_enrichment or _env_true("CVE_NVD_ENRICH")
        enable_cisco = self.config.enable_cisco_provider or _env_true("CVE_CISCO_PSIRT")
        enable_tenable = self.config.enable_tenable_provider or _env_true("CVE_TENABLE_PROVIDER")

        if providers is not None:
            self.providers = providers
        else:
            # Order matters:
            # 1) Local JSON base
            # 2) Enrichers/providers that can add metadata (non-destructive merge)
            self.providers = [LocalJsonProvider(self.config.data_dir)]

            if enable_nvd:
                self.providers.append(NvdEnricherProvider())

            if enable_cisco:
                self.providers.append(CiscoAdvisoryProvider())

            if enable_tenable:
                self.providers.append(TenableProvider())

        self.cves: List[CVEEntry] = []

    # -------------------------
    # Merge strategy (v0.3.3)
    # -------------------------
    def _merge_entries(self, base: CVEEntry, patch: CVEEntry) -> CVEEntry:
        """
        Merge 'patch' into 'base' without destroying curated fields.

        Rules:
        - Keep base platforms/affected/fixed_in/workaround if base has them.
        - Fill missing metadata fields from patch:
            source, cvss_score, cvss_vector, cwe, published, last_modified, references
        - Merge references (dedup).
        """
        update = {}

        # Metadata fields we allow to enrich
        for field in (
            "source",
            "cvss_score",
            "cvss_vector",
            "cwe",
            "published",
            "last_modified",
        ):
            base_val = getattr(base, field, None)
            patch_val = getattr(patch, field, None)
            if base_val in (None, "", []) and patch_val not in (None, "", []):
                update[field] = patch_val

        # Advisory URL/title/description are curated in local JSON,
        # so only fill them if missing.
        for field in ("advisory_url", "title", "description"):
            base_val = getattr(base, field, None)
            patch_val = getattr(patch, field, None)
            if base_val in (None, "", []) and patch_val not in (None, "", []):
                update[field] = patch_val

        # References: merge + dedup
        base_refs = list(getattr(base, "references", []) or [])
        patch_refs = list(getattr(patch, "references", []) or [])
        if patch_refs:
            merged = []
            seen = set()
            for r in base_refs + patch_refs:
                if not r:
                    continue
                if r in seen:
                    continue
                seen.add(r)
                merged.append(r)
            update["references"] = merged

        if not update:
            return base

        if hasattr(base, "model_copy"):  # pydantic v2
            return base.model_copy(update=update)
        return base.copy(update=update)  # type: ignore[attr-defined]

    # -------------------------
    # Loading
    # -------------------------
    def load_all(self) -> None:
        loaded_by_provider: List[List[CVEEntry]] = []

        for provider in self.providers:
            try:
                loaded_by_provider.append(provider.load())
            except Exception as e:
                print(f"[WARN] CVE provider failed: {provider.name} ({e})")
                loaded_by_provider.append([])

        # Start from first provider as base, then merge enrichers
        by_id: Dict[str, CVEEntry] = {}

        if loaded_by_provider:
            for entry in loaded_by_provider[0]:
                by_id[entry.cve_id] = entry

        # Merge subsequent provider outputs
        for provider_entries in loaded_by_provider[1:]:
            for patch in provider_entries:
                if patch.cve_id in by_id:
                    by_id[patch.cve_id] = self._merge_entries(by_id[patch.cve_id], patch)
                else:
                    # If an external provider returns a CVE we don't have locally,
                    # we store it, but it may not match due to missing affected/platforms.
                    by_id[patch.cve_id] = patch

        self.cves = list(by_id.values())

    # -------------------------
    # Matching
    # -------------------------
    def match(self, platform: str, version: str) -> List[CVEEntry]:
        matched: List[CVEEntry] = []
        target_ver = _tokenize_version(version)

        # v0.3.5 (2026-04-19): product-family taxonomy strict filter.
        # If we can recognize the user's query platform as a canonical family,
        # exclude CVEs whose titles explicitly identify OTHER product families
        # (e.g. SSM On-Prem, CUCM, Webex mislabeled as "IOS XE" by the PSIRT
        # importer). Falls back to legacy fuzzy matching when family is UNKNOWN.
        query_family = normalize_user_platform(platform)

        for cve in self.cves:
            if not platform_matches(platform, cve.platforms):
                continue

            # Family-level strict filter (2026-04-19 fix for CTO memo P0.1/P0.3)
            if query_family is not None:
                title = getattr(cve, "title", "") or ""
                description = getattr(cve, "description", "") or ""
                cve_families = detect_all_families(title, description)
                # Skip placeholder/policy entries: if fixed_in is prose (no version)
                # AND title doesn't match any family, it's likely not a real CVE.
                if not is_cve_in_scope_for_query(query_family, cve_families):
                    continue

            # v0.3.4 (2026-04-19): P2.1 placeholder filter — CVEs whose fixed_in
            # is advisory prose ("Migrate to X", "Remove default Y") rather than
            # a version token are hardening rules, not applicable CVEs.
            fix = getattr(cve, "fixed_in", None)
            if fix and _is_prose_not_version(fix):
                # Skip from matched list (but keep in DB for reference)
                continue

            min_ver, max_ver, inclusive_max = parse_affected_range(
                cve.affected.min,
                cve.affected.max,
                fix,
            )

            # target < min → not yet affected
            if _cmp_tuples(target_ver, min_ver) < 0:
                continue

            # target > max (or >= when exclusive) → already fixed, skip
            if inclusive_max:
                if _cmp_tuples(target_ver, max_ver) > 0:
                    continue
            else:
                if _cmp_tuples(target_ver, max_ver) >= 0:
                    continue

            matched.append(cve)

        # KEV / actively-exploited CVEs first, then critical/high, then CVE ID
        def _kev_flag(c: CVEEntry) -> int:
            tags = [t.lower() for t in (getattr(c, "tags", []) or [])]
            return 0 if any(t in tags for t in ("kev", "actively-exploited", "zero-day")) else 1

        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        matched.sort(
            key=lambda x: (
                _kev_flag(x),
                severity_rank.get((x.severity or "").lower(), 99),
                x.cve_id,
            )
        )
        return matched

    # -------------------------
    # Summary
    # -------------------------
    def summary(self, matched: List[CVEEntry]) -> Dict[str, int]:
        levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for cve in matched:
            sev = (cve.severity or "").lower()
            if sev in levels:
                levels[sev] += 1
        return levels

    # -------------------------
    # Recommended upgrade
    # -------------------------
    def recommended_upgrade(self, matched: List[CVEEntry]) -> Optional[str]:
        """
        Return the MINIMUM SAFE version: the lowest version that fixes EVERY
        applicable critical/high CVE. This is max(fix_versions), not min.

        Fixed 2026-04-19 per defect report CVE-002: previous logic picked the
        LOWEST fix version, producing false "patched" state (e.g. recommending
        17.15.2 while CVE-2025-20352 first-fixed in 17.15.4a).
        """
        # Collect (fixed_in_string, parsed_version_tuple, driver_cve) for each
        # critical/high CVE that has a fix version. Skip CVEs without fixed_in.
        candidates: List[Tuple[str, Tuple[int, ...], CVEEntry]] = []
        for cve in matched:
            sev = (cve.severity or "").lower()
            if sev not in ("critical", "high"):
                continue
            if not cve.fixed_in:
                continue
            parsed = _extract_version(cve.fixed_in)
            if parsed is None:
                # Can't compare this one safely → skip it rather than let a
                # non-parseable fix version hide a real upgrade requirement.
                continue
            candidates.append((cve.fixed_in, parsed, cve))

        if not candidates:
            return None

        # Pick the MAXIMUM — any lower version leaves at least one CVE unpatched.
        best_str, best_ver, driver = candidates[0]
        for fix_str, fix_ver, cve in candidates[1:]:
            if _cmp_tuples(fix_ver, best_ver) > 0:
                best_str, best_ver, driver = fix_str, fix_ver, cve

        # Annotate driver CVE for operator trust
        driver_tags = [t.lower() for t in (getattr(driver, "tags", []) or [])]
        is_kev = any(t in driver_tags for t in ("kev", "actively-exploited", "zero-day"))
        kev_note = " (KEV, actively exploited)" if is_kev else ""
        return f"{best_str} — driven by {driver.cve_id}{kev_note}"
