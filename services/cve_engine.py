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


# -----------------------------
# Version parsing & comparison (v0.3+)
# -----------------------------
# Sentinels for unbounded ranges: min=all → (-inf), max=all → (+inf)
_MIN_SENTINEL: Tuple[int, ...] = (-1,)
_MAX_SENTINEL: Tuple[int, ...] = (10**9,)

# Regex to extract a dotted version (with optional rebuild letter) from free text.
# Matches "17.15.4a", "17.12.3", "15.7(3)M5" (captures "15.7.3"), etc.
_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:[.\(](\d+)[.\)]?(?:[Mm](\d+))?)?([a-z])?")


def _extract_version(text: str) -> Optional[Tuple[int, ...]]:
    """Extract the first version-like token from free text. Returns tuple or None."""
    if not text:
        return None
    m = _VERSION_RE.search(text)
    if not m:
        return None
    parts: List[int] = []
    for g in m.groups()[:4]:
        if g is None:
            parts.append(0)
            continue
        try:
            parts.append(int(g))
        except ValueError:
            parts.append(0)
    # rebuild letter → small tiebreaker (a=1, b=2, ...); absent = 0
    letter = m.group(5)
    if letter:
        parts.append(ord(letter.lower()) - ord("a") + 1)
    return tuple(parts) if parts else None


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
    engine_version: str = "0.3.4"
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
    CVE Engine v0.3.4

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

        for cve in self.cves:
            if not platform_matches(platform, cve.platforms):
                continue

            min_ver, max_ver, inclusive_max = parse_affected_range(
                cve.affected.min,
                cve.affected.max,
                getattr(cve, "fixed_in", None),
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
