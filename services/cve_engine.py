import os
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
def _tokenize_version(v: str) -> Tuple[int, ...]:
    v = (v or "").strip()
    if not v:
        return (0,)

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


def compare_versions(a: str, b: str) -> int:
    ta = _tokenize_version(a)
    tb = _tokenize_version(b)

    max_len = max(len(ta), len(tb))
    ta = ta + (0,) * (max_len - len(ta))
    tb = tb + (0,) * (max_len - len(tb))

    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


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
    engine_version: str = "0.3.3"
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
    CVE Engine v0.3.3

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
        for cve in self.cves:
            if not platform_matches(platform, cve.platforms):
                continue

            if compare_versions(version, cve.affected.min) < 0:
                continue
            if compare_versions(version, cve.affected.max) > 0:
                continue

            matched.append(cve)

        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        matched.sort(
            key=lambda x: (
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
        candidates: List[str] = []
        for cve in matched:
            if (cve.severity or "").lower() in ("critical", "high") and cve.fixed_in:
                candidates.append(cve.fixed_in)

        if not candidates:
            return None

        best = candidates[0]
        for v in candidates[1:]:
            if compare_versions(v, best) < 0:
                best = v
        return best
