"""
CVE Mitigation Service
Loads and serves mitigation recommendations for CVEs.
"""

import json
from pathlib import Path
from typing import Optional, List

from models.mitigation_model import CVEMitigation, MitigationResponse


class MitigationService:
    """Service for loading and querying CVE mitigations."""

    def __init__(self, mitigations_dir: str = "cve_mitigations"):
        self.mitigations_dir = Path(mitigations_dir)
        self._cache: dict[str, CVEMitigation] = {}
        self._load_all()

    def _load_all(self) -> None:
        """Load all mitigation files into cache."""
        if not self.mitigations_dir.exists():
            return

        for file_path in self.mitigations_dir.glob("CVE-*.json"):
            try:
                with open(file_path, "r") as f:
                    data = json.load(f)
                    mitigation = CVEMitigation(**data)
                    self._cache[mitigation.cve_id.upper()] = mitigation
            except Exception as e:
                print(f"Error loading {file_path}: {e}")

    def get_mitigation(self, cve_id: str) -> MitigationResponse:
        """Get mitigation for a specific CVE."""
        cve_id_upper = cve_id.upper()

        if cve_id_upper in self._cache:
            return MitigationResponse(
                found=True,
                cve_id=cve_id_upper,
                mitigation=self._cache[cve_id_upper]
            )

        return MitigationResponse(
            found=False,
            cve_id=cve_id_upper,
            message=f"No mitigation data available for {cve_id_upper}. Check Cisco PSIRT for official advisories."
        )

    def get_mitigation_for_platform(
        self,
        cve_id: str,
        platform: Optional[str] = None,
        version: Optional[str] = None,
    ) -> MitigationResponse:
        """Get mitigation with platform/version applicability check.

        Uses CVEEngine to determine whether the CVE actually affects the
        target (platform, version) tuple. Returns the full mitigation
        regardless (so informational reading is still possible), but adds
        `applicability` / `applicability_reason` fields so the UI can flag
        "this CVE does not affect your device" when appropriate.

        Lazy-import CVEEngine to avoid circular deps and to keep the base
        get_mitigation() path free of CVE DB load cost.
        """
        resp = self.get_mitigation(cve_id)

        if not resp.found or not resp.mitigation:
            return resp

        # No context provided → return full mitigation without applicability.
        if not platform and not version:
            return resp

        try:
            from services.cve_engine import CVEEngine, CVEEngineConfig
            engine = _get_cached_cve_engine()
            matched = engine.match(platform or "", version or "")
            matched_ids = {c.cve_id.upper() for c in matched}
            is_applicable = resp.cve_id.upper() in matched_ids

            if is_applicable:
                resp.applicability = "applicable"
                resp.applicability_reason = (
                    f"CVE engine confirms {resp.cve_id} affects {platform} "
                    f"{version}. Apply the mitigation below."
                )
            else:
                resp.applicability = "not_applicable"
                resp.applicability_reason = (
                    f"CVE engine does not match {resp.cve_id} to "
                    f"{platform} {version}. The mitigation below is "
                    f"informational — it may not apply to your device. "
                    f"Verify against the Cisco PSIRT advisory before acting."
                )
        except Exception as e:
            resp.applicability = "unknown"
            resp.applicability_reason = (
                f"Could not determine applicability: {type(e).__name__}. "
                f"Treat mitigation as informational."
            )

        return resp

    def list_available(self) -> List[str]:
        """List all CVEs with available mitigations."""
        return sorted(self._cache.keys())

    def get_by_tag(self, tag: str) -> List[CVEMitigation]:
        """Get all mitigations with a specific tag."""
        return [m for m in self._cache.values() if tag.lower() in [t.lower() for t in m.tags]]

    def get_critical(self) -> List[CVEMitigation]:
        """Get all critical mitigations."""
        return self.get_by_tag("critical")

    def reload(self) -> int:
        """Reload all mitigations from disk. Returns count loaded."""
        self._cache.clear()
        self._load_all()
        return len(self._cache)


# Singleton instance
_service: Optional[MitigationService] = None
_cve_engine_instance = None  # type: ignore


def get_mitigation_service() -> MitigationService:
    """Get or create the mitigation service singleton."""
    global _service
    if _service is None:
        _service = MitigationService()
    return _service


def _get_cached_cve_engine():
    """Lazy-initialized CVE engine singleton, used only by
    get_mitigation_for_platform(). Separate from CVEEngine instances the
    /analyze/cve endpoint creates per-request, to avoid repeated 142-file
    JSON load cost on every mitigation query."""
    global _cve_engine_instance
    if _cve_engine_instance is None:
        from services.cve_engine import CVEEngine, CVEEngineConfig
        _cve_engine_instance = CVEEngine(
            config=CVEEngineConfig(engine_version="0.3.7")
        )
        _cve_engine_instance.load_all()
    return _cve_engine_instance
