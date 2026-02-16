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


def get_mitigation_service() -> MitigationService:
    """Get or create the mitigation service singleton."""
    global _service
    if _service is None:
        _service = MitigationService()
    return _service
