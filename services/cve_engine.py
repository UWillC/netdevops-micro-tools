import os
import json
from typing import List, Dict, Any, Optional

from models.cve_model import CVEEntry
from services.utils import compare_versions


class CVEEngine:
    """
    Full CVE engine for v0.2.0.
    - loads CVE JSON files
    - matches platforms
    - checks version ranges
    - groups by severity
    - recommends upgrade target
    """

    def __init__(self, data_dir: str = "cve_data/ios_xe"):
        self.data_dir = data_dir
        self.cves: List[CVEEntry] = []

    # -------------------------
    # Load all CVE JSON files
    # -------------------------
    def load_all(self) -> None:
        """
        Load all CVE JSON files from data_dir.
        """
        if not os.path.isdir(self.data_dir):
            return

        for filename in os.listdir(self.data_dir):
            if not filename.endswith(".json"):
                continue

            path = os.path.join(self.data_dir, filename)
            with open(path, "r") as f:
                try:
                    data = json.load(f)
                    entry = CVEEntry(**data)
                    self.cves.append(entry)
                except Exception as e:
                    print(f"[WARN] Skipping invalid CVE file: {filename} ({e})")

    # -------------------------
    # Matching logic
    # -------------------------
    def match(self, platform: str, version: str) -> List[CVEEntry]:
        platform_norm = platform.lower()

        matched = []
        for cve in self.cves:
            # platform match
            platforms_norm = [p.lower() for p in cve.platforms]
            if platform_norm not in platforms_norm and "ios xe" not in platform_norm:
                continue

            # version range match
            if compare_versions(version, cve.affected.min) < 0:
                continue
            if compare_versions(version, cve.affected.max) > 0:
                continue

            matched.append(cve)

        return matched

    # -------------------------
    # Summary statistics
    # -------------------------
    def summary(self, matched: List[CVEEntry]) -> Dict[str, int]:
        levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for cve in matched:
            sev = cve.severity.lower()
            if sev in levels:
                levels[sev] += 1

        return levels

    # -------------------------
    # Recommended upgrade
    # -------------------------
    def recommended_upgrade(self, matched: List[CVEEntry]) -> Optional[str]:
        """Return minimal fixed-in version for critical/high issues."""
        upgrade_candidates = []

        for cve in matched:
            if cve.severity in ("critical", "high") and cve.fixed_in:
                upgrade_candidates.append(cve.fixed_in)

        if not upgrade_candidates:
            return None

        # pick lowest fixed version
        best = upgrade_candidates[0]
        for v in upgrade_candidates[1:]:
            if compare_versions(v, best) < 0:
                best = v

        return best
