from typing import List, Dict, Any, Optional
from models.cve_model import CVEEntry


class CVEEngine:
    """
    CVE matching engine skeleton for v0.2.0.
    Responsible for:
      - loading CVE JSON files from cve_data/
      - matching platform + version ranges
      - generating summary and recommendations
    """

    def __init__(self, data_dir: str = "cve_data"):
        self.data_dir = data_dir
        self.cves: List[CVEEntry] = []

    def load_all(self) -> None:
        """
        Load all CVE entries from JSON files.
        (To be implemented in v0.2.0)
        """
        pass

    def match(self, platform: str, version: str) -> List[CVEEntry]:
        """
        Return list of CVEs affecting given platform/version.
        """
        return []

    def recommended_upgrade(self, matched: List[CVEEntry]) -> Optional[str]:
        """
        Compute recommended upgrade target based on matched CVEs.
        """
        return None

    def summary(self, matched: List[CVEEntry]) -> Dict[str, Any]:
        """
        Return summary statistics (critical/high/medium count, etc.)
        """
        return {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
