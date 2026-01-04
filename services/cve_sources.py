import json
import os
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from models.cve_model import CVEEntry, CVEAffectedRange
from services.cve_importers import NvdImporter
from services.http_client import http_get_json

# Cache configuration
NVD_CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", "cache", "nvd")
NVD_CACHE_TTL = 24 * 3600  # 24 hours in seconds


class CVEProvider(ABC):
    name: str = "base"

    @abstractmethod
    def load(self) -> List[CVEEntry]:
        raise NotImplementedError


class LocalJsonProvider(CVEProvider):
    name = "local-json"

    def __init__(self, data_dir: str):
        self.data_dir = data_dir

    def _ensure_source(self, entry: CVEEntry) -> CVEEntry:
        if getattr(entry, "source", None):
            return entry
        if hasattr(entry, "model_copy"):
            return entry.model_copy(update={"source": self.name})
        return entry.copy(update={"source": self.name})  # type: ignore[attr-defined]

    def load(self) -> List[CVEEntry]:
        results: List[CVEEntry] = []
        if not os.path.isdir(self.data_dir):
            return results

        for filename in os.listdir(self.data_dir):
            if not filename.endswith(".json"):
                continue
            path = os.path.join(self.data_dir, filename)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                entry = CVEEntry(**data)
                results.append(self._ensure_source(entry))
            except Exception as e:
                print(f"[WARN] Skipping invalid CVE file: {filename} ({e})")

        return results


# -----------------------------
# v0.3.3: NVD Enricher (REAL fetch)
# -----------------------------
class NvdEnricherProvider(CVEProvider):
    """
    Fetches CVE metadata from NVD by CVE ID.

    Notes:
    - This is enrichment only. We do NOT try to derive Cisco platform/version ranges from NVD.
    - You enable it via env: CVE_NVD_ENRICH=1
    - Rate limits may apply. Keep your local curated dataset small/curated.
    - v0.3.4: File-based cache (24h TTL) to avoid rate limiting.
    """

    name = "nvd"

    def __init__(self, cve_ids: Optional[List[str]] = None):
        # If None: provider will try to read CVE IDs from local dataset at runtime (not available here),
        # so default behaviour is: no IDs -> no-op.
        self.cve_ids = cve_ids or []
        self.importer = NvdImporter()

    def _get_cache_path(self, cve_id: str) -> str:
        """Return path to cache file for given CVE ID."""
        safe_id = cve_id.upper().replace("/", "_")
        return os.path.join(NVD_CACHE_DIR, f"{safe_id}.json")

    def _read_cache(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Read from cache if valid (exists and not expired)."""
        path = self._get_cache_path(cve_id)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            cached_at = cached.get("cached_at", 0)
            if time.time() - cached_at > NVD_CACHE_TTL:
                return None  # Expired
            print(f"[CACHE] Using cached NVD data for {cve_id}")
            return cached.get("data")
        except Exception:
            return None

    def _write_cache(self, cve_id: str, data: Dict[str, Any]) -> None:
        """Write NVD response to cache."""
        os.makedirs(NVD_CACHE_DIR, exist_ok=True)
        path = self._get_cache_path(cve_id)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"cached_at": time.time(), "data": data}, f)
            print(f"[CACHE] Saved NVD data for {cve_id}")
        except Exception as e:
            print(f"[WARN] Failed to cache {cve_id}: {e}")

    def _fetch_with_cache(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch from cache or NVD API."""
        # Try cache first
        cached = self._read_cache(cve_id)
        if cached is not None:
            return cached
        # Fetch from NVD
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        data = http_get_json(url, timeout_seconds=10)
        # Cache the response
        self._write_cache(cve_id, data)
        return data

    def load(self) -> List[CVEEntry]:
        if not self.cve_ids:
            # Safe no-op if not provided any IDs
            print("[INFO] NVD enricher enabled but no CVE IDs provided; skipping.")
            return []

        out: List[CVEEntry] = []
        for cve_id in self.cve_ids:
            try:
                # v0.3.4: Use cache to avoid rate limiting
                data = self._fetch_with_cache(cve_id)
                if data is None:
                    continue
                normalized = self.importer.parse(data)

                # Expect 0 or 1 for cveId query, but handle list anyway
                for n in normalized:
                    # Create a "patch" CVEEntry with minimal required fields.
                    # affected/platforms are placeholders because we only merge metadata onto existing local entries.
                    out.append(
                        CVEEntry(
                            cve_id=n.cve_id,
                            title=n.title or cve_id,
                            severity=n.severity or "medium",
                            platforms=["IOS XE"],  # placeholder (won't be used if merging onto local)
                            affected=CVEAffectedRange(min="0.0.0", max="999.999.999"),
                            fixed_in=None,
                            tags=[],
                            description=n.description or "",
                            workaround=None,
                            advisory_url=None,
                            confidence="partial",
                            source="nvd",
                            cvss_score=n.cvss_score,
                            cvss_vector=n.cvss_vector,
                            cwe=n.cwe,
                            published=n.published,
                            last_modified=n.last_modified,
                            references=n.references or [],
                        )
                    )
            except Exception as e:
                print(f"[WARN] NVD enrich failed for {cve_id}: {e}")

        return out


# -----------------------------
# External providers (still stubs for now)
# -----------------------------
class CiscoAdvisoryProvider(CVEProvider):
    name = "cisco-advisories"

    def load(self) -> List[CVEEntry]:
        print("[INFO] Cisco provider stub (v0.3.3): not implemented yet.")
        return []


class TenableProvider(CVEProvider):
    name = "tenable"

    def load(self) -> List[CVEEntry]:
        print("[INFO] Tenable provider stub (v0.3.3): not implemented yet.")
        return []
