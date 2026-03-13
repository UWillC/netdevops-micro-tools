import json
import os
import re
import time
import urllib.parse
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from models.cve_model import CVEEntry, CVEAffectedRange
from services.cve_importers import NvdImporter
from services.http_client import (
    http_get_json,
    HttpClientError,
    HttpTimeoutError,
    HttpConnectionError,
)

# Cache configuration
NVD_CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", "cache", "nvd")
NVD_CACHE_TTL = 24 * 3600  # 24 hours in seconds

CISCO_CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", "cache", "cisco")
CISCO_CACHE_TTL = 6 * 3600  # 6 hours
CISCO_CREDENTIALS_PATH = os.path.expanduser("~/.config/cisco-psirt/credentials.json")


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
        """Fetch from cache or NVD API with error handling."""
        # Try cache first
        cached = self._read_cache(cve_id)
        if cached is not None:
            return cached
        # Fetch from NVD
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            print(f"[NVD] Fetching {cve_id} from NVD API...")
            data = http_get_json(url, timeout_seconds=10)
            # Cache the response
            self._write_cache(cve_id, data)
            return data
        except HttpTimeoutError:
            print(f"[ERROR] NVD API timeout for {cve_id} - using local data only")
            return None
        except HttpConnectionError as e:
            print(f"[ERROR] NVD API connection failed for {cve_id}: {e}")
            return None
        except HttpClientError as e:
            print(f"[ERROR] NVD API error for {cve_id}: {e}")
            return None

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
# Cisco PSIRT openVuln API Provider
# -----------------------------
class CiscoAdvisoryProvider(CVEProvider):
    """
    Fetches CVE advisories from Cisco PSIRT openVuln API.

    Requires credentials at ~/.config/cisco-psirt/credentials.json:
    {
        "client_id": "...",
        "client_secret": "...",
        "token_url": "https://id.cisco.com/oauth2/default/v1/token",
        "api_base": "https://apix.cisco.com/security/advisories/v2"
    }

    Enable via env: CVE_CISCO_PSIRT=1
    """

    name = "cisco-advisories"

    PLATFORM_PRODUCTS = {
        "iosxe": "Cisco IOS XE Software",
        "ios": "Cisco IOS Software",
        "nxos": "Cisco NX-OS Software",
        "asa": "Cisco Adaptive Security Appliance (ASA) Software",
    }

    def __init__(self, platform: str = "iosxe", max_pages: int = 5):
        self.platform = platform
        self.max_pages = max_pages
        self._token: Optional[str] = None
        self._token_expires: float = 0
        self._credentials: Optional[Dict[str, str]] = None

    def _load_credentials(self) -> Optional[Dict[str, str]]:
        if self._credentials:
            return self._credentials

        # Try file first
        if os.path.exists(CISCO_CREDENTIALS_PATH):
            try:
                with open(CISCO_CREDENTIALS_PATH, "r") as f:
                    self._credentials = json.load(f)
                return self._credentials
            except Exception as e:
                print(f"[ERROR] Failed to read Cisco PSIRT credentials: {e}")

        # Fallback: environment variables (for cloud deployment)
        client_id = os.getenv("CISCO_CLIENT_ID")
        client_secret = os.getenv("CISCO_CLIENT_SECRET")
        if client_id and client_secret:
            self._credentials = {
                "client_id": client_id,
                "client_secret": client_secret,
                "token_url": "https://id.cisco.com/oauth2/default/v1/token",
                "api_base": "https://apix.cisco.com/security/advisories/v2",
            }
            print("[INFO] Cisco PSIRT credentials loaded from environment variables")
            return self._credentials

        print(f"[WARN] Cisco PSIRT credentials not found (file or env)")
        return None

    def _get_token(self) -> Optional[str]:
        if self._token and time.time() < self._token_expires:
            return self._token

        creds = self._load_credentials()
        if not creds:
            return None

        token_url = creds.get("token_url", "https://id.cisco.com/oauth2/default/v1/token")
        data = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        }).encode("utf-8")

        try:
            req = urllib.request.Request(token_url, data=data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode("utf-8"))
            self._token = result["access_token"]
            self._token_expires = time.time() + result.get("expires_in", 3600) - 60
            print("[CISCO] OAuth2 token acquired")
            return self._token
        except Exception as e:
            print(f"[ERROR] Cisco PSIRT OAuth2 failed: {e}")
            return None

    def _api_get(self, url: str) -> Optional[Dict[str, Any]]:
        token = self._get_token()
        if not token:
            return None
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("Authorization", f"Bearer {token}")
            req.add_header("Accept", "application/json")
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print(f"[ERROR] Cisco PSIRT API 403 Forbidden — check developer account status")
            elif e.code == 429:
                print(f"[WARN] Cisco PSIRT API rate limited (429)")
            else:
                print(f"[ERROR] Cisco PSIRT API HTTP {e.code}: {e.reason}")
            return None
        except Exception as e:
            print(f"[ERROR] Cisco PSIRT API request failed: {e}")
            return None

    def _read_cache(self) -> Optional[List[Dict[str, Any]]]:
        os.makedirs(CISCO_CACHE_DIR, exist_ok=True)
        cache_path = os.path.join(CISCO_CACHE_DIR, f"{self.platform}.json")
        if not os.path.exists(cache_path):
            return None
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            if time.time() - cached.get("cached_at", 0) > CISCO_CACHE_TTL:
                return None
            print(f"[CACHE] Using cached Cisco PSIRT data for {self.platform}")
            return cached.get("advisories", [])
        except Exception:
            return None

    def _write_cache(self, advisories: List[Dict[str, Any]]) -> None:
        os.makedirs(CISCO_CACHE_DIR, exist_ok=True)
        cache_path = os.path.join(CISCO_CACHE_DIR, f"{self.platform}.json")
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump({"cached_at": time.time(), "advisories": advisories}, f)
            print(f"[CACHE] Saved {len(advisories)} Cisco advisories for {self.platform}")
        except Exception as e:
            print(f"[WARN] Failed to cache Cisco advisories: {e}")

    def _parse_severity(self, sir: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        return mapping.get(sir.lower(), "medium")

    def _parse_advisory(self, adv: Dict[str, Any]) -> List[CVEEntry]:
        """Parse a single Cisco advisory into CVEEntry objects (one per CVE ID)."""
        entries = []
        cves = adv.get("cves", [])
        if not cves or cves == ["NA"]:
            return entries

        sir = adv.get("sir", "Medium")
        severity = self._parse_severity(sir)
        cvss = None
        try:
            cvss = float(adv.get("cvssBaseScore", 0))
            if cvss == 0:
                cvss = None
        except (ValueError, TypeError):
            cvss = None

        title = adv.get("advisoryTitle", "")
        summary = adv.get("summary", "")
        # Strip HTML tags from summary
        summary_clean = re.sub(r"<[^>]+>", "", summary).strip()
        if len(summary_clean) > 500:
            summary_clean = summary_clean[:497] + "..."

        advisory_url = adv.get("publicationUrl", "")
        published = adv.get("firstPublished", "")
        if published and "T" in published:
            published = published.split("T")[0]
        last_modified = adv.get("lastUpdated", "")
        if last_modified and "T" in last_modified:
            last_modified = last_modified.split("T")[0]

        cwe_list = adv.get("cwe", [])
        cwe = cwe_list[0] if cwe_list and cwe_list != ["NA"] else None

        tags = []
        if severity == "critical":
            tags.append("critical")
        if "ipsSignatures" in adv and adv["ipsSignatures"] != ["NA"]:
            tags.append("ips-signature")
        tags.append("cisco-psirt")

        for cve_id in cves:
            if not cve_id.startswith("CVE-"):
                continue
            entries.append(CVEEntry(
                cve_id=cve_id,
                title=title,
                severity=severity,
                platforms=["IOS XE"] if self.platform == "iosxe" else [self.platform.upper()],
                affected=CVEAffectedRange(min="0.0.0", max="999.999.999"),
                fixed_in=None,
                tags=tags,
                description=summary_clean,
                workaround=None,
                advisory_url=advisory_url,
                confidence="partial",
                source="cisco-advisories",
                cvss_score=cvss,
                cvss_vector=None,
                cwe=cwe,
                published=published,
                last_modified=last_modified,
                references=[advisory_url] if advisory_url else [],
            ))
        return entries

    def load(self) -> List[CVEEntry]:
        all_advisories: List[Dict[str, Any]] = []

        # Try cache first
        cached = self._read_cache()
        if cached is not None:
            all_advisories = cached
            print(f"[CISCO] Using {len(all_advisories)} cached advisories")
        else:
            # Fetch from API
            creds = self._load_credentials()
            if not creds:
                return []

            api_base = creds.get("api_base", "https://apix.cisco.com/security/advisories/v2")

            product_name = self.PLATFORM_PRODUCTS.get(self.platform, self.platform)
            product_encoded = urllib.parse.quote(product_name)

            for page in range(1, self.max_pages + 1):
                url = f"{api_base}/product?product={product_encoded}&pageIndex={page}&pageSize=100"
                print(f"[CISCO] Fetching page {page}...")
                data = self._api_get(url)
                if not data:
                    break
                advisories = data.get("advisories", [])
                if not advisories:
                    break
                all_advisories.extend(advisories)
                # Respect rate limit: 30 calls/minute = 1 per 2 seconds
                if page < self.max_pages and len(advisories) == 100:
                    time.sleep(2)
                else:
                    break  # Last page (less than 100 results)

            if all_advisories:
                self._write_cache(all_advisories)

        # Auto-sync: import NEW CVEs to local files + generate mitigations
        try:
            from services.cisco_sync import auto_sync_new_cves
            auto_sync_new_cves(all_advisories)
        except Exception as e:
            print(f"[WARN] Auto-sync failed (non-fatal): {e}")

        entries = []
        for adv in all_advisories:
            entries.extend(self._parse_advisory(adv))

        print(f"[CISCO] Loaded {len(entries)} CVEs from {len(all_advisories)} advisories")
        return entries


class TenableProvider(CVEProvider):
    name = "tenable"

    def load(self) -> List[CVEEntry]:
        print("[INFO] Tenable provider stub (v0.3.3): not implemented yet.")
        return []
