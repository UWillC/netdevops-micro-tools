# Changelog

All notable changes to this project will be documented in this file.

---

## [v0.3.5] – 2026-01-11

### Added

- Profiles × CVE integration:
  - Device profiles now include `platform` and `version` fields for CVE matching.
  - New endpoint `GET /profiles/vulnerabilities` for batch vulnerability checking.
  - Vulnerability status mapping: critical / high / medium / low / clean / unknown.
  - Response includes per-profile CVE count, max CVSS score, and matched CVE IDs.
- **Vulnerability Status widget** in Web UI:
  - Summary badges (critical/high/medium/low/clean counts)
  - Per-profile vulnerability cards with status indicator
  - Real-time fetch from `/profiles/vulnerabilities` endpoint
- New Pydantic schemas:
  - `ProfileVulnerabilityResult`, `ProfileVulnerabilitySummary`, `ProfileVulnerabilitiesResponse`.
- New feature flag: `profiles_cve`.
- Unit tests: 13 tests for Profiles × CVE service (`tests/test_profiles.py`).

### Changed

- Sample profiles updated with device info:
  - `lab.json`: ISR4451-X, 17.5.1
  - `branch.json`: Catalyst 9300, 17.9.4
  - `dc.json`: Nexus 9000, 10.2.3
- Web UI: Unified grid layout for SNMP/NTP/AAA/Golden Config generators (consistent with CVE/Profiles)

---

## [v0.3.4] – 2026-01-04

### Added

- NVD API response cache:
  - File-based cache in `cache/nvd/` directory.
  - 24-hour TTL to avoid rate limiting.
  - Transparent caching with `[CACHE]` log messages for visibility.
- New feature flag: `nvd_cache`.

### Changed

- `NvdEnricherProvider` now uses `_fetch_with_cache()` method.
- Real CVE data in local database (CVE-2023-20198, CVE-2023-20273, CVE-2025-20188).

---

## [v0.3.3] – 2025-12-30

### Added

- CVE Engine v0.3.3:
  - Real NVD API v2.0 integration (read-only enrichment).
  - Safe merge strategy: local JSON is source of truth, NVD adds metadata.
  - New fields: `cvss_score`, `cvss_vector`, `cwe`, `published`, `last_modified`, `references`.
  - Environment variable `CVE_NVD_ENRICH=1` to enable NVD enrichment.
- HTTP client with proper User-Agent header.
- NVD response parser (`cve_importers.py`).

### Notes

- NVD enrichment is opt-in and rate-limit aware.
- Cisco and Tenable providers remain stubs for future implementation.

---

## [v0.3.2] – 2025-12-28

### Added

- CVE Engine provider architecture:
  - Importer skeletons for Cisco, NVD, and Tenable providers.
  - Modular design for future external data sources.

---

## [v0.3.1] – 2025-12-26

### Added

- CVE data enrichment fields in model (`source`, `cvss_score`, `cvss_vector`, `cwe`, `references`).
- Web UI displays enriched CVE metadata (CVSS, CWE, references).

---

## [v0.3.0] – 2025-12-24

### Added

- CVE Engine v0.3:
  - Provider-based architecture (`CVEProvider` abstract class).
  - `LocalJsonProvider` as primary data source.
  - Improved version comparison and platform matching logic.
  - Severity-based sorting of matched CVEs.

### Changed

- CVE Analyzer API response now includes `source` field per CVE entry.
- Refactored `cve_engine.py` for extensibility.

---

## [v0.2.1] – 2025-12-22

### Added

- Profiles v2 (backend + Web UI):
  - Backend-driven editable device profiles (save / list / load / delete).
  - Dedicated Profiles tab in the Web UI.
  - Docker volume guidance for persisting profiles across container restarts.

### Improved

- Web UI UX polish:
  - Clearer layouts and navigation.
  - More consistent action buttons and feedback.
  - Improved output UX (copy / download actions).
- Documentation updates:
  - README refreshed to reflect Web UI v2, Profiles v2, and current capabilities.

### Notes

- Patch release.
- No breaking API changes intended.

---

## [v0.2.0] – 2025-12-15

### Added

- CVE Engine v0.2:
  - JSON-based CVE dataset under `cve_data/ios_xe/`.
  - CVE matching by platform and IOS XE version.
  - Severity breakdown (critical / high / medium / low).
  - Recommended upgrade target based on fixed-in versions.
- CVE Analyzer API v2:
  - Structured `/analyze/cve` response including matched CVEs, summary, and metadata.
- Web UI v2:
  - Sidebar-based layout for tool navigation.
  - CVE Analyzer view with security posture summary.
- Initial service and model layers:
  - `services/` and `models/` directories.
  - Pydantic models for CVE and metadata.

### Improved

- CVE Analyzer Web UI now renders detailed CVE information:
  - titles, tags, descriptions, fixed-in versions, workarounds, and advisory links.
- Project structure refined toward a micro-SaaS–style backend.

### Notes

- CVE data is curated demo content and must not be used as a production security authority.

---

## [v0.1.0] – 2025-12-08

### Added

- FastAPI backend with SNMPv3, NTP, AAA/TACACS+, and Golden Config generators.
- Initial CVE Analyzer (MVP).
- Dockerized API.
- Web UI with generators and CVE tab.
- UX improvements:
  - Basic profiles (Lab / Branch / Datacenter).
  - Persistent form values using `localStorage`.
  - Copy and download actions for outputs.

### Notes

- First public, micro-SaaS–ready release.
- CVE dataset is demo-only.

---

## [Unreleased]

- Authentication and multi-user support.
- Security Score feature (aggregate risk metric).
- Export formats (Markdown / JSON).
- Advanced Profiles UX (rename, duplicate, diff preview).
