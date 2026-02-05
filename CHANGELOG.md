# Changelog

All notable changes to this project will be documented in this file.

---

## [v0.4.6] – 2026-02-04

### Added

- **Markdown Export** — security report as downloadable `.md` file:
  - New format option `GET /export/security-report?format=md`.
  - Formatted tables, headers, CVE breakdown.
  - Frontend: "Export MD" button in Security Scores widget.

---

## [v0.4.5] – 2026-02-03

### Added

- **JSON Export** — security report as raw JSON:
  - New format option `GET /export/security-report?format=json`.
  - Returns full data structure for programmatic access.
  - Frontend: "Export JSON" button in Security Scores widget.

---

## [v0.4.4] – 2026-02-02

### Added

- **iPerf3 Multi-platform Scripts** — output format selection:
  - Bash script (`.sh`) — Linux/macOS ready.
  - PowerShell script (`.ps1`) — Windows native.
  - Python script (`.py`) — cross-platform.
  - Frontend: dropdown with 4 output formats (Commands / Bash / PowerShell / Python).
  - Dynamic download filename based on selected format.

---

## [v0.4.3] – 2026-01-31

### Added

- **CLI Tool** — terminal interface for power users:
  - Commands: `snmpv3`, `ntp`, `aaa`, `golden`, `subnet`, `mtu`, `cve`, `parse`, `health`.
  - Framework: click.
  - Connects to API via `NETDEVOPS_API_URL` (default: Render cloud).
- New dependency: `click`, `requests`.

---

## [v0.4.2] – 2026-01-30

### Added

- **Export PDF** — security report as downloadable PDF:
  - New endpoint `GET /export/security-report`.
  - Uses `fpdf2` library for PDF generation.
  - Report includes: executive summary, score breakdown, CVE details per profile.
- Frontend: "Export PDF" button in Security Scores widget.

---

## [v0.4.1] – 2026-01-29

### Added

- **Cloud Deployment** — product is now LIVE on Render!
  - Live URL: https://netdevops-micro-tools.onrender.com
  - API Docs: https://netdevops-micro-tools.onrender.com/docs
- Backend serves frontend files (`/`, `/style.css`, `/app.js`).
- Auto-detect `API_BASE_URL` (file://, localhost, cloud).
- `render.yaml` for one-click deployment.

### New Modules (January 2026)

- **iPerf3 Command Generator** (v1.0):
  - TCP/UDP tests, link speeds (100M/1G/10G), directions.
  - Hints panel with quick reference commands.
- **IP Subnet Calculator** (v1.0):
  - Subnet info, split, supernet, CIDR reference table.
  - 5 endpoints under `/tools/subnet/*`.
- **MTU Calculator** (v1.0):
  - Tunnel overhead calculation (GRE, IPSec, VXLAN, MPLS, LISP).
  - TCP MSS recommendations, Cisco config suggestions.
- **Config Parser** (v1.0):
  - Parse `show running-config` to structured JSON.
  - Extracts: hostname, interfaces, SNMP, NTP, AAA, users, banners.

### Improved

- **SNMP Multi-Host Generator** — per-host settings, specific traps, logging section.
- **NTP v2** — network tier hierarchy (CORE/DIST/ACCESS), NTP master, peer support.
- **AAA v2.1** — SSH prerequisites, local fallback user, server groups.
- **Golden Config v2** — modular baseline sections, custom banner.
- **Verification Tooltips** — ~120 educational tooltips with example output.

---

## [v0.4.0] – 2026-01-13

### Added

- **Security Score** — numeric security assessment (0-100) for device profiles:
  - Algorithm: Base score 100, penalties per CVE based on severity.
  - Severity penalties: critical (-25), high (-15), medium (-8), low (-3).
  - Modifiers: exploited-in-wild (×1.5), patch-available (×0.7), aged >365d (×1.2).
  - Score categories: Excellent (90-100), Good (70-89), Fair (50-69), Poor (25-49), Critical (0-24).
- New endpoint `GET /profiles/security-scores`:
  - Returns per-profile scores with full CVE breakdown.
  - Aggregated stats: average, lowest, highest score.
  - Summary counts by category.
- **Security Score widget** in Web UI (Profiles tab):
  - Circular score badge with color-coded label.
  - CVE breakdown showing individual penalties and modifiers.
  - Stats line (avg/low/high).
  - Summary badges for score distribution.
- New Pydantic models:
  - `CVEScoreBreakdown`, `ProfileSecurityScore`, `SecurityScoreSummary`, `SecurityScoreResponse`.
- Design specification: `docs/DESIGN_SECURITY_SCORE.md`.
- New feature flag: `security_score`.

### Changed

- ProfileService extended with `calculate_all_security_scores()` method.
- Helper functions: `_cve_age_days()`, `_calculate_cve_breakdown()`.

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
- Stripe billing integration.
- CVE Mitigation Advisor (hardening recommendations).
- Cisco PSIRT / Tenable integrations.
- Advanced Profiles UX (rename, duplicate, diff preview).
