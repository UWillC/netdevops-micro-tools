# Changelog

All notable changes to this project will be documented in this file.

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
- External CVE ingestion (Cisco advisories / NVD).
- Export formats (Markdown / JSON).
- Advanced Profiles UX (rename, duplicate, diff preview).
