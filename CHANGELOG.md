# Changelog

All notable changes to this project will be documented in this file.

---

## [v0.2.0] – 2025-12-15

### Added
- **CVE Engine v0.2.0**
  - JSON-based CVE dataset under `cve_data/ios_xe/`.
  - `CVEEngine` service (`services/cve_engine.py`) to load, match and summarize CVEs.
  - Matching by platform + IOS XE version range.
  - Severity breakdown (critical / high / medium / low).
  - Recommended upgrade target based on fixed-in versions.
- **CVE Analyzer API v2**
  - Updated `/analyze/cve` endpoint returning structured data:
    - `matched` CVEs (full objects)
    - `summary` severity stats
    - `recommended_upgrade`
    - timestamp and metadata.
- **Web UI v2**
  - New layout with a left-hand sidebar for tool navigation.
  - Dedicated CVE Analyzer view with a “Security posture” side panel.
  - Severity breakdown and upgrade recommendation visible at a glance.
- **Service & model layer**
  - Initial service layer under `services/` (CVE engine, utils, profiles skeleton).
  - Pydantic models under `models/` (`cve_model`, `profile_model`, `meta`).
  - Test skeletons in `tests/` for future automated tests.

### Improved
- CVE Analyzer Web UI now consumes the new v0.2.0 API response and renders:
  - platform, version, timestamp,
  - matched CVEs (title, tags, description, fixed-in, workaround, advisory),
  - severity summary,
  - recommended upgrade target.
- Overall project structure is now closer to a production-ready micro-SaaS backend.

### Notes
- CVE data is still a curated demo dataset and **must not** be used as a source of truth for production security decisions.

---

## [v0.1.0] – 2025-12-08

### Added
- Full FastAPI backend (SNMPv3, NTP, AAA/TACACS+, Golden Config).
- CVE Analyzer (MVP) with demo CVE dataset.
- Dockerfile and API containerization.
- Web UI with four generators + CVE tab.
- UX improvements:
  - Profiles (Lab / Branch / Datacenter).
  - Persistent form values (`localStorage`).
  - Download as `.txt` buttons for all outputs.
  - Copy buttons in every output panel.

### Notes
- This version marks the first minimal “micro-SaaS-ready” release.
- CVE dataset is demo-only and not meant for production use.

---

## [Unreleased]
- Editable device profiles (backend + Web UI).
- Web UI v2.5 polish (severity badges inline, collapsible CVE items).
- Authentication and multi-user mode.
- Real CVE ingestion from external sources.
