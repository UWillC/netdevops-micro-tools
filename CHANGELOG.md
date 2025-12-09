# Changelog

All notable changes to this project will be documented in this file.

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
- Real CVE ingestion.
- Deploy-to-device (SSH) experimental flow.
- Authentication + multi-user mode.
- Cloud deployment template (Railway/Fly.io).
