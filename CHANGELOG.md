# Changelog

All notable changes to this project will be documented in this file.

---

## [v0.6.7] – 2026-04-19 (late evening)

### Changed — Rename "banner" CSS classes to avoid ad-blocker cosmetic filters

Even after the /critical-feed → /advisories route rename in v0.6.6, users
still saw the Arc / Brave "not working correctly" popup on first visit.
Root cause found: EasyList-based cosmetic filters (Brave Shields, uBlock
Origin) hide ANY element with `class*="banner"` pattern. The DOM still
had `.quickstart-banner` and `.gate-banner` classes, which triggered the
shield warning regardless of whether content actually looked like ads.

- `.quickstart-banner` → `.quickstart-card` (6 occurrences across index.html,
  style-home.css, app-core.js).
- `.gate-banner`, `.gate-banner-content`, `.gate-banner-icon`,
  `.gate-banner-text`, `.gate-banner-btn`, `#gate-banner` → `.gate-notice*`
  equivalents (app-gate.js, style-base.css).
- Form field names `include_banner` / `custom_banner` (Cisco MOTD config)
  preserved — they're API payload fields, not CSS selectors.

Version bump: app 0.6.6 → 0.6.7.

---

## [v0.6.6] – 2026-04-19 (late evening)

### Changed

- **Route rename to avoid ad-blocker false positive**:
  `/analyze/critical-feed` → `/analyze/advisories`.
  Arc / Brave / uBlock Origin heuristics flagged the old endpoint because
  "critical-feed" matches ad/tracking feed naming conventions (e.g.
  `criteo.com/critical-feed`, Brave triggered on the suffix). The new
  endpoint uses neutral "advisories" language which is standard security
  terminology and doesn't match blocker patterns. Old route kept as
  deprecated alias for backward compat.
- Frontend (`web/app-feeds.js`) updated to call `/analyze/advisories`.

Version bump: app 0.6.5 → 0.6.6.

---

## [v0.6.5] – 2026-04-19 (late evening)

### Changed — Quickstart banner UX

User feedback: "New here?" banner helpful for first-time visitors,
noise for returning users who already know the tools.

- **Manual dismiss button** (×) in top-right of banner. Click persists
  via `localStorage['netdevops_quickstart_dismissed']`.
- **Auto-hide after 3 visits**. Counter
  `localStorage['netdevops_visit_count']` increments on each page
  load. Visit 4+ → banner hidden.
- Counter resets if user clears localStorage (re-onboarding is cheap).
- Hidden state uses `display: none` via `.hidden` class; zero layout
  impact when removed.

Version bump: app 0.6.4 → 0.6.5.

---

## [v0.6.4] – 2026-04-19 (late evening)

### Added — CVE Analyzer severity transparency (engine 0.3.7, backend only)

CTO memo P1.3: `[CRITICAL]` label on CVE-2025-20352 with CVSS 8.8 confuses
operators — they see a contradiction between the displayed severity and the
base score. Add transparency so the API response explains the relationship.

- `cvss_rating_from_score(score)` helper: returns NVD CVSS v3.x qualitative
  rating (LOW / MEDIUM / HIGH / CRITICAL) from a numeric score.
- `severity_info(cve)` helper returns dict:
  - `cvss_score` (raw), `cvss_rating` (derived), `effective_label` (what the
    tool displays), `escalation_reason` (why label differs from CVSS rating —
    e.g. "Listed in CISA KEV catalog + Actively exploited in the wild"),
    `label_matches_cvss` (bool).
- `CVEAnalyzeResponse` now includes `severity_details: dict[cve_id, info]`
  populated for every matched CVE.

Example for CVE-2025-20352:
```
  cvss_score: 8.8
  cvss_rating: HIGH
  effective_label: CRITICAL
  escalation_reason: "Listed in CISA KEV catalog + Actively exploited in the wild + Zero-day"
  label_matches_cvss: false
```

Frontend UI display still pending (API consumer gets enriched data already).

### Audit finding

Of 142 CVEs in local dataset, 10 had label ≠ CVSS rating:
- 1 legitimate (CVE-2025-20352 — KEV-escalated).
- 9 unexplained (labeled HIGH, CVSS 5.9-6.7) — Cisco SIR rating bleeding
  through without escalation tags. These will surface in the API as
  `label_matches_cvss: false, escalation_reason: null`, which is the
  correct signal for downstream cleanup (W19+).

---

## [v0.6.3] – 2026-04-19 (late evening)

### Added — CVE Analyzer v0.5 (engine 0.3.6)

3 canonical CVEs manually added to local dataset to close the biggest
feed-gap items from CTO memo P0.2:

- **CVE-2018-0101** — Cisco ASA Webvpn/AnyConnect RCE + DoS. CVSS 10.0.
  Affected: all Cisco ASA Software with Webvpn/AnyConnect configured.
  Fixed in 9.9.1.2 (per-train fixes: 9.1.7.20, 9.2.4.25, 9.4.4.14,
  9.5.3.9, 9.6.3.20, 9.7.1.16, 9.8.2.14). Previously 100% missing for
  ASA queries.

- **CVE-2019-1652** — Cisco RV320/RV325 command injection. CVSS 7.2.
  Fixed in 1.4.2.22. Flagship RV-series advisory, previously missing.

- **CVE-2019-1653** — Cisco RV320/RV325 information disclosure. CVSS 7.5.
  Fixed in 1.4.2.20. Commonly chained with CVE-2019-1652 for full
  device compromise. Previously missing.

### Fixed

- **Version parser regex** (`_extract_version`): previously truncated
  4-component versions to 3 (e.g. "1.4.2.19" → (1, 4, 2, 0) instead of
  (1, 4, 2, 19)), causing incorrect range matching for RV-series and
  ASA interim-release versions. Rewrote using two-regex approach
  (IOS-classic `15.7(3)M5` + generic N-component dotted), preserving
  arbitrary depth + optional rebuild letter.

### Test results vs CTO memo 2026-04-19

| Platform | Version | Expected | Before | After |
|----------|---------|----------|--------|-------|
| Cisco ASA | 9.8.1 | CVE-2018-0101 present | ❌ missing | ✅ present |
| Cisco RV320 | 1.4.2.19 | CVE-2019-1652 + 1653 | ❌ missing | ✅ both present |
| Cisco RV320 | 1.4.2.20 | CVE-2019-1652 still vuln, 1653 patched | ❌ missing | ✅ 1652 shown, 1653 excluded |
| Cisco RV320 | 1.4.2.22 | Both patched, excluded | ❌ missing | ✅ both excluded |
| Cisco IOS XE | 17.9.1 | CVE-2025-20352 present | ✅ | ✅ (regression clear) |

### Remaining (W19+ sprint)

- P0.1 PSIRT importer refactor (3-5 dni) — still the authoritative fix
  for systemic "IOS XE" mislabeling at feed level.
- P0.2 additional missing CVEs — need audit of PSIRT back-catalog for
  platforms where feed gap is wide (NX-OS, FXOS, IOS XR).
- P1.1 Safe-upgrade 3-level fallback.
- P1.2 EoL registry.
- P1.3 CVSS-vs-label severity transparency in UI.

---

## [v0.6.2] – 2026-04-19 (evening)

### Fixed — CVE Analyzer v0.4 (engine 0.3.5)

Post-CTO memo 3-platform testing revealed that the first round of fixes
(commit 69c6856) cleared IOS XE issues but left ASA and RV Series queries
with systemic false positives due to the PSIRT importer tagging all
advisories as "IOS XE". This release adds a data-layer fix that detects
true product families from CVE titles and strict-filters cross-family
matches.

- **Product-family taxonomy** (`services/platform_taxonomy.py`): new module
  mapping CVE titles to canonical `ProductFamily` values (ASA, IOS XE,
  IOS XR, NX-OS, RV Series, CUCM, Webex, SSM On-Prem, Meraki, etc.).
  User input normalization + in-scope compatibility matrix.
- **Strict family filter in `match()`**: CVEs whose title explicitly
  names a different family are excluded from query results. Shared
  advisories ("Cisco IOS, IOS XE, and IOS XR Software ...") still match
  all mentioned families.
- **Placeholder filter** (CTO memo P2.1): CVEs whose `fixed_in` is prose
  ("Migrate to SNMPv3...", "Remove default community strings...") rather
  than a version string are treated as hardening rules and excluded from
  applicable-CVE lists.

### Test results vs CTO memo 2026-04-19

| Platform | Before | After | Change |
|----------|--------|-------|--------|
| IOS XE 17.9.1 | 110 matches | 104 matches | -6 (SSM/CUCM/AP false positives removed) |
| ASA 9.8.1 | 74 matches | 13 matches | -61 (IOS-only cross-contamination eliminated) |
| RV Series 1.4.2.22 | 8 matches | 4 matches | -4 (product-unclear L2 VLAN CVEs remain) |

### Remaining (W19+ sprint, full CTO memo P0.1 refactor)

- **Feed gaps:** CVE-2018-0101 (ASA Webvpn RCE, CVSS 10.0) and
  CVE-2019-1652/1653 (RV Series command injection) not present in the
  current local JSON dataset — pure data issue, requires importer
  expansion or manual entry.
- **PSIRT importer refactor** (P0.1): preserve `affected_products` from
  advisory instead of defaulting to "IOS XE" — estimated 3-5 days.
- **Severity transparency** (P1.3): CVSS score vs label escalation
  reasoning — deferred for frontend work.
- **EoL registry** (P1.2): RV Series EoL 2025-01 should flag before CVE
  list — requires external data source.

---

## [v0.6.1] – 2026-04-19

### Fixed

- **CVE Analyzer v0.3** (engine 0.3.4) — 2 CRITICAL defects from 2026-04-19 self-audit:
  - **CVE-001:** CVE-2025-20352 (SNMP stack-overflow, CISA KEV, actively
    exploited) was silently excluded for every IOS/IOS XE target because
    `_tokenize_version("all versions before 17.15.4a...")` parsed the free-text
    max field as `(0,)`. New `parse_affected_range()` handles `all` / `all
    versions before X` / `X and earlier` / `prior to X` / empty strings and
    falls back to `fixed_in` when the max field is not a version token.
  - **CVE-002:** `recommended_upgrade()` returned the LOWEST fix version
    across applicable CVEs, producing a false "patched" state (e.g.
    recommending 17.15.2 while the SNMP KEV first-fixes in 17.15.4a). Now
    returns `max(fix_versions)` and annotates the driver CVE + KEV flag:
    *"17.15.4a — driven by CVE-2025-20352 (KEV, actively exploited)"*.

### Changed

- `_tokenize_version()` parses rebuild letters correctly (`17.15.4a` → tuple
  with letter tiebreaker; distinguishes from `17.15.4`).
- `match()` sorts KEV / actively-exploited / zero-day CVEs before
  critical/high — operators see the worst-risk items first.

### Frontend

- **Quickstart banner** added to homepage: guided entry for first-time users
  (Subnet Calculator, Timezone + NATO DTG, MTU Calculator — all free, no email).
- **Favicon** — network topology SVG (5-node diagram, gradient hub).
- Quickstart buttons bound to tab navigation (`app-core.js`).

### Remaining from 2026-04-19 defect report (queued W19+)

- CIS-001 / CIS-003 CRITICAL: VTY range parser, SNMP community parser.
- CVE-003 / CVE-004 / CVE-005 HIGH: product-family and hardware-family
  taxonomy to eliminate scope leakage.
- CVE-006 CRITICAL: version-range matching for local-json source is now
  partially correct (via `parse_affected_range`); remaining work is to
  extend the parser to IOS classic trains (`15.7(3)M5` style) and SMU
  suffixes.
- XCUT-001 HIGH: correlate CIS findings with CVE exploitability.

---

## [v0.6.0] – 2026-03-13

### Added

- **Cisco Threat Feed** (v1.0) — live CVE dashboard:
  - Cisco PSIRT API integration (`/latest/50`)
  - Platform filter: All / IOS XE / IOS / NX-OS / ASA / FTD
  - Home dashboard widget, 6h cache TTL, CVSS badge coloring
- **IP Path Tracer** (v1.0) — traceroute analyzer:
  - Parse output from Linux traceroute, Windows tracert, Cisco IOS
  - Latency spike detection, packet loss, RFC1918 boundaries
  - Command generator for 6 platforms (IOS, IOS-XE, NX-OS, ASA, Linux, Windows)
- **Port Auditor** (v1.0) — unused port detection:
  - Parse `show interface status` + optional `show interfaces`
  - Detect unused ports with configurable threshold
  - Generate shutdown config for inactive ports
- **Config Explainer** (v1.0) — plain English explanations:
  - Rule-based: 150+ Cisco command patterns, zero LLM cost
  - Risk flags (critical/warning/info), security notes
  - Standard and Junior-friendly modes
- **Config Drift Detection** (v1.0) — compare two configs:
  - Section-by-section diff (added/removed)
  - Risk flags on security-sensitive changes
  - Drift score 0-100%
- **CIS Compliance Audit** (v1.0) — hardening benchmark:
  - 37 rules based on CIS Cisco IOS Benchmark
  - Level 1 (28 rules) / Level 2 (37 rules)
  - Compliance score with letter grade (A-F)
  - Remediation commands per failed rule

### Changed

- **Frontend refactored** from monolithic files to modular architecture:
  - `app.js` (3,900 lines) → 8 domain-specific JS modules
  - `style.css` (3,000 lines) → 3 CSS modules (base, home, tools)
- Security Tools badge count: 2 → 5 (added CIS Audit)
- Network Tools badge count: 6 → 9 (added Port Auditor, Config Drift, + IP Path Tracer)
- Quick Access icons added for all new tools
- Version bumped to 0.6.0

---

## [v0.5.1] – 2026-02-23

### Added

- **UI/UX Redesign** — complete frontend overhaul:
  - **Grouped Sidebar** — tools organized by category:
    - Config Generators (SNMPv3, SNMP Multi-Host, NTP, AAA, Golden Config)
    - Security Tools (CVE Mitigation Advisor, Security Score)
    - Network Tools (iPerf3, Subnet Calculator, MTU Calculator, Timezone Converter, Config Parser)
    - Profiles (Device Profiles)
  - **Collapsible Navigation** — expand/collapse groups with smooth animations.
  - **Category Colors** — visual distinction (blue/red/green/purple).
  - **Icons & Badges** — tool count per category.
  - **Quick Access** — recent tools history (last 3 used).
  - **Home Page** — landing with all tools as cards.
  - **Dark/Light Mode Toggle** — full theme support with localStorage persistence.
  - **Hover Animations** — subtle feedback on interactive elements.

### Changed

- Sidebar layout from flat list to grouped hierarchy.
- All hardcoded dark backgrounds replaced with CSS variables for theme support.

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
  - Live URL: https://netdevops-tools.thebackroom.ai
  - API Docs: https://netdevops-tools.thebackroom.ai/docs
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
- Email capture / signup flow.
- Stripe billing integration.
- Network Config Backup (script generator).
- Tenable vulnerability scanner integration.
