# ROADMAP — NetDevOps Micro-Tools

Current version: **v0.4.6** (LIVE)
Live URL: https://netdevops-micro-tools.onrender.com
Last updated: 2026-02-05

---

## ✅ Completed (v0.1.0 → v0.4.3)

### v0.1.0 — MVP Release (Dec 2025)
- [x] FastAPI backend with SNMPv3, NTP, AAA, Golden Config generators
- [x] Initial CVE Analyzer (static demo dataset)
- [x] Dockerized API
- [x] Web UI with generators and CVE tab
- [x] Basic profiles (Lab / Branch / Datacenter)

### v0.2.0 — Product Shaping (Dec 2025)
- [x] CVE Engine v0.2 with JSON-based dataset
- [x] Web UI v2 (sidebar layout, CVE dashboard)
- [x] Profiles v2 (backend-driven, save/load/delete)
- [x] Security posture summary panel
- [x] Services and models layer architecture

### v0.3.x — External Integration (Dec 2025 - Jan 2026)
- [x] CVE Engine v0.3 with provider architecture
- [x] NVD API v2.0 enrichment (real external integration)
- [x] CVSS, CWE, references fields
- [x] NVD response caching (file-based, 24h TTL)
- [x] Profiles × CVE integration
- [x] Vulnerability Status widget in Web UI

### v0.4.0 — Security Score (Jan 2026)
- [x] Security Score (0-100 per profile)
- [x] Score algorithm with CVE penalties and modifiers
- [x] Security Score widget in Web UI

### v0.4.1 — Cloud Deployment (Jan 2026)
- [x] **LIVE on Render** — https://netdevops-micro-tools.onrender.com
- [x] Backend serves frontend (single deployment)
- [x] render.yaml for one-click deploy

### v0.4.2 — Export PDF (Jan 2026)
- [x] PDF security reports
- [x] Export button in Security Scores widget

### v0.4.3 — CLI Tool + New Modules (Jan 2026)
- [x] CLI tool for power users (click framework)
- [x] iPerf3 Command Generator
- [x] IP Subnet Calculator (5 endpoints)
- [x] MTU Calculator (tunnel overhead)
- [x] Config Parser (show run → JSON)
- [x] SNMP Multi-Host Generator
- [x] NTP v2 (network tier hierarchy)
- [x] AAA v2.1 (SSH prerequisites, local fallback)
- [x] Golden Config v2 (modular baseline)
- [x] Verification Tooltips (~120 educational hints)

### v0.4.4 — iPerf3 Multi-platform Scripts (Feb 2026)
- [x] Bash script output (.sh)
- [x] PowerShell script output (.ps1)
- [x] Python script output (.py)
- [x] Frontend dropdown with 4 output formats

### v0.4.5 — JSON Export (Feb 2026)
- [x] JSON format for security report (`?format=json`)
- [x] "Export JSON" button in Security Scores widget

### v0.4.6 — Markdown Export (Feb 2026)
- [x] Markdown format for security report (`?format=md`)
- [x] "Export MD" button in Security Scores widget
- [x] 3 export formats: PDF, JSON, Markdown

---

## 🎯 Current Phase: Validation (Q1 2026)

Focus: Confirm product-market fit before monetization.

### Targets

| Metric | Target | Status |
|--------|--------|--------|
| Discovery calls | 5 | 🔴 0/5 |
| Beta users | 10 | 🔴 0/10 |
| LinkedIn followers | 500 | 🟡 ~50 |

### Key Activities

- [ ] Discovery calls with network engineers
- [ ] LinkedIn content (3x/week)
- [ ] Demo at Kirk Byers conference (March 9-12)
- [ ] Collect beta tester feedback

---

## 🚀 v0.5.0 — SaaS Monetization (Q2 2026)

Focus: Multi-user support and billing.

### Authentication & Authorization
- [ ] User registration and login
- [ ] JWT-based authentication
- [ ] API key support for programmatic access

### Multi-tenant Architecture
- [ ] User-scoped profiles
- [ ] Isolated CVE analysis history
- [ ] Usage tracking per user

### Billing Integration
- [ ] Stripe integration
- [ ] Subscription tiers (Free / Pro / Team)
- [ ] Usage-based billing option

---

## 🔮 Future (v0.6.0+)

### CVE Mitigation Advisor (Killer Feature)
- [ ] Hardening config recommendations per CVE
- [ ] Patch recommendations
- [ ] Risk explanations
- [ ] Links to Cisco PSIRT and Field Notices
- **Note:** ZERO competition in this space

### External Data Providers
- [ ] Cisco PSIRT Advisory integration
- [ ] Tenable vulnerability scanner integration
- [ ] Custom CVE dataset upload

### Advanced Features
- [ ] Config diff / drift detection
- [ ] Compliance checking (CIS benchmarks)
- [ ] Network topology awareness
- [ ] Scheduled email reports

---

## 📊 2026 Goals

| Metric | Q1 | Q2 | EOY |
|--------|-----|-----|-----|
| Beta users | 10 | — | — |
| Paying customers | — | 5 | 50 |
| MRR | $0 | $50 | $500 |

---

_This roadmap is updated as priorities evolve. See CHANGELOG.md for release history._
