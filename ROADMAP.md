# ROADMAP — NetDevOps Micro-Tools

Current version: **v0.3.4**
Last updated: 2026-01-07

---

## ✅ Completed (v0.1.0 → v0.3.4)

### v0.1.0 — MVP Release
- [x] FastAPI backend with SNMPv3, NTP, AAA, Golden Config generators
- [x] Initial CVE Analyzer (static demo dataset)
- [x] Dockerized API
- [x] Web UI with generators and CVE tab
- [x] Basic profiles (Lab / Branch / Datacenter)

### v0.2.0 — Product Shaping
- [x] CVE Engine v0.2 with JSON-based dataset
- [x] Web UI v2 (sidebar layout, CVE dashboard)
- [x] Profiles v2 (backend-driven, save/load/delete)
- [x] Security posture summary panel
- [x] Services and models layer architecture

### v0.3.x — External Integration
- [x] CVE Engine v0.3 with provider architecture
- [x] NVD API v2.0 enrichment (real external integration)
- [x] CVSS, CWE, references fields
- [x] Safe merge strategy (local JSON as source of truth)

### v0.3.4 — Stability & Performance
- [x] NVD response caching (file-based, 24h TTL)
- [x] Graceful error handling (HttpTimeoutError, HttpConnectionError)
- [x] Real CVE data (CVE-2023-20198, CVE-2023-20273, CVE-2025-20188)
- [x] .gitignore and project cleanup

---

## 🎯 Next: v0.3.5 — Profile Intelligence

Focus: Connect profiles with CVE analysis.

### Planned features

#### 1. Profiles × CVE Integration
- "Which saved profiles are affected by known CVEs?"
- Cross-reference profile IOS versions with CVE database
- Alert panel in Profiles tab
- Batch analysis endpoint

#### 2. Security Score (0-100)
- Aggregate score based on:
  - Number of critical/high CVEs
  - Max CVSS score
  - Availability of fixes
- Visual indicator in Web UI per profile
- Score history tracking

#### 3. Web UI Improvements
- Loading states during NVD enrichment
- Profile vulnerability badges
- One-click "Check all profiles" button

---

## 🚀 v0.4.0 — SaaS Readiness

Focus: Multi-user support and cloud deployment.

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
- [ ] Subscription tiers (Free / Pro)
- [ ] Usage-based billing option

### Cloud Deployment
- [ ] Railway / Render / Fly.io deployment
- [ ] Environment configuration
- [ ] Health monitoring

---

## 🔮 Future (v0.5.0+)

### External Data Providers
- [ ] Cisco PSIRT Advisory integration
- [ ] Tenable vulnerability scanner integration
- [ ] Custom CVE dataset upload

### Export & Reporting
- [ ] PDF security reports
- [ ] Markdown export
- [ ] Scheduled email reports

### CLI Tool
- [ ] Terminal-based interface for power users
- [ ] Scriptable config generation
- [ ] CI/CD integration support

### Advanced Features
- [ ] Config diff / drift detection
- [ ] Compliance checking (CIS benchmarks)
- [ ] Network topology awareness

---

## 📊 Success Metrics (Q1 2026)

| Metric | Target |
|--------|--------|
| Beta users | 10 |
| Discovery calls | 5 |
| API uptime | 99% |
| NVD cache hit rate | >80% |

---

_This roadmap is updated as priorities evolve. See CHANGELOG.md for release history._
