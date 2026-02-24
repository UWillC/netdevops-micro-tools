# NetDevOps Micro-Tools

![Version](https://img.shields.io/badge/version-0.5.1-blue)
![Python](https://img.shields.io/badge/python-3.10+-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Status](https://img.shields.io/badge/status-LIVE-brightgreen)

**Small tools. Real automation. AI-assisted.**

🚀 **Live:** https://netdevops-tools.thebackroom.ai

📧 **Pricing & Updates:** https://netdevops.thebackroom.ai/

![Demo](demo/netdevops-demo.gif)

A **micro-SaaS backend + Web UI** for generating **secure Cisco IOS / IOS XE configurations**,
performing **security analysis** (CVE awareness), and **network calculations**.

This project is built publicly as an engineering-focused product prototype, with emphasis on:
- secure-by-default configuration patterns,
- repeatability via profiles,
- clean API design (FastAPI),
- and gradual evolution toward a SaaS-style architecture.

> ⚠️ **Disclaimer**  
> CVE data included in this project is **demo / curated only** and must not be treated as a production security authority.
> Always consult official Cisco advisories for real-world decisions.

---

## 🚀 Why this project exists

As network engineers, we often:
- copy-paste configuration snippets from old devices,
- re-type the same secure baselines again and again,
- rely on ad-hoc scripts with no UI or consistency,
- lack quick visibility into *“is this IOS XE version already known-bad?”*

NetDevOps Micro-Tools aims to solve this by providing:
- opinionated but configurable secure defaults,
- reusable **device profiles**,
- a simple **Web UI** on top of a versioned API,
- and a clear path toward automation or SaaS deployment.

---

## ✨ Core Features

### 🔧 Configuration Generators

#### SNMPv3 Generator
- Secure defaults, balanced and legacy-compatible modes
- SHA / AES-based configuration
- CLI or one-line output formats

#### NTP Generator
- Primary and secondary servers
- Optional authentication
- Timezone configuration

#### AAA / TACACS+ Generator
- TACACS+ with local fallback
- Local-only mode
- Optional source-interface support

#### Golden Config Builder
- Combine SNMPv3 / NTP / AAA snippets
- Modular baseline sections (Banner, Logging, Security)
- Custom banner text support
- Designed to evolve into compliance / drift detection workflows

### 🧮 Network Tools

#### iPerf3 Command Generator
- TCP/UDP throughput tests
- Link speeds: 100M / 1G / 10G
- Directions: upload / download / bidirectional
- Hints panel with quick reference

#### IP Subnet Calculator
- Subnet info (network, broadcast, host range)
- Subnet splitting and supernetting
- CIDR ↔ Netmask conversion
- Full CIDR reference table (/8 to /32)

#### MTU Calculator
- Tunnel overhead calculation
- Supports: GRE, IPSec, VXLAN, MPLS, LISP, GRE over IPSec
- TCP MSS recommendations
- Cisco config suggestions

#### Config Parser
- Parse `show running-config` to structured JSON
- Extracts: hostname, interfaces, SNMP, NTP, AAA, users, banners
- Summary mode for quick stats

### 💻 CLI Tool (v0.4.3)

Terminal interface for power users:
```bash
pip install click requests
python cli.py snmpv3 --host 10.0.0.1 --user monitoring
python cli.py subnet info 192.168.1.0/24
python cli.py cve --platform "Cisco IOS XE" --version 17.3.1
```

---

## 🔐 CVE Analyzer & Security Score

A lightweight CVE awareness engine focused on Cisco IOS XE with NVD enrichment.

**Capabilities:**
- Platform + software version matching
- Severity classification (critical / high / medium / low)
- Upgrade recommendations based on known fixed versions
- **Security Score** (0-100) per device profile
- **Export PDF** security reports
- Real-time NVD API enrichment

**Key features:**
- **Profiles × CVE** — batch vulnerability checking across all device profiles
- **Security Score** — numeric assessment with CVE breakdown and modifiers
- **PDF Export** — downloadable security reports
- **File-based cache** — NVD responses cached for 24h (eliminates rate limiting)

**Data enrichment fields:**
- CVSS score and vector
- CWE classification
- Published/modified dates
- External references

**Web UI features:**
- Text-based CVE report
- Collapsible CVE cards with full metadata
- Severity badges
- Security posture summary panel (with Max CVSS)

> ℹ️ Local CVE dataset includes real Cisco IOS XE vulnerabilities. Enable NVD enrichment for additional metadata.

---

## 📁 Profiles v2 (UI + API)

Profiles allow you to **capture, reuse and reapply configuration intent**.

### What is a profile?
A profile is a named snapshot of:
- SNMPv3 configuration
- NTP configuration
- AAA / TACACS+ configuration

### What you can do
- Save current form values as a profile
- List available profiles
- Load a profile into the Web UI
- Delete profiles you no longer need

### API Endpoints
```
GET    /profiles/list
GET    /profiles/load/{name}
POST   /profiles/save
DELETE /profiles/delete/{name}
GET    /profiles/vulnerabilities   # NEW in v0.3.5
```

### Profiles × CVE (v0.3.5)

Check all profiles for known vulnerabilities in one call:

```bash
curl http://localhost:8000/profiles/vulnerabilities
```

Response includes:
- Per-profile vulnerability status (critical/high/medium/low/clean/unknown)
- CVE count and max CVSS score per profile
- Summary counts across all profiles

Profiles are stored on disk and can be persisted via Docker volumes.

---

## 🖥 Web UI v2

The Web UI provides a clean, distraction-free interface for daily use.

**Highlights:**
- Sidebar-based navigation
- Dedicated views for each generator
- CVE Analyzer with expandable CVE cards
- Profiles management UI (Profiles v2)
- Copy & download buttons for all outputs
- Persistent form state using `localStorage`

---

## 🧱 Architecture Overview

```
netdevops-micro-tools/
├── api/
│   ├── main.py              # FastAPI app, CORS, routers
│   └── routers/
│       ├── snmpv3.py        # POST /generate/snmpv3
│       ├── ntp.py           # POST /generate/ntp
│       ├── aaa.py           # POST /generate/aaa
│       ├── golden_config.py # POST /generate/golden-config
│       ├── cve.py           # POST /analyze/cve, GET /analyze/cve/{id}
│       └── profiles.py      # /profiles/* endpoints
├── services/                # Business logic layer
│   ├── cve_engine.py        # CVE matching engine
│   ├── cve_sources.py       # Providers (Local, NVD, Cisco, Tenable)
│   ├── http_client.py       # HTTP client + error classes
│   └── profile_service.py   # Profile CRUD
├── models/                  # Pydantic v2 models
│   ├── cve_model.py
│   ├── profile_model.py
│   └── meta.py
├── cache/
│   └── nvd/                 # NVD API response cache (24h TTL)
├── cve_data/
│   └── ios_xe/              # Local CVE database (JSON)
├── profiles/                # Saved device profiles
├── web/
│   ├── index.html           # SPA entry
│   ├── app.js               # Frontend logic
│   └── style.css
├── Dockerfile
├── .gitignore
└── README.md
```

---

## 🚀 Running locally (development)

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn api.main:app --reload
```

Swagger UI:
```
http://127.0.0.1:8000/docs
```

---

## 🐳 Running with Docker

### Build image
```bash
docker build -t netdevops-micro-tools .
```

### Run (ephemeral profiles)
```bash
docker run --rm -p 8000:8000 netdevops-micro-tools
```

### Run with persistent profiles (recommended)
```bash
docker run --rm -p 8000:8000 \
  -v "$(pwd)/profiles:/app/profiles" \
  netdevops-micro-tools
```

This ensures that profiles created via `/profiles/save`
are persisted across container restarts.

---

## 🧪 CVE Data Disclaimer (Important)

- CVE entries are **demo-only**
- Intended to showcase:
  - matching logic
  - severity aggregation
  - UI presentation
- This tool **must not** be used as a replacement for official Cisco advisories

---

## 🛣 Roadmap (high level)

**v0.4.3 (current):** ✅ LIVE
- 12 production modules (generators, analyzers, calculators)
- Cloud deployment on Render
- CLI tool for power users
- PDF security reports
- Security Score (0-100)

**v0.5.0 (next):**
- Authentication & multi-user mode
- Stripe billing integration
- User-scoped profiles and history

**Future:**
- CVE Mitigation Advisor (hardening recommendations)
- Cisco PSIRT / Tenable integrations
- Config drift detection
- Compliance checking (CIS benchmarks)

See `CHANGELOG.md` for version history.

---

## 📄 License

MIT

---

## 👤 Author / Notes

Built as a public engineering project focused on:
- network automation,
- secure configuration practices,
- and SaaS-oriented backend design.

Contributions, feedback and discussion are welcome.
