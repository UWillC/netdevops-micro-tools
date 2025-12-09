# Cisco Micro-Tool Generator  

## **Automated configuration & security tools for Cisco engineers**

This project is part of a micro-SaaS toolkit designed for network engineers who work with Cisco IOS/XE.  
The goal is simple: eliminate repetitive CLI work and generate secure, production-ready configurations in seconds.

---

## **Project Mission**

Cisco Micro-Tool Generator aims to provide a set of lightweight micro-tools that:

* generate Cisco configurations in a few seconds  
* validate and improve security baselines  
* help assess vulnerabilities and mitigation options  
* speed up troubleshooting by automating repetitive tasks  

Long-term, this evolves into a **micro-SaaS ecosystem for network engineers**.

---

## **Roadmap (v0.1 → v1.0)**

### v0.1 (MVP – current focus)

* **SNMPv3 Config Generator**
* **NTP Config Generator**
* **AAA/TACACS+ Generator**
* **Golden Config Generator**

### v0.5 (next)

* **Cisco CVE Analyzer**  
  Input: device model + OS version → output: relevant CVEs + mitigation ideas

* **Security Hardening Advisor**  
  Input: running configuration → output: recommended fixes / hardening tips

### v1.0 (SaaS Beta)

* Web UI  
* API endpoints  
* User accounts / profiles  
* Configuration history  
* Simple subscription model  

---

## **Project Structure**

```text
/cisco-microtool-generator
│
├── snmpv3-generator/
│   ├── snmpv3_mvp.py       # main SNMPv3 config generator (CLI tool)
│   └── snmpv3_demo.py      # fixed demo script used for GIFs and docs
│
├── ntp-generator/
│   └── ntp_mvp.py          # NTP config generator (CLI tool)
│
├── aaa/
│   └── aaa_basic_template.py   # AAA / TACACS+ generator (CLI tool)
│
├── golden-config/
│   ├── golden_config_mvp.py    # initial golden config builder (v0.1)
│   └── golden_config_v02.py    # golden config v0.2 with auto-detected modules
│
├── cve-analyzer/
│   └── cve_mvp.py          # placeholder for future CVE analyzer module
│
├── demo/
│   ├── README.md           # explanation of the SNMPv3 demo
│   └── snmpv3_demo.gif     # CLI demo GIF of the SNMPv3 generator
│
└── README.md               # this file
```

---

## **Why this project exists**

I’m a network engineer returning to networking after years in SysOps and infrastructure. In day-to-day work I see that:

* engineers waste 30–60 minutes on basic but repetitive configs
* it’s not always clear which CVEs actually affect which devices and software versions
* there is a lack of small, focused automation tools for Cisco security baselines

> This project is my way of solving those problems step-by-step and turning that experience into a usable product.

---

## **Current Modules**

### SNMPv3 Config Generator

Generates a complete SNMPv3 configuration aligned with security best practices, including:

* security modes (secure-default, balanced, legacy-compatible, custom)
* multi-user support
* password validation and warnings
* multiple output formats:
  * CLI (multi-line)
  * oneline (single line, ; separated)
  * YAML template (for automation tools like Ansible)

### NTP Config Generator

Builds consistent NTP configuration for Cisco devices:

* primary and secondary NTP servers
* timezone configuration
* optional NTP authentication (key ID + MD5 key)
* supports CLI and single-line output
* optional export to file

### AAA/TACACS+ Generator

Creates a baseline AAA configuration with two modes:

* local-only AAA (no external server)
* TACACS+ with local fallback (primary and optional secondary TACACS+ server)

Features:

* optional enable secret with basic password quality checks
* optional TACACS+ source interface
* CLI and one-line formats
* ready to paste into Cisco IOS/XE device configs

### Golden Config Generator

Generates a golden baseline configuration for new Cisco devices by combining:

* SNMPv3 configuration
* NTP configuration
* AAA/TACACS+ configuration
* login banner
* logging baseline
* security baseline (with multiple modes in v0.2)

### Golden Config v0.2 can:

* auto-detect module config files in the current directory (e.g. snmpv3_config*.txt, ntp_config*.txt, aaa_tacacs*.txt)
* merge them into a single baseline configuration
* apply different security profiles: standard, secure, hardened
* export the final golden config to a file (e.g. golden_config_secure.txt)

### CVE Analyzer (MVP)

The CVE Analyzer module introduces the first “smart” capability in the Cisco Micro-Tool Generator.  
It allows you to check whether a given Cisco platform and IOS XE software version are affected by any known (demo) CVEs included in the MVP dataset.

**Important:**  
The CVE database in this MVP is a demo dataset meant for development and testing only.  
It is **NOT** suitable for production security decisions.

#### How it works

Send a request such as:

```json
POST /analyze/cve
{
  "platform": "ISR4451-X",
  "version": "17.5.1",
  "include_suggestions": true
}
```

The API responds with:

* matched CVEs (demo dataset)
* severity and description
* fixed-in version (if applicable)
* workarounds
* advisory links
* a generated recommendation (optional)
* timestamp and metadata

Example response:

```json
{
  "platform": "ISR4451-X",
  "version": "17.5.1",
  "matched_cves": [
    {
      "cve_id": "CVE-DEMO-0001",
      "severity": "critical",
      "title": "Example privilege escalation in IOS XE web management",
      "workaround": "Disable HTTP/HTTPS management on WAN-facing interfaces."
    }
  ],
  "recommended_action": "One or more critical/high issues affect this platform/version. Consider upgrading to at least IOS XE 17.7.1.",
  "timestamp": "2025-12-06T18:30:00Z",
  "note": "This CVE data is a demo dataset for the Cisco Micro-Tool Generator MVP."
}
```

#### Web UI Integration

The Web UI now includes a CVE Analyzer tab where you can:

* type platform + software version
* click Analyze CVEs
* instantly see results, recommendations, and advisories

This marks the first step toward building deeper Cisco automation and security intelligence features.

---

## 🚀 SaaS-ready Demo

This project is evolving into a micro-SaaS focused on generating secure, production-ready configurations for Cisco IOS/XE devices.  
The goal: automate repetitive CLI work and deliver consistent, security-aligned configs in seconds.

Below is a short demo of the **SNMPv3 Config Generator** running in secure-default mode.

<details>
  <summary><strong>Click to expand the GIF</strong></summary>

![SNMPv3 Demo](./demo/snmpv3_demo.gif)

</details>

---

## **Requirements**

* Python 3.9+
* Optional libraries (planned / future):
  `requests`
  `rich`
* In the future:
  * Docker
  * FastAPI (for API / SaaS version)

---

## 🐳 Run the API with Docker

You can run the Cisco Micro-Tool Generator API as a Docker container.

### 1. Build the image

From the repository root:

```bash
docker build -t cisco-microtool-api .
```

### 2. Run the container

```bash
docker run --rm -p 8000:8000 cisco-microtool-api
```

The API will be available at:

* Health check: <http://127.0.0.1:8000/>
* Swagger UI: <http://127.0.0.1:8000/docs>

From there you can call:

* POST /generate/snmpv3
* POST /generate/ntp
* POST /generate/aaa
* POST /generate/golden-config

All endpoints return JSON with both the generated configuration and metadata.

---

## 🖥 Web UI (Experimental)

On top of the FastAPI backend, this project also includes a small web UI for generating configs directly from the browser.

The UI lives in the `web/` folder and supports:

* SNMPv3 Config Generator  
* NTP Config Generator  
* AAA / TACACS+ Generator  
* Golden Config Builder  

It is a thin client on top of the existing API endpoints:

* `POST /generate/snmpv3`  
* `POST /generate/ntp`  
* `POST /generate/aaa`  
* `POST /generate/golden-config`  

### How to run the Web UI (local dev)

1. Start the API (Python):

   ```bash
   python3 -m uvicorn api.main:app --reload --port 8000
   ```

or run it via Docker:

  ```bash
  docker run --rm -p 8000:8000 cisco-microtool-api
  ```

2. Open the `web/` folder and serve `index.html` using any static file server.
For example, with VS Code **Live Server** extension:

* open `web/index.html`
* choose “Open with Live Server”

3. The UI will send requests to `http://127.0.0.1:8000` (configured in `web/app.js` as `API_BASE_URL`).
If you change the API port, update `API_BASE_URL` accordingly.

The Web UI is intentionally minimal and focused on network engineers:
you fill in parameters, click **Generate**, and get a ready-to-paste Cisco configuration

## 🧩 UX Enhancements (Profiles, Persistence & Downloads)

To make the Web UI more practical for day-to-day use by network engineers, several quality-of-life features were added:

### Profiles (Lab / Branch / Datacenter)

The UI now includes predefined configuration profiles that automatically populate SNMPv3, NTP and AAA fields with sensible defaults for:

* **Lab router**
* **Branch router**
* **Datacenter router**

This allows you to generate complete configs with almost zero typing.

### Persistent form values (`localStorage`)

All input forms (SNMPv3, NTP, AAA, Golden Config and CVE Analyzer) now save the last used values locally in the browser.  
When you refresh or reopen the tool, your previous inputs automatically reappear.

This drastically speeds up repetitive config generation.

### Download as `.txt`

Each generator output panel now includes a **Download** button that exports the generated configuration or CVE analysis as a clean `.txt` file — ready to attach to tickets, email threads, documentation, or device deployment workflows.

These UX improvements aim to move the project closer to a real micro-SaaS experience, not just a backend API with forms.

---

## **Status**

The project is under active development.
Current focus:

* solid CLI tools for SNMPv3, NTP, AAA, Golden Config
* preparing the codebase for an API and web UI

Target: **first public SaaS demo environment.**

---

## **Contact**

LinkedIn: [https://www.linkedin.com/in/przemyslaw-snow](https://www.linkedin.com/in/przemyslaw-snow)
