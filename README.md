# Cisco Micro-Tool Generator  
### **Automated configuration & security tools for Cisco engineers**

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

```
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

## **Status**

The project is under active development.
Current focus:

* solid CLI tools for SNMPv3, NTP, AAA, Golden Config
* preparing the codebase for an API and web UI

Target: **first public SaaS demo environment.**

---

## **Contact**

LinkedIn: [https://www.linkedin.com/in/przemyslaw-snow](https://www.linkedin.com/in/przemyslaw-snow)