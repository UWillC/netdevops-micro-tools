# Cisco Micro-Tool Generator

### **Automated configuration & security tools for Cisco engineers**

Cisco Micro-Tool Generator to zestaw narzędzi, który automatyzuje powtarzalną pracę inżynierów sieciowych.
Generuje konfiguracje, analizuje CVE, proponuje hardening oraz skraca troubleshooting z godzin do minut.

---

## **Misja projektu**

Stworzyć zestaw lekkich micro-narzędzi, które:

* generują konfiguracje Cisco w kilka sekund
* analizują konfiguracje pod kątem bezpieczeństwa
* oceniają podatności i rekomendują aktualizacje
* analizują logi i wskazują możliwe przyczyny problemów

Docelowo: **ekosystem SaaS dla network engineerów.**

---

## **Moduły (roadmap v0.1 → v1.0)**

###v0.1 (MVP – to build now)

* **SNMPv3 Config Generator**
* **NTP Config Generator**
* **AAA/TACACS+ Basic Template**
* **Base Golden Config Template**

###v0.5 (next)

* **Cisco CVE Analyzer**
  Input: device model + OS version → output: list of CVE + mitigation steps

* **Security Hardening Advisor**
  Input: running-config → output: recommended fixes

###v1.0 (SaaS Beta)

* Web UI
* API endpoints
* User profiles
* Configuration history
* Simple subscription model

---

## **Struktura projektu**

```
/cisco-microtool-generator
│
├── snmpv3-generator/
│   └── snmpv3_mvp.py
│
├── ntp-generator/
│   └── ntp_mvp.py
│
├── aaa/
│   └── aaa_basic_template.py
│
├── golden-config/
│   └── base_template.py
│
├── cve-analyzer/
│   └── cve_mvp.py
│
└── README.md
```

---

## **Dlaczego ten projekt powstaje**

Jestem inżynierem sieciowym, który wraca do networkingu po latach SysOps.
Widzę, że:

* inżynierowie tracą 30–60 minut na proste configi,
* nikt nie wie, które CVE dotyczą których urządzeń,
* brakuje automatycznych narzędzi bezpieczeństwa dla Cisco.

> Ten projekt eliminuje te problemy — krok po kroku.

---

## **Wymagania**

* Python 3.10+
* Biblioteki: `requests`, `rich` (opcjonalnie)
* (W przyszłości) Docker + FastAPI

---

## **Status**

Projekt jest w aktywnym rozwoju.
Aktualna faza: **MVP SNMPv3 + NTP + AAA**
Cel: **pierwsze demo SaaS do końca Q1 2026**.

---

## **Kontakt**

LinkedIn: [https://www.linkedin.com/in/przemyslaw-snow](https://www.linkedin.com/in/przemyslaw-snow)
