# ROADMAP v0.2.0 — Product Shaping Release

Goal: Move from “working MVP” → “early-stage product ready for real users”.
v0.2.0 will focus on strengthening the intelligence layer, improving UX, and preparing architecture for future SaaS features.

---

## 1. CVE Analyzer v0.2 — Realistic Engine

The MVP uses a static demo dataset.
v0.2.0 introduces a real, structured and extensible CVE engine.

### Planned features

#### 1.1. Real CVE data structure

Introduce:

```
cve_data/
  ios_xe/
    cve-2024-12345.json
    cve-2024-56789.json
  asa/
  nxos/
```

Each file shaped like:

```json
{
  "cve_id": "CVE-2024-12345",
  "title": "Example privilege escalation",
  "severity": "critical",
  "platforms": ["IOS XE", "ISR4451-X"],
  "affected": {
    "min": "17.3.1",
    "max": "17.9.9"
  },
  "fixed_in": "17.10.1",
  "tags": ["web-ui", "auth-bypass"],
  "description": "...",
  "workaround": "...",
  "advisory_url": "..."
}
```

#### 1.2. Dynamic loading

A new module:

`services/cve_engine.py`

Responsibilities:

* load all JSON files from `cve_data/`
* version comparison engine
* platform → version matching logic
* filtering, grouping, sorting

#### 1.3. Improved analysis output

API returns:

* affected CVEs grouped by severity
* summary statistics
* recommended upgrade target
* affected features (tags)
* optional Markdown export

#### 1.4. Confidence level

Add field:

```json
"confidence": "demo" | "validated" | "partial"
```

Allows future real integrations.

---

## 2. Web UI Upgrade v2 — From Tool → Dashboard

Goal: Turn the current form-based UI into a small but professional dashboard.

### Planned UI improvements:

#### 2.1. Left-hand navigation panel

Replace top tabs with a sidebar:

```
SNMPv3
NTP
AAA
Golden Config
CVE Analyzer
Profiles
About
```

#### 2.2. “Security Posture Summary” panel

When using CVE Analyzer, display:

* number of critical CVEs
* number of high CVEs
* recommended upgrade
* risk score meter
* quick links to advisories

#### 2.3. Export formats

For each generator:

* Download `.txt` (already done in 0.1.0)
* NEW: Download `.md`
* NEW: Download `.json`

#### 2.4. Inline validation

Examples:

* highlight invalid IP
* highlight missing tacacs1_key when mode = tacacs
* check empty passwords for SNMPv3

#### 2.5. Template editor for Golden Config

Let user insert/remove building blocks dynamically.

---

## 3. Device Profiles v2 — Editable & Persistent

Profiles move from hardcoded JS → configurable files.

### Directory:

```
profiles/
  lab.json
  branch.json
  dc.json
  custom/
    my-company.json
```

### Planned features:

* UI: list available profiles
* UI: create custom profile
* UI: edit profile
* Backend: `/profiles/list` and `/profiles/save`
* Future: authenticated profiles per user (v0.3.0+)

---

## 4. Architecture Improvements

To prepare for future features like auth, multi-user mode, cloud deployment.

### Planned changes:

#### 4.1. Add services/ layer

Folder:

```
services/
  cve_engine.py
  golden_builder.py
  device_profiles.py
  utils.py
```

Router → service → response model
Clear separation of concerns.

#### 4.2. Pydantic v2 schemas for CVE

Introduce:

```
models/
  cve.py
  generator.py
  profile.py
```

#### 4.3. Testing structure

Add folder:

```
tests/
  test_cve_engine.py
  test_profiles.py
```

Use pytest.

#### 4.4. Improve version comparison

Extract version logic into utility:

```javascript
from services.utils import compare_versions
```

---

## 5. Preparation for Authentication (v0.3.0 Preview)

Not part of v0.2.0 but groundwork will be laid.

### Includes:

* Decide on auth mode:
    * API key?
    * JWT?
    * Auth0 login?
* Create `/auth/` router skeleton
* Add CORS rules for authenticated mode
* Frontend placeholder for login

---

## 6. Other Enhancements in v0.2.0

### Better error messages

Consistent error responses:

```json
{
  "error": "Invalid input",
  "details": { ... }
}
```
### Add `/health` endpoint

For monitoring and readiness.

### Add `/meta/version` endpoint

Returns:

```json
{
  "version": "0.2.0-dev",
  "build_time": "...",
  "feature_flags": [...]
}
```

### CI placeholder

Add a GitHub Actions workflow:

* lint
* test
* build container (without deploy)

---

## Deliverables of v0.2.0

By the end of v0.2.0 you'll have:

* Realistic CVE engine
* *More professional Web UI
* Editable device profiles
* Cleaner backend architecture
* Basic testing structure
* Ready for v0.3.0 (auth, multi-user SaaS)

This is a major step toward a real micro-SaaS.
