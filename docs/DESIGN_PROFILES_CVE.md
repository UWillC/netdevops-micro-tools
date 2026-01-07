# Design Doc: Profiles × CVE Integration

**Version:** v0.3.5 (planned)
**Author:** @elon
**Created:** 2026-01-07
**Status:** Draft

---

## 1. Problem Statement

Currently, profiles and CVE analysis are separate features:
- **Profiles** store device configuration intent (platform, version, SNMPv3 settings)
- **CVE Analyzer** checks if a platform/version is affected by known vulnerabilities

Users must manually:
1. Open a profile
2. Note the platform and version
3. Go to CVE Analyzer tab
4. Enter the same platform/version
5. Check results

**Pain point:** "Are any of my saved devices vulnerable?" requires N manual checks.

---

## 2. Proposed Solution

### Core Feature: Batch Profile CVE Check

Add an endpoint that:
1. Reads all saved profiles
2. Runs CVE analysis on each
3. Returns aggregated results

### UI Enhancement

Add to Profiles tab:
- "Check All Profiles" button
- Vulnerability badge per profile (🔴 critical, 🟠 high, 🟡 medium, 🟢 clean)
- Expandable CVE list per profile

---

## 3. API Design

### New Endpoint

```
GET /profiles/vulnerabilities
```

**Response:**
```json
{
  "timestamp": "2026-01-07T18:00:00Z",
  "profiles_checked": 3,
  "summary": {
    "critical": 1,
    "high": 2,
    "medium": 0,
    "clean": 0
  },
  "results": [
    {
      "profile_name": "lab",
      "platform": "ISR4451-X",
      "version": "17.5.1",
      "status": "critical",
      "cve_count": 2,
      "max_cvss": 10.0,
      "cves": ["CVE-2023-20198", "CVE-2023-20273"]
    },
    {
      "profile_name": "branch",
      "platform": "Catalyst 9300",
      "version": "17.9.4",
      "status": "high",
      "cve_count": 1,
      "max_cvss": 7.2,
      "cves": ["CVE-2023-20273"]
    }
  ]
}
```

### Alternative: Single Profile Check

```
GET /profiles/{name}/vulnerabilities
```

Returns CVE analysis for a specific profile.

---

## 4. Data Flow

```
┌─────────────┐     ┌─────────────────┐     ┌────────────┐
│  profiles/  │ --> │ ProfileService  │ --> │ CVEEngine  │
│  *.json     │     │ load all        │     │ match()    │
└─────────────┘     └─────────────────┘     └────────────┘
                                                   │
                                                   v
                                            ┌────────────┐
                                            │ Aggregated │
                                            │ Results    │
                                            └────────────┘
```

---

## 5. Implementation Steps

### Phase 1: Backend (2-3h)

1. **Add to `profile_model.py`:**
   - `ProfileVulnerabilityResult` schema
   - `ProfileVulnerabilitySummary` schema

2. **Add to `profiles.py` router:**
   - `GET /profiles/vulnerabilities` endpoint
   - `GET /profiles/{name}/vulnerabilities` endpoint

3. **Add to `profile_service.py`:**
   - `check_all_vulnerabilities()` method
   - `check_profile_vulnerability(name)` method

### Phase 2: Frontend (2h)

1. **Profiles tab:**
   - Add "Check All" button
   - Add vulnerability badge component
   - Add CVE expandable list

2. **Styling:**
   - Badge colors (critical/high/medium/clean)
   - Loading state during check

### Phase 3: Testing (1h)

1. Unit tests for new service methods
2. API endpoint tests
3. Manual UI testing

---

## 6. Profile Schema Consideration

Current profile structure (from `profiles/*.json`):

```json
{
  "platform": "ISR4451-X",
  "version": "17.5.1",
  "snmpv3": { ... },
  "ntp": { ... },
  "aaa": { ... }
}
```

**Note:** We need `platform` and `version` fields to exist in profiles for CVE matching.

**Action:** Verify all profile templates include these fields.

---

## 7. Security Score (Future)

After Profiles × CVE is implemented, Security Score becomes straightforward:

```
score = 100 - (critical * 25) - (high * 15) - (medium * 5)
score = max(0, score)  # Floor at 0
```

This can be added in v0.3.5 or as a separate v0.3.6.

---

## 8. Open Questions

1. **NVD enrichment for batch check?**
   - Option A: Always use local CVE data only (fast, no rate limits)
   - Option B: Allow opt-in enrichment (slower, richer data)
   - **Recommendation:** A for batch, B optional for single profile

2. **Caching batch results?**
   - Profiles can change, so cache invalidation is tricky
   - **Recommendation:** No caching for v0.3.5, evaluate later

---

## 9. Timeline

| Task | Effort | Sprint |
|------|--------|--------|
| Backend implementation | 2-3h | #7-#8 |
| Frontend implementation | 2h | #9-#10 |
| Testing | 1h | #10 |
| **Total** | **5-6h** | **4-5 sprints** |

---

_This document will be updated as implementation progresses._
