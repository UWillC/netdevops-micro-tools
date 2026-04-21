"""
Integration test for the CVE-003 + CVE-006 pipeline end-to-end.

Simulates what Phase 4 of both sprints will do when wiring the new primitives
into services/cve_sources.py::_parse_advisory():

  raw PSIRT advisory dict
      │
      ├─ productNames → normalize_cisco_product_names() → Set[ProductFamily]
      │                                                    │
      │                                                    ▼
      │                                                CVEEntry.product_families
      │
      ├─ productNames (capped to 50)  ─────────────→ CVEEntry.affected_versions_raw
      │
      └─ firstFixed per-family map  ───────────────→ CVEEntry.first_fixed_version
                                                      │
                                                      ▼
                                               data_confidence() → "verified"

Acts as executable spec for Phase 4. When _parse_advisory is updated to
populate these fields, it MUST make this test pass end-to-end with real
cache-format inputs. Until then, this test exercises the primitives in
the same order the importer will use.
"""

from models.cve_model import CVEAffectedRange, CVEEntry, CVEFirstFixed
from services.cve_engine import data_confidence
from services.platform_taxonomy import (
    ProductFamily,
    normalize_cisco_product_names,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _simulate_parse_advisory(adv: dict) -> CVEEntry:
    """Mimic what _parse_advisory() will do post-Phase-4.

    NOT the production code — an executable spec that exercises the new
    primitives in the importer's order, so we can assert the full chain
    produces the expected output shape.
    """
    product_names = adv.get("productNames", [])

    # CVE-003 Phase 2: collapse raw names to canonical families.
    families = normalize_cisco_product_names(product_names)
    product_families_str = sorted(f.value for f in families)

    # Storage cap: keep first 50 raw names for display / debugging.
    affected_raw = [n for n in product_names if n][:50]

    # CVE-006 Phase 3: build per-family fix map from advisory firstFixed data.
    first_fixed = None
    ff_map = adv.get("firstFixed", {})
    if isinstance(ff_map, dict) and ff_map:
        # Only keep entries for families actually present in this advisory.
        family_fixes = {
            fam: ver
            for fam, ver in ff_map.items()
            if fam in product_families_str and ver
        }
        if family_fixes:
            first_fixed = CVEFirstFixed(fixes=family_fixes)

    # Legacy `platforms` still populated for backward-compat with existing
    # matcher fallback path.
    legacy_platforms = [f.upper() for f in product_families_str] or ["UNKNOWN"]

    return CVEEntry(
        cve_id=adv["cveId"],
        title=adv.get("title", ""),
        severity=adv.get("sir", "medium").lower(),
        platforms=legacy_platforms,
        affected=CVEAffectedRange(min="0.0.0", max="999.999.999"),
        fixed_in=None,  # superseded by first_fixed_version when populated
        description=adv.get("summary", ""),
        source="cisco-psirt-import",
        product_families=product_families_str,
        affected_versions_raw=affected_raw,
        first_fixed_version=first_fixed,
    )


# ---------------------------------------------------------------------------
# Single-family advisory (most common PSIRT shape)
# ---------------------------------------------------------------------------

def test_single_family_ios_xe_pipeline():
    """Typical IOS XE-only advisory with concrete firstFixed version."""
    adv = {
        "cveId": "CVE-2025-20352",
        "title": "Cisco IOS XE Software Web UI Privilege Escalation",
        "sir": "High",
        "summary": "Summary here.",
        "productNames": [
            "Cisco IOS XE Software 17.9.1",
            "Cisco IOS XE Software 17.9.2",
            "Cisco IOS XE Software 17.9.3",
        ],
        "firstFixed": {"ios-xe": "17.9.4a"},
    }

    cve = _simulate_parse_advisory(adv)

    # Phase 3 model assertions
    assert cve.product_families == ["ios-xe"]
    assert len(cve.affected_versions_raw) == 3
    assert cve.first_fixed_version is not None
    assert cve.first_fixed_version.fixes == {"ios-xe": "17.9.4a"}

    # Phase 3 data_confidence integration
    dc = data_confidence(cve)
    assert dc["confidence"] == "verified"
    assert "ios-xe" in dc["rationale"]


# ---------------------------------------------------------------------------
# Multi-family advisory (CVE-003 true value demonstration)
# ---------------------------------------------------------------------------

def test_multi_family_shared_advisory():
    """Shared IOS + IOS XE advisory (3242-name case shape)."""
    adv = {
        "cveId": "CVE-2017-6736",
        "title": "Cisco IOS and IOS XE Software SNMP Subsystem RCE",
        "sir": "Critical",
        "summary": "...",
        "productNames": [
            "Cisco IOS XR Software ",
            "Cisco IOS 12.2(15)B",
            "Cisco IOS 12.2(16)B1",
            "Cisco IOS 12.2(16)B3",
            "Cisco IOS XE Software 3.1.0.SG",
            "Cisco IOS XE Software 3.2.0.SG",
        ] + [f"Cisco IOS 12.2({i})T" for i in range(100)],  # simulate bloat
        "firstFixed": {"ios-xe": "3.10.0", "ios": "15.7(3)M1", "ios-xr": "6.2.3"},
    }

    cve = _simulate_parse_advisory(adv)

    # All three families detected
    assert set(cve.product_families) == {"ios", "ios-xe", "ios-xr"}

    # Storage cap enforced — 50 entries, not 106
    assert len(cve.affected_versions_raw) == 50

    # Per-family fixes preserved
    assert cve.first_fixed_version.fixes == {
        "ios-xe": "3.10.0",
        "ios": "15.7(3)M1",
        "ios-xr": "6.2.3",
    }

    # Verified with all three families cited in rationale
    dc = data_confidence(cve)
    assert dc["confidence"] == "verified"
    for fam in ("ios", "ios-xe", "ios-xr"):
        assert fam in dc["rationale"]


# ---------------------------------------------------------------------------
# Mixed security-platform advisory (FTD + ASA anchor case)
# ---------------------------------------------------------------------------

def test_asa_ftd_anchor_case():
    """CVE-2025-20363: unauth-on-ASA, auth-on-IOS-XE — different fix paths."""
    adv = {
        "cveId": "CVE-2025-20363",
        "title": "Cisco Secure Firewall ASA and Cisco IOS XE Web Services Auth Bypass",
        "sir": "Critical",
        "summary": "Unauthenticated on ASA path, authenticated on IOS XE path.",
        "productNames": [
            "Cisco Secure Firewall Adaptive Security Appliance",
            "Cisco IOS XE Software 17.9.4",
            "Cisco Secure Firewall Threat Defense (FTD)",
        ],
        "firstFixed": {
            "asa": "9.18.4",
            "ios-xe": "17.9.4a",
            "ftd": "7.4.2",
        },
    }

    cve = _simulate_parse_advisory(adv)
    assert set(cve.product_families) == {"asa", "ios-xe", "ftd"}
    assert cve.first_fixed_version.fixes["asa"] != cve.first_fixed_version.fixes["ios-xe"]
    assert data_confidence(cve)["confidence"] == "verified"


# ---------------------------------------------------------------------------
# Degraded-data scenarios (Phase 4 edge cases)
# ---------------------------------------------------------------------------

def test_missing_firstfixed_falls_through_to_max_bound():
    """Phase 1 detail fetch failure / empty firstFixed → falls through the
    data_confidence chain to max-bound via affected.max (or uncertain if
    that's also unbounded). This test simulates the pre-Phase-1 state of
    every PSIRT-import CVE today (129/129 gap)."""
    adv = {
        "cveId": "CVE-2024-20000",
        "title": "Legacy advisory",
        "sir": "High",
        "summary": "",
        "productNames": ["Cisco IOS XE Software 17.9.1"],
        # No firstFixed — Phase 1 endpoint didn't return data
    }

    cve = _simulate_parse_advisory(adv)
    assert cve.product_families == ["ios-xe"]
    assert cve.first_fixed_version is None

    # affected.max is the hardcoded 999.999.999 default from the simulator —
    # this IS a bounded max string so data_confidence treats it as max-bound.
    # Not ideal (the real max is still unknown) but matches current behavior
    # and will be corrected by Phase 6 published-date fallback in the real
    # _parse_advisory.
    dc = data_confidence(cve)
    assert dc["confidence"] in ("max-bound", "uncertain")


def test_unknown_platform_gets_unknown_family():
    """Unrecognized product names → {UNKNOWN} fallback, not empty set."""
    adv = {
        "cveId": "CVE-9999-99999",
        "title": "Some new Cisco product",
        "sir": "Low",
        "summary": "",
        "productNames": ["Cisco Something Completely New 2026"],
    }

    cve = _simulate_parse_advisory(adv)
    assert cve.product_families == [ProductFamily.UNKNOWN.value]


def test_empty_product_names_still_produces_valid_cve():
    """Defensive: advisory with no productNames (rare but possible) must
    still yield a valid CVEEntry rather than blowing up."""
    adv = {
        "cveId": "CVE-9999-99998",
        "title": "Sparse advisory",
        "sir": "Medium",
        "summary": "",
        "productNames": [],
    }

    cve = _simulate_parse_advisory(adv)
    assert cve.product_families == [ProductFamily.UNKNOWN.value]
    assert cve.affected_versions_raw == []
    assert cve.first_fixed_version is None
