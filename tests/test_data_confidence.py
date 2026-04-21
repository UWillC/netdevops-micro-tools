"""
CVE data-quality confidence tests (v0.6.23).

Tests the data_confidence() helper that classifies each CVE record by how
reliable its version-range matching is. This is a transparency layer
shipped while the full CVE-006 PSIRT closure is parked for W19+ sprint.
"""
from models.cve_model import CVEAffectedRange, CVEEntry, CVEFirstFixed
from services.cve_engine import data_confidence


def _make(cve_id="CVE-X", fixed_in=None, aff_min="", aff_max="", first_fixed_version=None):
    return CVEEntry(
        cve_id=cve_id,
        title="t",
        severity="high",
        platforms=["IOS XE"],
        affected=CVEAffectedRange(min=aff_min, max=aff_max),
        fixed_in=fixed_in,
        description="d",
        first_fixed_version=first_fixed_version,
    )


def test_verified_when_fixed_in_has_concrete_version():
    cve = _make(fixed_in="17.9.4a")
    result = data_confidence(cve)
    assert result["confidence"] == "verified"
    assert "17.9.4a" in result["rationale"]


def test_verified_when_fixed_in_with_prefix():
    """'IOS XE 17.15.4a' is a full-text fix version — still verified."""
    cve = _make(fixed_in="IOS XE 17.15.4a")
    assert data_confidence(cve)["confidence"] == "verified"


def test_max_bound_when_no_fixed_in_but_max_is_version():
    """PSIRT-import case: affected.max populated, fixed_in empty."""
    cve = _make(fixed_in=None, aff_min="3.2.0", aff_max="17.11.99")
    result = data_confidence(cve)
    assert result["confidence"] == "max-bound"
    assert "PSIRT-import" in result["rationale"] or "max" in result["rationale"].lower()


def test_max_bound_when_fixed_in_empty_string():
    """Empty string fixed_in treated same as None."""
    cve = _make(fixed_in="", aff_max="16.5.1")
    assert data_confidence(cve)["confidence"] == "max-bound"


def test_uncertain_when_both_empty():
    """No fix, no bounded max → uncertain bucket."""
    cve = _make(fixed_in=None, aff_max="")
    assert data_confidence(cve)["confidence"] == "uncertain"


def test_uncertain_when_max_is_unbounded_keyword():
    """'all' / 'any' / '*' in affected.max = unbounded → uncertain."""
    for keyword in ("all", "any", "*", "none"):
        cve = _make(fixed_in=None, aff_max=keyword)
        assert data_confidence(cve)["confidence"] == "uncertain", f"failed on keyword '{keyword}'"


def test_prose_fixed_in_treated_as_unverified():
    """Placeholder fixed_in like 'Migrate to SNMPv3' is not a version. With a
    bounded affected.max, should fall through to max-bound not verified."""
    cve = _make(
        fixed_in="Migrate to SNMPv3 authPriv",
        aff_max="17.11.99",
    )
    # The _is_prose_not_version check filters out prose fixed_in → fall
    # through to affected.max check.
    result = data_confidence(cve)
    assert result["confidence"] in ("max-bound", "uncertain")
    # Specifically: max is bounded, so max-bound
    assert result["confidence"] == "max-bound"


def test_rationale_explains_cve_006_context():
    """max-bound rationale should reference W19+ CVE-006 fix path so user
    understands this is a known gap being worked on, not a permanent flaw."""
    cve = _make(fixed_in=None, aff_max="17.11.99")
    rationale = data_confidence(cve)["rationale"].lower()
    assert "cve-006" in rationale or "w19" in rationale or "full correction" in rationale


# ---------------------------------------------------------------------------
# v0.6.24 — first_fixed_version integration (CVE-006 Phase 3)
# ---------------------------------------------------------------------------

def test_verified_when_first_fixed_version_populated():
    """Richest data path: per-family fixes from PSIRT advisory-detail."""
    cve = _make(
        fixed_in=None,
        aff_max="17.11.99",  # would normally trigger max-bound
        first_fixed_version=CVEFirstFixed(fixes={"ios-xe": "17.9.4a"}),
    )
    result = data_confidence(cve)
    assert result["confidence"] == "verified"
    assert "ios-xe" in result["rationale"]
    assert "per-family" in result["rationale"].lower() or "advisory-detail" in result["rationale"]


def test_first_fixed_beats_scalar_fixed_in():
    """When BOTH are populated, rationale should cite per-family path
    (the richer signal) — both paths agree on 'verified' confidence."""
    cve = _make(
        fixed_in="17.9.4a",
        first_fixed_version=CVEFirstFixed(fixes={"ios-xe": "17.9.4a", "ios": "15.2(7)E8"}),
    )
    result = data_confidence(cve)
    assert result["confidence"] == "verified"
    # Multi-family rationale preferred over scalar
    assert "ios-xe" in result["rationale"] and "ios" in result["rationale"]


def test_empty_first_fixed_falls_through():
    """first_fixed_version present but with empty fixes dict → fall through
    to existing logic. Should not short-circuit to 'verified'."""
    cve = _make(
        fixed_in=None,
        aff_max="17.11.99",
        first_fixed_version=CVEFirstFixed(fixes={}),
    )
    assert data_confidence(cve)["confidence"] == "max-bound"


def test_multi_family_fixes_in_rationale():
    """Multi-family advisories (e.g. CVE-2025-20363 unauth-on-ASA + auth-on-IOS-XE)
    should surface all family paths in the rationale for transparency."""
    cve = _make(
        first_fixed_version=CVEFirstFixed(fixes={"asa": "9.18.4", "ios-xe": "17.9.4a", "ftd": "7.4.2"}),
    )
    rationale = data_confidence(cve)["rationale"]
    assert "asa" in rationale
    assert "ios-xe" in rationale
    assert "ftd" in rationale
