"""
CVE data-quality confidence tests (v0.6.23).

Tests the data_confidence() helper that classifies each CVE record by how
reliable its version-range matching is. This is a transparency layer
shipped while the full CVE-006 PSIRT closure is parked for W19+ sprint.
"""
from models.cve_model import CVEAffectedRange, CVEEntry
from services.cve_engine import data_confidence


def _make(cve_id="CVE-X", fixed_in=None, aff_min="", aff_max=""):
    return CVEEntry(
        cve_id=cve_id,
        title="t",
        severity="high",
        platforms=["IOS XE"],
        affected=CVEAffectedRange(min=aff_min, max=aff_max),
        fixed_in=fixed_in,
        description="d",
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
