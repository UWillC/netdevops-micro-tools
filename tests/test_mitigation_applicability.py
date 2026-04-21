"""
CVE Mitigation Advisor — platform/version applicability tests (v0.6.22).

Closes the api/routers/mitigation.py:58 TODO. When the POST /mitigate/cve
endpoint receives a (platform, version) tuple, the response must carry an
`applicability` annotation derived from the CVE engine.
"""
from services.mitigation_service import get_mitigation_service


def test_applicable_cve_on_vulnerable_version():
    """CVE-2023-20198 is fixed in IOS XE 17.9.4a. Target 17.9.4 is vulnerable
    (before fix) → applicability must be 'applicable'."""
    svc = get_mitigation_service()
    r = svc.get_mitigation_for_platform("CVE-2023-20198", "IOS XE", "17.9.4")
    assert r.found is True
    assert r.mitigation is not None
    assert r.applicability == "applicable"
    assert r.applicability_reason is not None
    assert "affects" in r.applicability_reason.lower() or "apply" in r.applicability_reason.lower()


def test_not_applicable_on_patched_version():
    """17.15.4a is the fix version for CVE-2023-20198. Target 17.15.4a is NOT
    vulnerable → applicability must be 'not_applicable'."""
    svc = get_mitigation_service()
    r = svc.get_mitigation_for_platform("CVE-2023-20198", "IOS XE", "17.15.4a")
    assert r.found is True
    assert r.mitigation is not None  # mitigation still returned for reference
    assert r.applicability == "not_applicable"
    assert "not match" in r.applicability_reason.lower() or \
           "informational" in r.applicability_reason.lower()


def test_no_context_skips_applicability():
    """When platform and version both omitted, skip applicability check.
    Response should be identical to the unfiltered GET endpoint."""
    svc = get_mitigation_service()
    r = svc.get_mitigation_for_platform("CVE-2023-20198", None, None)
    assert r.found is True
    assert r.mitigation is not None
    assert r.applicability is None
    assert r.applicability_reason is None


def test_not_found_cve_does_not_set_applicability():
    """For unknown CVE, skip applicability — there is no mitigation to
    annotate. Response should be the standard not-found shape."""
    svc = get_mitigation_service()
    r = svc.get_mitigation_for_platform(
        "CVE-9999-99999", "IOS XE", "17.9.4"
    )
    assert r.found is False
    assert r.mitigation is None
    assert r.applicability is None
    assert "No mitigation data" in (r.message or "")


def test_partial_context_still_triggers_check():
    """Only platform given (no version) should still attempt applicability
    check — CVEEngine.match() accepts empty version and reports based on
    platform family alone."""
    svc = get_mitigation_service()
    r = svc.get_mitigation_for_platform("CVE-2023-20198", "IOS XE", None)
    assert r.found is True
    # Applicability field is populated (one of the 3 valid values)
    assert r.applicability in ("applicable", "not_applicable", "unknown")


def test_original_get_mitigation_unchanged():
    """The unfiltered get_mitigation() method must NOT touch applicability
    fields. This is the contract for GET /mitigate/cve/{id}."""
    svc = get_mitigation_service()
    r = svc.get_mitigation("CVE-2023-20198")
    assert r.found is True
    assert r.applicability is None
    assert r.applicability_reason is None
