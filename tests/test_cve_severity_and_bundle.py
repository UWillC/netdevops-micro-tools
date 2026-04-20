"""
CVE-007 + CVE-010 tests (v0.6.16).

CVE-007: NVD CVSS bucket primary, Cisco SIR secondary.
CVE-010: Bundled-publication detection for Cisco semi-annual advisories.
"""
from models.cve_model import CVEAffectedRange, CVEEntry
from services.cve_engine import cvss_rating_from_score, detect_bundle, severity_info


def _make(cve_id="CVE-2024-20265", severity="high", cvss=None,
          title="Test CVE", published=None, cisco_sir=None, bundle=None,
          tags=None):
    return CVEEntry(
        cve_id=cve_id,
        title=title,
        severity=severity,
        platforms=["IOS XE"],
        affected=CVEAffectedRange(min="", max=""),
        description="test",
        cvss_score=cvss,
        published=published,
        cisco_sir=cisco_sir,
        bundle=bundle,
        tags=tags or [],
    )


# -----------------------------
# CVE-007: CVSS bucket canonical
# -----------------------------

def test_cvss_rating_boundaries():
    """NVD CVSS v3.x scale: https://nvd.nist.gov/vuln-metrics/cvss"""
    assert cvss_rating_from_score(None) == "UNKNOWN"
    assert cvss_rating_from_score(0.0) == "NONE"
    assert cvss_rating_from_score(0.1) == "LOW"
    assert cvss_rating_from_score(3.9) == "LOW"
    assert cvss_rating_from_score(4.0) == "MEDIUM"
    assert cvss_rating_from_score(6.9) == "MEDIUM"
    assert cvss_rating_from_score(7.0) == "HIGH"
    assert cvss_rating_from_score(8.9) == "HIGH"
    assert cvss_rating_from_score(9.0) == "CRITICAL"
    assert cvss_rating_from_score(10.0) == "CRITICAL"


def test_severity_info_cisco_sir_distinct_from_cvss():
    """Defect-report example: CVE-2024-20265 — Cisco SIR HIGH, CVSS 5.9 (Medium).
    Tool must show MEDIUM as primary and flag Cisco SIR HIGH as secondary.
    """
    cve = _make(cve_id="CVE-2024-20265", severity="high", cvss=5.9)
    info = severity_info(cve)
    assert info["cvss_rating"] == "MEDIUM"
    assert info["primary_severity"] == "MEDIUM"
    assert info["cisco_sir"] == "HIGH"
    assert info["label_matches_cvss"] is False


def test_severity_info_aligned_no_secondary_tag():
    """When the curated label matches CVSS bucket, no Cisco SIR tag needed."""
    cve = _make(cve_id="CVE-2023-20198", severity="critical", cvss=10.0)
    info = severity_info(cve)
    assert info["cvss_rating"] == "CRITICAL"
    assert info["primary_severity"] == "CRITICAL"
    assert info["cisco_sir"] is None
    assert info["label_matches_cvss"] is True


def test_severity_info_no_cvss_falls_back_to_label():
    """When CVSS score unavailable, fall back to the curated label."""
    cve = _make(cve_id="CVE-2020-99999", severity="high", cvss=None)
    info = severity_info(cve)
    assert info["cvss_rating"] == "UNKNOWN"
    assert info["primary_severity"] == "HIGH"
    assert info["cisco_sir"] is None


def test_severity_info_explicit_cisco_sir_field_wins():
    """If cisco_sir field is set explicitly, it's used as secondary tag."""
    cve = _make(cve_id="CVE-X", severity="critical", cvss=9.5, cisco_sir="High")
    info = severity_info(cve)
    assert info["primary_severity"] == "CRITICAL"
    assert info["cisco_sir"] == "HIGH"  # normalized to upper


def test_severity_info_escalation_reason_from_kev_tag():
    cve = _make(cve_id="CVE-2025-20352", severity="high", cvss=7.7, tags=["kev"])
    info = severity_info(cve)
    assert info["primary_severity"] == "HIGH"
    assert info["escalation_reason"] is not None
    assert "KEV" in info["escalation_reason"]


# -----------------------------
# CVE-010: Bundle detection
# -----------------------------

def test_detect_bundle_explicit_field_wins():
    cve = _make(cve_id="CVE-X", bundle="2025-09")
    assert detect_bundle(cve) == "2025-09"


def test_detect_bundle_semiannual_title_september():
    cve = _make(
        title="Semiannual Cisco IOS and IOS XE Software Security Advisory Bundled Publication",
        published="2025-09-24T00:00:00Z",
    )
    assert detect_bundle(cve) == "2025-09"


def test_detect_bundle_semiannual_title_march():
    cve = _make(
        title="Semiannual Cisco IOS and IOS XE Software Security Advisory Bundled Publication",
        published="2025-03-26",
    )
    assert detect_bundle(cve) == "2025-03"


def test_detect_bundle_semiannual_ios_only_variant():
    """Older bundles said just 'Cisco IOS' before the IOS-XE split — still a bundle."""
    cve = _make(
        title="Semiannual Cisco IOS Software Security Advisory Bundled Publication",
        published="2024-03-27",
    )
    assert detect_bundle(cve) == "2024-03"


def test_detect_bundle_non_bundle_returns_none():
    cve = _make(
        title="Cisco IOS XE Software Web UI Privilege Escalation Vulnerability",
        published="2023-10-16",
    )
    assert detect_bundle(cve) is None


def test_detect_bundle_semiannual_without_published_date():
    cve = _make(
        title="Semiannual Cisco IOS and IOS XE Software Security Advisory Bundled Publication",
        published=None,
    )
    # Still identified as a bundle; date bucket unknown.
    assert detect_bundle(cve) == "unknown"
