"""
Tests for CiscoAdvisoryProvider._parse_advisory Phase 4 wiring (CVE-003 + CVE-006).

Verifies the env-gated enrichment path:
- Flag OFF (default): legacy behavior preserved (all new fields default empty/None,
  no detail fetch call, platforms tagged with self.platform)
- Flag ON: product_families populated, affected_versions_raw populated,
  first_fixed_version populated when detail fetch returns firstFixed
- Flag ON + detail fetch fails: product_families still populated (from list endpoint),
  first_fixed_version=None, no crash
- Flag ON + no advisoryId: skip detail fetch, families still populated
- Flag ON + no productNames: empty fields, no detail fetch attempted

The env flag CVE_CISCO_DETAIL_FETCH=1 is the safety gate for Phase 4 production
rollout. Default OFF until manual verification confirms behavior on real PSIRT
data. Tests both paths to catch regression in either direction.
"""

import os
from unittest.mock import patch

from services.cve_sources import CiscoAdvisoryProvider


# ---------------------------------------------------------------------------
# Helper: minimal advisory fixture
# ---------------------------------------------------------------------------

_DEFAULT_CVES = ["CVE-2025-12345"]


def _make_advisory(
    cves=None,
    advisory_id="cisco-sa-test",
    product_names=None,
    sir="High",
    title="Test advisory",
    summary="Summary text",
):
    return {
        "advisoryId": advisory_id,
        "advisoryTitle": title,
        # Distinguish None (use default) from [] (caller wants empty)
        "cves": cves if cves is not None else _DEFAULT_CVES,
        "sir": sir,
        "summary": summary,
        "publicationUrl": "https://example.com/advisory",
        "firstPublished": "2025-04-15T00:00:00Z",
        "lastUpdated": "2025-04-15T00:00:00Z",
        "cvssBaseScore": "8.5",
        "productNames": product_names if product_names is not None else [],
    }


# ---------------------------------------------------------------------------
# Flag OFF: legacy behavior preserved
# ---------------------------------------------------------------------------

def test_parse_advisory_legacy_path_when_flag_off(monkeypatch):
    """Default (flag OFF): legacy behavior, no detail fetch, empty new fields."""
    monkeypatch.delenv("CVE_CISCO_DETAIL_FETCH", raising=False)

    provider = CiscoAdvisoryProvider(platform="iosxe")
    adv = _make_advisory(product_names=["Cisco IOS XE Software 17.9.4"])

    with patch.object(provider, "_fetch_advisory_detail") as mock_fetch:
        entries = provider._parse_advisory(adv)

    # Legacy path: no detail fetch attempted
    mock_fetch.assert_not_called()

    assert len(entries) == 1
    e = entries[0]
    assert e.platforms == ["IOS XE"]  # Legacy hardcoded label
    assert e.product_families == []
    assert e.affected_versions_raw == []
    assert e.first_fixed_version is None


def test_parse_advisory_legacy_asa_platform_label(monkeypatch):
    """Legacy path on platform=asa tags as ASA (uppercase)."""
    monkeypatch.delenv("CVE_CISCO_DETAIL_FETCH", raising=False)

    provider = CiscoAdvisoryProvider(platform="asa")
    adv = _make_advisory()

    entries = provider._parse_advisory(adv)
    assert entries[0].platforms == ["ASA"]


# ---------------------------------------------------------------------------
# Flag ON: enrichment populates new fields
# ---------------------------------------------------------------------------

def test_parse_advisory_phase4_full_enrichment(monkeypatch):
    """Flag ON: product_families + affected_versions_raw + first_fixed_version populated."""
    monkeypatch.setenv("CVE_CISCO_DETAIL_FETCH", "1")

    provider = CiscoAdvisoryProvider(platform="iosxe")
    adv = _make_advisory(
        advisory_id="cisco-sa-multi",
        product_names=[
            "Cisco IOS XE Software 17.9.3",
            "Cisco IOS XE Software 17.9.4",
            "Cisco ASA Software 9.18.3",
        ],
    )

    detail_response = {
        "advisoryId": "cisco-sa-multi",
        "firstFixed": [
            "Cisco IOS XE Software 17.9.4a",
            "Cisco ASA Software 9.18.4",
        ],
    }

    with patch.object(provider, "_fetch_advisory_detail") as mock_fetch:
        mock_fetch.return_value = detail_response
        entries = provider._parse_advisory(adv)

    mock_fetch.assert_called_once_with("cisco-sa-multi")

    assert len(entries) == 1
    e = entries[0]
    # CVE-003: families detected from productNames
    assert "ios-xe" in e.product_families
    assert "asa" in e.product_families
    # affected_versions_raw preserved (first 50)
    assert "Cisco IOS XE Software 17.9.4" in e.affected_versions_raw
    assert "Cisco ASA Software 9.18.3" in e.affected_versions_raw
    # CVE-006: first_fixed_version populated per family
    assert e.first_fixed_version is not None
    assert e.first_fixed_version.fixes == {"ios-xe": "17.9.4a", "asa": "9.18.4"}
    # Legacy platforms enriched from families
    assert "IOS-XE" in e.platforms
    assert "ASA" in e.platforms


def test_parse_advisory_phase4_detail_fetch_fails_partial_enrichment(monkeypatch):
    """Flag ON, detail fetch returns None: families OK, first_fixed_version=None."""
    monkeypatch.setenv("CVE_CISCO_DETAIL_FETCH", "1")

    provider = CiscoAdvisoryProvider(platform="iosxe")
    adv = _make_advisory(
        advisory_id="cisco-sa-detail-fail",
        product_names=["Cisco IOS XE Software 17.9.4"],
    )

    with patch.object(provider, "_fetch_advisory_detail") as mock_fetch:
        mock_fetch.return_value = None  # 404 / network / rate limit
        entries = provider._parse_advisory(adv)

    e = entries[0]
    assert e.product_families == ["ios-xe"]
    assert e.first_fixed_version is None  # Graceful degradation


def test_parse_advisory_phase4_no_advisory_id_skips_detail_fetch(monkeypatch):
    """Flag ON, missing advisoryId: skip detail fetch, families still populated."""
    monkeypatch.setenv("CVE_CISCO_DETAIL_FETCH", "1")

    provider = CiscoAdvisoryProvider(platform="iosxe")
    adv = _make_advisory(
        advisory_id=None,  # Missing/None advisoryId
        product_names=["Cisco IOS XE Software 17.9.4"],
    )
    adv.pop("advisoryId", None)

    with patch.object(provider, "_fetch_advisory_detail") as mock_fetch:
        entries = provider._parse_advisory(adv)

    mock_fetch.assert_not_called()
    e = entries[0]
    assert e.product_families == ["ios-xe"]
    assert e.first_fixed_version is None


def test_parse_advisory_phase4_no_product_names(monkeypatch):
    """Flag ON, missing productNames: families empty, detail still fetched."""
    monkeypatch.setenv("CVE_CISCO_DETAIL_FETCH", "1")

    provider = CiscoAdvisoryProvider(platform="iosxe")
    adv = _make_advisory(advisory_id="cisco-sa-no-products", product_names=[])

    detail_response = {"firstFixed": ["Cisco IOS XE Software 17.9.4a"]}

    with patch.object(provider, "_fetch_advisory_detail") as mock_fetch:
        mock_fetch.return_value = detail_response
        entries = provider._parse_advisory(adv)

    e = entries[0]
    assert e.product_families == []
    assert e.affected_versions_raw == []
    # First-fixed STILL populated even without productNames (detail endpoint
    # is independent source). Acceptable: matcher uses the fix when family
    # is detected from elsewhere.
    assert e.first_fixed_version is not None
    assert e.first_fixed_version.fixes == {"ios-xe": "17.9.4a"}
    # Platforms fall back to legacy label since no families detected
    assert e.platforms == ["IOS XE"]


def test_parse_advisory_phase4_empty_first_fixed_in_detail(monkeypatch):
    """Flag ON, detail returns empty firstFixed: families OK, first_fixed_version=None."""
    monkeypatch.setenv("CVE_CISCO_DETAIL_FETCH", "1")

    provider = CiscoAdvisoryProvider(platform="iosxe")
    adv = _make_advisory(
        advisory_id="cisco-sa-empty-fix",
        product_names=["Cisco IOS XE Software 17.9.4"],
    )

    detail_response = {"advisoryId": "cisco-sa-empty-fix", "firstFixed": []}

    with patch.object(provider, "_fetch_advisory_detail") as mock_fetch:
        mock_fetch.return_value = detail_response
        entries = provider._parse_advisory(adv)

    e = entries[0]
    assert e.product_families == ["ios-xe"]
    # Empty fix_map -> no CVEFirstFixed object created
    assert e.first_fixed_version is None


# ---------------------------------------------------------------------------
# Multi-CVE advisory: each entry gets same enriched fields
# ---------------------------------------------------------------------------

def test_parse_advisory_phase4_multi_cve_same_fields(monkeypatch):
    """Multi-CVE advisory: each CVEEntry has identical enriched fields (per advisory)."""
    monkeypatch.setenv("CVE_CISCO_DETAIL_FETCH", "1")

    provider = CiscoAdvisoryProvider(platform="iosxe")
    adv = _make_advisory(
        cves=["CVE-2025-1111", "CVE-2025-2222", "CVE-2025-3333"],
        advisory_id="cisco-sa-multicve",
        product_names=["Cisco IOS XE Software 17.9.4"],
    )

    detail_response = {"firstFixed": ["Cisco IOS XE Software 17.9.4a"]}

    with patch.object(provider, "_fetch_advisory_detail") as mock_fetch:
        mock_fetch.return_value = detail_response
        entries = provider._parse_advisory(adv)

    assert len(entries) == 3
    for e in entries:
        assert e.product_families == ["ios-xe"]
        assert e.first_fixed_version.fixes == {"ios-xe": "17.9.4a"}

    # Detail endpoint called only ONCE per advisory (not per CVE)
    mock_fetch.assert_called_once()


# ---------------------------------------------------------------------------
# NA / invalid CVEs handled
# ---------------------------------------------------------------------------

def test_parse_advisory_no_cves_returns_empty(monkeypatch):
    """Empty / NA cves: empty entries list, no enrichment work done."""
    monkeypatch.setenv("CVE_CISCO_DETAIL_FETCH", "1")

    provider = CiscoAdvisoryProvider(platform="iosxe")

    # cves=[] case
    adv_empty = _make_advisory(cves=[])
    with patch.object(provider, "_fetch_advisory_detail") as mock_fetch:
        entries = provider._parse_advisory(adv_empty)
    assert entries == []
    mock_fetch.assert_not_called()

    # cves=["NA"] case
    adv_na = _make_advisory(cves=["NA"])
    with patch.object(provider, "_fetch_advisory_detail") as mock_fetch:
        entries = provider._parse_advisory(adv_na)
    assert entries == []
    mock_fetch.assert_not_called()
