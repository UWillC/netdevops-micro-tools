"""
Tests for CiscoAdvisoryProvider._extract_fix_versions (CVE-006 Phase 4 Step 2).

Verifies the standalone firstFixed parser:
- Multi-family advisory: returns one entry per family
- Single family: returns single entry
- First-occurrence-wins on duplicate families
- Empty / missing / malformed firstFixed yields empty dict
- ASA-style versions (don't parse via cisco_version) still recorded
- Non-string entries skipped defensively
- Unknown family entries skipped (no false-positive families)

Phase 4 Step 2 ships the helper standalone — _parse_advisory() is NOT
yet wired to call it. Wiring happens in Step 3.
"""

from services.cve_sources import CiscoAdvisoryProvider


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_extract_multi_family_advisory():
    """Multi-family advisory (CVE-2025-20363 style): one fix per family."""
    detail = {
        "advisoryId": "cisco-sa-multi-family",
        "firstFixed": [
            "Cisco IOS XE Software 17.9.4a",
            "Cisco IOS Software 15.2(7)E8",
            "Cisco ASA Software 9.18.4",
        ],
    }
    fixes = CiscoAdvisoryProvider._extract_fix_versions(detail)

    assert fixes == {
        "ios-xe": "17.9.4a",
        "ios": "15.2(7)E8",
        "asa": "9.18.4",
    }


def test_extract_single_family():
    """Single family entry yields single fix."""
    detail = {"firstFixed": ["Cisco IOS XE Software 17.12.1"]}
    fixes = CiscoAdvisoryProvider._extract_fix_versions(detail)

    assert fixes == {"ios-xe": "17.12.1"}


def test_extract_smu_suffix():
    """IOS XE SMU suffix preserved (17.9.4.s1)."""
    detail = {"firstFixed": ["Cisco IOS XE Software 17.9.4.s1"]}
    fixes = CiscoAdvisoryProvider._extract_fix_versions(detail)

    assert fixes == {"ios-xe": "17.9.4.s1"}


def test_extract_short_format_no_software_word():
    """'Cisco IOS XE 17.9.4' (no 'Software' word) still detected."""
    detail = {"firstFixed": ["Cisco IOS XE 17.9.4a"]}
    fixes = CiscoAdvisoryProvider._extract_fix_versions(detail)

    assert fixes == {"ios-xe": "17.9.4a"}


# ---------------------------------------------------------------------------
# First-wins on duplicate families
# ---------------------------------------------------------------------------

def test_extract_first_occurrence_wins_per_family():
    """Same family listed twice: first kept, second dropped."""
    detail = {
        "firstFixed": [
            "Cisco IOS XE Software 17.9.4a",
            "Cisco IOS XE Software 17.12.1",  # duplicate family
        ]
    }
    fixes = CiscoAdvisoryProvider._extract_fix_versions(detail)

    assert fixes == {"ios-xe": "17.9.4a"}


# ---------------------------------------------------------------------------
# Edge cases / defensive
# ---------------------------------------------------------------------------

def test_extract_empty_first_fixed_list():
    """Empty list yields empty dict."""
    detail = {"firstFixed": []}
    fixes = CiscoAdvisoryProvider._extract_fix_versions(detail)
    assert fixes == {}


def test_extract_missing_first_fixed():
    """Missing firstFixed key yields empty dict."""
    detail = {"advisoryId": "no-firstFixed-field"}
    fixes = CiscoAdvisoryProvider._extract_fix_versions(detail)
    assert fixes == {}


def test_extract_non_list_first_fixed():
    """firstFixed as string (schema drift) yields empty dict, no crash."""
    detail = {"firstFixed": "single string instead of list"}
    fixes = CiscoAdvisoryProvider._extract_fix_versions(detail)
    assert fixes == {}


def test_extract_non_string_entries_skipped():
    """List with mixed types: non-strings skipped defensively."""
    detail = {
        "firstFixed": [
            "Cisco IOS XE Software 17.9.4a",
            None,
            123,
            {"nested": "dict"},
            "Cisco ASA Software 9.18.4",
        ]
    }
    fixes = CiscoAdvisoryProvider._extract_fix_versions(detail)
    assert fixes == {"ios-xe": "17.9.4a", "asa": "9.18.4"}


def test_extract_empty_string_skipped():
    """Empty / whitespace-only entries skipped."""
    detail = {
        "firstFixed": [
            "",
            "   ",
            "Cisco IOS XE Software 17.9.4",
        ]
    }
    fixes = CiscoAdvisoryProvider._extract_fix_versions(detail)
    assert fixes == {"ios-xe": "17.9.4"}


def test_extract_unknown_family_skipped():
    """Entry with unknown product (no family match) skipped."""
    detail = {
        "firstFixed": [
            "Cisco Random Unknown Product 2.5.0",  # no family match
            "Cisco IOS XE Software 17.9.4",
        ]
    }
    fixes = CiscoAdvisoryProvider._extract_fix_versions(detail)
    assert fixes == {"ios-xe": "17.9.4"}


def test_extract_no_version_substring_skipped():
    """Entry without trailing digit substring is skipped."""
    detail = {
        "firstFixed": [
            "Cisco IOS XE Software (no version specified)",  # no trailing digits
            "Cisco ASA Software 9.18.4",
        ]
    }
    fixes = CiscoAdvisoryProvider._extract_fix_versions(detail)
    # First entry skipped (no version), second succeeds
    assert fixes == {"asa": "9.18.4"}


# ---------------------------------------------------------------------------
# ASA-style versions (don't fit IOS XE / IOS classic regex)
# ---------------------------------------------------------------------------

def test_extract_asa_version_recorded_despite_unparseable():
    """ASA versions like 9.18.4 don't fit cisco_version parser, still stored."""
    detail = {"firstFixed": ["Cisco ASA Software 9.18.4"]}
    fixes = CiscoAdvisoryProvider._extract_fix_versions(detail)

    # ASA family detected, version recorded (matcher in Step 3 handles parse)
    assert fixes == {"asa": "9.18.4"}


# ---------------------------------------------------------------------------
# NX-OS, IOS XR, FTD
# ---------------------------------------------------------------------------

def test_extract_nxos_family():
    """Cisco NX-OS Software detected as nx-os family."""
    detail = {"firstFixed": ["Cisco NX-OS Software 10.3(2)"]}
    fixes = CiscoAdvisoryProvider._extract_fix_versions(detail)
    assert "nx-os" in fixes
    assert fixes["nx-os"] == "10.3(2)"


def test_extract_iosxr_family():
    """Cisco IOS XR Software detected as ios-xr family."""
    detail = {"firstFixed": ["Cisco IOS XR Software 7.10.1"]}
    fixes = CiscoAdvisoryProvider._extract_fix_versions(detail)
    assert "ios-xr" in fixes
    assert fixes["ios-xr"] == "7.10.1"


def test_extract_ftd_family():
    """Firepower Threat Defense detected as ftd family."""
    detail = {"firstFixed": ["Cisco Firepower Threat Defense Software 7.4.1"]}
    fixes = CiscoAdvisoryProvider._extract_fix_versions(detail)
    assert "ftd" in fixes
    assert fixes["ftd"] == "7.4.1"
