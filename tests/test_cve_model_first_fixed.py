"""
Tests for CVEFirstFixed + CVEEntry.first_fixed_version (CVE-006 Phase 3).

Per-family fix-version model extension. Covers:
  - CVEFirstFixed default (empty fixes dict)
  - Populated fixes dict round-trip
  - CVEEntry.first_fixed_version defaults to None (legacy compat)
  - Accepts a populated CVEFirstFixed instance
  - Serialization preserves nested structure
  - Accepts dict input at CVEEntry construction (Pydantic coerces to model)
"""

import json

import pytest
from pydantic import ValidationError

from models.cve_model import CVEAffectedRange, CVEEntry, CVEFirstFixed


def _make_minimal_cve(**overrides):
    base = dict(
        cve_id="CVE-2026-00002",
        title="Test",
        severity="high",
        affected=CVEAffectedRange(min="1.0", max="2.0"),
        description="d",
    )
    base.update(overrides)
    return CVEEntry(**base)


class TestCVEFirstFixedModel:
    def test_default_empty_fixes(self):
        ff = CVEFirstFixed()
        assert ff.fixes == {}

    def test_populated_fixes(self):
        ff = CVEFirstFixed(fixes={"ios-xe": "17.9.4a", "ios": "15.2(7)E8"})
        assert ff.fixes["ios-xe"] == "17.9.4a"
        assert ff.fixes["ios"] == "15.2(7)E8"
        assert len(ff.fixes) == 2

    def test_json_round_trip(self):
        ff = CVEFirstFixed(fixes={"ios-xe": "17.9.4a", "asa": "9.18.4"})
        restored = CVEFirstFixed(**json.loads(ff.model_dump_json()))
        assert restored.fixes == ff.fixes

    def test_rejects_non_string_version(self):
        """Values must be strings (version). Non-string should fail validation."""
        with pytest.raises(ValidationError):
            CVEFirstFixed(fixes={"ios-xe": 17})  # int, not str


class TestCVEEntryIntegration:
    def test_default_first_fixed_is_none(self):
        """Legacy compat: CVEs constructed without the new field stay at None."""
        cve = _make_minimal_cve()
        assert cve.first_fixed_version is None

    def test_accepts_cvefirstfixed_instance(self):
        ff = CVEFirstFixed(fixes={"ios-xe": "17.9.4a"})
        cve = _make_minimal_cve(first_fixed_version=ff)
        assert cve.first_fixed_version is not None
        assert cve.first_fixed_version.fixes == {"ios-xe": "17.9.4a"}

    def test_accepts_dict_input_coerced_to_model(self):
        """PSIRT-import path may construct CVEEntry from raw dict. Pydantic
        should coerce nested dict into CVEFirstFixed."""
        cve = _make_minimal_cve(
            first_fixed_version={"fixes": {"ios-xe": "17.9.4a", "asa": "9.18.4"}}
        )
        assert isinstance(cve.first_fixed_version, CVEFirstFixed)
        assert cve.first_fixed_version.fixes["asa"] == "9.18.4"

    def test_multi_family_advisory_carries_distinct_fixes(self):
        """CVE-2025-20363 anchor case: unauth on ASA, auth on IOS XE,
        different fix paths per family."""
        ff = CVEFirstFixed(fixes={
            "asa": "9.18.4",
            "ios-xe": "17.9.4a",
            "ftd": "7.4.2",
        })
        cve = _make_minimal_cve(
            cve_id="CVE-2025-20363",
            first_fixed_version=ff,
        )
        assert cve.first_fixed_version.fixes["asa"] != cve.first_fixed_version.fixes["ios-xe"]


class TestSerialization:
    def test_full_round_trip_through_json(self):
        cve = _make_minimal_cve(
            first_fixed_version=CVEFirstFixed(fixes={"ios-xe": "17.9.4a"}),
        )
        dumped = cve.model_dump_json()
        parsed = json.loads(dumped)
        # Nested structure preserved
        assert parsed["first_fixed_version"]["fixes"]["ios-xe"] == "17.9.4a"

        restored = CVEEntry(**parsed)
        assert isinstance(restored.first_fixed_version, CVEFirstFixed)
        assert restored.first_fixed_version.fixes == {"ios-xe": "17.9.4a"}

    def test_dump_omits_none_if_not_populated(self):
        """None default serializes to None in dump — not a missing key."""
        cve = _make_minimal_cve()
        dumped = cve.model_dump()
        assert dumped["first_fixed_version"] is None
