"""
Tests for CVEEntry model extensions (CVE-003 Phase 3).

Verifies the new `product_families` and `affected_versions_raw` fields:
  - Default to empty list (backward compat with existing local-json records)
  - Accept list values from PSIRT-import path
  - Serialize/deserialize cleanly through Pydantic JSON round-trip
  - Do NOT break existing validation on required fields
"""

import json

from models.cve_model import CVEAffectedRange, CVEEntry


def _make_minimal_cve(**overrides):
    base = dict(
        cve_id="CVE-2026-00001",
        title="Test advisory",
        severity="high",
        affected=CVEAffectedRange(min="1.0", max="2.0"),
        description="t",
    )
    base.update(overrides)
    return CVEEntry(**base)


class TestDefaults:
    def test_new_fields_default_to_empty_list(self):
        """Backward compat: legacy local-json records don't carry these fields.
        Model must accept their absence without error."""
        cve = _make_minimal_cve()
        assert cve.product_families == []
        assert cve.affected_versions_raw == []

    def test_legacy_record_still_validates(self):
        """A CVEEntry constructed from a pre-v0.6.24 dict (no new fields)
        must validate cleanly — this is the critical backward-compat contract."""
        legacy_dict = {
            "cve_id": "CVE-2024-20000",
            "title": "Legacy record",
            "severity": "medium",
            "platforms": ["IOS XE"],
            "affected": {"min": "17.0.0", "max": "17.9.4"},
            "description": "...",
        }
        cve = CVEEntry(**legacy_dict)
        assert cve.product_families == []
        assert cve.affected_versions_raw == []


class TestPopulatedFields:
    def test_product_families_list(self):
        cve = _make_minimal_cve(product_families=["ios-xe", "ios"])
        assert cve.product_families == ["ios-xe", "ios"]

    def test_affected_versions_raw_list(self):
        raw = [
            "Cisco IOS XE Software 17.9.4",
            "Cisco IOS XE Software 17.9.4a",
            "Cisco IOS XE Software 17.9.5",
        ]
        cve = _make_minimal_cve(affected_versions_raw=raw)
        assert cve.affected_versions_raw == raw

    def test_large_raw_list_accepted(self):
        """Model itself doesn't enforce the 50-entry cap — that's the
        responsibility of _parse_advisory in Phase 4. Model accepts any size."""
        huge = [f"Cisco IOS XE Software 17.9.{i}" for i in range(500)]
        cve = _make_minimal_cve(affected_versions_raw=huge)
        assert len(cve.affected_versions_raw) == 500


class TestSerialization:
    def test_json_round_trip(self):
        cve = _make_minimal_cve(
            product_families=["ios-xe", "ios"],
            affected_versions_raw=["Cisco IOS XE Software 17.9.4"],
        )
        as_json = cve.model_dump_json()
        parsed = json.loads(as_json)
        assert parsed["product_families"] == ["ios-xe", "ios"]
        assert parsed["affected_versions_raw"] == ["Cisco IOS XE Software 17.9.4"]

        # Round-trip back through constructor
        restored = CVEEntry(**parsed)
        assert restored.product_families == cve.product_families
        assert restored.affected_versions_raw == cve.affected_versions_raw

    def test_dump_omits_nothing_when_populated(self):
        cve = _make_minimal_cve(product_families=["nx-os"])
        dumped = cve.model_dump()
        assert "product_families" in dumped
        assert "affected_versions_raw" in dumped

    def test_dump_includes_empty_lists_by_default(self):
        """Pydantic default behavior: empty-list fields appear in dump."""
        cve = _make_minimal_cve()
        dumped = cve.model_dump()
        assert dumped["product_families"] == []
        assert dumped["affected_versions_raw"] == []
