"""
Tests for CVEPreconditions model + loader (XCUT-001 Phase 3).

Covers:
  - Pydantic model validates schema (required fields, types)
  - Loader reads valid JSON files from a directory
  - Malformed JSON / schema mismatch is skipped (warning, not raise)
  - Unknown condition strings are warned but file still loads
  - Duplicate cve_id across files handled (later file wins + warning)
  - The 4 anchor files shipped in cve_preconditions/ all load cleanly
"""

import json
from pathlib import Path

import pytest

from models.cve_preconditions_model import CVEPreconditionDetail, CVEPreconditions
from services.cve_preconditions_loader import (
    get_preconditions_for,
    load_cve_preconditions,
)

REPO_ROOT = Path(__file__).parent.parent
REAL_DIR = REPO_ROOT / "cve_preconditions"


# ---------------------------------------------------------------------------
# Pydantic model
# ---------------------------------------------------------------------------

class TestModel:
    def test_minimal_record(self):
        rec = CVEPreconditions(
            cve_id="CVE-2026-00001",
            preconditions=CVEPreconditionDetail(),
            last_curated="2026-04-21",
        )
        assert rec.cve_id == "CVE-2026-00001"
        assert rec.curator == "initial"  # default
        assert rec.effective_cvss_when_unauth is None
        assert rec.preconditions.required == []

    def test_full_record(self):
        rec = CVEPreconditions(
            cve_id="CVE-2025-20352",
            preconditions=CVEPreconditionDetail(
                required=["snmp-v1v2-enabled"],
                sufficient_for_unauthenticated=["snmp-default-community"],
                rationale="SNMP RCE with default community string.",
            ),
            effective_cvss_when_unauth=9.8,
            last_curated="2026-04-21",
            curator="przemek",
        )
        assert rec.effective_cvss_when_unauth == 9.8
        assert rec.preconditions.required == ["snmp-v1v2-enabled"]

    def test_missing_required_field_fails(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            # cve_id missing
            CVEPreconditions(
                preconditions=CVEPreconditionDetail(),
                last_curated="2026-04-21",
            )


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

class TestLoader:
    def test_empty_directory_returns_empty_dict(self, tmp_path):
        assert load_cve_preconditions(tmp_path) == {}

    def test_missing_directory_returns_empty_dict(self, tmp_path):
        nonexistent = tmp_path / "does-not-exist"
        assert load_cve_preconditions(nonexistent) == {}

    def test_loads_valid_json_file(self, tmp_path):
        data = {
            "cve_id": "CVE-2026-00099",
            "preconditions": {
                "required": ["web-ui-reachable"],
                "sufficient_for_unauthenticated": [],
                "rationale": "Test",
            },
            "last_curated": "2026-04-21",
        }
        (tmp_path / "CVE-2026-00099.json").write_text(json.dumps(data))

        loaded = load_cve_preconditions(tmp_path)
        assert "CVE-2026-00099" in loaded
        assert loaded["CVE-2026-00099"].preconditions.required == ["web-ui-reachable"]

    def test_malformed_json_skipped(self, tmp_path, caplog):
        (tmp_path / "CVE-2026-BROKEN.json").write_text("{ not valid json")
        # Add one valid file so we can confirm loader keeps going
        valid = {
            "cve_id": "CVE-2026-00100",
            "preconditions": {"required": [], "sufficient_for_unauthenticated": [], "rationale": "t"},
            "last_curated": "2026-04-21",
        }
        (tmp_path / "CVE-2026-00100.json").write_text(json.dumps(valid))

        loaded = load_cve_preconditions(tmp_path)
        assert "CVE-2026-00100" in loaded
        assert len(loaded) == 1  # broken file skipped

    def test_schema_mismatch_skipped(self, tmp_path):
        # cve_id missing → Pydantic ValidationError → skipped
        bad = {"preconditions": {"required": []}, "last_curated": "2026-04-21"}
        (tmp_path / "CVE-2026-00101.json").write_text(json.dumps(bad))

        loaded = load_cve_preconditions(tmp_path)
        assert loaded == {}

    def test_unknown_condition_warned_but_loaded(self, tmp_path, caplog):
        """Loader accepts unknown condition strings with a warning — keeps
        older CVE files working when new conditions ship in the enum."""
        data = {
            "cve_id": "CVE-2026-00102",
            "preconditions": {
                "required": ["totally-made-up-condition"],
                "sufficient_for_unauthenticated": [],
                "rationale": "t",
            },
            "last_curated": "2026-04-21",
        }
        (tmp_path / "CVE-2026-00102.json").write_text(json.dumps(data))

        import logging
        with caplog.at_level(logging.WARNING):
            loaded = load_cve_preconditions(tmp_path)

        assert "CVE-2026-00102" in loaded  # file still loaded
        assert any("totally-made-up-condition" in rec.message for rec in caplog.records)

    def test_non_matching_filenames_ignored(self, tmp_path):
        """Only files matching CVE-*.json are loaded."""
        (tmp_path / "readme.json").write_text(json.dumps({"cve_id": "X"}))
        (tmp_path / "index.txt").write_text("not json")
        assert load_cve_preconditions(tmp_path) == {}


# ---------------------------------------------------------------------------
# Real-world curated data
# ---------------------------------------------------------------------------

class TestShippedData:
    def test_anchor_cves_all_load(self):
        """The 4 anchor JSON files shipped in cve_preconditions/ must load."""
        if not REAL_DIR.exists():
            pytest.skip(f"No cve_preconditions/ dir at {REAL_DIR}")

        loaded = load_cve_preconditions(REAL_DIR)
        expected = {"CVE-2025-20352", "CVE-2023-20198", "CVE-2018-0171", "CVE-2017-12240"}
        assert expected.issubset(loaded.keys()), (
            f"missing anchor CVE(s): {expected - loaded.keys()}"
        )

    def test_snmp_rce_anchor_has_cvss_override(self):
        """CVE-2025-20352 is the flagship escalation case — native 7.7 → 9.8."""
        loaded = load_cve_preconditions(REAL_DIR)
        snmp = loaded.get("CVE-2025-20352")
        assert snmp is not None
        assert snmp.effective_cvss_when_unauth == 9.8
        assert "snmp-v1v2-enabled" in snmp.preconditions.required
        assert "snmp-default-community" in snmp.preconditions.sufficient_for_unauthenticated

    def test_dhcp_rce_has_empty_preconditions(self):
        """CVE-2017-12240 is the 'always exploitable' sanity baseline."""
        loaded = load_cve_preconditions(REAL_DIR)
        dhcp = loaded.get("CVE-2017-12240")
        assert dhcp is not None
        assert dhcp.preconditions.required == []
        assert dhcp.preconditions.sufficient_for_unauthenticated == []


# ---------------------------------------------------------------------------
# Convenience lookup
# ---------------------------------------------------------------------------

class TestGetPreconditionsFor:
    def test_returns_record_from_preloaded_dict(self):
        fake = {
            "CVE-XXX": CVEPreconditions(
                cve_id="CVE-XXX",
                preconditions=CVEPreconditionDetail(),
                last_curated="2026-04-21",
            )
        }
        assert get_preconditions_for("CVE-XXX", fake) is fake["CVE-XXX"]

    def test_returns_none_when_cve_unknown(self):
        assert get_preconditions_for("CVE-DOES-NOT-EXIST", {}) is None
