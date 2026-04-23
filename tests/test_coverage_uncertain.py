"""
Tests for coverage_uncertain_ids helper (CVE-006 Phase 5).

Validates the subset-of-matched bucket used by the UI to render lower-confidence
CVEs in a secondary section. The helper wraps data_confidence() — anything
not "verified" goes into the bucket.
"""
from models.cve_model import CVEAffectedRange, CVEEntry, CVEFirstFixed
from services.cve_engine import coverage_uncertain_ids


def _verified(cve_id):
    """CVE with concrete fix_version → confidence: verified."""
    return CVEEntry(
        cve_id=cve_id,
        title="t",
        severity="high",
        platforms=["IOS XE"],
        affected=CVEAffectedRange(min="17.0.0", max="17.9.3"),
        fixed_in="17.9.4a",
        description="d",
    )


def _max_bound(cve_id):
    """CVE without fix_in but with bounded affected.max → confidence: max-bound."""
    return CVEEntry(
        cve_id=cve_id,
        title="t",
        severity="high",
        platforms=["IOS XE"],
        affected=CVEAffectedRange(min="17.0.0", max="17.11.99"),
        fixed_in=None,
        description="d",
    )


def _uncertain(cve_id):
    """CVE with no fix and unbounded max → confidence: uncertain."""
    return CVEEntry(
        cve_id=cve_id,
        title="t",
        severity="high",
        platforms=["IOS XE"],
        affected=CVEAffectedRange(min="", max=""),
        fixed_in=None,
        description="d",
    )


def _first_fixed_verified(cve_id):
    """CVE with per-family fix (first_fixed_version populated) → verified."""
    return CVEEntry(
        cve_id=cve_id,
        title="t",
        severity="high",
        platforms=["IOS XE"],
        affected=CVEAffectedRange(min="17.0.0", max="17.11.99"),
        fixed_in=None,
        first_fixed_version=CVEFirstFixed(fixes={"ios-xe": "17.9.4a"}),
        description="d",
    )


class TestCoverageUncertainIds:
    def test_empty_matched_returns_empty(self):
        assert coverage_uncertain_ids([]) == []

    def test_all_verified_returns_empty(self):
        matched = [_verified("CVE-2023-0001"), _verified("CVE-2024-0002")]
        assert coverage_uncertain_ids(matched) == []

    def test_all_max_bound_returns_all(self):
        matched = [_max_bound("CVE-2023-0001"), _max_bound("CVE-2024-0002")]
        assert coverage_uncertain_ids(matched) == ["CVE-2023-0001", "CVE-2024-0002"]

    def test_all_uncertain_returns_all(self):
        matched = [_uncertain("CVE-2023-0001"), _uncertain("CVE-2024-0002")]
        assert coverage_uncertain_ids(matched) == ["CVE-2023-0001", "CVE-2024-0002"]

    def test_mixed_returns_only_non_verified(self):
        matched = [
            _verified("CVE-A"),         # excluded
            _max_bound("CVE-B"),        # included
            _uncertain("CVE-C"),        # included
            _verified("CVE-D"),         # excluded
            _max_bound("CVE-E"),        # included
        ]
        assert coverage_uncertain_ids(matched) == ["CVE-B", "CVE-C", "CVE-E"]

    def test_preserves_input_order(self):
        """Deterministic order for snapshot tests / UI rendering."""
        matched = [
            _max_bound("CVE-Z"),
            _max_bound("CVE-A"),
            _max_bound("CVE-M"),
        ]
        assert coverage_uncertain_ids(matched) == ["CVE-Z", "CVE-A", "CVE-M"]

    def test_returns_subset_of_input_ids(self):
        """The bucket must NEVER contain CVE IDs that aren't in matched."""
        matched = [_verified("CVE-A"), _max_bound("CVE-B"), _uncertain("CVE-C")]
        result = coverage_uncertain_ids(matched)
        input_ids = {cve.cve_id for cve in matched}
        assert set(result).issubset(input_ids)

    def test_first_fixed_version_promotes_to_verified(self):
        """When first_fixed_version populated → verified → NOT in bucket.
        This is the CVE-006 Phase 3 path (PSIRT advisory-detail fetch success)."""
        matched = [_first_fixed_verified("CVE-2025-20363")]
        assert coverage_uncertain_ids(matched) == []

    def test_mixed_confidence_sources_classified_correctly(self):
        """Full matrix: scalar fixed_in verified + first_fixed verified + max-bound + uncertain."""
        matched = [
            _verified("CVE-SCALAR"),         # verified via fixed_in
            _first_fixed_verified("CVE-FF"), # verified via first_fixed_version
            _max_bound("CVE-MAX"),           # uncertain
            _uncertain("CVE-UNK"),           # uncertain
        ]
        assert coverage_uncertain_ids(matched) == ["CVE-MAX", "CVE-UNK"]


class TestIntegrationWithCVEAnalyzeResponse:
    """Sanity check that the router-side integration works end-to-end."""

    def test_field_serializable_empty(self):
        """Default empty list serializes cleanly in Pydantic response model."""
        from api.routers.cve import CVEAnalyzeResponse

        resp = CVEAnalyzeResponse(
            platform="Cisco IOS XE",
            version="17.9.4",
            matched=[],
            summary={},
            recommended_upgrade=None,
            timestamp="2026-04-22T00:00:00Z",
        )
        assert resp.coverage_uncertain == []

    def test_field_serializable_populated(self):
        from api.routers.cve import CVEAnalyzeResponse

        resp = CVEAnalyzeResponse(
            platform="Cisco IOS XE",
            version="17.9.4",
            matched=[_max_bound("CVE-2023-0001"), _max_bound("CVE-2024-0002")],
            coverage_uncertain=["CVE-2023-0001", "CVE-2024-0002"],
            summary={},
            recommended_upgrade=None,
            timestamp="2026-04-22T00:00:00Z",
        )
        assert resp.coverage_uncertain == ["CVE-2023-0001", "CVE-2024-0002"]
        # coverage_uncertain IDs must be subset of matched IDs
        matched_ids = {cve.cve_id for cve in resp.matched}
        assert set(resp.coverage_uncertain).issubset(matched_ids)
