"""
Tests for published_date_demoted_ids + helpers (CVE-006 Phase 6).

Validates the belt-and-braces safety heuristic that flags CVEs as uncertain
when they're >3 years older than the queried version AND lack a per-family
fix version. Used by the router to union with Phase 5's coverage_uncertain
bucket.
"""
import json

from models.cve_model import CVEAffectedRange, CVEEntry, CVEFirstFixed
from services.cve_engine import (
    _cve_published_is_stale,
    _load_version_release_dates,
    _query_version_release_date,
    published_date_demoted_ids,
)


# ---------------------------------------------------------------------------
# Helper fixtures
# ---------------------------------------------------------------------------

def _cve(cve_id, published=None, first_fixed_fixes=None):
    ff = None
    if first_fixed_fixes:
        ff = CVEFirstFixed(fixes=first_fixed_fixes)
    return CVEEntry(
        cve_id=cve_id,
        title="t",
        severity="high",
        platforms=["IOS XE"],
        affected=CVEAffectedRange(min="17.0.0", max="17.11.99"),
        fixed_in=None,
        description="d",
        published=published,
        first_fixed_version=ff,
    )


# ---------------------------------------------------------------------------
# _load_version_release_dates — JSON integrity
# ---------------------------------------------------------------------------

class TestVersionReleaseDatesLoader:
    def test_returns_dict(self):
        data = _load_version_release_dates()
        assert isinstance(data, dict)

    def test_has_expected_families(self):
        data = _load_version_release_dates()
        assert "IOS_XE" in data
        assert "IOS" in data

    def test_meta_filtered_out(self):
        """_meta block is metadata, not a family — must not appear in loaded data."""
        data = _load_version_release_dates()
        assert "_meta" not in data

    def test_known_version_present(self):
        """17.9 (a major NetDevOps target) must have a date."""
        data = _load_version_release_dates()
        assert "17.9" in data["IOS_XE"]

    def test_dates_are_iso_format(self):
        """All values must be parseable as ISO dates (YYYY-MM-DD)."""
        import datetime
        data = _load_version_release_dates()
        for family, versions in data.items():
            for ver, date_str in versions.items():
                try:
                    datetime.date.fromisoformat(date_str)
                except ValueError:
                    raise AssertionError(
                        f"{family}/{ver}: '{date_str}' is not ISO YYYY-MM-DD"
                    )


# ---------------------------------------------------------------------------
# _query_version_release_date — major.minor reduction
# ---------------------------------------------------------------------------

class TestQueryVersionLookup:
    def test_exact_major_minor(self):
        assert _query_version_release_date("IOS_XE", "17.9") is not None

    def test_maint_stripped(self):
        """17.9.4 should match 17.9 lookup key."""
        assert _query_version_release_date("IOS_XE", "17.9.4") == _query_version_release_date("IOS_XE", "17.9")

    def test_rebuild_letter_stripped(self):
        """17.9.4a should match 17.9."""
        assert _query_version_release_date("IOS_XE", "17.9.4a") == _query_version_release_date("IOS_XE", "17.9")

    def test_missing_version(self):
        assert _query_version_release_date("IOS_XE", "99.99") is None

    def test_unknown_family(self):
        assert _query_version_release_date("NONEXISTENT_FAMILY", "17.9") is None

    def test_garbage_version(self):
        assert _query_version_release_date("IOS_XE", "not-a-version") is None


# ---------------------------------------------------------------------------
# _cve_published_is_stale — 3-year threshold
# ---------------------------------------------------------------------------

class TestCVEPublishedIsStale:
    def test_stale_by_5_years(self):
        assert _cve_published_is_stale("2017-01-15", "2023-05-15") is True

    def test_not_stale_by_1_year(self):
        assert _cve_published_is_stale("2022-01-15", "2023-05-15") is False

    def test_boundary_just_over_3_years(self):
        """>3 years triggers (strictly greater). 3 years + 1 day = stale."""
        assert _cve_published_is_stale("2020-05-14", "2023-05-15") is True

    def test_exactly_3_years(self):
        """Exactly 3 years (1095 days) should NOT trigger (strictly greater)."""
        assert _cve_published_is_stale("2020-05-15", "2023-05-15") is False

    def test_missing_published(self):
        assert _cve_published_is_stale(None, "2023-05-15") is False
        assert _cve_published_is_stale("", "2023-05-15") is False

    def test_missing_release_date(self):
        assert _cve_published_is_stale("2017-01-15", None) is False
        assert _cve_published_is_stale("2017-01-15", "") is False

    def test_malformed_dates_fail_open(self):
        """Heuristic is best-effort — malformed dates return False (don't flag)."""
        assert _cve_published_is_stale("not-a-date", "2023-05-15") is False
        assert _cve_published_is_stale("2017-01-15", "not-a-date") is False

    def test_published_with_time_suffix(self):
        """PSIRT publishes ISO datetime; we normalize to first 10 chars."""
        assert _cve_published_is_stale("2017-01-15T10:30:00", "2023-05-15") is True


# ---------------------------------------------------------------------------
# published_date_demoted_ids — top-level API
# ---------------------------------------------------------------------------

class TestPublishedDateDemotedIds:
    def test_stale_cve_without_first_fixed_is_flagged(self):
        """2017 CVE on IOS XE 17.9 query (released 2022-11) = 5 years apart."""
        matched = [_cve("CVE-2017-12240", published="2017-09-21")]
        result = published_date_demoted_ids(matched, "Cisco IOS XE", "17.9.4")
        assert "CVE-2017-12240" in result

    def test_recent_cve_not_flagged(self):
        matched = [_cve("CVE-2023-20198", published="2023-10-16")]
        result = published_date_demoted_ids(matched, "Cisco IOS XE", "17.9.4")
        assert result == []

    def test_stale_cve_with_first_fixed_NOT_flagged(self):
        """Heuristic defers to verified per-family fix data."""
        matched = [_cve(
            "CVE-2017-12240",
            published="2017-09-21",
            first_fixed_fixes={"ios-xe": "17.9.4a"},
        )]
        result = published_date_demoted_ids(matched, "Cisco IOS XE", "17.9.4")
        assert result == []

    def test_unknown_platform_returns_empty(self):
        matched = [_cve("CVE-2017-12240", published="2017-09-21")]
        # Platform not in _FAMILY_TO_DATES_KEY (only IOS_XE + IOS supported initially)
        assert published_date_demoted_ids(matched, "Cisco NX-OS", "9.3") == []

    def test_unknown_version_returns_empty(self):
        """99.99 not in lookup table → heuristic silently skips."""
        matched = [_cve("CVE-2017-12240", published="2017-09-21")]
        assert published_date_demoted_ids(matched, "Cisco IOS XE", "99.99") == []

    def test_empty_matched(self):
        assert published_date_demoted_ids([], "Cisco IOS XE", "17.9.4") == []

    def test_mixed_list_returns_only_stale(self):
        matched = [
            _cve("CVE-2017-old", published="2017-01-01"),        # stale ← flagged
            _cve("CVE-2023-new", published="2023-01-01"),        # recent, ignored
            _cve("CVE-2016-old-but-fixed", published="2016-01-01",
                 first_fixed_fixes={"ios-xe": "17.9.4a"}),       # stale but verified ← ignored
            _cve("CVE-2018-stale", published="2018-06-15"),      # stale ← flagged
        ]
        result = published_date_demoted_ids(matched, "Cisco IOS XE", "17.9.4")
        assert result == ["CVE-2017-old", "CVE-2018-stale"]

    def test_ios_classic_query_works(self):
        """Heuristic covers IOS classic too (15.x versions). Uses 'Cisco IOS
        Software' phrasing which is how PSIRT prose labels these."""
        matched = [_cve("CVE-2010-0001", published="2010-03-15")]
        result = published_date_demoted_ids(matched, "Cisco IOS Software", "15.7(3)M5")
        assert "CVE-2010-0001" in result

    def test_cve_without_published_date_not_flagged(self):
        """Fail-open: missing published → skip (can't evaluate)."""
        matched = [_cve("CVE-X", published=None)]
        assert published_date_demoted_ids(matched, "Cisco IOS XE", "17.9.4") == []


# ---------------------------------------------------------------------------
# JSON file integrity (catch curator mistakes)
# ---------------------------------------------------------------------------

def test_release_dates_json_has_no_regressions():
    """Each family must have at least one entry; within the SAME major train
    (e.g. 17.x), minor versions must be chronologically monotonic.
    Cross-major comparisons are NOT checked because Cisco maintains parallel
    trains (e.g. IOS XE 3.17 was released 2017 alongside 16.x starting 2016)."""
    import datetime
    from collections import defaultdict
    data = _load_version_release_dates()

    for family, versions in data.items():
        assert versions, f"{family}: empty — delete family or add at least one version"
        # Group by major, check monotonicity within each major separately.
        by_major = defaultdict(list)
        for ver, date_str in versions.items():
            try:
                d = datetime.date.fromisoformat(date_str)
            except ValueError:
                raise AssertionError(f"{family}/{ver}: bad date '{date_str}'")
            major = int(ver.split(".")[0])
            minor = int(ver.split(".")[1])
            by_major[major].append((minor, ver, d))

        for major, entries in by_major.items():
            entries.sort(key=lambda e: e[0])
            prev_date = None
            for minor, ver, d in entries:
                if prev_date is not None:
                    assert d >= prev_date, (
                        f"{family}/{ver} released {d} but earlier minor in same "
                        f"major released {prev_date} — chronology broken within {major}.x"
                    )
                prev_date = d
