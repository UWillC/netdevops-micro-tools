"""
CISA KEV catalog lookup and its use in the feed and the analyzer (KEV-X).

The bug this closes: KEV badges came only from curated local records, because
PSIRT does not expose KEV status. On production CVE-2026-76460 had a badge and
CVE-2026-76461 — in KEV for four days — did not. A badge present on some
exploited CVEs and absent on others reads as "this one is not exploited".

Network: tests/conftest.py sets KEV_CATALOG_OFFLINE for the whole suite and
points the disk cache at a temp dir. Tests that need a fetch stub http_get_json.
"""

import datetime
import json
import os
import time

import pytest

from services import kev_catalog

RAW = {
    "catalogVersion": "2026.09.16",
    "vulnerabilities": [
        {"cveID": "CVE-2026-76460", "dateAdded": "2026-09-16", "dueDate": "2026-09-19",
         "notes": "https://x ; BOD 26-04: https://www.cisa.gov/...",
         "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2026-76461", "dateAdded": "2026-09-14", "dueDate": "2026-09-17",
         "notes": "https://x", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2023-20198", "dateAdded": "2023-10-16", "dueDate": "2023-10-20",
         "notes": "", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "not-a-cve", "dateAdded": "2026-01-01", "dueDate": "2026-01-02"},
    ],
}


@pytest.fixture
def online(monkeypatch):
    """Allow the fetch path, with http_get_json replaced by a counter stub."""
    calls = {"n": 0, "raise": None, "payload": RAW}

    def fake(url, timeout_seconds=10):
        calls["n"] += 1
        if calls["raise"]:
            raise calls["raise"]
        return calls["payload"]

    monkeypatch.delenv("KEV_CATALOG_OFFLINE", raising=False)
    monkeypatch.setattr(kev_catalog, "http_get_json", fake)
    return calls


class TestIndex:
    def test_builds_compact_records(self, online):
        idx = kev_catalog.load_kev_index()
        assert idx["CVE-2026-76460"]["due_date"] == "2026-09-19"
        assert idx["CVE-2026-76460"]["catalog_version"] == "2026.09.16"

    def test_directive_is_parsed_from_notes(self, online):
        idx = kev_catalog.load_kev_index()
        assert idx["CVE-2026-76460"]["directive"] == "BOD 26-04"
        assert idx["CVE-2026-76461"]["directive"] is None

    def test_ransomware_flag(self, online):
        assert kev_catalog.load_kev_index()["CVE-2026-76461"]["ransomware"] == "Known"

    def test_malformed_ids_are_dropped(self, online):
        assert "NOT-A-CVE" not in kev_catalog.load_kev_index()

    def test_lookup_is_case_and_space_insensitive(self, online):
        assert kev_catalog.kev_status("  cve-2026-76460 ")["due_date"] == "2026-09-19"

    def test_unknown_and_empty(self, online):
        assert kev_catalog.kev_status("CVE-1999-0001") is None
        assert kev_catalog.kev_status(None) is None
        assert kev_catalog.kev_status("") is None


class TestCachingAndFailure:
    def test_one_fetch_per_ttl(self, online):
        kev_catalog.load_kev_index()
        kev_catalog.load_kev_index()
        kev_catalog.kev_status("CVE-2026-76460")
        assert online["n"] == 1

    def test_disk_cache_survives_a_process_restart(self, online):
        kev_catalog.load_kev_index()
        kev_catalog.reset_for_tests()
        kev_catalog.load_kev_index()
        assert online["n"] == 1
        assert os.path.exists(kev_catalog.KEV_CACHE_PATH)

    def test_failure_with_no_cache_yields_empty_not_an_exception(self, online):
        online["raise"] = RuntimeError("cisa.gov down")
        assert kev_catalog.load_kev_index() == {}

    def test_failure_is_negatively_cached(self, online):
        """An outage must not add a timeout to every page load."""
        online["raise"] = RuntimeError("down")
        for _ in range(5):
            kev_catalog.load_kev_index()
        assert online["n"] == 1

    def test_stale_disk_copy_beats_empty(self, online):
        os.makedirs(kev_catalog.KEV_CACHE_DIR, exist_ok=True)
        with open(kev_catalog.KEV_CACHE_PATH, "w") as f:
            json.dump({"cached_at": time.time() - 10 * 86400, "catalog": RAW}, f)
        online["raise"] = RuntimeError("down")
        assert "CVE-2026-76460" in kev_catalog.load_kev_index()

    def test_payload_without_vulnerabilities_is_rejected(self, online):
        online["payload"] = {"catalogVersion": "x", "vulnerabilities": []}
        assert kev_catalog.load_kev_index() == {}
        assert not os.path.exists(kev_catalog.KEV_CACHE_PATH)

    def test_offline_switch_never_fetches(self, online, monkeypatch):
        monkeypatch.setenv("KEV_CATALOG_OFFLINE", "1")
        assert kev_catalog.load_kev_index() == {}
        assert online["n"] == 0

    def test_suite_default_is_offline(self):
        """Guards conftest: a bare test must not be able to reach the network."""
        assert os.environ.get("KEV_CATALOG_OFFLINE") == "1"
        assert kev_catalog.load_kev_index() == {}


class TestFirstKevHit:
    def test_checks_every_cve_not_only_the_first(self, online):
        hit = kev_catalog.first_kev_hit(["CVE-2026-00001", "CVE-2026-76461"])
        assert hit["cve_id"] == "CVE-2026-76461"

    def test_nearest_deadline_wins(self, online):
        hit = kev_catalog.first_kev_hit(["CVE-2026-76460", "CVE-2026-76461"])
        assert hit["cve_id"] == "CVE-2026-76461"  # due 09-17 before 09-19

    def test_no_hit_and_junk_input(self, online):
        assert kev_catalog.first_kev_hit(["CVE-1999-0001"]) is None
        assert kev_catalog.first_kev_hit([]) is None
        assert kev_catalog.first_kev_hit(None) is None
        assert kev_catalog.first_kev_hit([None, 7, "CVE-2026-76460"])["cve_id"] == "CVE-2026-76460"


def adv(adv_id, cves, products="Cisco Secure Email Gateway", updated="2026-09-14"):
    return {"advisoryId": adv_id, "advisoryTitle": "T " + adv_id, "sir": "Critical",
            "cvssBaseScore": "9.8", "cves": cves, "cwe": ["CWE-77"],
            "productNames": [products], "firstPublished": updated, "lastUpdated": updated,
            "publicationUrl": "https://example.invalid/" + adv_id}


class TestFeed:
    def test_the_production_bug(self, kev_index):
        """CVE-2026-76461 has no local record; it must still get its badge."""
        from api.routers.cve import _advisories_to_feed
        kev_index({"CVE-2026-76461": {"date_added": "2026-09-14", "due_date": "2026-09-17"}})
        row = _advisories_to_feed([adv("cisco-sa-esa-inj", ["CVE-2026-76461"])], "all")[0]
        assert row.kev["due_date"] == "2026-09-17"

    def test_exploited_cve_need_not_be_the_row_label(self, kev_index):
        from api.routers.cve import _advisories_to_feed
        kev_index({"CVE-2026-76461": {"date_added": "2026-09-14", "due_date": "2026-09-17"}})
        row = _advisories_to_feed([adv("a", ["CVE-2026-11111", "CVE-2026-76461"])], "all")[0]
        assert row.cve_id == "CVE-2026-11111"          # label unchanged (dedup key)
        assert row.kev["cve_id"] == "CVE-2026-76461"   # but the badge names the real one

    def test_no_catalog_means_no_badge_not_an_error(self):
        from api.routers.cve import _advisories_to_feed
        assert _advisories_to_feed([adv("a", ["CVE-2026-76461"])], "all")[0].kev is None

    def test_local_directive_survives_when_catalog_has_none(self, kev_index):
        from api.routers.cve import _local_records_to_feed
        kev_index({"CVE-2026-76460": {"date_added": "2026-09-16", "due_date": "2026-09-19"}})
        row = {r.cve_id: r for r in _local_records_to_feed("ise")}["CVE-2026-76460"]
        assert row.kev["directive"] == "BOD 26-04"
        assert row.kev["catalog_version"] == "2026.09.16"

    def test_catalog_dates_override_the_local_snapshot(self, kev_index):
        from api.routers.cve import _local_records_to_feed
        kev_index({"CVE-2026-76460": {"date_added": "2026-09-16", "due_date": "2026-09-25"}},
                  version="2026.09.30")
        row = {r.cve_id: r for r in _local_records_to_feed("ise")}["CVE-2026-76460"]
        assert row.kev["due_date"] == "2026-09-25"
        assert row.kev["catalog_version"] == "2026.09.30"

    def test_lookup_miss_never_erases_a_local_kev_block(self):
        """A miss can also mean 'no catalog obtainable' — keep what we know."""
        from api.routers.cve import _local_records_to_feed
        row = {r.cve_id: r for r in _local_records_to_feed("ise")}["CVE-2026-76460"]
        assert row.kev["due_date"] == "2026-09-19"


class TestFreshnessWindow:
    """KEV badge is permanent; the ranking boost expires after 30 days."""

    TODAY = datetime.date(2026, 9, 18)

    def test_recent_listing_is_fresh(self):
        from api.routers.cve import _kev_is_fresh
        assert _kev_is_fresh({"date_added": "2026-09-16"}, self.TODAY)
        assert _kev_is_fresh({"date_added": "2026-08-19"}, self.TODAY)   # day 30

    def test_old_listing_is_not(self):
        from api.routers.cve import _kev_is_fresh
        assert not _kev_is_fresh({"date_added": "2026-08-18"}, self.TODAY)  # day 31
        assert not _kev_is_fresh({"date_added": "2023-10-16"}, self.TODAY)

    @pytest.mark.parametrize("bad", [None, {}, {"date_added": None}, {"date_added": "soon"}])
    def test_unparseable_gets_no_boost(self, bad):
        from api.routers.cve import _kev_is_fresh
        assert not _kev_is_fresh(bad, self.TODAY)

    def test_old_kev_keeps_badge_but_not_the_top_slot(self, kev_index):
        """Otherwise 'Latest Threats' becomes a list of 2023 KEV entries."""
        from api.routers.cve import _advisories_to_feed
        kev_index({"CVE-2023-20198": {"date_added": "2023-10-16", "due_date": "2023-10-20"}})
        rows = _advisories_to_feed([
            adv("old", ["CVE-2023-20198"], updated="2023-10-16"),
            adv("new", ["CVE-2026-55555"], updated="2026-09-17"),
        ], "all")
        assert [r.cve_id for r in rows] == ["CVE-2026-55555", "CVE-2023-20198"]
        assert rows[1].kev is not None

    def test_fresh_kev_still_outranks_a_newer_quiet_advisory(self, kev_index):
        from api.routers.cve import _advisories_to_feed
        kev_index({"CVE-2026-76461": {"date_added": "2026-09-14", "due_date": "2026-09-17"}})
        rows = _advisories_to_feed([
            adv("quiet", ["CVE-2026-55555"], updated="2026-09-18"),
            adv("kev", ["CVE-2026-76461"], updated="2026-09-14"),
        ], "all")
        assert rows[0].cve_id == "CVE-2026-76461"


class TestAnalyzer:
    def call(self, platform, version):
        from api.routers.cve import CVEAnalyzeRequest, analyze_cve
        return analyze_cve(CVEAnalyzeRequest(platform=platform, version=version))

    def test_untagged_cve_gets_kev_from_the_catalog_and_moves_up(self, kev_index):
        kev_index({"CVE-2026-20352": {"date_added": "2026-09-17", "due_date": "2026-09-20"}})
        r = self.call("ISE", "3.4 Patch 5")
        by_id = {c.cve_id: c for c in r.matched}
        assert by_id["CVE-2026-20352"].kev.due_date == "2026-09-20"
        # High severity, yet it now sits above the quiet criticals.
        top = [c.cve_id for c in r.matched[:2]]
        assert "CVE-2026-20352" in top

    def test_without_a_catalog_the_local_kev_block_is_untouched(self):
        r = self.call("ISE", "3.4 Patch 5")
        assert r.matched[0].cve_id == "CVE-2026-76460"
        assert r.matched[0].kev.directive == "BOD 26-04"

    def test_feed_response_reports_the_catalog_version(self, kev_index, monkeypatch):
        from api.routers import cve as cve_router
        kev_index({})
        monkeypatch.setattr(cve_router.kev_catalog, "catalog_version", lambda: "2026.09.16")
        monkeypatch.setattr(cve_router, "_load_latest_cache", lambda: ([], None))
        monkeypatch.setattr(cve_router, "_fetch_latest_advisories", lambda: [])
        assert cve_router._get_advisories_feed("all").kev_catalog_version == "2026.09.16"
