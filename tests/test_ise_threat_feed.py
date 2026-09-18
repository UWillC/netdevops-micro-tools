"""
Threat-feed integration for ISE (ISE-02, 2026-09-18).

The "Cisco — Latest Threats" widget was PSIRT-only: with no API credentials it
rendered an empty state forever, and ISE was not even in the platform filter.
These tests cover the local-dataset path, the merge with PSIRT, KEV-first
ordering, and the ISE filter.

NOTE: nothing here calls _get_advisories_feed() without stubbing the PSIRT
loaders first. That path can reach the live API and, with credentials present,
auto-imports advisories into cve_data/ — a test must not write to the dataset
it is testing.
"""

import pytest

from api.routers import cve as cve_router
from api.routers.cve import (
    FeedItem,
    _advisories_to_feed,
    _local_records_to_feed,
    _merge_feed_items,
    _sort_feed_items,
)

KEV_CVE = "CVE-2026-76460"


def psirt_adv(advisory_id, cves, sir="critical", score="9.0", products=None,
              updated="2026-09-16"):
    return {
        "advisoryId": advisory_id,
        "advisoryTitle": "Test advisory " + advisory_id,
        "sir": sir,
        "cvssBaseScore": score,
        "cves": cves,
        "productNames": products or ["Cisco Identity Services Engine"],
        "firstPublished": updated,
        "lastUpdated": updated,
        "publicationUrl": "https://example.invalid/" + advisory_id,
    }


class TestLocalRecordsToFeed:
    def test_ise_records_are_returned(self):
        items = _local_records_to_feed("ise")
        assert len(items) == 8
        assert all(i.source == "local" for i in items)

    def test_unknown_platform_is_empty_not_error(self):
        assert _local_records_to_feed("nxos") == []
        assert _local_records_to_feed("") == []

    def test_kev_block_is_carried_through(self):
        kev = {i.cve_id: i.kev for i in _local_records_to_feed("ise")}
        assert kev[KEV_CVE]["due_date"] == "2026-09-19"
        assert kev[KEV_CVE]["directive"] == "BOD 26-04"

    def test_only_the_kev_record_has_a_kev_block(self):
        with_kev = [i.cve_id for i in _local_records_to_feed("ise") if i.kev]
        assert with_kev == [KEV_CVE]

    def test_cvss_and_severity_survive(self):
        item = {i.cve_id: i for i in _local_records_to_feed("ise")}[KEV_CVE]
        assert item.cvss == 10.0
        assert item.severity == "critical"
        assert item.url.startswith("https://sec.cloudapps.cisco.com/")

    def test_broken_file_is_skipped_not_fatal(self, tmp_path, monkeypatch):
        """One malformed record must not take the whole home page down."""
        bad = tmp_path / "ise"
        bad.mkdir()
        (bad / "cve-bad.json").write_text("{not json", encoding="utf-8")
        (bad / "cve-ok.json").write_text(
            '{"cve_id":"CVE-2026-1","title":"t","severity":"high",'
            '"affected":{"min":"3.1","max":"3.5"},"description":"d"}', encoding="utf-8")
        monkeypatch.setattr(cve_router.os.path, "isdir", lambda p: True)
        monkeypatch.setattr(cve_router.os, "listdir", lambda p: ["cve-bad.json", "cve-ok.json"])
        monkeypatch.setattr(cve_router.os.path, "normpath", lambda p: str(bad))
        items = _local_records_to_feed("ise")
        assert [i.cve_id for i in items] == ["CVE-2026-1"]


class TestMerge:
    def local_kev(self):
        return [i for i in _local_records_to_feed("ise") if i.cve_id == KEV_CVE]

    def test_psirt_row_wins_on_conflict(self):
        psirt = _advisories_to_feed([psirt_adv("cisco-sa-x", [KEV_CVE])], "ise")
        merged = _merge_feed_items(psirt, self.local_kev())
        assert len(merged) == 1
        assert merged[0].source == "psirt"

    def test_local_donates_kev_to_the_psirt_row(self):
        """PSIRT does not expose KEV; losing it on merge would hide the
        single most important signal on the page."""
        psirt = _advisories_to_feed([psirt_adv("cisco-sa-x", [KEV_CVE])], "ise")
        assert psirt[0].kev is None
        merged = _merge_feed_items(psirt, self.local_kev())
        assert merged[0].kev["due_date"] == "2026-09-19"

    def test_local_only_rows_collapse_per_advisory(self):
        """With no PSIRT at all, the 8 ISE records become 3 rows.

        Six of them are the September hardening release and share one advisory
        URL; the other two (auth bypass, RADIUS DoS) have their own. The widget
        is a per-advisory triage list, so one row per advisory is correct — and
        the link target is the advisory either way.
        """
        merged = _merge_feed_items([], _local_records_to_feed("ise"))
        assert len(merged) == 3
        assert len({i.url for i in merged}) == 3
        assert all(i.source == "local" for i in merged)

    def test_local_only_keeps_the_kev_row_distinct(self):
        merged = _merge_feed_items([], _local_records_to_feed("ise"))
        kev_rows = [i for i in merged if i.kev]
        assert [i.cve_id for i in kev_rows] == [KEV_CVE]

    def test_local_rows_from_an_already_listed_advisory_collapse(self):
        """PSIRT rows are advisory-granular, local rows are CVE-granular.

        The ISE hardening release holds six CVEs; without URL dedup it filled
        six of the ten slots while PSIRT already had one row for it.
        """
        url = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-hardening-ise-XU5EwX5T"
        psirt = [FeedItem(cve_id="CVE-2026-20130", title="hardening", severity="critical",
                          cvss=10.0, published="2026-09-16", updated="2026-09-16",
                          url=url, platforms=["Cisco Identity Services Engine"])]
        merged = _merge_feed_items(psirt, _local_records_to_feed("ise"))
        from_hardening = [i for i in merged if i.url == url]
        assert len(from_hardening) == 1
        assert from_hardening[0].source == "psirt"

    def test_kev_is_donated_even_across_different_cve_ids(self):
        """The KEV advisory listed by PSIRT under another CVE still gets the badge."""
        kev_url = self.local_kev()[0].url
        psirt = [FeedItem(cve_id="CVE-2026-00000", title="same advisory, other cve",
                          severity="critical", cvss=10.0, published="2026-09-16",
                          updated="2026-09-16", url=kev_url, platforms=[])]
        merged = _merge_feed_items(psirt, self.local_kev())
        assert len(merged) == 1
        assert merged[0].kev["due_date"] == "2026-09-19"

    def test_distinct_advisories_are_all_kept(self):
        a = FeedItem(cve_id="CVE-X", title="a", severity="high", cvss=8.0,
                     published="2026-09-16", updated="2026-09-16",
                     url="https://example.invalid/a", platforms=[])
        b = FeedItem(cve_id="CVE-Y", title="b", severity="high", cvss=8.0,
                     published="2026-09-16", updated="2026-09-16",
                     url="https://example.invalid/b", platforms=[], source="local")
        assert len(_merge_feed_items([a], [b])) == 2

    def test_no_duplicate_cve_ids(self):
        psirt = _advisories_to_feed(
            [psirt_adv("cisco-sa-x", [KEV_CVE]), psirt_adv("cisco-sa-y", ["CVE-2026-20192"])],
            "ise")
        merged = _merge_feed_items(psirt, _local_records_to_feed("ise"))
        ids = [i.cve_id for i in merged]
        assert len(ids) == len(set(ids))


class TestSorting:
    def item(self, cve_id, cvss, severity, updated, kev=None):
        return FeedItem(cve_id=cve_id, title="t", severity=severity, cvss=cvss,
                        published=updated, updated=updated, url=None, platforms=[],
                        kev=kev)

    def test_kev_outranks_a_higher_cvss(self):
        items = [
            self.item("CVE-A", 10.0, "critical", "2026-09-18"),
            self.item("CVE-B", 6.5, "medium", "2026-09-10",
                      kev={"date_added": "2026-09-16", "due_date": "2026-09-19"}),
        ]
        _sort_feed_items(items)
        assert items[0].cve_id == "CVE-B"

    def test_without_kev_newest_still_wins(self):
        items = [
            self.item("CVE-OLD", 10.0, "critical", "2026-01-01"),
            self.item("CVE-NEW", 7.0, "high", "2026-09-18"),
        ]
        _sort_feed_items(items)
        assert items[0].cve_id == "CVE-NEW"

    def test_kev_row_keeps_its_own_severity(self):
        """Ordering changes; the score does not. KEV is not an escalation."""
        item = self.item("CVE-B", 6.5, "medium", "2026-09-10", kev={"due_date": "x"})
        _sort_feed_items([item])
        assert item.severity == "medium" and item.cvss == 6.5


class TestIsePlatformFilter:
    def test_ise_advisory_passes(self):
        out = _advisories_to_feed([psirt_adv("a", ["CVE-1"])], "ise")
        assert len(out) == 1

    def test_non_ise_advisory_is_filtered_out(self):
        adv = psirt_adv("b", ["CVE-2"], products=["Cisco IOS XE Software"])
        assert _advisories_to_feed([adv], "ise") == []

    def test_ise_advisory_does_not_leak_into_iosxe(self):
        assert _advisories_to_feed([psirt_adv("a", ["CVE-1"])], "iosxe") == []

    def test_all_platforms_keeps_ise(self):
        assert len(_advisories_to_feed([psirt_adv("a", ["CVE-1"])], "all")) == 1

    def test_word_ise_matches_but_substring_does_not(self):
        """'wise' or 'precise' in a product name must not match ISE."""
        adv = psirt_adv("c", ["CVE-3"], products=["Cisco Precise Wiseguy Appliance"])
        assert _advisories_to_feed([adv], "ise") == []


class TestEndpointWithoutNetwork:
    """_get_advisories_feed with the PSIRT side stubbed out."""

    @pytest.fixture(autouse=True)
    def no_psirt(self, monkeypatch):
        monkeypatch.setattr(cve_router, "_load_latest_cache", lambda: ([], None))
        monkeypatch.setattr(cve_router, "_fetch_latest_advisories", lambda: [])
        monkeypatch.setattr(cve_router, "_load_platform_cache", lambda p: [])
        # An empty platform cache sends _get_advisories_feed down the
        # "then fetch it" branch, which builds a real CiscoAdvisoryProvider.
        # With credentials on the machine that hits the live API AND
        # auto-imports advisories into cve_data/ — a test writing ~1000 files
        # into the dataset it is testing. Stub the provider too.
        class _DeadProvider:
            def __init__(self, *a, **kw):
                pass

            def _load_credentials(self):
                return None

            def load(self):  # pragma: no cover - must never be reached
                raise AssertionError("test attempted a live PSIRT fetch")

        monkeypatch.setattr(cve_router, "CiscoAdvisoryProvider", _DeadProvider)

    def test_ise_is_served_from_local_dataset_alone(self):
        resp = cve_router._get_advisories_feed("ise")
        assert resp.items, "ISE must not render an empty widget without PSIRT credentials"
        assert all(i.source == "local" for i in resp.items)

    def test_kev_record_is_first(self):
        assert cve_router._get_advisories_feed("ise").items[0].cve_id == KEV_CVE

    def test_all_view_includes_local_ise(self):
        ids = [i.cve_id for i in cve_router._get_advisories_feed("all").items]
        assert KEV_CVE in ids

    def test_total_counts_local_records(self):
        assert cve_router._get_advisories_feed("ise").total_advisories == 8

    def test_at_most_ten_items(self):
        assert len(cve_router._get_advisories_feed("all").items) <= 10
