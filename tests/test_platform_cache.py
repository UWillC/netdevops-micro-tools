"""
Platform cache freshness, local-fallback scope, and auto-sync scope (CACHE-01).

Three defects behind one symptom — the "IOS XE" filter in Latest Threats
showing half-year-old advisories and other products:

  A. _load_platform_cache() accepted a file of any age and the feed never asked
     for a new one while the file existed. cache/cisco/iosxe.json reached
     189 days.
  B. The local-dataset fallback (added in ISE-02) read cve_data/ios_xe raw.
     Seven of its 142 records are other product families the PSIRT importer
     mislabelled; the engine filters them with the taxonomy, the feed did not.
  C. CiscoAdvisoryProvider.load() ran auto_sync_new_cves() for every platform,
     and that function writes into cve_data/ios_xe with platforms=["IOS XE"].
     Once the feed could ask for ISE, ISE advisories were filed as IOS XE.
"""

import json
import os
import time

import pytest

from api.routers import cve as cve_router
from services import cve_sources


def write_cache(tmp_path, platform, age_hours, advisories=None):
    path = tmp_path / f"{platform}.json"
    path.write_text(json.dumps({
        "cached_at": time.time() - age_hours * 3600,
        "advisories": advisories if advisories is not None else [{"advisoryId": "a1"}],
    }), encoding="utf-8")
    return path


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(cve_router, "CISCO_CACHE_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def quiet_feed(monkeypatch):
    monkeypatch.setattr(cve_router, "_load_latest_cache", lambda: ([], 0.1))
    monkeypatch.setattr(cve_router, "_fetch_latest_advisories", lambda: [])


@pytest.fixture
def spawned(monkeypatch):
    """Record background work instead of running it."""
    calls = []
    monkeypatch.setattr(cve_router, "_spawn", lambda target, *args: calls.append((target, args)))
    return calls


class TestCacheAge:
    def test_age_is_reported(self, cache_dir):
        write_cache(cache_dir, "iosxe", age_hours=48)
        assert 47.9 <= cve_router._platform_cache_age_hours("iosxe") <= 48.1

    def test_missing_cache_has_no_age(self, cache_dir):
        assert cve_router._platform_cache_age_hours("iosxe") is None

    def test_corrupt_cache_has_no_age_and_no_data(self, cache_dir):
        (cache_dir / "iosxe.json").write_text("{broken", encoding="utf-8")
        assert cve_router._platform_cache_age_hours("iosxe") is None
        assert cve_router._load_platform_cache("iosxe") == []

    def test_stale_data_is_still_served(self, cache_dir):
        write_cache(cache_dir, "iosxe", age_hours=24 * 189)
        assert cve_router._load_platform_cache("iosxe") == [{"advisoryId": "a1"}]


class TestStaleWhileRevalidate:
    def test_fresh_cache_does_not_refresh(self, cache_dir, quiet_feed, spawned):
        write_cache(cache_dir, "iosxe", age_hours=1)
        resp = cve_router._get_advisories_feed("iosxe")
        assert spawned == []
        assert resp.platform_cache_refreshing is False

    def test_stale_cache_refreshes_in_background_and_is_flagged(self, cache_dir, quiet_feed, spawned):
        write_cache(cache_dir, "iosxe", age_hours=24 * 189)
        resp = cve_router._get_advisories_feed("iosxe")
        assert len(spawned) == 1 and spawned[0][1] == ("iosxe",)
        assert resp.platform_cache_refreshing is True
        assert resp.platform_cache_age_hours > 24 * 188

    def test_missing_cache_refreshes_without_blocking(self, cache_dir, quiet_feed, spawned):
        """Used to call provider.load() inline: up to five pages, 2 s apart."""
        resp = cve_router._get_advisories_feed("nxos")
        assert len(spawned) == 1
        assert resp.platform_cache_age_hours is None

    def test_all_view_touches_no_platform_cache(self, cache_dir, quiet_feed, spawned):
        resp = cve_router._get_advisories_feed("all")
        assert spawned == []
        assert resp.platform_cache_age_hours is None

    def test_only_one_refresh_in_flight(self, cache_dir, quiet_feed, spawned):
        write_cache(cache_dir, "iosxe", age_hours=100)
        cve_router._get_advisories_feed("iosxe")
        second = cve_router._get_advisories_feed("iosxe")
        assert len(spawned) == 1
        assert second.platform_cache_refreshing is False

    def test_failed_refresh_backs_off(self, cache_dir, quiet_feed, spawned):
        write_cache(cache_dir, "iosxe", age_hours=100)
        cve_router._platform_refresh_failed_at["iosxe"] = time.time()
        cve_router._get_advisories_feed("iosxe")
        assert spawned == []

    def test_backoff_expires(self, cache_dir, quiet_feed, spawned):
        write_cache(cache_dir, "iosxe", age_hours=100)
        cve_router._platform_refresh_failed_at["iosxe"] = (
            time.time() - cve_router.PLATFORM_REFRESH_BACKOFF - 1)
        cve_router._get_advisories_feed("iosxe")
        assert len(spawned) == 1


class TestRefreshWorker:
    def provider(self, monkeypatch, creds=True, load=None):
        state = {"loaded": 0}

        class P:
            def __init__(self, platform="iosxe"):
                self.platform = platform

            def _load_credentials(self):
                return {"k": "v"} if creds else None

            def load(self):
                state["loaded"] += 1
                if load:
                    load(self.platform)
                return []

        monkeypatch.setattr(cve_router, "CiscoAdvisoryProvider", P)
        return state

    def test_no_credentials_is_a_recorded_failure_not_a_fetch(self, cache_dir, monkeypatch):
        state = self.provider(monkeypatch, creds=False)
        cve_router._refresh_platform_cache("iosxe")
        assert state["loaded"] == 0
        assert "iosxe" in cve_router._platform_refresh_failed_at

    def test_success_clears_the_in_flight_marker(self, cache_dir, monkeypatch):
        self.provider(monkeypatch, load=lambda p: write_cache(cache_dir, p, age_hours=0))
        cve_router._platform_refresh_running.add("iosxe")
        cve_router._refresh_platform_cache("iosxe")
        assert "iosxe" not in cve_router._platform_refresh_running
        assert "iosxe" not in cve_router._platform_refresh_failed_at

    def test_load_that_writes_nothing_counts_as_failure(self, cache_dir, monkeypatch):
        """e.g. rate limited: load() returns, cache is still stale."""
        write_cache(cache_dir, "iosxe", age_hours=100)
        self.provider(monkeypatch)
        cve_router._refresh_platform_cache("iosxe")
        assert "iosxe" in cve_router._platform_refresh_failed_at

    def test_exception_is_contained(self, cache_dir, monkeypatch):
        def boom(_):
            raise RuntimeError("psirt down")
        self.provider(monkeypatch, load=boom)
        cve_router._platform_refresh_running.add("iosxe")
        cve_router._refresh_platform_cache("iosxe")          # must not raise
        assert "iosxe" not in cve_router._platform_refresh_running
        assert "iosxe" in cve_router._platform_refresh_failed_at


class TestLocalFallbackScope:
    FOREIGN = ["CVE-2019-1653", "CVE-2019-1652", "CVE-2018-0101", "CVE-2026-20079",
               "CVE-2024-20310", "CVE-2024-20419", "CVE-2024-20265"]

    def test_foreign_families_are_not_shown_under_ios_xe(self):
        ids = {i.cve_id for i in cve_router._local_records_to_feed("iosxe")}
        leaked = [c for c in self.FOREIGN if c in ids]
        assert leaked == [], f"other product families under the IOS XE filter: {leaked}"

    def test_records_declaring_another_platform_are_not_shown(self):
        """The taxonomy cannot name FMC or the SD-WAN Controller from a title,
        but these curated records declare it themselves in `platforms`."""
        ids = {i.cve_id for i in cve_router._local_records_to_feed("iosxe")}
        assert "CVE-2026-20131" not in ids      # platforms: FMC
        assert "CVE-2026-20127" not in ids      # platforms: SD-WAN Controller

    def test_real_ios_xe_records_are_kept(self):
        ids = {i.cve_id for i in cve_router._local_records_to_feed("iosxe")}
        assert "CVE-2023-20198" in ids          # IOS XE Web UI
        assert "CVE-2025-20352" in ids          # IOS XE SNMP, KEV
        assert 100 < len(ids) < 142             # most of the directory, not all of it

    def test_every_shown_record_declares_ios_xe(self):
        import json as _json, glob as _glob, os as _os
        root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
        declared = {}
        for path in _glob.glob(_os.path.join(root, "cve_data", "ios_xe", "cve-*.json")):
            d = _json.load(open(path))
            declared[d["cve_id"]] = [p.lower() for p in d.get("platforms", [])] + d.get("product_families", [])
        for item in cve_router._local_records_to_feed("iosxe"):
            assert any(x in ("ios xe", "ios-xe", "iosxe") for x in declared[item.cve_id]), item.cve_id

    def test_ise_fallback_is_unaffected(self):
        assert len(cve_router._local_records_to_feed("ise")) == 56


class TestAutoSyncScope:
    @pytest.fixture
    def synced(self, monkeypatch):
        calls = []
        import services.cisco_sync as cisco_sync
        monkeypatch.setattr(cisco_sync, "auto_sync_new_cves",
                            lambda advs, platform="iosxe": calls.append((platform, len(advs))))
        monkeypatch.setattr(cve_sources.CiscoAdvisoryProvider, "_read_cache",
                            lambda self: [{"advisoryId": "x", "cves": []}])
        return calls

    @pytest.mark.parametrize("platform", ["iosxe", "ios"])
    def test_ios_xe_family_still_syncs(self, synced, platform):
        cve_sources.CiscoAdvisoryProvider(platform=platform).load()
        assert synced == [(platform, 1)]

    def test_ise_syncs_into_its_own_dataset(self, synced):
        """ISE-04: the platform is passed through, so the ISE importer — not the
        IOS XE one — handles it."""
        cve_sources.CiscoAdvisoryProvider(platform="ise").load()
        assert synced == [("ise", 1)]

    @pytest.mark.parametrize("platform", ["asa", "nxos", "ftd"])
    def test_other_platforms_never_write_into_the_ios_xe_dataset(self, synced, platform):
        cve_sources.CiscoAdvisoryProvider(platform=platform).load()
        assert synced == []

    def test_constant_is_what_the_tests_assume(self):
        assert cve_sources.AUTO_SYNC_PLATFORMS == ("iosxe", "ios", "ise")
