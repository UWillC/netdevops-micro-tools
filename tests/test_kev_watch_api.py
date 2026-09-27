"""
KEV Watch endpoint, GET /api/kev/watch (KW-01.2).

AC 2: the only source is kev_catalog; every response carries catalogVersion and
the fetch date; when CISA is down the last good copy is served with an explicit
date and `stale: true`, never an empty table passing for "nothing new"; with no
catalog at all the answer is 503.

Network: conftest.py keeps KEV offline and the disk cache in a temp dir. Tests
that need a "live" fetch stub http_get_json.
"""

import datetime
import json
import os
import time

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.routers import kev_watch
from services import kev_catalog
from tests.test_kev_catalog import WATCH_RAW, WATCH_TODAY

client = TestClient(app)


@pytest.fixture(autouse=True)
def _frozen_watch_day(monkeypatch):
    monkeypatch.setattr(kev_watch, "_today", lambda: WATCH_TODAY)
    monkeypatch.delenv("KEV_WATCH_VENDORS", raising=False)


@pytest.fixture
def live(monkeypatch):
    """CISA reachable: http_get_json returns WATCH_RAW (or raises)."""
    calls = {"n": 0, "raise": None}

    def fake(url, timeout_seconds=10):
        calls["n"] += 1
        if calls["raise"]:
            raise calls["raise"]
        return WATCH_RAW

    monkeypatch.delenv("KEV_CATALOG_OFFLINE", raising=False)
    monkeypatch.setattr(kev_catalog, "http_get_json", fake)
    return calls


def _write_disk(cached_at):
    os.makedirs(kev_catalog.KEV_CACHE_DIR, exist_ok=True)
    with open(kev_catalog.KEV_CACHE_PATH, "w") as f:
        json.dump({"cached_at": cached_at, "catalog": WATCH_RAW}, f)


def _ids(body):
    return [i["cve_id"] for i in body["items"]]


class TestLive:
    def test_200_with_items_and_provenance(self, live):
        r = client.get("/api/kev/watch?days=7&vendors=Cisco")
        assert r.status_code == 200
        body = r.json()
        assert _ids(body) == ["CVE-2026-89999", "CVE-2026-90001", "CVE-2026-90002"]
        assert body["count"] == 3
        assert body["days"] == 7
        assert body["vendors"] == ["Cisco"]
        cat = body["catalog"]
        assert cat["catalog_version"] == "2026.09.27"
        assert cat["date_released"] == "2026-09-27T17:00:00.000Z"
        assert cat["fetched_at"].endswith("+00:00")
        assert cat["source"] == "live"
        assert cat["stale"] is False
        assert body["generated_at"].endswith("+00:00")

    def test_item_fields(self, live):
        item = client.get("/api/kev/watch?days=7").json()["items"][1]
        assert item["cve_id"] == "CVE-2026-90001"
        assert item["vendor_project"] == "Cisco"
        assert item["product"] == "IOS XE Software"
        assert item["date_added"] == "2026-09-27"
        assert item["due_date"] == "2026-10-18"
        assert item["catalog_version"] == "2026.09.27"

    def test_default_vendors_is_watch_list(self, live):
        body = client.get("/api/kev/watch?days=7").json()
        assert body["vendors"] == ["Cisco"]
        assert "CVE-2026-90004" not in _ids(body)

    def test_default_vendors_follow_env(self, live, monkeypatch):
        monkeypatch.setenv("KEV_WATCH_VENDORS", "Fortinet")
        body = client.get("/api/kev/watch?days=7").json()
        assert body["vendors"] == ["Fortinet"]
        assert _ids(body) == ["CVE-2026-90004"]

    def test_blank_vendors_means_default(self, live):
        body = client.get("/api/kev/watch?days=7&vendors=%20,%20").json()
        assert body["vendors"] == ["Cisco"]

    def test_default_days_is_14(self, live):
        body = client.get("/api/kev/watch").json()
        assert body["days"] == 14
        assert "CVE-2026-90003" in _ids(body)   # 2026-09-19, 8 days back

    def test_several_vendors_case_insensitive_deduplicated(self, live):
        body = client.get("/api/kev/watch?days=7&vendors=cisco,FORTINET, Microsoft ,Cisco").json()
        assert body["vendors"] == ["cisco", "FORTINET", "Microsoft"]
        assert _ids(body) == ["CVE-2026-89999", "CVE-2026-90001", "CVE-2026-90005",
                              "CVE-2026-90004", "CVE-2026-90002"]

    def test_unknown_vendor_is_empty_not_error(self, live):
        body = client.get("/api/kev/watch?days=30&vendors=NoSuchVendor").json()
        assert body["items"] == [] and body["count"] == 0
        assert body["catalog"]["stale"] is False   # a real "nothing new", provably fresh

    def test_window_boundary_inclusive(self, live):
        # 2026-09-20 is exactly 7 days before WATCH_TODAY; 2026-09-19 is 8.
        ids = _ids(client.get("/api/kev/watch?days=7").json())
        assert "CVE-2026-90002" in ids and "CVE-2026-90003" not in ids
        ids = _ids(client.get("/api/kev/watch?days=8").json())
        assert "CVE-2026-90003" in ids


class TestNotesLinks:
    def test_items_carry_notes_urls_and_advisory(self, live):
        items = {i["cve_id"]: i for i in client.get("/api/kev/watch?days=7").json()["items"]}
        asa = items["CVE-2026-90002"]
        assert asa["notes_urls"][0] == "https://www.cisa.gov/ed-26-03"
        assert len(asa["notes_urls"]) == 3
        assert asa["advisory_url"].endswith("/cisco-sa-asa-x")
        assert items["CVE-2026-90001"]["notes_urls"] == []
        assert items["CVE-2026-90001"]["advisory_url"] is None


class TestValidation:
    @pytest.mark.parametrize("days", ["0", "91", "-1", "abc"])
    def test_days_out_of_range(self, live, days):
        assert client.get(f"/api/kev/watch?days={days}").status_code == 422

    @pytest.mark.parametrize("days", ["1", "90"])
    def test_days_bounds_accepted(self, live, days):
        assert client.get(f"/api/kev/watch?days={days}").status_code == 200

    def test_too_many_vendors(self, live):
        vendors = ",".join(f"v{i}" for i in range(kev_watch.MAX_VENDORS + 1))
        assert client.get(f"/api/kev/watch?vendors={vendors}").status_code == 422

    def test_vendor_name_too_long(self, live):
        assert client.get("/api/kev/watch?vendors=" + "x" * 65).status_code == 422


class TestCacheAndStale:
    def test_fresh_disk_copy_is_cache_not_stale(self):
        _write_disk(time.time() - 60)
        cat = client.get("/api/kev/watch?days=7").json()["catalog"]
        assert cat["source"] == "cache"
        assert cat["stale"] is False

    def test_cisa_down_serves_last_good_copy_marked_stale(self, live):
        cached_at = datetime.datetime(2026, 9, 18, 12, 0, tzinfo=datetime.timezone.utc).timestamp()
        _write_disk(cached_at)
        live["raise"] = RuntimeError("CISA down")
        r = client.get("/api/kev/watch?days=14")
        assert r.status_code == 200
        body = r.json()
        assert live["n"] == 1
        assert body["catalog"]["stale"] is True
        assert body["catalog"]["source"] == "cache"
        assert body["catalog"]["fetched_at"] == "2026-09-18T12:00:00+00:00"
        assert body["catalog"]["catalog_version"] == "2026.09.27"
        assert body["count"] == 4

    def test_offline_with_old_disk_copy_is_stale(self):
        _write_disk(time.time() - kev_catalog.KEV_TTL_SECONDS - 60)
        body = client.get("/api/kev/watch?days=7").json()
        assert body["catalog"]["stale"] is True
        assert body["count"] == 3


class TestUnavailable:
    def test_no_catalog_at_all_is_503(self):
        r = client.get("/api/kev/watch?days=7")
        assert r.status_code == 503
        assert "not an empty result" in r.json()["detail"]

    def test_cisa_down_and_no_disk_is_503(self, live):
        live["raise"] = RuntimeError("CISA down")
        assert client.get("/api/kev/watch?days=7").status_code == 503


class TestCatalogStatus:
    def test_nothing_loaded(self):
        assert kev_catalog.catalog_status() == {
            "catalog_version": None, "date_released": None, "fetched_at": None,
            "source": None, "stale": True}

    def test_stale_threshold_is_ttl(self, live):
        kev_catalog.load_kev_index()
        fetched = kev_catalog._memo["fetched_at"]
        assert kev_catalog.catalog_status(now=fetched + kev_catalog.KEV_TTL_SECONDS)["stale"] is False
        assert kev_catalog.catalog_status(now=fetched + kev_catalog.KEV_TTL_SECONDS + 1)["stale"] is True


# ---------------------------------------------------------------------------
# KW-01.3: the KEV Watch tab. Static assets are whitelisted and wired in.
# ---------------------------------------------------------------------------

from api import main as api_main  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _web(name):
    with open(os.path.join(ROOT, "web", name), encoding="utf-8") as f:
        return f.read()


class TestKevWatchTab:
    def test_assets_are_whitelisted_and_served(self):
        assert "app-kev" in api_main.JS_FILES
        assert "style-kev" in api_main.CSS_FILES
        js = client.get("/app-kev.js")
        assert js.status_code == 200 and "loadKevWatch" in js.text
        css = client.get("/style-kev.css")
        assert css.status_code == 200 and ".kev-table" in css.text

    def test_index_wires_tab_and_assets(self):
        html = _web("index.html")
        assert 'data-tab="kev-watch"' in html
        assert 'id="tab-kev-watch"' in html
        assert 'src="app-kev.js' in html and 'href="style-kev.css' in html
        assert "https://netdevops.thebackroom.ai/patch-sheet/" in html

    def test_tab_is_free(self):
        assert '"kev-watch"' in _web("app-gate.js").split("FREE_TOOLS", 1)[1].split("]", 1)[0]

    def test_vendor_list_uses_exact_kev_names(self):
        js = _web("app-kev.js")
        for name in ("Cisco", "Fortinet", "Palo Alto Networks", "Juniper", "Arista", "F5",
                     "Check Point", "Citrix", "SonicWall", "Ivanti", "Zyxel", "MikroTik"):
            assert f'"{name}"' in js

    def test_no_em_dash_in_tab_text(self):
        html = _web("index.html")
        tab = html.split('id="tab-kev-watch"', 1)[1].split("</section>", 1)[0]
        for text in (tab, _web("app-kev.js")):
            assert "\u2014" not in text
