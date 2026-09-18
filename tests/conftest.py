"""
Suite-wide safety net (KEV-X, 2026-09-18).

Code under test can now reach the network to refresh the CISA KEV catalog. No
test should ever do that: it makes the suite slow, flaky, and dependent on a
third-party site. This fixture switches the fetch off for every test and points
the on-disk cache at a temp directory, so a developer's real cache/kev/ can
neither leak into assertions nor be overwritten by them.

Tests that need KEV data install their own index via the `kev_index` fixture.

Background: earlier the same day a feed test wandered into a live PSIRT branch
and auto-imported ~1000 advisories into cve_data/. Same class of mistake,
closed here by default instead of per test.
"""

import datetime

import pytest

from services import kev_catalog

# The day the ISE / KEV fixtures were written. The feed gives a KEV listing a
# ranking boost only for KEV_PRIORITY_WINDOW_DAYS after `date_added`; without a
# frozen clock every "KEV row is first" assertion in this suite would start
# failing on 2026-10-17 for no reason related to the code.
FROZEN_TODAY = datetime.date(2026, 9, 18)


@pytest.fixture(autouse=True)
def _kev_offline(monkeypatch, tmp_path):
    monkeypatch.setenv("KEV_CATALOG_OFFLINE", "1")
    monkeypatch.setattr(kev_catalog, "KEV_CACHE_DIR", str(tmp_path / "kev"))
    monkeypatch.setattr(kev_catalog, "KEV_CACHE_PATH", str(tmp_path / "kev" / "catalog.json"))
    kev_catalog.reset_for_tests()
    yield
    kev_catalog.reset_for_tests()


@pytest.fixture(autouse=True)
def _frozen_clock(monkeypatch):
    from api.routers import cve as cve_router
    monkeypatch.setattr(cve_router, "_today", lambda: FROZEN_TODAY)


@pytest.fixture
def kev_index(monkeypatch):
    """Install a fake KEV index: kev_index({"CVE-…": {"due_date": …}})."""
    def _install(records, version="2026.09.16"):
        index = {}
        for cve_id, rec in records.items():
            full = {"cve_id": cve_id, "date_added": None, "due_date": None,
                    "catalog_version": version, "directive": None, "ransomware": None}
            full.update(rec)
            index[cve_id] = full
        monkeypatch.setattr(kev_catalog, "load_kev_index", lambda force_refresh=False: index)
        return index
    return _install
