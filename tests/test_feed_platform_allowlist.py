"""HF-U1 (v0.6.67): the Threat Feed platform filter is a closed list.

Before, any slug matching ^[a-z0-9_-]{1,32}$ was accepted: `?platform=zzz`
returned 200 and started a background PSIRT pull for product "zzz" (up to five
pages against the shared 30/min limit) plus a cache/cisco/zzz.json file. Now
only the values of the Threat Feed dropdown are accepted; anything else is 400
before any PSIRT call or cache write.
"""

import os
import re

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.routers import cve as cve_router

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTES = ("/analyze/advisories", "/analyze/critical-feed")
UI_PLATFORMS = ["all", "iosxe", "ios", "nxos", "asa", "ftd", "ise"]

client = TestClient(app)


@pytest.fixture
def psirt(monkeypatch, tmp_path):
    """Record every path to PSIRT and keep the cache in a temp dir."""
    calls = {"provider": [], "latest": 0}

    class FakeProvider:
        def __init__(self, platform=None, *a, **kw):
            calls["provider"].append(platform)

        def _load_credentials(self):
            return None

        def load(self):
            raise AssertionError("PSIRT must not be called")

    def fake_latest():
        calls["latest"] += 1
        return []

    monkeypatch.setattr(cve_router, "CiscoAdvisoryProvider", FakeProvider)
    monkeypatch.setattr(cve_router, "_fetch_latest_advisories", fake_latest)
    monkeypatch.setattr(cve_router, "_load_latest_cache", lambda: ([], None))
    monkeypatch.setattr(cve_router, "_spawn", lambda target, *args: target(*args))
    monkeypatch.setattr(cve_router, "CISCO_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(cve_router, "_platform_refresh_failed_at", {})
    monkeypatch.setattr(cve_router, "_platform_refresh_running", set())
    calls["cache_dir"] = tmp_path
    return calls


def test_closed_list_matches_ui_dropdown():
    """One source of truth server-side; this keeps it in step with the UI."""
    html = open(os.path.join(REPO, "web", "index.html"), encoding="utf-8").read()
    m = re.search(r'<select id="cisco-advisories-platform"[^>]*>(.*?)</select>', html, re.S)
    assert m, "Threat Feed dropdown not found"
    ui_values = re.findall(r'<option value="([^"]*)"', m.group(1))
    assert ui_values == UI_PLATFORMS
    assert list(cve_router.FEED_PLATFORMS) == ui_values


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("platform", UI_PLATFORMS)
def test_ui_platforms_accepted(route, platform, psirt):
    r = client.get(route, params={"platform": platform})
    assert r.status_code == 200
    assert "items" in r.json()


def test_default_platform_is_all(psirt):
    for route in ROUTES:
        assert client.get(route).status_code == 200
    assert psirt["provider"] == []


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("platform", [
    "zzzrandom",
    "zzz",
    "xr",
    "iosxr",
    "fmc",
    "sdwan",
    "latest",
    "ALL",
    "IOSXE",
    "ios-xe",
    "ios_xe",
    "",
    " iosxe",
    "iosxe ",
])
def test_unknown_platform_rejected_without_psirt(route, platform, psirt):
    r = client.get(route, params={"platform": platform})
    assert r.status_code == 400
    assert psirt["provider"] == []
    assert psirt["latest"] == 0
    assert os.listdir(psirt["cache_dir"]) == []
    assert cve_router._platform_refresh_failed_at == {}
    assert cve_router._platform_refresh_running == set()
