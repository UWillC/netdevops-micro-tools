"""Third review of the day: free-text platform, KEV chip, hardening grouping, empty results."""
import os
import re

import pytest
from fastapi.testclient import TestClient

from api.main import app
from services.advisory_text import summarize_advisory_text
from services.cve_engine import ambiguous_release, severity_info

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
client = TestClient(app)


def _analyze(platform, version):
    r = client.post("/analyze/cve", json={"platform": platform, "version": version, "include_suggestions": True})
    assert r.status_code == 200, r.text
    return r.json()


# ---------- "bla bla bla" + 10.2(6) returned 322 IOS findings ----------

@pytest.mark.parametrize("platform,version,expected", [
    ("bla bla bla", "10.2(6)", True),
    ("Nexus9k-ish box", "9.3(10)", False),          # "nexus" is recognised -> NX-OS decides
    ("C93180YC-FX", "7.0(3)I7(9)", True),           # model name, NX-OS-shaped release
    ("Catalyst 2960", "15.2(7)E8", False),          # 15.x is classic IOS, never NX-OS
    ("WS-C3750", "12.2(55)SE12", False),
    ("ISR4451-X", "17.9.4a", False),                # IOS XE shape is unambiguous
    ("NX-OS", "10.2(6)", False),
    ("IOS", "10.2(6)", False),                      # the user said IOS; believe them
])
def test_ambiguous_release(platform, version, expected):
    assert ambiguous_release(platform, version) is expected


def test_unrecognised_platform_with_nxos_shaped_release_is_not_evaluated():
    data = _analyze("bla bla bla", "10.2(6)")
    assert data["matched"] == []
    assert data["coverage_note"].startswith("NOT EVALUATED") and "IOS or Cisco NX-OS" in data["coverage_note"]


def test_model_names_with_unambiguous_releases_still_work():
    assert len(_analyze("ISR4451-X", "17.9.4")["matched"]) > 10
    assert _analyze("ISR4451-X", "17.9.4")["coverage_note"] is None


# ---------- KEV chip ----------

def test_kev_from_the_live_catalog_reaches_the_card_chip():
    from models.cve_model import CVEEntry, CVEKevStatus
    cve = CVEEntry(cve_id="CVE-2024-20399", title="t", severity="medium", platforms=["NX-OS"],
                   affected={"min": "0", "max": "9"}, description="d", cvss_score=6.0, tags=["cisco-psirt", "nx-os"])
    assert severity_info(cve)["escalation_reason"] is None
    cve.kev = CVEKevStatus(date_added="2024-07-02", due_date="2024-07-23")
    assert severity_info(cve)["escalation_reason"] == "Listed in CISA KEV catalog"
    cve.tags = ["kev", "actively-exploited"]
    assert severity_info(cve)["escalation_reason"].count("Listed in CISA KEV catalog") == 1


# ---------- advisory summaries ----------

def test_summary_drops_boilerplate_and_ends_on_a_sentence():
    raw = ("<p>A vulnerability in X could allow Y. This vulnerability is due to Z.</p>"
           "<p>Cisco has released software updates that address this vulnerability. There are no workarounds that address this vulnerability.</p>"
           "<p>This advisory is available at the following link:https://sec.cloudapps.cisco.com/x</p>"
           "<p>This advisory is part of the August 2025 Cisco FXOS and NX-OS Software Security Advisory Bundled Publication. "
           "For a complete list of the advisories and links to them, see Cisco Event Response: whatever.</p>")
    out = summarize_advisory_text(raw)
    assert out == "A vulnerability in X could allow Y. This vulnerability is due to Z."
    long = summarize_advisory_text("A sentence about the bug. " * 80)
    assert len(long) <= 700 and long.endswith(".")


def test_nxos_descriptions_are_clean():
    import glob
    import json
    for path in glob.glob(os.path.join(ROOT, "cve_data/nx_os/cve-*.json")):
        d = json.load(open(path, encoding="utf-8"))["description"]
        assert "This advisory is available at" not in d and "Bundled Publication" not in d, path
        assert len(d) <= 705, path


# ---------- the page ----------

def _web(name):
    return open(os.path.join(ROOT, "web", name), encoding="utf-8").read()


def test_platform_is_a_select_of_covered_platforms_only():
    html = _web("index.html")
    form = html[html.index('id="cve-form"'):html.index('id="cve-form"') + 2500]
    assert '<select name="platform"' in form and 'type="text" name="platform"' not in form
    values = re.findall(r'<option value="([^"]+)"', form[:form.index("</select>")])
    assert values == ["IOS XE", "IOS", "NX-OS", "ISE"]
    from services.cve_engine import uncovered_family
    from services.platform_taxonomy import normalize_user_platform
    for v in values:
        assert normalize_user_platform(v) is not None and uncovered_family(v) is None, v


def test_every_option_example_is_a_release_the_engine_can_read():
    html = _web("index.html")
    for value, example in re.findall(r'<option value="([^"]+)" data-example="([^"]+)"', html):
        data = _analyze(value, example)
        assert not (data["coverage_note"] or "").startswith("NOT EVALUATED"), (value, example)


def test_empty_result_shows_the_coverage_note():
    js = _web("app-security.js")
    branch = js[js.index("data.matched.length === 0"):js.index("data.matched.length === 0") + 2200]
    assert "coverage_note" in branch and "Not evaluated" in branch


def test_report_separates_confirmed_from_unconfirmed_and_groups_hardening_releases():
    js = _web("app-security.js")
    for needle in ("confirmedItems", "unconfirmedItems", "ONE JOB", "NOT confirmed for your release",
                   "confirmed matches only"):
        assert needle in js, needle


def test_asset_cache_version_follows_the_app_version():
    """Scripts were served as ?v=0.6.29 through nineteen releases, so a browser
    could keep yesterday's JS against today's API."""
    from api.main import app as _app
    html = _web("index.html")
    versions = set(re.findall(r'\.(?:js|css)\?v=([0-9.]+)', html))
    assert versions == {_app.version}, (versions, _app.version)


def test_one_version_everywhere():
    from api.main import app as _app
    from api.routers import cve as cve_router
    from version import APP_VERSION
    assert _app.version == APP_VERSION == cve_router._APP_VERSION
    assert client.get("/meta/version").json()["version"] == APP_VERSION
    assert _analyze("IOS XE", "17.9.4")["provenance"]["tool_version"] == APP_VERSION
    assert re.match(r"^\d+\.\d+\.\d+$", APP_VERSION)
