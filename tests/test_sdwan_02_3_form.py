"""
SDWAN-02.3 (2026-11-06): SD-WAN in the CVE Analyzer form, one platform list,
and "NOT EVALUATED" for an SD-WAN answer with zero matches that is not clean.

Before: the form offered 4 platforms (no SD-WAN, which worked only through the
API) and the report text listed them in a separate hand-written string. With
zero matches the form said "No CVEs from the current dataset matched" in four
cases where nothing was really decided (wycena @cto 06.11, sekcja 4):
  1. a release that cannot be read ("abc"),
  2. a build the Fixed Software tables do not name (N1: 20.12.401, .01),
  3. Cisco's CSAF list and Fixed Software table disagree (S1: Controller 20.18.3),
  4. a train newer than every train in the dataset (27.1.1; rule 3 of
     match_sdwan_record says "not affected" about a train no advisory describes).
Now the coverage note starts with "NOT EVALUATED" in those cases, and the form's
existing orange "Not evaluated" branch (web/app-security.js) shows it.
"""
import os
import re

import pytest
from fastapi.testclient import TestClient

from api.main import app
from services.cve_engine import (
    COVERED_PLATFORMS, _COVERED_PLATFORMS_TEXT, data_dir_for_platform, platform_coverage_note,
)

client = TestClient(app)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANAGER_ALL = sorted(["CVE-2026-20122", "CVE-2026-20127", "CVE-2026-20128",
                      "CVE-2026-20133", "CVE-2026-20182", "CVE-2026-76504"])


def _analyze(platform, version):
    r = client.post("/analyze/cve", json={"platform": platform, "version": version})
    assert r.status_code == 200
    body = r.json()
    return sorted(m["cve_id"] for m in body["matched"]), body


def _form_select():
    with open(os.path.join(ROOT, "web", "index.html"), encoding="utf-8") as f:
        html = f.read()
    m = re.search(r'<select name="platform" id="cve-platform".*?</select>', html, re.S)
    assert m, "CVE Analyzer platform select not found"
    hint = re.search(r'id="cve-platform-hint"[^>]*>(.*?)</small>', html, re.S)
    assert hint, "CVE Analyzer platform hint not found"
    return m.group(0), hint.group(1)


# --- one platform list -------------------------------------------------------

def test_form_options_are_the_covered_platform_list():
    select, _ = _form_select()
    values = re.findall(r'<option value="([^"]+)"', select)
    assert values == [v for v, _ in COVERED_PLATFORMS]


def test_report_text_is_built_from_the_list():
    for _, name in COVERED_PLATFORMS:
        assert name in _COVERED_PLATFORMS_TEXT
    note = platform_coverage_note("ASA", "9.18.1")
    assert note.startswith("NOT EVALUATED")
    assert _COVERED_PLATFORMS_TEXT in note
    assert "Cisco Catalyst SD-WAN Manager" in note


def test_old_hand_written_list_is_gone():
    old = "Cisco IOS XE, Cisco IOS, Cisco NX-OS and Cisco ISE"
    hits = []
    for base in ("services", "api", "web"):
        for dirpath, _, files in os.walk(os.path.join(ROOT, base)):
            for fn in files:
                if fn.endswith((".py", ".js", ".html")):
                    with open(os.path.join(dirpath, fn), encoding="utf-8") as f:
                        if old in f.read():
                            hits.append(os.path.join(dirpath, fn))
    assert hits == []


def test_every_form_option_has_its_own_dataset_route_and_example():
    select, _ = _form_select()
    for value, example in re.findall(r'<option value="([^"]+)" data-example="([^"]+)"', select):
        assert example, value
        if value.startswith("Catalyst SD-WAN"):
            assert example == "20.12.5"
            assert data_dir_for_platform(value) == "cve_data/sdwan_controllers"


def test_hint_says_fmc_is_api_only():
    _, hint = _form_select()
    assert "FMC" in hint and "only through the API" in hint and "2 curated advisories" in hint
    assert "—" not in hint


# --- the form value gives the same answer as the API ------------------------

def test_manager_option_gives_the_api_answer():
    ids, body = _analyze("Catalyst SD-WAN Manager", "20.12.5")
    assert ids == MANAGER_ALL
    assert body["coverage_note"].startswith("Catalyst SD-WAN Manager/Controller/Validator coverage")


@pytest.mark.parametrize("platform", ["Catalyst SD-WAN Controller", "Catalyst SD-WAN Validator"])
def test_controller_and_validator_get_only_their_advisories(platform):
    ids, _ = _analyze(platform, "20.12.5")
    assert ids == ["CVE-2026-20127", "CVE-2026-20182"]


# --- NOT EVALUATED at zero matches -------------------------------------------

@pytest.mark.parametrize("version", ["abc", "latest", "n/a"])
def test_unreadable_release_is_not_evaluated(version):
    ids, body = _analyze("Catalyst SD-WAN Manager", version)
    assert ids == []
    assert body["coverage_note"].startswith("NOT EVALUATED")
    assert "could not be read" in body["coverage_note"]


@pytest.mark.parametrize("version", ["20.12.401", "20.12.8.2.01"])
def test_build_release_is_not_evaluated(version):
    ids, body = _analyze("Catalyst SD-WAN Manager", version)
    assert ids == []
    note = body["coverage_note"]
    assert note.startswith("NOT EVALUATED")
    assert "build" in note
    assert "Verify in Cisco Software Checker" in note        # N1 sentence kept


def test_csaf_conflict_with_zero_matches_is_not_evaluated():
    ids, body = _analyze("Catalyst SD-WAN Controller", "20.18.3")
    assert ids == []
    assert body["cisco_source_conflicts"] == ["CVE-2026-20182"]
    note = body["coverage_note"]
    assert note.startswith("NOT EVALUATED")
    assert "disagree" in note and "CVE-2026-20182" in note


def test_train_newer_than_the_dataset_is_not_evaluated():
    ids, body = _analyze("Catalyst SD-WAN Manager", "27.1.1")
    assert ids == []
    note = body["coverage_note"]
    assert note.startswith("NOT EVALUATED")
    assert "27.1" in note and "newest 26.2" in note


def test_conflict_with_other_matches_stays_a_normal_report():
    # Manager 20.18.3: 76504 matches, 20182 is a CSAF conflict. Not empty, so
    # the posture is computed and the note keeps its usual opening.
    ids, body = _analyze("Catalyst SD-WAN Manager", "20.18.3")
    assert "CVE-2026-76504" in ids
    assert "CVE-2026-20182" in body["cisco_source_conflicts"]
    assert body["coverage_note"].startswith("Catalyst SD-WAN Manager/Controller/Validator coverage")


@pytest.mark.parametrize("version", ["20.12.8.2", "26.2.1"])
def test_fixed_release_inside_the_data_is_not_flagged(version):
    # A plain release the tables place at or past every fix: the usual note,
    # which still says "never assumed clean" for advisories outside the dataset.
    ids, body = _analyze("Catalyst SD-WAN Manager", version)
    assert ids == []
    assert body["coverage_note"].startswith("Catalyst SD-WAN Manager/Controller/Validator coverage")
    assert "never assumed clean" in body["coverage_note"]


def test_new_text_has_no_em_dash():
    _, body = _analyze("Catalyst SD-WAN Manager", "27.1.1")
    head = body["coverage_note"].split("Catalyst SD-WAN Manager/Controller/Validator coverage")[0]
    assert "—" not in head


@pytest.mark.parametrize("platform,version", [
    ("IOS XE", "17.9.4a"), ("ISE", "3.4 Patch 5"), ("NX-OS", "10.2(6)"),
])
def test_other_platforms_never_get_the_sdwan_rule(platform, version):
    _, body = _analyze(platform, version)
    assert "Catalyst SD-WAN release" not in (body["coverage_note"] or "")
    assert "newer than every train" not in (body["coverage_note"] or "")


# --- @ciso W1 (06.11): newest train per component ---------------------------
# CVE-2026-76504 (the only record naming 26.2) is Manager only. Controller and
# Validator advisories stop at 26.1, so 26.2.x is not described for them.

@pytest.mark.parametrize("platform", ["Catalyst SD-WAN Controller", "Catalyst SD-WAN Validator"])
@pytest.mark.parametrize("version", ["26.2", "26.2.0", "26.2.1"])
def test_w1_controller_validator_26_2_is_not_evaluated(platform, version):
    ids, body = _analyze(platform, version)
    assert ids == []
    note = body["coverage_note"]
    assert note.startswith("NOT EVALUATED")
    assert "newest 26.1" in note


def test_w1_manager_26_2_1_keeps_the_usual_note():
    ids, body = _analyze("Catalyst SD-WAN Manager", "26.2.1")
    assert ids == []
    assert body["coverage_note"].startswith("Catalyst SD-WAN Manager/Controller/Validator coverage")


def test_w1_bare_catalyst_sdwan_26_2_1_keeps_the_usual_note():
    # All three components: newest train 26.2, so 26.2.1 is inside the data.
    ids, body = _analyze("Catalyst SD-WAN", "26.2.1")
    assert ids == []
    assert body["coverage_note"].startswith("Catalyst SD-WAN Manager/Controller/Validator coverage")


def test_w1_newest_train_per_component():
    from services.cve_engine import CVEEngine, CVEEngineConfig, sdwan_newest_train
    eng = CVEEngine(config=CVEEngineConfig(engine_version="0.3.7",
                                           data_dir="cve_data/sdwan_controllers"))
    eng.load_all()
    assert sdwan_newest_train(eng.cves) == (26, 2)
    assert sdwan_newest_train(eng.cves, "manager") == (26, 2)
    assert sdwan_newest_train(eng.cves, "controller") == (26, 1)
    assert sdwan_newest_train(eng.cves, "validator") == (26, 1)


# --- @ciso W2 (06.11): a release with no "N.N" token is not read as 20.0 ------

SDWAN_COMPONENTS = ["Catalyst SD-WAN Manager", "Catalyst SD-WAN Controller",
                    "Catalyst SD-WAN Validator"]


@pytest.mark.parametrize("platform", SDWAN_COMPONENTS)
@pytest.mark.parametrize("version", ["20", "20.", "20.x"])
def test_w2_unreadable_release_has_no_matches(platform, version):
    ids, body = _analyze(platform, version)
    assert ids == []
    note = body["coverage_note"]
    assert note.startswith("NOT EVALUATED")
    assert f'Release "{version}" could not be read' in note


@pytest.mark.parametrize("platform,expected", [
    ("Catalyst SD-WAN Manager", 6), ("Catalyst SD-WAN Controller", 2),
    ("Catalyst SD-WAN Validator", 2),
])
@pytest.mark.parametrize("version", ["20.12", "x20.12", "020.012.005"])
def test_w2_readable_releases_unchanged(platform, expected, version):
    ids, body = _analyze(platform, version)
    assert len(ids) == expected
    assert body["coverage_note"].startswith("Catalyst SD-WAN Manager/Controller/Validator coverage")
