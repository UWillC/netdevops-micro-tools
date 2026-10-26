"""
SDWAN-02.2 N1 (2026-10-26): build numbers came out silently clean.

Cisco's CSAF affected lists name builds the Fixed Software tables never use
(scripts/seed_sdwan_controllers_cve_data.py docstring, read 2026-10-01):
  CVE-2026-76504: 20.9.10.1.01, 20.12.8.2.01, 20.15.6.1.01, 20.18.4.1.01,
                  26.1.2.1.01, 20.12.401
  CVE-2026-20127 and CVE-2026-20182: 20.12.401
Compared as numbers, 20.12.8.2.01 = (20,12,8,2,1) >= fix 20.12.8.2 and
20.12.401 = (20,12,401) > every 20.12.x fix, so all 6 (release, CVE) pairs
answered "not affected" with no conflict sentence. A build cannot be placed
before or after a fix from the table: such a release now gets None from
match_sdwan_record and is reported in cisco_source_conflicts with "Verify in
Cisco Software Checker". Never a match from guesswork, never "clean".

20.12.8.2 (the plain release) is deliberately NOT treated as the same release
as 20.12.8.2.01: Cisco's table calls 20.12.8.2 fixed for 76504 and its CSAF list
names 20.12.8.2.01 as affected. "Same result" applies to forms of one input.
"""
import json
import os

import pytest
from fastapi.testclient import TestClient

from api.main import app
from models.cve_model import CVEEntry
from services.cve_engine import CVEEngine, CVEEngineConfig, match_sdwan_record, sdwan_build_release

client = TestClient(app)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "cve_data", "sdwan_controllers")
KEV3 = ["CVE-2026-20127", "CVE-2026-20182", "CVE-2026-76504"]
# SDWAN-02.2 authbp (Manager only): a build past their fix (20.12.6.1) is not placeable either.
AUTHBP = ["CVE-2026-20122", "CVE-2026-20128", "CVE-2026-20133"]
MANAGER_KEV = sorted(KEV3 + AUTHBP)
N1_BUILDS = ["20.12.8.2.01", "20.12.401"]
# Every build the CSAF list of 76504 names (seed docstring).
CSAF_BUILDS_76504 = ["20.9.10.1.01", "20.12.8.2.01", "20.15.6.1.01", "20.18.4.1.01",
                     "26.1.2.1.01", "20.12.401"]


def _rec(cve_id):
    with open(os.path.join(DATA_DIR, cve_id.lower() + ".json"), encoding="utf-8") as f:
        return CVEEntry(**json.load(f))


def _analyze(platform, version):
    r = client.post("/analyze/cve", json={"platform": platform, "version": version})
    assert r.status_code == 200
    body = r.json()
    return [m["cve_id"] for m in body["matched"]], body


# --- shape detection ---------------------------------------------------------

@pytest.mark.parametrize("version", CSAF_BUILDS_76504 + ["Release 20.12.8.2.01", " 20.12.401 "])
def test_builds_are_detected(version):
    assert sdwan_build_release(version)


@pytest.mark.parametrize("version", [
    "20.12.5", "20.12.8.2", "20.9.10.1", "20.15.6.1", "26.1.2.1", "20.18.2.1",
    "20.12.5.4", "20.15.4.4", "20.9", "17.9.4a", "", "latest",
])
def test_ordinary_releases_are_not_builds(version):
    assert not sdwan_build_release(version)


# --- matcher: the 6 pairs from the backlog -----------------------------------

@pytest.mark.parametrize("version", N1_BUILDS)
@pytest.mark.parametrize("cve_id", KEV3)
def test_n1_pairs_are_unreadable_not_clean(cve_id, version):
    assert match_sdwan_record(_rec(cve_id), version) is None


@pytest.mark.parametrize("version", CSAF_BUILDS_76504)
def test_no_csaf_listed_build_is_clean_for_76504(version):
    assert match_sdwan_record(_rec("CVE-2026-76504"), version) is not False


def test_build_below_the_fix_still_matches():
    # A build of a release before the fix stays "affected": only the
    # "not affected" answer is withheld for builds.
    assert match_sdwan_record(_rec("CVE-2026-76504"), "20.12.5.01") is True
    assert match_sdwan_record(_rec("CVE-2026-76504"), "20.10.401") is True   # migrate train


def test_build_on_a_train_newer_than_the_table_is_unchanged():
    # 20127 has no 26.x row (newest train 20.18): same answer as for 26.1.2.1.
    rec = _rec("CVE-2026-20127")
    assert match_sdwan_record(rec, "26.1.2.1.01") is match_sdwan_record(rec, "26.1.2.1") is False


# --- API: reported, with "verify" --------------------------------------------

@pytest.mark.parametrize("version", N1_BUILDS)
def test_manager_build_is_reported_not_clean(version):
    ids, body = _analyze("Catalyst SD-WAN Manager", version)
    assert ids == []
    assert body["cisco_source_conflicts"] == MANAGER_KEV
    note = body["coverage_note"]
    assert "build number" in note
    assert "Verify in Cisco Software Checker" in note
    assert "disagree" not in note          # the S1 sentence (table names it fixed) does not apply


def test_controller_build_respects_the_component_filter():
    _, body = _analyze("Catalyst SD-WAN Controller", "20.12.401")
    assert body["cisco_source_conflicts"] == ["CVE-2026-20127", "CVE-2026-20182"]


def test_plain_fixed_release_is_not_the_build():
    ids, body = _analyze("Catalyst SD-WAN Manager", "20.12.8.2")
    assert ids == [] and body["cisco_source_conflicts"] == []
    assert "build number" not in body["coverage_note"]


def test_s1_conflict_sentence_still_used_for_plain_releases():
    _, body = _analyze("Catalyst SD-WAN Manager", "20.18.3")
    assert body["cisco_source_conflicts"] == ["CVE-2026-20182"]
    assert "disagree" in body["coverage_note"]
    assert "build number" not in body["coverage_note"]


# --- forms of one input = same result (MATCH-02 spirit) -----------------------

FORMS = {
    "20.12.8.2.01": ["20.12.8.2.01", " 20.12.8.2.01 ", "Release 20.12.8.2.01"],
    "20.12.401": ["20.12.401", " 20.12.401 ", "Release 20.12.401"],
}
PLATFORMS = ["Catalyst SD-WAN Manager", "vManage", "Catalyst SD-WAN", "Cisco SD-WAN Controllers"]


@pytest.mark.parametrize("build", N1_BUILDS)
def test_all_forms_and_platform_names_give_one_result(build):
    results = set()
    for platform in PLATFORMS:
        for form in FORMS[build]:
            ids, body = _analyze(platform, form)
            results.add((tuple(ids), tuple(body["cisco_source_conflicts"])))
    assert results == {((), tuple(MANAGER_KEV))}


def test_rematch_keeps_the_callers_build_state():
    eng = CVEEngine(config=CVEEngineConfig(data_dir="cve_data/sdwan_controllers"))
    eng.load_all()
    assert eng.match("Catalyst SD-WAN Manager", "20.12.401") == []
    assert sorted(eng.sdwan_unplaced_builds) == MANAGER_KEV
    eng._rematch("Catalyst SD-WAN Manager", "20.12.8.2")
    assert sorted(eng.sdwan_unplaced_builds) == MANAGER_KEV
    eng.match("Catalyst SD-WAN Manager", "20.12.8.2")
    assert eng.sdwan_unplaced_builds == []
