"""
SDWAN-02.1 fixes after the @ciso review (2026-10-01).

K1  "Catalyst SD-WAN" / "SD-WAN Control Components" with a 20.x / 26.x release
    went to the IOS XE dataset and a stale cEdge-shaped CVE-2026-20127 record
    (20.6.1-20.18.1, fixed 20.18.2.1, no KEV): 20.18.2.1 looked clean of 76504
    and 20182 with no coverage note, 20.12.8.2 got a false 20127. Now routed to
    the controller dataset (all components); cEdge 17.x unchanged; the stale
    record is gone and cannot be re-imported as IOS XE.
K2  "Cisco SD-WAN Controllers" (plural, Cisco's old name for all three) was read
    as vSmart only, so Manager 20.12.5 lost CVE-2026-76504.
S1  Releases Cisco's CSAF affected list names although the Fixed Software table
    calls them fixed are reported in cisco_source_conflicts with "Verify in
    Cisco Software Checker", never silently clean.
"""
import json
import os

import pytest
from fastapi.testclient import TestClient

import services.cisco_sync as cisco_sync
from api.main import app
from services.cve_engine import (SDWAN_ALL_COMPONENTS, data_dir_for_platform,
                                 sdwan_component, sdwan_effective_platform)
from services.platform_taxonomy import ProductFamily, normalize_user_platform

client = TestClient(app)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _analyze(platform, version):
    r = client.post("/analyze/cve", json={"platform": platform, "version": version})
    assert r.status_code == 200
    body = r.json()
    return [m["cve_id"] for m in body["matched"]], body


# --- K1 ----------------------------------------------------------------------

def test_catalyst_sdwan_20_18_2_1_is_a_controller_answer():
    ids, body = _analyze("Catalyst SD-WAN", "20.18.2.1")
    assert set(ids) == {"CVE-2026-76504", "CVE-2026-20182"}   # 20127 fixed in 20.18.2.1
    assert body["coverage_note"].startswith("Catalyst SD-WAN Manager/Controller/Validator coverage")
    assert body["platform"] == "Catalyst SD-WAN"                # echo what the user typed


def test_catalyst_sdwan_20_12_8_2_no_false_20127():
    ids, body = _analyze("Catalyst SD-WAN", "20.12.8.2")
    assert "CVE-2026-20127" not in ids
    assert ids == []
    assert "never assumed clean" in body["coverage_note"]


@pytest.mark.parametrize("platform", [
    "Catalyst SD-WAN", "Cisco Catalyst SD-WAN", "SD-WAN", "Cisco SD-WAN",
    "SD-WAN Control Components", "Catalyst SD-WAN Control Components",
])
@pytest.mark.parametrize("version", ["20.12.5", "26.1.1"])
def test_unspecific_sdwan_with_controller_release_goes_to_controllers(platform, version):
    eff = sdwan_effective_platform(platform, version)
    assert normalize_user_platform(eff) == ProductFamily.SDWAN_CONTROLLERS
    assert data_dir_for_platform(eff) == "cve_data/sdwan_controllers"
    assert sdwan_component(eff) is None                         # all three components


@pytest.mark.parametrize("platform,version", [
    ("Catalyst SD-WAN", "17.9.4a"), ("Catalyst SD-WAN", "17.12.3"),
    ("cEdge", "20.12.5"), ("Cisco IOS XE SD-WAN", "20.12.5"), ("IOS XE SD-WAN", "17.9.4"),
    ("vEdge", "20.9.1"), ("IOS XE", "17.9.4a"), ("ISE", "3.4 Patch 5"),
])
def test_cedge_and_others_unchanged(platform, version):
    assert sdwan_effective_platform(platform, version) == platform


def test_catalyst_sdwan_17x_stays_on_ios_xe():
    ids, body = _analyze("Catalyst SD-WAN", "17.9.4a")
    assert not {"CVE-2026-76504", "CVE-2026-20182", "CVE-2026-20127"} & set(ids)
    assert not (body["coverage_note"] or "").startswith("Catalyst SD-WAN Manager")


def test_stale_ios_xe_20127_record_is_gone():
    assert not os.path.exists(os.path.join(ROOT, "cve_data", "ios_xe", "cve-2026-20127.json"))


def test_cve_lookup_finds_controller_records_locally():
    for cve_id in ("CVE-2026-20127", "CVE-2026-76504", "CVE-2026-20182"):
        r = client.get("/analyze/cve/" + cve_id).json()
        assert r["found"] is True
        assert r["entry"]["product_families"] == ["sd-wan-controllers"]


def test_sync_never_recreates_a_controller_cve_as_ios_xe(tmp_path, monkeypatch):
    data, mit = tmp_path / "cve", tmp_path / "mit"
    data.mkdir(); mit.mkdir()
    (mit / "CVE-2026-20127.json").write_text("{}", encoding="utf-8")  # no network for mitigation
    monkeypatch.setattr(cisco_sync, "CVE_DATA_DIR", str(data))
    monkeypatch.setattr(cisco_sync, "MITIGATION_DIR", str(mit))
    adv = {"advisoryId": "cisco-sa-sdwan-rpa-EHchtZk", "advisoryTitle": "Cisco Catalyst SD-WAN",
           "sir": "Critical", "cvssBaseScore": "10.0", "cves": ["CVE-2026-20127"], "cwe": ["CWE-287"],
           "summary": "s", "firstPublished": "2026-02-25", "lastUpdated": "2026-06-16",
           "publicationUrl": "https://sec.cloudapps.cisco.com/x", "productNames": ["Cisco SD-WAN"]}
    assert cisco_sync.auto_sync_new_cves([adv]) == 0
    assert not (data / "cve-2026-20127.json").exists()


# --- K2 ----------------------------------------------------------------------

@pytest.mark.parametrize("platform", [
    "Cisco SD-WAN Controllers", "Catalyst SD-WAN Controllers", "SD-WAN Control Components",
])
def test_plural_and_control_components_name_no_single_component(platform):
    assert sdwan_component(platform) is None


@pytest.mark.parametrize("platform,component", [
    ("Catalyst SD-WAN Controller", "controller"), ("vSmart", "controller"),
    ("Catalyst SD-WAN Manager", "manager"), ("vManage", "manager"),
    ("Catalyst SD-WAN Validator", "validator"), ("vBond", "validator"),
])
def test_singular_names_still_pick_their_component(platform, component):
    assert sdwan_component(platform) == component


def test_cisco_sdwan_controllers_20_12_5_gets_76504():
    ids, _ = _analyze("Cisco SD-WAN Controllers", "20.12.5")
    assert "CVE-2026-76504" in ids
    assert {"CVE-2026-20127", "CVE-2026-20182"} <= set(ids)


def test_singular_controller_still_has_no_manager_only_cve():
    ids, _ = _analyze("Catalyst SD-WAN Controller", "20.12.5")
    assert "CVE-2026-76504" not in ids


# --- S1 ----------------------------------------------------------------------

@pytest.mark.parametrize("version", [
    "20.9.9.2", "20.12.5.4", "20.12.7.2", "20.15.4.5", "20.15.5.2", "20.15.5.3",
    "20.18.2.2", "20.18.3",
])
def test_20182_list_vs_table_conflict_is_reported(version):
    ids, body = _analyze("Catalyst SD-WAN Manager", version)
    assert "CVE-2026-20182" not in ids
    assert "CVE-2026-20182" in body["cisco_source_conflicts"]
    assert "Verify in Cisco Software Checker" in body["coverage_note"]


def test_20127_list_vs_table_conflict_is_reported():
    ids, body = _analyze("Catalyst SD-WAN Manager", "20.9.9")
    assert "CVE-2026-20127" not in ids
    assert body["cisco_source_conflicts"] == ["CVE-2026-20127"]
    assert "CVE-2026-20127" in body["coverage_note"]


def test_manager_20_18_3_reports_20182_conflict_and_matches_76504():
    ids, body = _analyze("Catalyst SD-WAN Manager", "20.18.3")
    assert ids == ["CVE-2026-76504"]
    assert body["cisco_source_conflicts"] == ["CVE-2026-20182"]


@pytest.mark.parametrize("version", ["20.12.8.2", "20.18.4.1", "20.12.7.1", "20.15.4.4"])
def test_release_without_conflict_gets_no_conflict_sentence(version):
    _, body = _analyze("Catalyst SD-WAN Manager", version)
    assert body["cisco_source_conflicts"] == []
    assert "disagree" not in body["coverage_note"]


def test_conflicts_respect_the_component_filter():
    # 20182 affects all three components, so a Validator query gets the note too.
    _, body = _analyze("Catalyst SD-WAN Validator", "20.18.3")
    assert body["cisco_source_conflicts"] == ["CVE-2026-20182"]


def test_seed_lists_are_on_disk():
    with open(os.path.join(ROOT, "cve_data", "sdwan_controllers", "cve-2026-20182.json")) as f:
        assert "20.18.3" in json.load(f)["csaf_listed_past_fix"]
    with open(os.path.join(ROOT, "cve_data", "sdwan_controllers", "cve-2026-76504.json")) as f:
        assert json.load(f)["csaf_listed_past_fix"] == []
