"""
SDWAN-02.1 (2026-10-01): first batch of cve_data/sdwan_controllers/.

Three Cisco-Critical, CISA-KEV advisories for Catalyst SD-WAN Manager /
Controller / Validator, seeded from Cisco CSAF by
scripts/seed_sdwan_controllers_cve_data.py:
  CVE-2026-76504  cisco-sa-sdwan-webauth-xr8beuuU  (Manager only, KEV 2026-09-30)
  CVE-2026-20127  cisco-sa-sdwan-rpa-EHchtZk       (all three components)
  CVE-2026-20182  cisco-sa-sdwan-rpa2-v69WY2SW     (all three components)

Expected values below are read off each advisory's Fixed Software table, not
computed from the records, so a wrong record fails here.
"""
import glob
import json
import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from api.main import app
from models.cve_model import CVEEntry
from services.cve_engine import (
    CVEEngine, CVEEngineConfig, data_dir_for_platform, match_sdwan_record,
    sdwan_component, sdwan_fix_for_version,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "cve_data", "sdwan_controllers")
PATHS = sorted(glob.glob(os.path.join(DATA_DIR, "*.json")))
client = TestClient(app)


def _rec(cve_id):
    with open(os.path.join(DATA_DIR, cve_id.lower() + ".json"), encoding="utf-8") as f:
        return CVEEntry(**json.load(f))


def _ids(platform, version):
    r = client.post("/analyze/cve", json={"platform": platform, "version": version})
    assert r.status_code == 200
    return [m["cve_id"] for m in r.json()["matched"]], r.json()


# --- dataset integrity -------------------------------------------------------

def test_seed_matches_disk():
    out = subprocess.run([sys.executable, "scripts/seed_sdwan_controllers_cve_data.py", "--check"],
                         cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr


def test_dataset_has_the_three_kev_criticals():
    assert {os.path.basename(p) for p in PATHS} == {
        "cve-2026-76504.json", "cve-2026-20127.json", "cve-2026-20182.json"}


@pytest.mark.parametrize("path", PATHS, ids=[os.path.basename(p) for p in PATHS])
def test_record_shape(path):
    with open(path, encoding="utf-8") as f:
        e = CVEEntry(**json.load(f))
    assert e.product_families == ["sd-wan-controllers"]
    assert e.cisco_sir == "Critical" and e.severity == "critical"
    assert e.kev is not None and e.kev.catalog_version == "2026.09.30"
    assert "kev" in e.tags
    assert any("/csaf/" in r for r in e.references)
    for key, fix in e.first_fixed_version.fixes.items():
        assert key.startswith("sd-wan-controllers-")
        assert fix == "migrate" or fix[0].isdigit()


def test_controller_query_reads_its_own_directory():
    assert data_dir_for_platform("Catalyst SD-WAN Manager") == "cve_data/sdwan_controllers"
    assert data_dir_for_platform("Catalyst SD-WAN") == "cve_data/ios_xe"   # cEdge unchanged


# --- the DONE criterion ------------------------------------------------------

def test_manager_20_12_5_gets_76504_and_20127():
    ids, body = _ids("Catalyst SD-WAN Manager", "20.12.5")
    assert "CVE-2026-76504" in ids
    assert "CVE-2026-20127" in ids        # 20.12 table: 20.12.5.3 / 20.12.6.1
    assert body["coverage_note"].startswith("Catalyst SD-WAN Manager/Controller/Validator coverage")
    hit = next(m for m in body["matched"] if m["cve_id"] == "CVE-2026-76504")
    assert hit["kev"]["date_added"] == "2026-09-30"


def test_manager_20_12_8_2_does_not_get_76504():
    ids, body = _ids("Catalyst SD-WAN Manager", "20.12.8.2")
    assert "CVE-2026-76504" not in ids
    assert ids == []
    assert "never assumed clean" in body["coverage_note"]


# --- per train, CVE-2026-76504 -----------------------------------------------
# Earlier than 20.9 Migrate | 20.9 20.9.10.1 | 20.12 20.12.8.2 | 20.15 20.15.6.1
# 20.18 20.18.4.1 | 26.1 26.1.2.1 | 26.2 26.2.1

@pytest.mark.parametrize("version,affected", [
    ("20.6.3", True), ("20.8.1", True),            # earlier than 20.9 -> migrate
    ("20.9.10", True), ("20.9.10.1", False),
    ("20.10.1", True), ("20.11.1.2", True),        # not in the table, listed affected -> migrate
    ("20.12.8.1", True), ("20.12.8.2", False),
    ("20.15.6", True), ("20.15.6.1", False),
    ("20.16.1", True),
    ("20.18.4", True), ("20.18.4.1", False),
    ("26.1.2", True), ("26.1.2.1", False),
    ("26.2.0", True), ("26.2.1", False),
])
def test_76504_per_train(version, affected):
    assert match_sdwan_record(_rec("CVE-2026-76504"), version) is affected


# --- per train, CVE-2026-20127 -----------------------------------------------
# 20.9 20.9.8.2 | 20.11 20.12.6.1 | 20.12 20.12.5.3 / 20.12.6.1 | 20.13-20.15 20.15.4.2
# 20.16 20.18.2.1 | 20.18 20.18.2.1 | no 26.x row

@pytest.mark.parametrize("version,affected", [
    ("20.9.8", True), ("20.9.8.2", False),
    ("20.11.1.2", True),                           # fix only on 20.12
    ("20.12.4", True), ("20.12.5.2", True), ("20.12.5.3", False),
    ("20.12.6", True), ("20.12.6.1", False), ("20.12.7", False),
    ("20.15.4.1", True), ("20.15.4.2", False),
    ("20.18.2", True), ("20.18.2.1", False),
    ("26.1.1", False),                             # newer than every train in the table
])
def test_20127_per_train(version, affected):
    assert match_sdwan_record(_rec("CVE-2026-20127"), version) is affected


# --- per train, CVE-2026-20182 -----------------------------------------------
# 20.9 20.9.9.1 | 20.10/20.11 20.12.7.1 | 20.12 20.12.5.4 / 20.12.6.2 / 20.12.7.1
# 20.13/20.14 20.15.5.2 | 20.15 20.15.4.4 / 20.15.5.2 | 20.16/20.18 20.18.2.2 | 26.1 26.1.1.1

@pytest.mark.parametrize("version,affected", [
    ("20.9.9", True), ("20.9.9.1", False),
    ("20.12.5.3", True), ("20.12.5.4", False),
    ("20.12.6.1", True), ("20.12.6.2", False),     # sorts above 20.12.5.4, still affected
    ("20.12.7", True), ("20.12.7.1", False),
    ("20.15.4.3", True), ("20.15.4.4", False),
    ("20.15.5.1", True), ("20.15.5.2", False),
    ("20.18.2.1", True), ("20.18.2.2", False),
    ("26.1.1", True), ("26.1.1.1", False),
])
def test_20182_per_train(version, affected):
    assert match_sdwan_record(_rec("CVE-2026-20182"), version) is affected


# --- components and recommendation -------------------------------------------

@pytest.mark.parametrize("platform,component", [
    ("Catalyst SD-WAN Manager", "manager"), ("vManage", "manager"),
    ("Catalyst SD-WAN Controller", "controller"), ("vSmart", "controller"),
    ("Catalyst SD-WAN Validator", "validator"), ("vBond", "validator"),
])
def test_component_detection(platform, component):
    assert sdwan_component(platform) == component


def test_manager_only_advisory_not_reported_for_controller():
    ids, _ = _ids("vSmart", "20.12.5")
    assert "CVE-2026-76504" not in ids
    assert set(ids) == {"CVE-2026-20127", "CVE-2026-20182"}


def test_recommendation_is_the_highest_fix_on_the_train():
    _, body = _ids("Catalyst SD-WAN Manager", "20.12.5")
    assert body["recommended_upgrade"].startswith("20.12.8.2")
    assert "CVE-2026-76504" in body["recommended_upgrade"]


def test_recommendation_says_migrate_when_cisco_names_no_fix():
    _, body = _ids("Catalyst SD-WAN Manager", "20.6.3")
    assert body["recommended_upgrade"].startswith("No fixed release exists")


def test_migrate_value_is_returned_for_old_trains():
    assert sdwan_fix_for_version(_rec("CVE-2026-76504"), "19.2.4") == "migrate"


def test_unreadable_release_matches_nothing():
    eng = CVEEngine(config=CVEEngineConfig(data_dir="cve_data/sdwan_controllers"))
    eng.load_all()
    assert eng.match("Catalyst SD-WAN Manager", "latest") == []
