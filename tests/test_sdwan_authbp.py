"""
SDWAN-02.2 authbp (2026-10-26): the three CISA KEV CVEs of
cisco-sa-sdwan-authbp-qwCX8D4v (Critical advisory, rev 1.3.0, 2026-04-22) in
cve_data/sdwan_controllers/:

  CVE-2026-20122  Arbitrary File Overwrite     SIR High  KEV 2026-04-20
  CVE-2026-20128  Information Disclosure (DCA) SIR High  KEV 2026-04-20
  CVE-2026-20133  Information Disclosure       SIR High  KEV 2026-04-20

CVE-2026-20126 and CVE-2026-20129 (same advisory) are not in KEV and stay out.

Expected values are typed from the advisory's Fixed Software table and Details
text, not computed from the records, so a wrong record fails here:
  Earlier than 20.9 Migrate | 20.9 20.9.8.2 | 20.10 20.12.6.1 | 20.11 20.12.6.1
  20.12 20.12.5.3 / 20.12.6.1 | 20.13 / 20.14 / 20.15 20.15.4.2
  20.16 20.18.2.1 | 20.18 20.18.2.1 | no 26.x row
  CVE-2026-20128: "releases 20.18 and later are not affected".
Manager only ("These vulnerabilities affect Cisco Catalyst SD-WAN Manager").
"""
import json
import os

import pytest
from fastapi.testclient import TestClient

from api.main import app
from models.cve_model import CVEEntry
from services.cve_engine import match_sdwan_record

client = TestClient(app)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "cve_data", "sdwan_controllers")
SLUG = "cisco-sa-sdwan-authbp-qwCX8D4v"
AUTHBP = ["CVE-2026-20122", "CVE-2026-20128", "CVE-2026-20133"]
NOT_IN_KEV = ["CVE-2026-20126", "CVE-2026-20129"]


def _rec(cve_id):
    with open(os.path.join(DATA_DIR, cve_id.lower() + ".json"), encoding="utf-8") as f:
        return CVEEntry(**json.load(f))


def _analyze(platform, version):
    r = client.post("/analyze/cve", json={"platform": platform, "version": version})
    assert r.status_code == 200
    body = r.json()
    return [m["cve_id"] for m in body["matched"]], body


# --- records: facts from the advisory and the KEV catalog --------------------

@pytest.mark.parametrize("cve_id,cvss,vector,cwe,bugs", [
    ("CVE-2026-20122", 7.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L", "CWE-648",
     ["CSCws33584", "CSCws33586"]),
    ("CVE-2026-20128", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-257",
     ["CSCws33585"]),
    ("CVE-2026-20133", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-200",
     ["CSCws33583"]),
])
def test_record_facts(cve_id, cvss, vector, cwe, bugs):
    e = _rec(cve_id)
    assert e.cisco_sir == "High" and e.severity == "high"
    assert (e.cvss_score, e.cvss_vector, e.cwe) == (cvss, vector, cwe)
    assert e.advisory_url.endswith(SLUG)
    assert any(r.endswith("/csaf/%s.json" % SLUG) for r in e.references)
    assert e.affected_versions_raw == ["Cisco Bug ID " + b for b in bugs]
    assert (e.published, e.last_modified) == ("2026-02-25", "2026-04-22")
    assert e.kev.date_added == "2026-04-20" and e.kev.due_date == "2026-04-23"
    assert e.kev.directive == "ED 26-03" and e.kev.catalog_version == "2026.10.23"
    assert "actively-exploited" in e.tags
    assert all("controller" not in p.lower() and "validator" not in p.lower()
               and "vsmart" not in p.lower() and "vbond" not in p.lower() for p in e.platforms)


def test_cvss_source_conflict_is_named_in_the_record():
    # Details text vs CSAF/CNA score disagree; the other value is said, not dropped.
    assert "5.4" in _rec("CVE-2026-20122").description
    assert "AV:L/AC:H/PR:H" in _rec("CVE-2026-20128").description
    assert "6.5" in _rec("CVE-2026-20133").description


@pytest.mark.parametrize("cve_id", NOT_IN_KEV)
def test_non_kev_cves_of_the_advisory_stay_out(cve_id):
    assert not os.path.exists(os.path.join(DATA_DIR, cve_id.lower() + ".json"))


# --- per train (20122 and 20133 share the table) -----------------------------

TABLE = [
    ("17.2.4", True), ("20.6.3", True), ("20.8.1", True),     # earlier than 20.9 -> migrate
    ("20.9.8", True), ("20.9.8.2", False), ("20.9.9", False),
    ("20.10.1.2", True),                                       # 20.10 -> 20.12.6.1 (rev 1.2.0)
    ("20.11.1.2", True),
    ("20.12.4", True), ("20.12.5.2", True), ("20.12.5.3", False),
    ("20.12.6", True), ("20.12.6.1", False), ("20.12.8.2", False),
    ("20.13.1", True), ("20.14.1", True),                     # -> 20.15.4.2
    ("20.15.4.1", True), ("20.15.4.2", False),
    ("20.16.1", True),                                         # -> 20.18.2.1
    ("20.18.2", True), ("20.18.2.1", False), ("20.18.4.1", False),
    ("26.1.1", False), ("26.1.2.1", False),                    # newer than every train
]


@pytest.mark.parametrize("cve_id", ["CVE-2026-20122", "CVE-2026-20133"])
@pytest.mark.parametrize("version,affected", TABLE)
def test_20122_20133_per_train(cve_id, version, affected):
    assert match_sdwan_record(_rec(cve_id), version) is affected


@pytest.mark.parametrize("version,affected",
                         [(v, a) for v, a in TABLE if not v.startswith("20.18")] +
                         [("20.18.1", False), ("20.18.2", False)])   # 20.18+ not affected
def test_20128_per_train(version, affected):
    assert match_sdwan_record(_rec("CVE-2026-20128"), version) is affected


# --- API -------------------------------------------------------------------------

def test_manager_20_12_5_gets_all_three_authbp_cves():
    ids, body = _analyze("Catalyst SD-WAN Manager", "20.12.5")
    assert set(AUTHBP) <= set(ids)
    for m in body["matched"]:
        if m["cve_id"] in AUTHBP:
            assert m["kev"]["date_added"] == "2026-04-20"


@pytest.mark.parametrize("platform", ["vManage", "SD-WAN Manager", "Catalyst SD-WAN"])
def test_manager_names_and_unspecific_sd_wan_get_them_too(platform):
    ids, _ = _analyze(platform, "20.12.5")
    assert set(AUTHBP) <= set(ids)


@pytest.mark.parametrize("platform", ["Catalyst SD-WAN Controller", "Catalyst SD-WAN Validator",
                                      "vSmart", "vBond"])
def test_controller_and_validator_do_not_get_manager_only_cves(platform):
    ids, _ = _analyze(platform, "20.12.5")
    assert not set(AUTHBP) & set(ids)
    assert {"CVE-2026-20127", "CVE-2026-20182"} <= set(ids)


def test_manager_20_18_1_gets_20122_and_20133_but_not_20128():
    ids, _ = _analyze("Catalyst SD-WAN Manager", "20.18.1")
    assert {"CVE-2026-20122", "CVE-2026-20133"} <= set(ids)
    assert "CVE-2026-20128" not in ids


def test_manager_26_1_1_reports_the_20128_source_conflict():
    # The CSAF list of 20128 names 26.1.1; the advisory text says 20.18+ is not affected.
    ids, body = _analyze("Catalyst SD-WAN Manager", "26.1.1")
    assert not set(AUTHBP) & set(ids)
    assert "CVE-2026-20128" in body["cisco_source_conflicts"]
    assert "disagree" in body["coverage_note"]
    assert "Verify in Cisco Software Checker" in body["coverage_note"]


def test_manager_fixed_release_is_clean_for_authbp():
    ids, body = _analyze("Catalyst SD-WAN Manager", "20.12.6.1")
    assert not set(AUTHBP) & set(ids)
    assert not set(AUTHBP) & set(body["cisco_source_conflicts"])


def test_coverage_note_counts_from_records_and_no_longer_says_all_critical():
    _, body = _analyze("Catalyst SD-WAN Manager", "20.12.5")
    note = body["coverage_note"]
    assert "only 4 advisories" in note
    assert "6 in CISA KEV" in note
    assert "3 Critical, 3 High" in note
    assert "all rated Critical" not in note
    for cve_id in AUTHBP:
        assert cve_id in note


def test_cedge_release_does_not_reach_the_controller_dataset():
    # Regression: "Catalyst SD-WAN" + 17.x is a cEdge (IOS XE) query.
    ids, _ = _analyze("Catalyst SD-WAN", "17.9.4")
    assert not set(AUTHBP) & set(ids)
