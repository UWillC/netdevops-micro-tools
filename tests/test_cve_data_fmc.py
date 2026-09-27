"""CVE-DATA-FMC (2026-09-27): FMC CVE-2026-20079 / 20131 fixed per train.

The records said fixed_in "7.6.0.1" (a release Cisco's Software Checker does
not know) with affected.max "7.6.0", so FMC 7.6.1-7.6.5 read as fixed while
Cisco lists them as affected by two CVSS 10 KEV bugs. Source of the tables
below: Cisco CSAF (20079 rev 2.6 2026-09-16, 20131 rev 1.2 2026-03-25) and
openVuln OSType/fmc firstFixes, read 2026-09-27.
"""
import json
import os

import pytest
from fastapi.testclient import TestClient

from api.main import app
from services.cve_engine import CVEEngine, train_fix_for_version
from services.platform_taxonomy import ProductFamily, normalize_user_platform

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
client = TestClient(app)

FMC_20079 = {"7.0": "7.0.10", "7.2": "7.2.12", "7.3": "7.4.8", "7.4": "7.4.8",
             "7.6": "7.6.6", "7.7": "7.7.13", "10.0": "10.0.2", "10.1": "10.1.0"}
FMC_20131 = {"7.0": "7.0.9", "7.2": "7.2.11", "7.3": "7.4.6", "7.4": "7.4.6",
             "7.6": "7.6.5", "7.7": "7.7.12", "10.0": "10.0.1"}


def _record(cve):
    with open(os.path.join(ROOT, "cve_data", "ios_xe", "%s.json" % cve.lower())) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def engine():
    e = CVEEngine()
    e.load_all()
    return e


def _ids(engine, platform, version):
    return {c.cve_id for c in engine.match(platform, version)}


@pytest.mark.parametrize("cve,table", [("CVE-2026-20079", FMC_20079), ("CVE-2026-20131", FMC_20131)])
def test_record_carries_cisco_per_train_table(cve, table):
    d = _record(cve)
    assert d["fixed_in"] is None                       # no single release is "the" fix
    fixes = d["first_fixed_version"]["fixes"]
    assert {k[len("fmc-"):]: v for k, v in fixes.items()} == table
    assert "7.6.0.1" not in json.dumps(d)
    assert any("/csaf/" in r for r in d["references"])
    assert "no workarounds" in d["workaround"].lower()   # Cisco: none


@pytest.mark.parametrize("platform", ["FMC 4600", "FMCv"])
@pytest.mark.parametrize("version,vuln_79,vuln_131", [
    ("7.6.0", True, True),
    ("7.6.0.1", True, True),     # the old "fix"
    ("7.6.1", True, True),
    ("7.6.4", True, True),       # the reported case
    ("7.6.5", True, False),      # 20131 fixed in 7.6.5, 20079 not until 7.6.6
    ("7.6.6", False, False),
    ("7.4.5", True, True),
    ("7.4.7", True, False),
    ("7.4.8", False, False),
    ("7.3.1.2", True, True),     # no 7.3 fix: migrate to 7.4.x
    ("7.1.0.3", True, True),     # no row for 7.1 -> range keeps it affected
    ("7.7.12", True, False),
    ("7.7.13", False, False),
    ("10.0.0", True, True),
    ("10.0.1", True, False),
    ("10.0.2", False, False),
    ("6.4.0.13", True, True),    # 20131 lists 6.4.0.13-18; 20079: "7.0 and earlier"
])
def test_fmc_release_matching(engine, platform, version, vuln_79, vuln_131):
    ids = _ids(engine, platform, version)
    assert ("CVE-2026-20079" in ids) is vuln_79, (version, ids)
    assert ("CVE-2026-20131" in ids) is vuln_131, (version, ids)


def test_train_fix_lookup_ignores_ise_and_missing_trains(engine):
    rec = next(c for c in engine.cves if c.cve_id == "CVE-2026-20079")
    assert train_fix_for_version(rec, "7.6.4") == "7.6.6"
    assert train_fix_for_version(rec, "7.1.0") is None
    assert train_fix_for_version(rec, "garbage") is None


@pytest.mark.parametrize("name", [
    "Cisco Secure Firewall Management Center", "Firewall Management Center",
    "Firepower Management Center", "Cisco Secure FMC", "FMC",
    "Cisco Secure Firewall Threat Defense",
])
def test_fmc_product_names_are_recognised(name):
    assert normalize_user_platform(name) is ProductFamily.FTD


def test_cisco_product_name_is_not_evaluated_instead_of_false_clean():
    """Was: 104 unrelated IOS/NTP/OpenSSL CVEs, neither FMC KEV bug, no note."""
    r = client.post("/analyze/cve", json={"platform": "Cisco Secure Firewall Management Center",
                                          "version": "7.6.4", "include_suggestions": True})
    data = r.json()
    assert data["matched"] == []
    assert data["coverage_note"].startswith("NOT EVALUATED")


def test_api_fmc_model_764_reports_both_kev_criticals():
    r = client.post("/analyze/cve", json={"platform": "FMC 4600", "version": "7.6.4",
                                          "include_suggestions": True})
    ids = {c["cve_id"] for c in r.json()["matched"]}
    assert {"CVE-2026-20079", "CVE-2026-20131"} <= ids


def test_asa_2018_0101_uses_cisco_rev_2_4_fixes(engine):
    d = _record("CVE-2018-0101")
    fixes = d["first_fixed_version"]["fixes"]
    assert fixes["asa-9.8"] == "9.8.2.20"              # record used to say 9.8.2.14
    assert "9.8.2.14" not in d["workaround"]
    rec = next(c for c in engine.cves if c.cve_id == "CVE-2018-0101")
    assert train_fix_for_version(rec, "9.8.2.14") == "9.8.2.20"
