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


# FMC-FREE-TEXT (2026-09-27, variant b): FMC is its own family. These names
# used to map to FTD (NOT EVALUATED, v0.6.60); they now reach the FMC records
# and nothing else, with a coverage note in every FMC report.
@pytest.mark.parametrize("name", [
    "Cisco Secure Firewall Management Center", "Firewall Management Center",
    "Firepower Management Center", "Cisco Secure FMC", "Secure FMC", "FMC", "FMCv",
    "FMC 4600", "FMC4700", "FMC 1600", "FMC 2600", "FMC 1700", "FMC 2700",
    "FMCv300", "FMC1600-K9", "Cisco FMC 2600",
])
def test_fmc_product_names_are_recognised(name):
    assert normalize_user_platform(name) is ProductFamily.FMC


def test_ftd_stays_ftd_and_not_evaluated():
    assert normalize_user_platform("Cisco Secure Firewall Threat Defense") is ProductFamily.FTD
    data = _analyze("FTD", "7.6.4")
    assert data["matched"] == []
    assert data["coverage_note"].startswith("NOT EVALUATED")


def _analyze(platform, version):
    r = client.post("/analyze/cve", json={"platform": platform, "version": version,
                                          "include_suggestions": True})
    assert r.status_code == 200
    return r.json()


def _fmc_note_expected(engine):
    from services.cve_engine import is_fmc_record
    ids = sorted(c.cve_id for c in engine.cves if is_fmc_record(c))
    return ids, ("FMC coverage: only %d advisories in the dataset (%s). Everything else "
                 "for this platform is not evaluated, never assumed clean."
                 % (len(ids), ", ".join(ids)))


def test_fmc_records_are_exactly_the_two_curated_ones(engine):
    ids, _ = _fmc_note_expected(engine)
    assert ids == ["CVE-2026-20079", "CVE-2026-20131"]


@pytest.mark.parametrize("platform", ["FMC 4600", "Cisco Secure Firewall Management Center",
                                      "Firepower Management Center", "FMC"])
def test_fmc_764_is_exactly_the_two_fmc_cves_plus_note(engine, platform):
    """Was ("FMC 4600"): the 2 FMC CVEs + 16 IOS/NTP/OpenSSL ones, no note.
    Was (Cisco's product name, v0.6.60): NOT EVALUATED, 0 CVEs."""
    data = _analyze(platform, "7.6.4")
    assert {c["cve_id"] for c in data["matched"]} == {"CVE-2026-20079", "CVE-2026-20131"}
    _, note = _fmc_note_expected(engine)
    assert data["coverage_note"].startswith(note)
    assert "only 2 advisories" in data["coverage_note"]


def test_fmcv_766_is_empty_but_never_reads_clean(engine):
    data = _analyze("FMCv", "7.6.6")
    assert data["matched"] == []
    _, note = _fmc_note_expected(engine)
    assert data["coverage_note"].startswith(note)
    assert not data["coverage_note"].startswith("NOT EVALUATED")


def test_fmc_note_counts_from_the_data_not_a_constant():
    from services.cve_engine import fmc_coverage_note

    class R:
        def __init__(self, cid, url):
            self.cve_id, self.advisory_url, self.title = cid, url, "x"
            self.platforms, self.product_families = ["FMC"], []
    one = fmc_coverage_note([R("CVE-1", "u1")])
    assert "only 1 advisory in the dataset (CVE-1)" in one
    three = fmc_coverage_note([R("CVE-1", "u1"), R("CVE-2", "u2"), R("CVE-3", "u2")])
    assert "only 2 advisories in the dataset (CVE-1, CVE-2, CVE-3)" in three
    assert "nothing was evaluated" in fmc_coverage_note([])


def test_fmc_note_has_no_em_dash(engine):
    from services.cve_engine import fmc_coverage_note
    assert "\u2014" not in fmc_coverage_note(engine.cves)
    assert "\u2014" not in fmc_coverage_note([])


def test_fmc_family_never_admits_other_families(engine):
    for version in ("7.6.4", "7.0.1", "6.4.0.13", "10.0.0", "15.2.4", "17.9.4"):
        ids = {c.cve_id for c in engine.match("FMC 4600", version)}
        assert ids <= {"CVE-2026-20079", "CVE-2026-20131"}, (version, ids)


def test_fmc_records_stay_out_of_ios_xe(engine):
    for version in ("7.6.4", "17.9.4", "16.12.4"):
        ids = {c.cve_id for c in engine.match("IOS XE", version)}
        assert not ids & {"CVE-2026-20079", "CVE-2026-20131"}, version


def test_api_fmc_model_764_reports_both_kev_criticals():
    ids = {c["cve_id"] for c in _analyze("FMC 4600", "7.6.4")["matched"]}
    assert ids == {"CVE-2026-20079", "CVE-2026-20131"}


def test_asa_2018_0101_uses_cisco_rev_2_4_fixes(engine):
    d = _record("CVE-2018-0101")
    fixes = d["first_fixed_version"]["fixes"]
    assert fixes["asa-9.8"] == "9.8.2.20"              # record used to say 9.8.2.14
    assert "9.8.2.14" not in d["workaround"]
    rec = next(c for c in engine.cves if c.cve_id == "CVE-2018-0101")
    assert train_fix_for_version(rec, "9.8.2.14") == "9.8.2.20"
