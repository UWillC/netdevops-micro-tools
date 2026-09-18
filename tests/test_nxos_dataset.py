"""NX-OS-01: NX-OS as its own dataset, matched on Cisco's release lists only."""
import glob
import json
import os

import pytest
from fastapi.testclient import TestClient

from api.main import app
from services.cisco_sync import build_nxos_record
from services.known_affected import _nxos_key, extract_known_affected, version_is_listed

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
client = TestClient(app)
RECORDS = [json.load(open(p, encoding="utf-8")) for p in sorted(glob.glob(os.path.join(ROOT, "cve_data/nx_os/cve-*.json")))]


def _analyze(version, platform="NX-OS"):
    r = client.post("/analyze/cve", json={"platform": platform, "version": version, "include_suggestions": True})
    assert r.status_code == 200, r.text
    return r.json()


# ---------- release spelling ----------

@pytest.mark.parametrize("typed,canonical", [
    ("10.2(6)", "10.2(6)"), ("10.2.6", "10.2(6)"), ("10.2(6)M", "10.2(6)"), ("10.3(4a)F", "10.3(4a)"),
    ("NX-OS 10.2(6)", "10.2(6)"), ("Cisco NX-OS Software 9.3(10)", "9.3(10)"), (" 10.02(06) ", "10.2(6)"),
    ("7.0(3)I7(9)", "7.0(3)i7(9)"),
])
def test_release_spellings(typed, canonical):
    assert _nxos_key(typed) == canonical


@pytest.mark.parametrize("typed", ["", "garbage", "3.4 Patch 3", "17.9", "v10"])
def test_not_an_nxos_release(typed):
    assert _nxos_key(typed) == ""


def test_neighbouring_builds_are_different_releases():
    listed = ["7.0(3)I7(9)", "10.2(6)"]
    assert version_is_listed("7.0(3)I7(9)", listed, "nx-os")
    assert not version_is_listed("7.0(3)I7(10)", listed, "nx-os")
    assert not version_is_listed("10.2(60)", listed, "nx-os")
    assert not version_is_listed("10.2(6a)", listed, "nx-os")


# ---------- list extraction ----------

def test_aci_mode_images_are_a_separate_family():
    adv = {"productNames": ["Cisco NX-OS Software 10.2(6)", "Cisco NX-OS System Software in ACI Mode 14.2(1i)",
                            "Cisco NX-OS Software ", "Cisco IOS XE Software 17.9.4"]}
    ka = extract_known_affected(adv)
    assert ka["nx-os"] == ["10.2(6)"] and ka["nx-os-aci"] == ["14.2(1i)"] and ka["ios-xe"] == ["17.9.4"]


# ---------- dataset invariants ----------

def test_dataset_is_seeded_and_every_record_is_checkable():
    assert len(RECORDS) >= 280
    for r in RECORDS:
        assert r["product_families"] == ["nx-os"] and r["platforms"] == ["NX-OS"], r["cve_id"]
        assert r["known_affected"]["nx-os"], r["cve_id"]           # admission rule
        assert r["fixed_in"] is None, r["cve_id"]                  # Cisco gives none; we invent none
        assert "ciscosecurityadvisory/cisco-sa-" in r["advisory_url"].lower(), r["cve_id"]   # 2013 ids are "Cisco-SA-..."
        assert r["severity"] in ("critical", "high", "medium", "low")


def test_no_html_entities_or_tags_in_text():
    for r in RECORDS:
        for field in ("title", "description"):
            assert "&nbsp;" not in r[field] and "<p>" not in r[field], (r["cve_id"], field)


def test_builder_refuses_nothing_but_keeps_facts_straight():
    adv = {"advisoryId": "cisco-sa-x-AbCd1234", "advisoryTitle": "T", "summary": "<p>S&nbsp;x</p>", "sir": "High",
           "cvssBaseScore": "8.6", "cves": ["CVE-2030-0001", "CVE-2030-0002"], "cwe": ["CWE-20"],
           "publicationUrl": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-x-AbCd1234",
           "firstPublished": "2030-01-02T16:00:00", "productNames": ["Cisco NX-OS Software 10.2(6)", "Cisco NX-OS Software 9.3(10)"]}
    rec = build_nxos_record("CVE-2030-0001", adv, {"vulnerabilities": {"CVE-2030-0001": {"cvss": 5.3, "vector": "V", "title": "Per CVE"}}})
    assert rec["cvss_score"] == 5.3 and rec["title"] == "Per CVE" and "cvss-advisory-level" not in rec["tags"]
    assert rec["affected"] == {"min": "9.3", "max": "10.2"} and rec["cwe"] is None   # CWE is per advisory, 2 CVEs
    other = build_nxos_record("CVE-2030-0002", adv, {})
    assert other["cvss_score"] == 8.6 and "cvss-advisory-level" in other["tags"]      # advisory maximum, and says so
    assert "&nbsp;" not in other["description"] and "<p>" not in other["description"]


# ---------- the report ----------

def test_the_10_2_6_report():
    data = _analyze("10.2(6)")
    ids = [c["cve_id"] for c in data["matched"]]
    assert len(ids) == sum(1 for r in RECORDS if version_is_listed("10.2(6)", r["known_affected"]["nx-os"], "nx-os"))
    assert 10 <= len(ids) <= 40
    assert all(c["platforms"] == ["NX-OS"] for c in data["matched"])
    assert data["coverage_uncertain"] == []
    assert len(ids) + len(data["excluded_not_listed"]) == len(RECORDS)
    assert "CVE-2024-20399" in ids                                  # NX-OS CLI injection, listed for 10.2(6)
    # nothing from the old false report
    assert not [c for c in data["matched"] if "SD-WAN" in c["title"] or "cBR" in c["title"] or "ASR 9" in c["title"]]


def test_same_answer_for_every_spelling():
    base = {c["cve_id"] for c in _analyze("10.2(6)")["matched"]}
    for spelled, platform in [("10.2.6", "NX-OS"), ("10.2(6)M", "nxos"), ("10.2(6)", "Nexus"), ("10.2(6)", "Cisco NX-OS")]:
        assert {c["cve_id"] for c in _analyze(spelled, platform)["matched"]} == base


def test_report_names_no_upgrade_target_and_says_why():
    data = _analyze("10.2(6)")
    assert "Software Checker" in data["recommended_upgrade"] and "No target computed" in data["recommended_upgrade"]
    assert data["coverage_note"].startswith("NX-OS coverage:") and "ACI-mode" in data["coverage_note"]


def test_unreadable_release_reports_nothing_instead_of_ruling_everything_out():
    data = _analyze("garbage")
    assert data["matched"] == [] and data["excluded_not_listed"] == []


def test_ios_xe_queries_do_not_read_the_nxos_dataset():
    ids = {c["cve_id"] for c in _analyze("17.9.4", "IOS XE")["matched"]}
    nxos_only = {r["cve_id"] for r in RECORDS} - {os.path.basename(p)[:-5].upper() for p in glob.glob(os.path.join(ROOT, "cve_data/ios_xe/cve-*.json"))}
    assert not ids & nxos_only


def test_provenance_names_the_nxos_dataset():
    local = next(s for s in _analyze("10.2(6)")["provenance"]["sources"] if s["name"] == "local-json")
    assert "cve_data/nx_os" in local["description"] and local["file_count"] == len(RECORDS)


def test_provenance_age_does_not_depend_on_the_host_timezone():
    import time
    from services.provenance import _hours_since
    assert _hours_since(time.time() - 1800) == pytest.approx(0.5, abs=0.05)
