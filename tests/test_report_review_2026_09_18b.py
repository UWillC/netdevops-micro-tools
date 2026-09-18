"""Regressions from reading two production reports (IOS-XE 17.12.04, NX-OS 10.2(6))."""
import json
import os

import pytest
from fastapi.testclient import TestClient

from api.main import app
from services.cve_engine import CVEEngine, platform_coverage_note, uncovered_family
from services.platform_taxonomy import ProductFamily, normalize_user_platform

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
client = TestClient(app)


def _analyze(platform, version):
    r = client.post("/analyze/cve", json={"platform": platform, "version": version, "include_suggestions": True})
    assert r.status_code == 200, r.text
    return r.json()


# ---------- spelling must not switch the family filter off ----------

@pytest.mark.parametrize("text,family", [
    ("IOS-XE", ProductFamily.IOS_XE), ("ios_xe", ProductFamily.IOS_XE), ("IOSXE", ProductFamily.IOS_XE),
    ("Cisco IOS-XE", ProductFamily.IOS_XE), ("IOS XE", ProductFamily.IOS_XE),
    ("NX-OS", ProductFamily.NX_OS), ("nxos", ProductFamily.NX_OS), ("NX OS", ProductFamily.NX_OS),
    ("ASA", ProductFamily.ASA), ("FTD", ProductFamily.FTD), ("IOS-XR", ProductFamily.IOS_XR),
    ("iosxr", ProductFamily.IOS_XR), ("IOS", ProductFamily.IOS), ("ISE", ProductFamily.ISE),
])
def test_platform_spellings(text, family):
    assert normalize_user_platform(text) == family


@pytest.mark.parametrize("text", ["ISR4451-X", "Catalyst 9300", "C9300-48P", "casa", ""])
def test_models_and_lookalikes_stay_unrecognised(text):
    assert normalize_user_platform(text) is None


def test_ui_default_spelling_keeps_foreign_products_out():
    ids = {c["cve_id"] for c in _analyze("IOS-XE", "17.12.04")["matched"]}
    # SSM On-Prem, Unified CM IM&P, Access Point software
    assert not ids & {"CVE-2024-20419", "CVE-2024-20310", "CVE-2024-20265"}
    assert ids == {c["cve_id"] for c in _analyze("IOS XE", "17.12.4")["matched"]}


# ---------- a platform we hold no data for ----------

def test_nxos_is_not_evaluated_instead_of_matched_as_1990s_ios():
    data = _analyze("NX-OS", "10.2(6)")
    assert data["matched"] == []
    assert data["coverage_note"].startswith("NOT EVALUATED")
    assert "not vulnerable" in data["coverage_note"]
    assert data["recommended_upgrade"] is None


@pytest.mark.parametrize("platform", ["ASA", "FTD", "IOS XR", "Nexus", "Meraki"])
def test_other_uncovered_platforms(platform):
    assert uncovered_family(platform) is not None
    assert _analyze(platform, "9.18.4")["matched"] == []
    assert platform_coverage_note(platform)


@pytest.mark.parametrize("platform", ["IOS-XE", "IOS", "ISE", "ISR4451-X", "Catalyst 9800", "cEdge"])
def test_covered_or_unknown_platforms_carry_no_not_evaluated_note(platform):
    assert platform_coverage_note(platform) is None


# ---------- CVE-2025-20188: 17.12.4 is not on Cisco's list ----------

def test_wlc_cve_does_not_match_a_release_cisco_does_not_list():
    assert "CVE-2025-20188" not in {c["cve_id"] for c in _analyze("IOS-XE", "17.12.04")["matched"]}
    assert "CVE-2025-20188" in {c["cve_id"] for c in _analyze("IOS-XE", "17.12.3")["matched"]}


def test_no_record_for_another_vendors_cve():
    # CVE-2026-28775 is an IDC satellite receiver CVE; it was filed as Cisco IOS XE.
    assert not os.path.exists(os.path.join(ROOT, "cve_data/ios_xe/cve-2026-28775.json"))
    assert not os.path.exists(os.path.join(ROOT, "cve_mitigations/CVE-2026-28775.json"))


def test_advisory_ids_look_like_cisco_ids():
    """Offline guard. Real Cisco ids end in a random token or are date-stamped;
    the invented ones were plain readable slugs."""
    import glob
    import re
    shape = re.compile(r"cisco-sa-(\d{8}-[\w-]+|[\w-]*-[A-Za-z0-9]{6,12}|[\w-]+)$")
    readable_slug = re.compile(r"cisco-sa-[a-z]+(-[a-z]+)+$")
    bad = []
    for path in glob.glob(os.path.join(ROOT, "cve_data/*/cve-*.json")):
        rec = json.load(open(path, encoding="utf-8"))
        m = re.search(r"CiscoSecurityAdvisory/([^/?#\s]+)", rec.get("advisory_url") or "")
        if m and (readable_slug.match(m.group(1)) or not shape.match(m.group(1))):
            bad.append((rec["cve_id"], m.group(1)))
    # date-stamped legacy ids such as cisco-sa-20180129-asa1 are fine
    assert bad == [], bad


# ---------- audit script logic ----------

def test_audit_classification():
    import importlib.util
    spec = importlib.util.spec_from_file_location("audit", os.path.join(ROOT, "scripts/audit_advisory_refs.py"))
    audit = importlib.util.module_from_spec(spec); spec.loader.exec_module(audit)
    url = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
    assert audit.classify({"advisory_url": url + "cisco-sa-x-AbC123"}, ["cisco-sa-x-AbC123"]) is None
    assert "does not exist" in audit.classify({"advisory_url": url + "cisco-sa-radius-blast"}, ["cisco-sa-x-AbC123"])
    assert "does not know" in audit.classify({"advisory_url": url + "cisco-sa-x"}, None)
    assert "not a Cisco advisory" in audit.classify({"advisory_url": "https://example.com"}, ["cisco-sa-x-AbC123"])


# ---------- ordering and the same-train hint ----------

def test_confirmed_match_outranks_unconfirmed_in_the_same_bucket():
    from models.cve_model import CVEEntry
    def mk(cid, score):
        return CVEEntry(cve_id=cid, title="t", severity="critical", platforms=["IOS XE"],
                        affected={"min": "0", "max": "999"}, description="d", cvss_score=score)
    out = CVEEngine._sort_matched([mk("CVE-1", 10.0), mk("CVE-2", 9.1)], uncertain_ids={"CVE-1"})
    assert [c.cve_id for c in out] == ["CVE-2", "CVE-1"]


def test_recommendation_says_when_it_is_on_another_train():
    rec = _analyze("IOS-XE", "17.12.04")["recommended_upgrade"]
    assert rec.startswith("IOS XE 17.15.4a")
    assert "different train" in rec and "17.12 ends at 17.12.5c" in rec and "Software Checker" in rec


def test_no_train_hint_when_already_on_the_target_train():
    rec = _analyze("IOS-XE", "17.15.1")["recommended_upgrade"] or ""
    assert "different train" not in rec
