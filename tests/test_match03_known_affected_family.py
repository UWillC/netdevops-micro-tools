"""
MATCH-03 (2026-10-25): "verified" / "exact hit" counts only the Known Affected
list of the queried family.

On the fully synced dataset 15 records reached an IOS XE 17.9.4 report with a
Known Affected list for classic IOS only (CVE-2012-0384, CVE-2011-3274/3282,
CVE-2012-1311, 11x OpenSSL March 2015). With no IOS XE list MATCH-01 falls back
to the 0.0.0-999 placeholder range, so they match; but data_confidence() and
matched_on_known_affected read ANY list, so the report said
"102 match(es) are an exact hit on your release" (truth: 87) and called those
15 "verified". Only the published-date heuristic kept them out of the
confirmed bucket.

Golden numbers (R3): the synced fixture is tests/fixtures/match03/ (how it is
built and why it holds 188 records only: build_fixture.py). A change in these
numbers must come with a deliberate fixture rebuild.
"""

import json
import os

import pytest

from api.routers import cve as cve_router
from api.routers.cve import CVEAnalyzeRequest, analyze_cve
from models.cve_model import CVEEntry
from services.cve_engine import data_confidence

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "match03", "iosxe_synced_17_9_4.json")

OTHER_FAMILY_ONLY = {
    "CVE-2012-0384", "CVE-2011-3274", "CVE-2011-3282", "CVE-2012-1311",
    # cisco-sa-20150320-openssl
    "CVE-2015-0207", "CVE-2015-0209", "CVE-2015-0285", "CVE-2015-0287",
    "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0290", "CVE-2015-0291",
    "CVE-2015-0292", "CVE-2015-0293", "CVE-2015-1787",
}


@pytest.fixture
def synced_dataset(monkeypatch, tmp_path):
    """Point the analyzer at the frozen synced IOS XE dataset."""
    with open(FIXTURE, encoding="utf-8") as f:
        records = json.load(f)["records"]
    data_dir = tmp_path / "ios_xe"
    data_dir.mkdir()
    for rec in records:
        (data_dir / f"{rec['cve_id'].lower()}.json").write_text(json.dumps(rec), encoding="utf-8")
    monkeypatch.setattr(cve_router, "data_dir_for_platform", lambda platform: str(data_dir))
    return records


def call(platform, version):
    return analyze_cve(CVEAnalyzeRequest(platform=platform, version=version))


def confirmed(report):
    return len(report.matched) - len(report.coverage_uncertain)


class TestGoldenNumbers:
    def test_synced_dataset_17_9_4(self, synced_dataset):
        r = call("IOS XE", "17.9.4")
        assert len(r.matched) == 188
        assert r.matched_on_known_affected == 87         # was 102
        assert confirmed(r) == 87
        assert len(r.coverage_uncertain) == 101
        quality = [v["confidence"] for v in r.data_quality.values()]
        assert quality.count("verified") == 87           # was 102

    def test_repository_dataset_17_9_4(self):
        r = call("IOS XE", "17.9.4")
        assert len(r.matched) == 71
        assert r.matched_on_known_affected == 66
        assert confirmed(r) == 66
        assert len(r.coverage_uncertain) == 5


class TestOtherFamilyList:
    def test_classic_ios_list_is_not_confirmation_for_ios_xe(self, synced_dataset, monkeypatch):
        # Without the published-date heuristic: the list itself must not confirm.
        monkeypatch.setattr(cve_router, "published_date_demoted_ids", lambda *a, **k: [])
        r = call("IOS XE", "17.9.4")
        matched = {c.cve_id for c in r.matched}
        assert OTHER_FAMILY_ONLY <= matched
        assert OTHER_FAMILY_ONLY <= set(r.coverage_uncertain)
        assert r.matched_on_known_affected == 87
        assert confirmed(r) == 87
        for cve_id in OTHER_FAMILY_ONLY:
            assert r.data_quality[cve_id]["confidence"] != "verified"
            assert "Known Affected" not in r.data_quality[cve_id]["rationale"]

    def test_classic_ios_query_on_the_ios_list_stays_verified(self, synced_dataset):
        r = call("IOS", "15.0(1)M")
        assert "CVE-2012-0384" in {c.cve_id for c in r.matched}
        dq = r.data_quality["CVE-2012-0384"]
        assert dq["confidence"] == "verified"
        assert "Known Affected" in dq["rationale"] and "ios" in dq["rationale"]
        assert "CVE-2012-0384" not in r.coverage_uncertain


class TestDataConfidenceFamily:
    def rec(self, known_affected):
        return CVEEntry(
            cve_id="CVE-X", title="t", severity="high", description="d", platforms=["IOS XE"],
            affected={"min": "0.0.0", "max": "999.999.999"}, fixed_in=None,
            known_affected=known_affected)

    def test_list_of_the_queried_family_verifies(self):
        assert data_confidence(self.rec({"ios-xe": ["17.9.4"]}), "ios-xe")["confidence"] == "verified"

    def test_list_of_another_family_does_not(self):
        info = data_confidence(self.rec({"ios": ["15.0(1)M"]}), "ios-xe")
        assert info["confidence"] != "verified"
        assert "Known Affected" not in info["rationale"]

    def test_rationale_names_only_the_queried_family(self):
        info = data_confidence(self.rec({"ios-xe": ["17.9.4"], "ios": ["15.0(1)M", "15.1(1)T"]}), "ios-xe")
        assert "1 releases across ios-xe" in info["rationale"]

    def test_no_family_keeps_the_family_agnostic_reading(self):
        assert data_confidence(self.rec({"ios": ["15.0(1)M"]}))["confidence"] == "verified"
