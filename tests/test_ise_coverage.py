"""
Full ISE coverage, admitted only where Cisco's data allows a check (ISE-04).

The flaw this closes. `ISE 3.4 Patch 3` reported "8 matched" from v0.6.31 to
v0.6.42. Cisco's publication of 2026-09-16 alone held 42 CVEs in 15 advisories;
the dataset had 8 CVEs from 3 of them and the report said nothing about being a
sample. Same query now: 54 CVEs, 17 of them Critical.

Admission rule. An ISE advisory is imported only when Cisco publishes a Known
Affected release list for it. All 25 ISE advisories of 2026 have one; none of
the 168 from 2013–2025 do. Importing those with a placeholder range would have
re-created, for ISE, the "100 of 104 matches are guesses" problem MATCH-01 had
just removed from IOS XE — so they are left out and every report says so.
"""

import json
import os

import pytest

import services.cisco_sync as cisco_sync
from services.cisco_sync import auto_sync_ise, build_ise_record
from services.ise_fixed_table import (
    MIGRATE, exploitation_confirmed_in_cvrf, fixes_as_paths, parse_ise_fixed_table,
    vulnerabilities_from_cvrf)
from services.known_affected import extract_known_affected, version_is_listed


def analyze(platform, version):
    from api.routers.cve import CVEAnalyzeRequest, analyze_cve
    return analyze_cve(CVEAnalyzeRequest(platform=platform, version=version))


class TestFixedTableParser:
    """Table text exactly as it appears, flattened, in the CVRF of 2026-09-16."""

    def test_plain_table(self):
        t = "Release First Fixed Release 3.1 3.1 Patch 12 3.2 3.2 Patch 11 3.3 3.3 Patch 12 3.4 3.4 Patch 7 3.51 3.5 Patch 4 1. Cisco ISE"
        assert parse_ise_fixed_table(t) == {"3.1": "3.1 Patch 12", "3.2": "3.2 Patch 11",
                                            "3.3": "3.3 Patch 12", "3.4": "3.4 Patch 7",
                                            "3.5": "3.5 Patch 4"}

    def test_footnote_digit_glued_to_the_train(self):
        """'3.12 3.1 Patch 12' is train 3.1 with footnote 2, not train 3.12."""
        assert parse_ise_fixed_table("First Fixed Release 3.12 3.1 Patch 12 3.53 3.5 Patch 4") == \
            {"3.1": "3.1 Patch 12", "3.5": "3.5 Patch 4"}

    def test_and_earlier_migrate_covers_older_trains(self):
        out = parse_ise_fixed_table("First Fixed Release 3.01 and earlier Migrate to fixed release. 3.1 3.1 Patch 12")
        assert out["3.0"] == MIGRATE and out["<3.0"] == MIGRATE and out["3.1"] == "3.1 Patch 12"

    def test_migrate_without_and_earlier_is_that_train_only(self):
        out = parse_ise_fixed_table("First Fixed Release 3.1 Migrate to a fixed release. 3.2 Migrate to a fixed release. 3.3 3.3 Patch 12")
        assert out == {"3.1": MIGRATE, "3.2": MIGRATE, "3.3": "3.3 Patch 12"}

    def test_not_vulnerable_rows_produce_nothing(self):
        out = parse_ise_fixed_table("First Fixed Release 3.1 and earlier Not vulnerable 3.2 3.2 Patch 11")
        assert out == {"3.2": "3.2 Patch 11"}

    def test_one_column_per_cve_keeps_the_highest_patch(self):
        """Anything lower would leave one of the CVEs open."""
        out = parse_ise_fixed_table("First Fixed Release 3.4 3.4 Patch 7 3.4 Patch 7 3.5 3.5 Patch 3 3.5 Patch 4 3.5 Patch 4")
        assert out == {"3.4": "3.4 Patch 7", "3.5": "3.5 Patch 4"}

    def test_unparseable_is_empty_not_a_guess(self):
        assert parse_ise_fixed_table("") == {}
        assert parse_ise_fixed_table("See the Cisco Software Checker.") == {}

    def test_paths(self):
        assert fixes_as_paths({"3.4": "3.4 Patch 7", "<3.0": MIGRATE}) == \
            {"ise-3.4": "3.4 Patch 7", "ise-<3.0": MIGRATE}


CVRF = """<?xml version="1.0"?><cvrfdoc xmlns="http://x/cvrf" xmlns:v="http://x/vuln">
<DocumentNotes><Note Title="Exploitation and Public Announcements">%s</Note></DocumentNotes>
<v:Vulnerability><v:Title>ERS API Authentication Bypass</v:Title><v:CVE>CVE-2026-76423</v:CVE>
<v:CVSSScoreSets><v:ScoreSetV3><v:BaseScoreV3>10.0</v:BaseScoreV3><v:VectorV3>CVSS:3.1/AV:N</v:VectorV3></v:ScoreSetV3></v:CVSSScoreSets></v:Vulnerability>
<v:Vulnerability><v:Title>SQL Injection</v:Title><v:CVE>CVE-2026-76426</v:CVE>
<v:CVSSScoreSets><v:ScoreSetV3><v:BaseScoreV3>4.9</v:BaseScoreV3><v:VectorV3>CVSS:3.1/AV:N/PR:H</v:VectorV3></v:ScoreSetV3></v:CVSSScoreSets></v:Vulnerability>
</cvrfdoc>"""


class TestCvrfDetails:
    def test_per_cve_scores_not_the_advisory_maximum(self):
        v = vulnerabilities_from_cvrf(CVRF % "x")
        assert v["CVE-2026-76423"]["cvss"] == 10.0 and v["CVE-2026-76426"]["cvss"] == 4.9
        assert v["CVE-2026-76426"]["title"] == "SQL Injection"

    def test_exploitation_needs_an_affirmative_statement(self):
        yes = "The Cisco PSIRT is aware of active exploitation of this vulnerability."
        no = "The Cisco PSIRT is not aware of any public announcements or malicious use of the vulnerability."
        assert exploitation_confirmed_in_cvrf(CVRF % yes) is True
        assert exploitation_confirmed_in_cvrf(CVRF % no) is False

    def test_broken_xml_is_not_fatal(self):
        assert vulnerabilities_from_cvrf("<broken") == {}
        assert exploitation_confirmed_in_cvrf("<broken") is False


def adv(adv_id="cisco-sa-ise-x", cves=("CVE-2026-1", "CVE-2026-2"), names=None, score="10.0"):
    names = names if names is not None else ["Cisco Identity Services Engine Software 3.4.0",
                                             "Cisco Identity Services Engine Software 3.4 Patch 1",
                                             "Cisco ISE Passive Identity Connector 3.4.0"]
    return {"advisoryId": adv_id, "advisoryTitle": "Cisco ISE Test Vulnerabilities", "sir": "Critical",
            "cvssBaseScore": score, "cves": list(cves), "cwe": ["CWE-20", "CWE-89"], "summary": "A&nbsp;B",
            "firstPublished": "2026-09-16T16:00:00", "lastUpdated": "2026-09-16T16:00:00",
            "publicationUrl": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/" + adv_id,
            "cvrfUrl": "https://sec.cloudapps.cisco.com/x.xml", "productNames": names}


DETAILS = {"fixes": {"ise-3.4": "3.4 Patch 2"}, "exploited": False,
           "vulnerabilities": {"CVE-2026-1": {"title": "One", "cvss": 10.0, "vector": "V1"},
                               "CVE-2026-2": {"title": "Two", "cvss": 4.9, "vector": "V2"}}}


class TestImporter:
    @pytest.fixture
    def ise_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cisco_sync, "ISE_DATA_DIR", str(tmp_path))
        return tmp_path

    def test_record_shape(self):
        r = build_ise_record("CVE-2026-2", adv(), DETAILS)
        assert r["title"] == "Two" and r["cvss_score"] == 4.9 and r["severity"] == "medium"
        assert r["cisco_sir"] == "Critical"                 # SIR kept, not used as severity
        assert r["cwe"] is None                             # multi-CVE: not knowable per CVE
        assert r["product_families"] == ["ise"] and r["bundle"] is None
        assert r["description"] == "A B"
        # ISE-PIC is filed with ISE, and "3.4.0" named by both is one release.
        assert r["known_affected"]["ise"] == ["3.4 Patch 1", "3.4.0"]

    def test_advisory_score_is_a_tagged_last_resort(self):
        r = build_ise_record("CVE-2026-2", adv(), {"vulnerabilities": {}})
        assert r["cvss_score"] == 10.0 and "cvss-advisory-level" in r["tags"]

    def test_single_cve_advisory_may_use_the_advisory_score_untagged(self):
        r = build_ise_record("CVE-2026-1", adv(cves=("CVE-2026-1",)), {"vulnerabilities": {}})
        assert "cvss-advisory-level" not in r["tags"] and r["cwe"] == "CWE-20"

    def test_no_release_list_no_record(self, ise_dir):
        """The admission rule. 168 of Cisco's 193 ISE advisories fall here."""
        nameless = adv(names=["Cisco Identity Services Engine Software "])
        assert auto_sync_ise([nameless], fetch_details=lambda a: DETAILS) == 0
        assert list(ise_dir.iterdir()) == []

    def test_imports_with_one_details_fetch_per_advisory(self, ise_dir):
        calls = []
        assert auto_sync_ise([adv()], fetch_details=lambda a: calls.append(1) or DETAILS) == 2
        assert calls == [1]
        assert json.loads((ise_dir / "cve-2026-2.json").read_text())["cvss_score"] == 4.9

    def test_existing_records_are_refreshed_not_refetched(self, ise_dir):
        auto_sync_ise([adv()], fetch_details=lambda a: DETAILS)
        calls = []
        revised = adv(names=["Cisco Identity Services Engine Software 3.4.0",
                             "Cisco Identity Services Engine Software 3.4 Patch 1",
                             "Cisco Identity Services Engine Software 3.4 Patch 2"])
        assert auto_sync_ise([revised], fetch_details=lambda a: calls.append(1) or DETAILS) == 0
        assert calls == []
        rec = json.loads((ise_dir / "cve-2026-1.json").read_text())
        assert "3.4 Patch 2" in rec["known_affected"]["ise"] and rec["title"] == "One"

    def test_details_failure_still_imports_without_inventing_a_fix(self, ise_dir):
        def boom(_):
            raise RuntimeError("cisco.com down")
        assert auto_sync_ise([adv()], fetch_details=boom) == 2
        rec = json.loads((ise_dir / "cve-2026-1.json").read_text())
        assert rec["first_fixed_version"] is None

    def test_no_ios_mitigation_templates_for_ise(self, ise_dir, tmp_path, monkeypatch):
        mit = tmp_path / "mit"
        mit.mkdir()
        monkeypatch.setattr(cisco_sync, "MITIGATION_DIR", str(mit))
        auto_sync_ise([adv()], fetch_details=lambda a: DETAILS)
        assert list(mit.iterdir()) == []


class TestIseReleaseSpellings:
    LISTED = ["3.4.0", "3.4 Patch 1", "3.1.0 p10", "1.1.1.268 Patch1"]

    @pytest.mark.parametrize("typed", ["3.4", "3.4.0", "ISE 3.4", "3.4.0.608", "3.4 Patch 1", "3.4P1",
                                       "3.1 Patch 10", "1.1.1 Patch 1"])
    def test_listed(self, typed):
        assert version_is_listed(typed, self.LISTED, "ise")

    @pytest.mark.parametrize("typed", ["3.4 Patch 2", "3.1 Patch 1", "3.5", "garbage", ""])
    def test_not_listed(self, typed):
        assert not version_is_listed(typed, self.LISTED, "ise")

    def test_ise_pic_is_filed_with_ise(self):
        out = extract_known_affected({"productNames": ["Cisco ISE Passive Identity Connector 3.4 Patch 1"]})
        assert out == {"ise": ["3.4 Patch 1"]}


class TestReport:
    def test_the_query_that_exposed_the_gap(self):
        r = analyze("ISE", "3.4 Patch 3")
        assert len(r.matched) == 54                                   # was 8
        assert sum(1 for c in r.matched if c.severity == "critical") == 17
        assert r.matched[0].cve_id == "CVE-2026-76460"
        assert r.recommended_upgrade.startswith("3.4 Patch 7")
        assert all(v["confidence"] == "verified" for v in r.data_quality.values())

    def test_every_ise_report_says_what_it_does_not_cover(self):
        note = analyze("ISE", "3.4 Patch 3").coverage_note
        assert "56 CVEs from 25 Cisco advisories" in note
        assert "NOT evaluated" in note and "Cisco Software Checker" in note
        assert analyze("ISE", "3.6").coverage_note == note        # even with 0 matches

    def test_other_platforms_carry_no_ise_note(self):
        assert analyze("IOS XE", "17.9.4").coverage_note is None

    def test_on_the_first_fixed_release_nothing_is_reported(self):
        for version in ("3.4 Patch 7", "3.5 Patch 4", "3.3 Patch 12"):
            r = analyze("ISE", version)
            assert r.matched == [] and r.recommended_upgrade is None, version

    def test_unpatched_build_string_is_not_mistaken_for_past_the_fix(self):
        """3.4.0.608: build 608 is not 'patch >= 7'."""
        assert len(analyze("ISE", "3.4.0.608").matched) == 56

    def test_unreadable_release_reports_nothing_and_excludes_nothing(self):
        r = analyze("ISE", "garbage")
        assert r.matched == [] and r.excluded_not_listed == []


class TestCiscoSourceConflicts:
    """30 of 217 (CVE, train) pairs: Cisco's release list includes exactly the
    release the advisory's own table names as first fixed. Each advisory states
    that PSIRT validates what is "documented in this advisory" — the table."""

    def test_the_table_wins_and_the_case_is_counted(self):
        r = analyze("ISE", "3.4 Patch 7")
        assert r.matched == []
        assert len(r.cisco_source_conflicts) == 8
        assert "CVE-2026-76431" in r.cisco_source_conflicts

    def test_no_conflict_below_the_fix(self):
        assert analyze("ISE", "3.4 Patch 6").cisco_source_conflicts == []

    def test_conflicts_are_never_also_matches(self):
        r = analyze("ISE", "3.5 Patch 3")
        assert r.cisco_source_conflicts
        assert not set(r.cisco_source_conflicts) & {c.cve_id for c in r.matched}
