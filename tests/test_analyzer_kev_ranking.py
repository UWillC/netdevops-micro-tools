"""
KEV ranking in the analyzer respects match confidence (v0.6.39).

Regression from v0.6.35 (KEV-X). Stamping KEV status from the live CISA catalog
made `_sort_matched` lift every KEV CVE to the top. On an IOS XE 17.9.4 report
that put nine 2017 SNMP CVEs — imported with a 0.0.0–999 placeholder range,
i.e. matched on almost nothing — above a verified CVSS 10.0.

"This CVE is in KEV" is a fact about the CVE. The top of the report claims
something more: that it affects *your version*. The boost now needs both.
"""

from models.cve_model import CVEAffectedRange, CVEEntry, CVEKevStatus
from services.cve_engine import CVEEngine

KEV = CVEKevStatus(date_added="2022-03-03", due_date="2022-03-24")


def cve(cve_id, severity, kev=None, tags=None):
    return CVEEntry(cve_id=cve_id, title="t", severity=severity, description="d",
                    affected=CVEAffectedRange(min="0", max="9"),
                    kev=kev, tags=tags or [])


def order(entries, uncertain=None):
    return [c.cve_id for c in CVEEngine._sort_matched(list(entries), uncertain_ids=uncertain)]


class TestSortMatched:
    def test_confirmed_kev_outranks_a_higher_severity(self):
        got = order([cve("CVE-A", "critical"), cve("CVE-B", "medium", kev=KEV)])
        assert got == ["CVE-B", "CVE-A"]

    def test_uncertain_kev_does_not(self):
        got = order([cve("CVE-A", "critical"), cve("CVE-B", "medium", kev=KEV)],
                    uncertain={"CVE-B"})
        assert got == ["CVE-A", "CVE-B"]

    def test_uncertain_kev_keeps_its_flag(self):
        entry = cve("CVE-B", "medium", kev=KEV)
        CVEEngine._sort_matched([entry], uncertain_ids={"CVE-B"})
        assert entry.kev is not None

    def test_tag_based_exploitation_follows_the_same_rule(self):
        tagged = cve("CVE-T", "high", tags=["actively-exploited"])
        assert order([cve("CVE-A", "critical"), tagged]) == ["CVE-T", "CVE-A"]
        assert order([cve("CVE-A", "critical"), tagged], uncertain={"CVE-T"}) == ["CVE-A", "CVE-T"]

    def test_no_uncertain_set_is_the_old_behaviour(self):
        got = order([cve("CVE-A", "critical"), cve("CVE-B", "medium", kev=KEV)], uncertain=None)
        assert got[0] == "CVE-B"

    def test_within_a_tier_severity_then_id(self):
        got = order([cve("CVE-2", "high"), cve("CVE-1", "high"), cve("CVE-0", "critical")])
        assert got == ["CVE-0", "CVE-1", "CVE-2"]


class TestIosXeReport:
    """The production case: IOS XE 17.9.4, with the 2017 SNMP CVEs in KEV."""

    SNMP_2017 = ["CVE-2017-6736", "CVE-2017-6737", "CVE-2017-6738", "CVE-2017-6739",
                 "CVE-2017-6740", "CVE-2017-6742", "CVE-2017-6743", "CVE-2017-6744"]

    def report(self, kev_index):
        from api.routers.cve import CVEAnalyzeRequest, analyze_cve
        recs = {c: {"date_added": "2022-03-03", "due_date": "2022-03-24"} for c in self.SNMP_2017}
        recs["CVE-2023-20198"] = {"date_added": "2023-10-16", "due_date": "2023-10-20"}
        kev_index(recs)
        return analyze_cve(CVEAnalyzeRequest(platform="IOS XE", version="17.9.4"))

    def test_the_exploited_block_on_top_holds_only_confirmed_matches(self, kev_index):
        """What the rule guarantees: the run of KEV entries that opens the
        report contains no low-confidence match. (It does not promise that
        every verified finding precedes every uncertain one — below the
        exploited block, ordering is by severity, as before.)"""
        r = self.report(kev_index)
        uncertain = set(r.coverage_uncertain)
        top_block = []
        for c in r.matched:
            if c.kev is None:
                break
            top_block.append(c.cve_id)
        assert top_block, "expected at least one confirmed KEV match on top"
        assert not [c for c in top_block if c in uncertain], top_block

    def test_the_2017_snmp_cves_are_flagged_but_not_on_top(self, kev_index):
        r = self.report(kev_index)
        ids = [c.cve_id for c in r.matched]
        by_id = {c.cve_id: c for c in r.matched}
        for c in self.SNMP_2017:
            assert by_id[c].kev is not None, c            # the fact survives
            assert c in r.coverage_uncertain, c           # the match is unproven
        assert ids.index("CVE-2025-20188") < min(ids.index(c) for c in self.SNMP_2017)

    def test_confirmed_kev_is_still_first(self, kev_index):
        assert self.report(kev_index).matched[0].cve_id == "CVE-2023-20198"

    def test_ise_report_is_unaffected(self, kev_index):
        from api.routers.cve import CVEAnalyzeRequest, analyze_cve
        kev_index({"CVE-2026-76460": {"date_added": "2026-09-16", "due_date": "2026-09-19"}})
        r = analyze_cve(CVEAnalyzeRequest(platform="ISE", version="3.4 Patch 3"))
        assert r.matched[0].cve_id == "CVE-2026-76460"
        assert r.coverage_uncertain == []
