"""
Threat-feed severity follows CVSS; Cisco SIR is a secondary tag (SIR-01).

Seen on production 2026-09-18: CVE-2026-20316 rendered as "5.3 — HIGH". The
feed put Cisco's Security Impact Rating in the severity slot, while the analyzer
has had the opposite, documented policy since v0.6.16
(CVEAnalyzeResponse.severity_policy): primary severity = NVD CVSS v3.x bucket,
Cisco SIR = a separate tag when it differs.
"""

import pytest

from api.routers.cve import _advisories_to_feed, _feed_severity, _local_records_to_feed


def adv(score, sir, cve="CVE-2026-20316"):
    return {"advisoryId": "a-" + cve, "advisoryTitle": "T", "sir": sir,
            "cvssBaseScore": score, "cves": [cve], "cwe": ["CWE-798"],
            "productNames": ["Cisco Secure Firewall Management Center"],
            "firstPublished": "2026-07-29", "lastUpdated": "2026-09-16",
            "publicationUrl": "https://example.invalid/" + cve}


class TestFeedSeverityRule:
    @pytest.mark.parametrize("score,bucket", [
        (10.0, "critical"), (9.0, "critical"), (8.9, "high"), (7.0, "high"),
        (6.9, "medium"), (5.3, "medium"), (4.0, "medium"), (3.9, "low"), (0.1, "low"),
    ])
    def test_severity_is_the_cvss_bucket(self, score, bucket):
        assert _feed_severity(score, bucket)[0] == bucket

    def test_the_production_case(self):
        """CVSS 5.3 with Cisco SIR High: medium, plus an SIR tag."""
        assert _feed_severity(5.3, "High") == ("medium", "high")

    def test_sir_is_omitted_when_it_agrees(self):
        assert _feed_severity(9.8, "Critical") == ("critical", None)
        assert _feed_severity(7.5, "high") == ("high", None)

    def test_sir_below_cvss_is_reported_too(self):
        """Divergence runs both ways; neither direction is hidden."""
        assert _feed_severity(9.1, "Medium") == ("critical", "medium")

    def test_no_score_falls_back_to_sir(self):
        assert _feed_severity(None, "High") == ("high", None)

    def test_no_score_and_no_sir(self):
        assert _feed_severity(None, None) == ("unknown", None)
        assert _feed_severity(None, "  ") == ("unknown", None)

    def test_case_and_whitespace(self):
        assert _feed_severity(5.3, "  HIGH ") == ("medium", "high")


class TestPsirtRows:
    def test_row_shows_bucket_and_separate_sir(self):
        row = _advisories_to_feed([adv("5.3", "High")], "all")[0]
        assert row.severity == "medium"
        assert row.cisco_sir == "high"
        assert row.cvss == 5.3

    def test_agreeing_row_has_no_sir_tag(self):
        row = _advisories_to_feed([adv("10.0", "Critical")], "all")[0]
        assert row.severity == "critical" and row.cisco_sir is None

    def test_unparseable_score_uses_sir(self):
        row = _advisories_to_feed([adv("NA", "High")], "all")[0]
        assert row.severity == "high" and row.cisco_sir is None and row.cvss is None

    def test_informational_advisories_are_still_excluded(self):
        assert _advisories_to_feed([adv("0.0", "Informational")], "all") == []


class TestLocalRows:
    def test_sir_cvss_divergence_record(self):
        """CVE-2026-20287: CVSS 6.5 inside a Critical-SIR hardening advisory."""
        row = {r.cve_id: r for r in _local_records_to_feed("ise")}["CVE-2026-20287"]
        assert row.severity == "medium"
        assert row.cisco_sir == "critical"

    def test_agreeing_local_record(self):
        row = {r.cve_id: r for r in _local_records_to_feed("ise")}["CVE-2026-76460"]
        assert row.severity == "critical" and row.cisco_sir is None

    def test_no_row_contradicts_its_own_score(self):
        """The invariant: a severity label never disagrees with the CVSS shown."""
        from services.cve_engine import cvss_rating_from_score
        for platform in ("ise", "iosxe"):
            for r in _local_records_to_feed(platform):
                if r.cvss is not None:
                    assert r.severity == cvss_rating_from_score(r.cvss).lower(), r.cve_id
