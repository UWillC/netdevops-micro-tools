"""
Exact matching on Cisco's Known Affected lists (MATCH-01, 2026-09-18).

Before: PSIRT-imported records carried affected = 0.0.0–999.999.999, a
placeholder that matches every release. `IOS XE 17.9.4` returned 104 CVEs, 100
of them self-declared "coverage uncertain", including nine SNMP bugs from 2017.

After: 71 CVEs, 66 verified. The 33 removed are exactly the records whose
advisory enumerates releases and does not list 17.9.4.
"""

import glob
import json
import os

import pytest

from models.cve_model import CVEAffectedRange, CVEEntry
from services.advisory_text import clean_advisory_text
from services.cve_engine import CVEEngine, CVEEngineConfig, data_confidence
from services.known_affected import (
    _norm, extract_known_affected, family_for_version, version_is_listed)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestExtract:
    def test_families_are_separated(self):
        adv = {"productNames": ["Cisco IOS XE Software 17.9.4", "Cisco IOS XE Software 17.9.4a",
                                "Cisco IOS 15.2(7)E8", "Cisco NX-OS Software 9.3(5)"]}
        assert extract_known_affected(adv) == {"ios-xe": ["17.9.4", "17.9.4a"], "ios": ["15.2(7)E8"],
                                               "nx-os": ["9.3(5)"]}   # NX-OS is a family of its own since NX-OS-01

    def test_ios_xe_is_never_read_as_ios_classic(self):
        assert "ios" not in extract_known_affected({"productNames": ["Cisco IOS XE Software 17.9.4"]})

    def test_product_named_without_a_release_gives_no_list(self):
        """Cisco sometimes lists "Cisco IOS XE Software " with no version.
        That is 'we were not told', so it must not become an empty-list veto."""
        assert extract_known_affected({"productNames": ["Cisco IOS XE Software ", "Cisco IOS "]}) == {}

    def test_junk_is_ignored(self):
        assert extract_known_affected({"productNames": [None, 7, ""]}) == {}
        assert extract_known_affected({}) == {}


class TestVersionIsListed:
    @pytest.mark.parametrize("given,listed", [
        ("17.9.4", "17.9.4"), ("17.09.04", "17.9.4"), ("17.9.4A", "17.9.4a"),
        ("  17.9.4a ", "17.9.4a"), ("15.2(07)E8", "15.2(7)E8"), ("17.10.1", "17.10.1"),
    ])
    def test_equivalent_spellings(self, given, listed):
        assert version_is_listed(given, [listed])

    @pytest.mark.parametrize("given,listed", [
        ("17.9.4", "17.9.4a"), ("17.9.4a", "17.9.4"), ("17.9.40", "17.9.4"),
        ("17.1.1", "17.10.1"), ("17.10.1", "17.1.1"), ("", "17.9.4"),
    ])
    def test_near_misses_do_not_match(self, given, listed):
        """A rebuild letter is a different release; zero-stripping must not
        turn 17.10 into 17.1."""
        assert not version_is_listed(given, [listed])

    def test_norm_keeps_significant_zeros(self):
        assert _norm("17.10.1") == "17.10.1" and _norm("17.09.04a") == "17.9.4a"

    def test_family_for_version(self):
        assert family_for_version("17.9.4a") == "ios-xe"
        assert family_for_version("15.2(7)E8") == "ios"
        assert family_for_version("3.4 Patch 3") == "ise"     # ISE-04
        assert family_for_version("") is None


def rec(cve_id, listed=None, amin="0.0.0", amax="999.999.999", fixed_in=None):
    return CVEEntry(cve_id=cve_id, title="Cisco IOS XE Software Something Vulnerability",
                    severity="high", description="d", platforms=["IOS XE"],
                    affected=CVEAffectedRange(min=amin, max=amax), fixed_in=fixed_in,
                    known_affected={"ios-xe": listed} if listed is not None else {})


class TestMatcher:
    def engine(self, records):
        e = CVEEngine(config=CVEEngineConfig(), providers=[])
        e.cves = list(records)
        return e

    def test_listed_release_matches(self):
        e = self.engine([rec("CVE-A", ["17.9.4", "17.9.3"])])
        assert [c.cve_id for c in e.match("IOS XE", "17.9.4")] == ["CVE-A"]
        assert e.excluded_by_known_affected == []

    def test_unlisted_release_is_excluded_despite_the_placeholder_range(self):
        e = self.engine([rec("CVE-A", ["16.6.1", "16.6.2"])])
        assert e.match("IOS XE", "17.9.4") == []
        assert e.excluded_by_known_affected == ["CVE-A"]

    def test_no_list_falls_back_to_the_range(self):
        """'We were not told' keeps the old behaviour and stays uncertain."""
        e = self.engine([rec("CVE-A")])
        assert [c.cve_id for c in e.match("IOS XE", "17.9.4")] == ["CVE-A"]
        assert e.excluded_by_known_affected == []

    def test_list_for_another_family_does_not_veto(self):
        r = rec("CVE-A")
        r.known_affected = {"ios": ["15.2(7)E8"]}
        assert [c.cve_id for c in self.engine([r]).match("IOS XE", "17.9.4")] == ["CVE-A"]

    def test_device_model_in_the_platform_box_still_uses_the_list(self):
        e = self.engine([rec("CVE-A", ["16.6.1"])])
        assert e.match("ISR4451-X", "17.9.4") == []

    def test_excluded_list_resets_between_calls(self):
        e = self.engine([rec("CVE-A", ["16.6.1"])])
        e.match("IOS XE", "17.9.4")
        e.match("IOS XE", "16.6.1")
        assert e.excluded_by_known_affected == []

    def test_confidence_is_verified_and_says_why(self):
        r = rec("CVE-A", ["17.9.4"])
        r.known_affected_as_of = "2026-09-18"
        info = data_confidence(r)
        assert info["confidence"] == "verified"
        assert "Known Affected" in info["rationale"] and "2026-09-18" in info["rationale"]


class TestProductionReport:
    def call(self, platform, version):
        from api.routers.cve import CVEAnalyzeRequest, analyze_cve
        return analyze_cve(CVEAnalyzeRequest(platform=platform, version=version))

    def test_the_17_9_4_report(self):
        r = self.call("IOS XE", "17.9.4")
        assert len(r.matched) == 71                      # was 104
        assert r.matched_on_known_affected == 66     # 65 until CVE-2025-20160 got its list (v0.6.47)
        assert len(r.coverage_uncertain) == 5            # was 100
        quality = [v["confidence"] for v in r.data_quality.values()]
        assert quality.count("verified") == 66           # was 4

    def test_previously_verified_findings_are_all_still_there(self):
        ids = {c.cve_id for c in self.call("IOS XE", "17.9.4").matched}
        # CVE-2025-20188 was in this set until v0.6.47. It was never a real finding for
        # 17.9.4: Cisco lists 17.11.1, 17.12.1-3, 17.13.1 and 17.14.1 only. The curated
        # record had a non-existent advisory id, so the list could not attach.
        assert {"CVE-2023-20198", "CVE-2025-20352", "CVE-2023-20273"} <= ids
        assert "CVE-2025-20188" not in ids

    def test_excluded_are_reported_not_hidden(self):
        r = self.call("IOS XE", "17.9.4")
        assert "CVE-2017-6736" in r.excluded_not_listed
        assert not set(r.excluded_not_listed) & {c.cve_id for c in r.matched}

    def test_zero_padded_version_gives_the_same_report(self):
        a, b = self.call("IOS XE", "17.9.4"), self.call("IOS XE", "17.09.04")
        assert [c.cve_id for c in a.matched] == [c.cve_id for c in b.matched]

    def test_ise_uses_the_same_mechanism(self):
        """ISE-04 extended list matching to ISE; see tests/test_ise_coverage.py."""
        r = self.call("ISE", "3.4 Patch 3")
        assert len(r.matched) == 54 and r.matched_on_known_affected == 54


class TestDatasetAndText:
    def test_no_html_entities_left_in_the_dataset(self):
        bad = []
        for path in glob.glob(os.path.join(ROOT, "cve_data", "ios_xe", "cve-*.json")):
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
            if "&nbsp;" in (d.get("description") or "") + (d.get("title") or ""):
                bad.append(os.path.basename(path))
        assert bad == []

    def test_lists_are_stored_with_their_date(self):
        n = 0
        for path in glob.glob(os.path.join(ROOT, "cve_data", "ios_xe", "cve-*.json")):
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
            if d.get("known_affected"):
                n += 1
                assert d.get("known_affected_as_of"), path
        assert n == 126   # 124 + CVE-2025-20160 and CVE-2025-20188 (v0.6.47)

    def test_cleaner(self):
        assert clean_advisory_text("Protocol&nbsp;(SNMP) of <b>Cisco</b>&nbsp;IOS &amp; XE") == \
            "Protocol (SNMP) of Cisco IOS & XE"
        assert clean_advisory_text(None) == ""

    def test_all_three_importers_store_the_full_list(self):
        import importlib.util
        from services.cisco_sync import _build_cve_json
        from services.cve_sources import CiscoAdvisoryProvider
        spec = importlib.util.spec_from_file_location(
            "import_cisco_to_local", os.path.join(ROOT, "scripts", "import_cisco_to_local.py"))
        script = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(script)
        adv = {"advisoryId": "cisco-sa-x", "advisoryTitle": "T", "sir": "High",
               "cvssBaseScore": "8.6", "cves": ["CVE-2026-1"], "cwe": ["CWE-20"],
               "summary": "A&nbsp;B",
               "productNames": ["Cisco IOS XE Software %d.1.1" % i for i in range(1, 81)],
               "firstPublished": "2026-01-01", "lastUpdated": "2026-01-01",
               "publicationUrl": "https://x/cisco-sa-x"}
        a = _build_cve_json("CVE-2026-1", adv, "0", "9")
        b = script.build_cve_data("CVE-2026-1", adv, "0", "9")
        c = CiscoAdvisoryProvider(platform="iosxe")._parse_advisory(adv)[0]
        for lists in (a["known_affected"], b["known_affected"], c.known_affected):
            assert len(lists["ios-xe"]) == 80          # not capped at 50
        assert a["description"] == b["description"] == c.description == "A B"
