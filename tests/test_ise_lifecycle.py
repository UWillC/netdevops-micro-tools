"""
ISE software-lifecycle notice and the lower bound of the hardening records
(EOSM-01, 2026-09-18).

v0.6.31 pasted the End-of-Software-Maintenance paragraph into seven of the
eight ISE record descriptions, so a report for a 3.4 deployment repeated it
seven times about trains the reader was not on. It is now one statement per
report, shown only when it applies. Writing the 2.x test below also exposed a
false negative: the hardening advisory says "3.0 and earlier", the records
said min=3.0, and ISE 2.7 came out as "not affected".
"""

import glob
import json
import os

import pytest

from services.cve_engine import ISE_LIFECYCLE_SOURCE, ise_lifecycle_note

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def analyze(platform, version):
    from api.routers.cve import CVEAnalyzeRequest, analyze_cve
    return analyze_cve(CVEAnalyzeRequest(platform=platform, version=version))


class TestNote:
    @pytest.mark.parametrize("version", ["3.3 Patch 9", "3.4 Patch 3", "3.5", "3.6"])
    def test_supported_trains_get_no_notice(self, version):
        assert ise_lifecycle_note("ISE", version) is None

    def test_30_says_no_fix_and_migrate(self):
        note = ise_lifecycle_note("ISE", "3.0")
        assert "End of Software Maintenance" in note and "migrating" in note

    @pytest.mark.parametrize("version", ["3.1 Patch 3", "3.2 Patch 10"])
    def test_31_and_32_say_critical_only(self, version):
        assert "Critical SIR fixes only" in ise_lifecycle_note("ISE", version)

    def test_pre_30_names_the_callers_own_release(self):
        note = ise_lifecycle_note("ISE", "2.7 Patch 8")
        assert "(2.7)" in note and "predates Cisco ISE 3.0" in note

    def test_ise_pic(self):
        note = ise_lifecycle_note("ISE-PIC", "3.4 Patch 3")
        assert "end-of-sale" in note and "3.4 is the last supported release" in note

    def test_every_notice_cites_its_source(self):
        for plat, ver in (("ISE", "3.0"), ("ISE", "3.2"), ("ISE-PIC", "3.4"), ("ISE", "2.4")):
            assert ISE_LIFECYCLE_SOURCE in ise_lifecycle_note(plat, ver)

    def test_no_dates_are_invented(self):
        """The advisory gives no lifecycle dates, so neither do we."""
        import re
        for plat, ver in (("ISE", "3.0"), ("ISE", "3.1"), ("ISE-PIC", "3.4")):
            body = ise_lifecycle_note(plat, ver).split("Source:")[0]
            assert not re.search(r"\b20\d\d\b", body), body

    @pytest.mark.parametrize("platform,version", [
        ("IOS XE", "17.9.4"), ("ISR4451-X", "3.0"), ("ISE", "garbage"), ("", ""), (None, None)])
    def test_not_ise_or_unparseable_is_none(self, platform, version):
        assert ise_lifecycle_note(platform, version) is None


class TestReport:
    def test_supported_train_report_has_no_lifecycle_text_at_all(self):
        r = analyze("ISE", "3.4 Patch 3")
        assert r.lifecycle_note is None
        blob = json.dumps(r.model_dump(), default=str)
        assert "End of Software Maintenance" not in blob
        assert "end-of-sale" not in blob

    def test_eosm_train_report_says_it_exactly_once(self):
        r = analyze("ISE", "3.0")
        blob = json.dumps(r.model_dump(), default=str)
        assert blob.count("End of Software Maintenance") == 1

    def test_it_does_not_hijack_the_hardware_eol_banner(self):
        """detect_eol() says 'replace the hardware' — false for a software phase."""
        assert analyze("ISE", "3.0").eol_status is None

    def test_records_no_longer_carry_the_paragraph(self):
        for path in glob.glob(os.path.join(ROOT, "cve_data", "ise", "cve-*.json")):
            with open(path, encoding="utf-8") as f:
                assert "End of Software Maintenance" not in json.load(f)["description"], path


class TestLowerBound:
    def test_pre_30_is_affected_by_the_hardening_release(self):
        """Cisco: '3.0 and earlier — Migrate to fixed release'."""
        r = analyze("ISE", "2.7 Patch 8")
        assert len(r.matched) == 6 and len(r.bundled_cves) == 6
        assert "No fixed release" in r.recommended_upgrade

    def test_auth_bypass_is_not_extended_below_30(self):
        """Its table lists 3.1–3.5 and footnotes 3.0; nothing speaks about 2.x,
        so we do not claim it."""
        ids = {c.cve_id for c in analyze("ISE", "2.7 Patch 8").matched}
        assert "CVE-2026-76460" not in ids

    def test_radius_dos_still_starts_at_32(self):
        ids = {c.cve_id for c in analyze("ISE", "2.7 Patch 8").matched}
        assert "CVE-2026-20352" not in ids

    def test_supported_trains_are_unchanged(self):
        assert len(analyze("ISE", "3.4 Patch 3").matched) == 54
        assert len(analyze("ISE", "3.4 Patch 7").matched) == 0
