"""
Accuracy of what the analyzer report *says about itself* (2026-09-18).

Found by reading a production report for ISE 3.4 Patch 3 as a reviewer would.
Three statements on the page were false, and all three came from work shipped
earlier the same day:

  1. "Cisco SIR ≠ CVSS: 8 CVE(s)" — one CVE diverges, not eight.
  2. Provenance named cve_data/ios_xe (142 files) for an ISE analysis that read
     cve_data/ise.
  3. "In Cisco bundle: 8 CVE(s)" — `bundle` means the semi-annual IOS / IOS XE
     publication; the ISE records are not part of it.
"""

import pytest

from models.cve_model import CVEAffectedRange, CVEEntry
from services.cve_engine import severity_info
from services.provenance import _file_count, cve_provenance


def analyze(platform, version):
    from api.routers.cve import CVEAnalyzeRequest, analyze_cve
    return analyze_cve(CVEAnalyzeRequest(platform=platform, version=version))


def entry(score, severity, sir=None):
    return CVEEntry(cve_id="CVE-T", title="t", severity=severity, description="d",
                    affected=CVEAffectedRange(min="1", max="2"),
                    cvss_score=score, cisco_sir=sir)


class TestSirIsReportedOnlyWhenItDiffers:
    """severity_info()'s docstring always said so; the code did not."""

    def test_explicit_sir_equal_to_bucket_is_not_a_divergence(self):
        assert severity_info(entry(10.0, "critical", "Critical"))["cisco_sir"] is None
        assert severity_info(entry(8.6, "high", "High"))["cisco_sir"] is None

    def test_explicit_sir_that_differs_is_reported(self):
        assert severity_info(entry(6.5, "medium", "Critical"))["cisco_sir"] == "CRITICAL"
        assert severity_info(entry(9.1, "critical", "Medium"))["cisco_sir"] == "MEDIUM"

    def test_explicit_sir_without_a_score_is_still_reported(self):
        """No bucket to agree with, so SIR is the only rating there is."""
        assert severity_info(entry(None, "high", "High"))["cisco_sir"] == "HIGH"

    def test_case_insensitive(self):
        assert severity_info(entry(10.0, "critical", "critical"))["cisco_sir"] is None

    def test_the_production_report(self):
        r = analyze("ISE", "3.4 Patch 3")
        diverging = [cid for cid, d in r.severity_details.items() if d.get("cisco_sir")]
        assert diverging == ["CVE-2026-20287"]


class TestProvenanceNamesTheDatasetThatWasRead:
    def sources(self, platform, version):
        return {s["name"]: s for s in analyze(platform, version).provenance["sources"]}

    def test_ise_analysis_names_the_ise_dataset(self):
        local = self.sources("ISE", "3.4 Patch 3")["local-json"]
        assert "cve_data/ise" in local["description"]
        assert local["file_count"] == 8

    def test_ios_xe_analysis_still_names_the_ios_xe_dataset(self):
        local = self.sources("ISR4451-X", "17.5.1")["local-json"]
        assert "cve_data/ios_xe" in local["description"]
        assert local["file_count"] == 142

    def test_default_argument_keeps_old_callers_working(self):
        block = cve_provenance("x", "y", [])
        local = [s for s in block["sources"] if s["name"] == "local-json"][0]
        assert "cve_data/ios_xe" in local["description"]

    def test_file_count_ignores_readme_and_dotfiles(self, tmp_path):
        for name in ("cve-1.json", "cve-2.json", "README.md", ".DS_Store", ".hidden.json"):
            (tmp_path / name).write_text("{}", encoding="utf-8")
        assert _file_count(str(tmp_path)) == 2


class TestKevCatalogIsInTheTrail:
    """KEV-X made the catalog an input to ranking and flags; an input that is
    not in the audit trail is an unexplained influence on the report."""

    def test_source_is_listed_with_its_version(self, monkeypatch):
        from api.routers import cve as cve_router
        monkeypatch.setattr(cve_router.kev_catalog, "catalog_version", lambda: "2026.09.16")
        kev = {s["name"]: s for s in analyze("ISE", "3.4 Patch 3").provenance["sources"]}["cisa-kev"]
        assert kev["catalog_version"] == "2026.09.16"

    def test_no_catalog_is_stated_not_omitted(self, monkeypatch):
        from api.routers import cve as cve_router
        monkeypatch.setattr(cve_router.kev_catalog, "catalog_version", lambda: None)
        kev = {s["name"]: s for s in analyze("ISE", "3.4 Patch 3").provenance["sources"]}["cisa-kev"]
        assert kev["catalog_version"] is None


class TestBundleFieldMeansWhatItSays:
    def test_ise_report_claims_no_semiannual_bundle(self):
        r = analyze("ISE", "3.4 Patch 3")
        assert all(v is None for v in r.bundles.values())

    def test_hardening_release_is_still_reported_separately(self):
        """Dropping the wrong `bundle` must not drop the right `bundled_cves`."""
        assert len(analyze("ISE", "3.4 Patch 3").bundled_cves) == 6
