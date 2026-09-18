"""
ISE in the CVE Analyzer + Cisco hardening-release CVEs (ISE-03 / CVE-007).

ISE-01 added cve_data/ise and ISE-02 showed it in the threat feed, but the
analyzer kept a hard-coded cve_data/ios_xe directory and a min/max range
matcher. So ISE looked wired up while /analyze/cve returned nothing for it —
and had it loaded the data, the range matcher would have been wrong anyway,
because Cisco fixes ISE per train.
"""

import pytest

from models.cve_model import CVEAffectedRange, CVEEntry, CVEFirstFixed
from services.cve_engine import (
    CVEEngine,
    CVEEngineConfig,
    DEFAULT_DATA_DIR,
    data_dir_for_platform,
    is_bundled_cve,
    ise_fix_for_version,
    match_ise_record,
)

KEV_CVE = "CVE-2026-76460"
RADIUS_CVE = "CVE-2026-20352"


@pytest.fixture(scope="module")
def engine():
    e = CVEEngine(config=CVEEngineConfig(data_dir=data_dir_for_platform("ISE")))
    e.load_all()
    return e


def by_id(engine, cve_id):
    return next(c for c in engine.cves if c.cve_id == cve_id)


class TestDatasetSelection:
    @pytest.mark.parametrize("platform", [
        "ISE", "Cisco ISE", "ise-pic", "Identity Services Engine"])
    def test_ise_spellings_select_ise_dir(self, platform):
        assert data_dir_for_platform(platform) == "cve_data/ise"

    @pytest.mark.parametrize("platform", ["ISR4451-X", "C9300", "", None, "nonsense"])
    def test_everything_else_keeps_the_default(self, platform):
        assert data_dir_for_platform(platform) == DEFAULT_DATA_DIR

    def test_ise_engine_loads_ise_records(self, engine):
        assert len(engine.cves) == 56   # 8 curated + 48 imported (ISE-04)


class TestIseMatching:
    """Fixes are per train: "3.4 Patch 7" says nothing about 3.3."""

    def test_below_fix_on_own_train_is_affected(self, engine):
        assert match_ise_record(by_id(engine, KEV_CVE), "3.4 Patch 5") is True

    def test_at_fix_is_not_affected(self, engine):
        assert match_ise_record(by_id(engine, KEV_CVE), "3.4 Patch 7") is False

    def test_above_fix_is_not_affected(self, engine):
        assert match_ise_record(by_id(engine, KEV_CVE), "3.4 Patch 9") is False

    def test_range_matcher_trap(self, engine):
        """3.4 Patch 5 sorts ABOVE the 3.3 fix (Patch 12) — a range matcher
        would call it fixed. Per-train matching must not."""
        assert match_ise_record(by_id(engine, KEV_CVE), "3.4 Patch 5") is True
        assert match_ise_record(by_id(engine, KEV_CVE), "3.3 Patch 12") is False

    def test_unpatched_train_is_affected(self, engine):
        assert match_ise_record(by_id(engine, KEV_CVE), "3.5") is True

    def test_eosm_train_is_affected_with_no_fix(self, engine):
        cve = by_id(engine, KEV_CVE)
        assert match_ise_record(cve, "3.0") is True
        assert ise_fix_for_version(cve, "3.0") is None

    def test_newer_train_than_advisory_is_not_affected(self, engine):
        assert match_ise_record(by_id(engine, KEV_CVE), "3.6") is False

    def test_radius_dos_excludes_31_and_earlier(self, engine):
        """Advisory: '3.1 and earlier — Not vulnerable'."""
        cve = by_id(engine, RADIUS_CVE)
        assert match_ise_record(cve, "3.1 Patch 3") is False
        assert match_ise_record(cve, "3.0") is False
        assert match_ise_record(cve, "3.2 Patch 10") is True

    def test_label_in_version_box_is_tolerated(self, engine):
        assert match_ise_record(by_id(engine, KEV_CVE), "ISE 3.4 Patch 5") is True
        assert match_ise_record(by_id(engine, KEV_CVE), "Cisco ISE 3.4 Patch 7") is False

    @pytest.mark.parametrize("bad", ["", "garbage", "17.9.4a", "Patch 7"])
    def test_unparseable_version_is_none_not_a_guess(self, engine, bad):
        assert match_ise_record(by_id(engine, KEV_CVE), bad) is None

    def test_unreadable_fix_fails_towards_review(self):
        cve = CVEEntry(cve_id="CVE-X", title="t", severity="high", description="d",
                       affected=CVEAffectedRange(min="3.1", max="3.5"),
                       product_families=["ise"],
                       first_fixed_version=CVEFirstFixed(fixes={"ise-3.4": "see advisory"}))
        assert match_ise_record(cve, "3.4 Patch 5") is True


class TestEngineMatch:
    def test_counts_per_version(self, engine):
        # ISE-04: full 2026 coverage, every match checked against Cisco's list.
        assert len(engine.match("ISE", "3.4 Patch 3")) == 54
        assert len(engine.match("ISE", "3.4 Patch 7")) == 0
        assert len(engine.match("ISE", "3.5 Patch 4")) == 0
        assert len(engine.match("ISE", "3.6")) == 0
        # 3.0: only the hardening release lists it. The auth-bypass advisory
        # lists 3.1–3.5, so it is not claimed for 3.0 (Cisco did not assess it).
        assert len(engine.match("ISE", "3.0")) == 6
        ids_31 = {c.cve_id for c in engine.match("ISE", "3.1 Patch 3")}
        assert "CVE-2026-20352" not in ids_31                 # RADIUS DoS: 3.2+

    def test_kev_is_first(self, engine):
        assert engine.match("ISE", "3.4 Patch 5")[0].cve_id == KEV_CVE

    def test_unparseable_version_matches_nothing(self, engine):
        assert engine.match("ISE", "garbage") == []


class TestRecommendation:
    def rec(self, engine, version):
        return engine.recommended_upgrade(engine.match("ISE", version), "ISE", version)

    def test_recommends_fix_on_callers_own_train(self, engine):
        assert self.rec(engine, "3.4 Patch 5").startswith("3.4 Patch 7")
        assert self.rec(engine, "3.3 Patch 2").startswith("3.3 Patch 12")
        assert self.rec(engine, "3.5 Patch 1").startswith("3.5 Patch 4")

    def test_software_maintenance_train_is_told_to_migrate(self, engine):
        """3.1 gets Critical fixes only. With the full dataset, 21 of its 52
        matches are Medium/High advisories whose table says "Migrate" — so no
        patch level on 3.1 closes everything, and the report says that instead
        of recommending 3.1 Patch 12."""
        r = self.rec(engine, "3.1 Patch 3")
        assert "No fixed release exists on the ISE 3.1 train" in r and "Migrate" in r

    def test_names_the_kev_driver(self, engine):
        r = self.rec(engine, "3.4 Patch 5")
        assert KEV_CVE in r and "KEV" in r

    def test_eosm_train_says_migrate_not_a_patch(self, engine):
        r = self.rec(engine, "3.0")
        assert "No fixed release" in r and "Migrate" in r
        assert "Patch" not in r.split("Migrate")[0].replace("No fixed release", "")

    def test_nothing_matched_recommends_nothing(self, engine):
        assert self.rec(engine, "3.4 Patch 7") is None

    def test_mentions_hardening_release_cves(self, engine):
        r = self.rec(engine, "3.4 Patch 5")
        assert "6 of 50 are hardening-release CVEs" in r   # 3.4 Patch 5
        assert "unit of remediation" in r

    def test_legacy_signature_still_works(self, engine):
        """recommended_upgrade(matched) with no platform/version = old path."""
        assert engine.recommended_upgrade([]) is None


class TestBundledCveSignature:
    """CVE-007. Signature verified against 6 hardening advisories in the PSIRT
    cache: id prefix, title, and len(cves) == len(cwe)."""

    def entry(self, **kw):
        base = dict(cve_id="CVE-T", title="Some Vulnerability", severity="high",
                    description="d", affected=CVEAffectedRange(min="1", max="2"))
        base.update(kw)
        return CVEEntry(**base)

    def test_tag(self):
        assert is_bundled_cve(self.entry(tags=["bundled-cve"]))

    def test_advisory_url(self):
        url = ("https://sec.cloudapps.cisco.com/security/center/content/"
               "CiscoSecurityAdvisory/cisco-sa-hardening-iosxr-qg64NcM")
        assert is_bundled_cve(self.entry(advisory_url=url))

    def test_title(self):
        assert is_bundled_cve(self.entry(
            title="Cisco IOS XR Software Security Hardening Release: September 2026"))

    def test_ordinary_cve_is_not_bundled(self):
        assert not is_bundled_cve(self.entry(
            title="Cisco IOS XE Software Web UI Privilege Escalation Vulnerability",
            advisory_url="https://sec.cloudapps.cisco.com/x/cisco-sa-iosxe-webui-privesc"))

    def test_publication_bundle_is_a_different_thing(self):
        """`bundle` marks same-day publication; it does not make a CVE a class."""
        assert not is_bundled_cve(self.entry(bundle="2026-09"))

    def test_ise_dataset_has_six(self, engine):
        assert sum(1 for c in engine.cves if is_bundled_cve(c)) == 6
        assert not is_bundled_cve(by_id(engine, KEV_CVE))
        assert not is_bundled_cve(by_id(engine, RADIUS_CVE))


class TestAnalyzeEndpoint:
    def call(self, platform, version):
        from api.routers.cve import CVEAnalyzeRequest, analyze_cve
        return analyze_cve(CVEAnalyzeRequest(platform=platform, version=version))

    def test_ise_query_returns_ise_matches(self):
        r = self.call("ISE", "3.4 Patch 5")
        assert len(r.matched) == 50 and r.matched[0].cve_id == KEV_CVE

    def test_bundled_cves_is_a_subset_of_matched(self):
        r = self.call("ISE", "3.4 Patch 5")
        assert len(r.bundled_cves) == 6
        assert set(r.bundled_cves) <= {c.cve_id for c in r.matched}

    def test_kev_block_reaches_the_client(self):
        r = self.call("ISE", "3.4 Patch 5")
        assert r.matched[0].kev.due_date == "2026-09-19"

    def test_ios_xe_path_is_untouched(self):
        r = self.call("ISR4451-X", "17.5.1")
        assert r.matched and r.bundled_cves == []
        assert all("ise" not in (c.product_families or []) for c in r.matched)
