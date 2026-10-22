"""
UPG-01 (2026-10-22): safe upgrade path in the CVE Analyzer.

First feedback from an outside user: "Add to the CVE Analyzer if recommendation
is to upgrade to provide the safe upgrade path." The analyzer named one target
(the lowest release closing every matched critical/high CVE) and never checked
it: on IOS XE 17.9.4 the target 17.15.4a still matched 5 medium CVEs the report
did not mention, and an ISE train without a fix got "Migrate to a supported
train" with no train named.
"""

import pytest

from services.cve_engine import CVEEngine, CVEEngineConfig, data_dir_for_platform


def analyze(platform, version):
    from api.routers.cve import CVEAnalyzeRequest, analyze_cve
    return analyze_cve(CVEAnalyzeRequest(platform=platform, version=version))


def engine_for(platform):
    e = CVEEngine(config=CVEEngineConfig(data_dir=data_dir_for_platform(platform)))
    e.load_all()
    return e


@pytest.fixture(scope="module")
def iosxe():
    return engine_for("IOS XE")


@pytest.fixture(scope="module")
def ise():
    return engine_for("ISE")


def check(engine, platform, version):
    matched = engine.match(platform, version)
    rec = engine.recommended_upgrade(matched, platform, version)
    return rec, engine.check_upgrade_target(platform, version, rec)


class TestIosXeTarget:
    def test_train_change_target_is_checked_and_safe(self, iosxe):
        rec, chk = check(iosxe, "IOS XE", "17.9.4")
        assert rec.startswith("IOS XE 17.15.4a")
        assert chk["target"] == "IOS XE 17.15.4a"
        assert chk["kind"] == "train-change"
        assert chk["safe"] is True and chk["critical_high"] == []

    def test_what_stays_open_on_the_target_is_listed(self, iosxe):
        _, chk = check(iosxe, "IOS XE", "17.9.4")
        assert chk["remaining_ids"], "the target still matches lower-severity CVEs"
        assert set(chk["remaining"]) <= {"medium", "low", "unknown"}
        assert "Still matched on it" in chk["statement"]
        assert "release notes" in chk["statement"]   # train change prerequisites

    def test_no_recommendation_no_check(self, iosxe):
        rec, chk = check(iosxe, "IOS XE", "17.15.4a")
        assert rec is None and chk is None

    def test_rematch_does_not_overwrite_report_state(self, iosxe):
        iosxe.match("IOS XE", "17.9.4")
        before = list(iosxe.excluded_by_known_affected)
        _, _ = check(iosxe, "IOS XE", "17.9.4")
        assert iosxe.excluded_by_known_affected == before

    def test_failed_target_is_never_called_safe(self, iosxe):
        # A target that is itself vulnerable must say so, not "safe".
        chk = iosxe.check_upgrade_target("IOS XE", "17.9.4",
                                         "IOS XE 17.9.4 — driven by CVE-TEST")
        assert chk["safe"] is False and chk["critical_high"]
        assert chk["statement"].startswith("Target check failed")


class TestIseTarget:
    def test_same_train_patch(self, ise):
        rec, chk = check(ise, "ISE", "3.4 Patch 5")
        assert chk["target"] == "3.4 Patch 7"
        assert chk["kind"] == "same-train" and chk["safe"] is True

    @pytest.mark.parametrize("version", ["3.2 Patch 4", "3.0 Patch 8"])
    def test_migration_names_a_supported_train(self, ise, version):
        rec, chk = check(ise, "ISE", version)
        assert rec.startswith("No fixed release exists")
        assert chk["kind"] == "migration" and chk["safe"] is True
        # never an EoSM / Software Maintenance train (3.0-3.2)
        assert chk["target"].split()[0] not in ("3.0", "3.1", "3.2")
        assert ise.check_upgrade_target("ISE", chk["target"], None) is None
        assert not [c for c in ise.match("ISE", chk["target"])
                    if (c.severity or "").lower() in ("critical", "high")]


class TestNoTarget:
    def test_nxos_has_no_target_check(self):
        e = engine_for("NX-OS")
        rec, chk = check(e, "NX-OS", "9.3(8)")
        assert chk is None


class TestApi:
    def test_response_carries_the_check(self):
        resp = analyze("IOS XE", "17.9.4")
        assert resp.upgrade_target_check["target"] == "IOS XE 17.15.4a"
        assert resp.upgrade_target_check["safe"] is True

    def test_regression_target_never_has_critical_high(self):
        for platform, version in [("IOS XE", "17.6.3"), ("IOS XE", "17.12.1"),
                                  ("ISE", "3.3 Patch 5"), ("ISE", "3.1 Patch 3")]:
            chk = analyze(platform, version).upgrade_target_check
            if chk and chk["target"]:
                assert chk["critical_high"] == [], (platform, version, chk)
