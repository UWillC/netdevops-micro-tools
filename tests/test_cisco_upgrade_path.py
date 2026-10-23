"""
UPG-02 (2026-10-22): Cisco's first-fixed path from the openVuln per-release query.

Fixtures mirror what the API returned on 2026-10-22 for IOS XE: 17.9.4 lists
the August 2026 hardening release (no firstFixed on 17.9) and High advisories
fixed up to 17.9.10; 17.9.10 lists one Medium. No network in this file.
"""

import pytest

from services import cisco_software_checker as csc

HARDENING = {"advisoryId": "cisco-sa-hardening-iosxe-V8NMuMZJ", "sir": "Critical",
             "firstFixed": [], "cves": ["CVE-2026-20267"]}
XMCP = {"advisoryId": "cisco-sa-ios-xmcp-thbAr34t", "sir": "High",
        "firstFixed": ["17.9.10"], "cves": ["CVE-2026-20301"]}
OLD = {"advisoryId": "cisco-sa-snmp-x4LPhte", "sir": "High",
       "firstFixed": ["17.9.8"], "cves": ["CVE-2025-20352"]}
OTHER_TRAIN = {"advisoryId": "cisco-sa-x", "sir": "High",
               "firstFixed": ["17.12.6", "17.9.9"], "cves": ["CVE-0000-1"]}
MEDIUM = {"advisoryId": "cisco-sa-snmpv3-qKEYvzsy", "sir": "Medium",
          "firstFixed": [], "cves": ["CVE-0000-2"]}


def fake(table):
    calls = []

    def fetch(ostype, release):
        calls.append((ostype, release))
        return table.get(release)
    fetch.calls = calls
    return fetch


@pytest.fixture(autouse=True)
def _fresh():
    csc.reset_for_tests()
    yield
    csc.reset_for_tests()


def test_walks_to_the_release_with_no_critical_high():
    f = fake({"17.9.4": [HARDENING, XMCP, OLD, OTHER_TRAIN], "17.9.10": [MEDIUM]})
    path = csc.first_fixed_path("iosxe", "17.9.4", fetch=f)
    assert path["target"] == "17.9.10"
    assert path["steps"] == ["17.9.4", "17.9.10"]
    assert path["same_train"] is True
    assert [r["advisoryId"] for r in path["remaining"]] == ["cisco-sa-snmpv3-qKEYvzsy"]
    assert "17.9.4 → 17.9.10" in path["statement"]
    assert "1 Medium" in path["statement"]


def test_highest_first_fixed_is_compared_as_a_version_not_text():
    # "17.9.10" sorts below "17.9.8" as text.
    f = fake({"17.9.4": [OLD, XMCP], "17.9.10": []})
    assert csc.first_fixed_path("iosxe", "17.9.4", fetch=f)["target"] == "17.9.10"


def test_other_train_fixes_are_ignored():
    f = fake({"17.9.4": [OTHER_TRAIN], "17.9.9": []})
    assert csc.first_fixed_path("iosxe", "17.9.4", fetch=f)["target"] == "17.9.9"


def test_unfixed_advisory_still_listed_at_the_end_stops_without_a_target():
    f = fake({"17.9.4": [HARDENING, XMCP], "17.9.10": [HARDENING]})
    path = csc.first_fixed_path("iosxe", "17.9.4", fetch=f)
    assert path["target"] is None
    assert "no release on the 17.9 train" in path["statement"]
    assert "cisco-sa-hardening-iosxe-V8NMuMZJ" in path["statement"]


def test_multi_step_walk():
    f = fake({"17.9.4": [OLD], "17.9.8": [XMCP], "17.9.10": []})
    path = csc.first_fixed_path("iosxe", "17.9.4", fetch=f)
    assert path["steps"] == ["17.9.4", "17.9.8", "17.9.10"]


def test_clean_release_gives_no_path():
    assert csc.first_fixed_path("iosxe", "17.9.10", fetch=fake({"17.9.10": [MEDIUM]})) is None


def test_failure_gives_none_and_is_cached():
    f = fake({})   # every call returns None = failure
    assert csc.first_fixed_path("iosxe", "17.9.4", fetch=f) is None
    assert csc.first_fixed_path("iosxe", "17.9.4", fetch=f) is None
    assert len(f.calls) == 1   # failure cached, no second network call


def test_results_are_cached():
    f = fake({"17.9.4": [XMCP], "17.9.10": []})
    csc.first_fixed_path("iosxe", "17.9.4", fetch=f)
    csc.first_fixed_path("iosxe", "17.9.4", fetch=f)
    assert len(f.calls) == 2


def test_offline_switch_turns_the_live_lookup_off(monkeypatch):
    monkeypatch.setenv("CISCO_CHECKER_OFFLINE", "1")
    assert csc.first_fixed_path("iosxe", "17.9.4") is None


class TestAnalyzer:
    def test_ostype_selection(self):
        from api.routers.cve import _openvuln_ostype
        assert _openvuln_ostype("IOS XE", "17.9.4") == "iosxe"
        assert _openvuln_ostype("ISR4451-X", "17.9.4") == "iosxe"
        assert _openvuln_ostype("ISE", "3.4 Patch 5") is None
        assert _openvuln_ostype("NX-OS", "9.3(8)") is None

    def test_response_carries_cisco_path(self, monkeypatch):
        from api.routers import cve as router
        f = fake({"17.9.4": [HARDENING, XMCP], "17.9.10": [MEDIUM]})
        monkeypatch.setattr(router, "first_fixed_path",
                            lambda ostype, release: csc.first_fixed_path(ostype, release, fetch=f))
        resp = router.analyze_cve(router.CVEAnalyzeRequest(platform="IOS XE",
                                                           version="IOS XE 17.9.4"))
        assert resp.cisco_upgrade_path["target"] == "17.9.10"
        assert f.calls[0] == ("iosxe", "17.9.4")   # bare release, not the label

    def test_offline_response_has_no_cisco_path(self):
        from api.routers import cve as router
        resp = router.analyze_cve(router.CVEAnalyzeRequest(platform="IOS XE", version="17.9.4"))
        assert resp.cisco_upgrade_path is None
        assert resp.upgrade_target_check is not None   # dataset answer still there


def test_unknown_next_release_is_said_and_does_not_poison_the_cache():
    f = fake({"17.15.4a": [XMCP | {"firstFixed": ["17.15.6"]}],
              "17.15.6": csc.UNKNOWN_RELEASE, "17.9.4": [XMCP], "17.9.10": []})
    path = csc.first_fixed_path("iosxe", "17.15.4a", fetch=f)
    assert path["target"] is None and "no data for 17.15.6" in path["statement"]
    assert csc.first_fixed_path("iosxe", "17.9.4", fetch=f)["target"] == "17.9.10"


def test_unknown_starting_release_gives_none():
    assert csc.first_fixed_path("iosxe", "99.1.1",
                                fetch=fake({"99.1.1": csc.UNKNOWN_RELEASE})) is None
