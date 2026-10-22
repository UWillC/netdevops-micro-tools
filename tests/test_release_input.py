"""
MATCH-02 (2026-10-22): the version box is free text.

Found while testing UPG-01: for platform "IOS XE", "17.9.4" matched 71 CVEs,
"IOS XE 17.9.4" matched 5 (a false near-clean report) and the first line of
`show version` matched 104 (no Known Affected filter). All spellings of one
release must give one answer.
"""

import pytest

from services.known_affected import clean_release_input


def analyze(platform, version):
    from api.routers.cve import CVEAnalyzeRequest, analyze_cve
    return analyze_cve(CVEAnalyzeRequest(platform=platform, version=version))


@pytest.mark.parametrize("raw, bare", [
    ("17.9.4", "17.9.4"),
    ("IOS XE 17.9.4", "17.9.4"),
    ("ios-xe 17.9.4", "17.9.4"),
    ("Cisco IOS XE 17.09.04a", "17.09.04a"),
    ("Cisco IOS XE Software, Version 17.9.4", "17.9.4"),
    ("Cisco IOS XE Software, Version 16.12.13", "16.12.13"),
    ("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc3)",
     "15.2(7)E3"),
    ("Cisco IOS Software [Fuji], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 16.9.4, RELEASE SOFTWARE",
     "16.9.4"),
    ("IOS 15.2(7)E3", "15.2(7)E3"),
])
def test_ios_labels_reduce_to_the_release(raw, bare):
    assert clean_release_input(raw) == bare


@pytest.mark.parametrize("raw", [
    "ISE 3.4 Patch 5", "3.4 Patch 5", "9.3(8)", "NX-OS 10.2(6)",
    "Catalyst SD-WAN 20.18.2.1", "7.4.2", "",
])
def test_other_products_are_left_alone(raw):
    assert clean_release_input(raw) == raw.strip()


@pytest.mark.parametrize("platform, spellings", [
    ("IOS XE", ["17.9.4", "IOS XE 17.9.4", "Cisco IOS XE Software, Version 17.9.4"]),
    ("IOS XE", ["17.12.1", "Cisco IOS XE 17.12.1"]),
])
def test_one_release_one_answer(platform, spellings):
    results = [sorted(c.cve_id for c in analyze(platform, v).matched) for v in spellings]
    assert results[0], "baseline must match something"
    for r in results[1:]:
        assert r == results[0]


def test_response_echoes_what_the_user_typed():
    raw = "Cisco IOS XE Software, Version 17.9.4"
    resp = analyze("IOS XE", raw)
    assert resp.version == raw
    assert resp.upgrade_target_check and resp.upgrade_target_check["safe"] is True
