"""v0.6.58 (C1 MITIG-AUDIT, 2026-09-25): Cisco's Workarounds section verbatim, ours labelled.

Audit of the 10 hand-written mitigations linked to CISA KEV: 7 disagreed with Cisco.
Three offered "workarounds" where Cisco says there are none; four missed or bent the one
mitigation Cisco does publish (CVE-2025-20352 lacked the SNMP view that excludes
cafSessionMethodsInfoEntry; CVE-2023-20025 skipped port 60443 and restricted the LAN instead
of the WAN; CVE-2023-20269 named the wrong tunnel groups; CVE-2026-20127 said "patch is the
ONLY mitigation" while Cisco lists an ACL on ports 22/830). Two records pointed at advisory
ids that do not exist.
"""
import glob
import io
import json
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.main import app
from services import cisco_workaround as cw
from services.cisco_workaround import fetch as real_fetch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIT = os.path.join(ROOT, "cve_mitigations")
client = TestClient(app)
DISCLAIMER = (" While this mitigation has been deployed and was proven successful in a test "
              "environment, customers should determine the applicability.")


def _mit(cve):
    with open(os.path.join(MIT, f"{cve}.json"), encoding="utf-8") as f:
        return json.load(f)


def _all_text(d):
    return json.dumps(d, ensure_ascii=False)


@pytest.mark.parametrize("text,expected", [
    ("There are no workarounds that address this vulnerability.", "none"),
    ("There are no workarounds that address this vulnerability." + DISCLAIMER, "none"),
    ("There are no workarounds that address this vulnerability. Administrators who do not "
     "use the BFD feature can disable it.", "mitigation"),
    ("If the release supports the crypto ikev2 limit queue command, set it. There are no "
     "workarounds that address this vulnerability.", "mitigation"),
    ("There are two mitigations that are preferred for addressing this.", "mitigation"),
    ("There is a workaround that addresses this vulnerability. Disable AUX.", "workaround"),
    ("Administrators may disable mLRE on an affected device.", "workaround"),
    ("", "unknown"),
])
def test_classify_follows_ciscos_wording(text, expected):
    assert cw.classify(text) == expected


def test_extract_takes_only_the_workarounds_note():
    csaf = {"document": {"notes": [
        {"title": "Summary", "text": "S"},
        {"title": "Workarounds", "text": "There are no workarounds that address this vulnerability."},
    ]}}
    built = cw.build(csaf, "cisco-sa-x", fetched="2026-09-25")
    assert built == {"status": "none",
                     "text": "There are no workarounds that address this vulnerability.",
                     "source": cw.CSAF_URL.format(sa="cisco-sa-x"), "fetched": "2026-09-25",
                     "cves": []}
    assert cw.build({"document": {"notes": []}}, "cisco-sa-x") is None


def test_advisory_id_from_url():
    url = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-x4LPhte"
    assert cw.advisory_id(url) == "cisco-sa-snmp-x4LPhte"
    assert cw.advisory_id(None) is None and cw.advisory_id("no id here") is None


def test_fetch_failure_is_none_never_an_exception():
    with patch.object(cw.urllib.request, "urlopen", side_effect=TimeoutError("t")):
        assert real_fetch("cisco-sa-x") is None
    assert real_fetch(None) is None


def test_fetch_success_builds_the_record():
    body = json.dumps({"document": {"notes": [{"title": "Workarounds", "text": "There is a workaround that addresses this vulnerability. X."}]}}).encode()

    class R(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch.object(cw.urllib.request, "urlopen", return_value=R(body)):
        assert real_fetch("cisco-sa-x")["status"] == "workaround"


def test_every_mitigation_file_carries_ciscos_text():
    files = glob.glob(os.path.join(MIT, "CVE-*.json"))
    assert len(files) == 150
    for p in files:
        with open(p, encoding="utf-8") as f:
            wa = json.load(f).get("cisco_workaround")
        assert wa and wa["text"].strip(), p
        assert wa["status"] in {"none", "mitigation", "workaround"}, p
        assert wa["source"].startswith("https://sec.cloudapps.cisco.com/"), p


def test_audited_sample_is_marked_reviewed():
    reviewed = {os.path.basename(p)[:-5] for p in glob.glob(os.path.join(MIT, "CVE-*.json"))
                if _mit(os.path.basename(p)[:-5]).get("steps_reviewed")}
    auto = {c for c in reviewed if _mit(c).get("review_method") == "auto-patch-only"}
    manual2 = {c for c in reviewed if _mit(c).get("review_method") == "manual-2of7"}
    manual3 = {c for c in reviewed if _mit(c).get("review_method") == "manual-3of7"}
    manual4 = {c for c in reviewed if _mit(c).get("review_method") == "manual-4of7"}
    manual5 = {c for c in reviewed if _mit(c).get("review_method") == "manual-5of7"}
    assert len(auto) == 54
    assert manual2 == MITIG_REVIEW_2
    assert manual3 == MITIG_REVIEW_3
    assert manual4 == MITIG_REVIEW_4
    assert manual5 == MITIG_REVIEW_5
    assert reviewed == C1_SAMPLE | MITIG_REVIEW_1 | auto | MITIG_REVIEW_2 | MITIG_REVIEW_3 | MITIG_REVIEW_4 | MITIG_REVIEW_5
    assert not auto & (C1_SAMPLE | MITIG_REVIEW_1 | MITIG_REVIEW_2 | MITIG_REVIEW_3 | MITIG_REVIEW_4 | MITIG_REVIEW_5)
    assert len(reviewed) == 150  # every mitigation file has been checked against Cisco's text


def test_every_mitigation_file_is_reviewed():
    for p in glob.glob(os.path.join(MIT, "CVE-*.json")):
        d = _mit(os.path.basename(p)[:-5])
        assert d.get("steps_reviewed"), p  # C1 sample + batch 1/7 predate review_method


C1_SAMPLE = {"CVE-2018-0171", "CVE-2018-0296", "CVE-2023-20025", "CVE-2023-20198",
             "CVE-2023-20269", "CVE-2023-20273", "CVE-2024-20353", "CVE-2024-20359",
             "CVE-2025-20352", "CVE-2026-20127"}

# MITIG-REVIEW 1/7 (2026-09-27): the 20 most recently KEV-added unreviewed files.
MITIG_REVIEW_1 = {"CVE-2026-20079", "CVE-2026-20131", "CVE-2023-20109", "CVE-2017-6742",
                  "CVE-2022-20699", "CVE-2019-1652", "CVE-2018-0175", "CVE-2018-0174",
                  "CVE-2018-0173", "CVE-2018-0172", "CVE-2018-0167", "CVE-2018-0158",
                  "CVE-2018-0156", "CVE-2018-0155", "CVE-2017-12319", "CVE-2017-12240",
                  "CVE-2017-12237", "CVE-2017-6744", "CVE-2017-6743", "CVE-2017-6740"}


# MITIG-REVIEW 2/7 (2026-09-27): 3 records under a wrong advisory, the 6 remaining KEV
# files, then the 11 most recent advisories (ties: CVE number descending).
MITIG_REVIEW_2 = {"CVE-2020-3452", "CVE-2024-20291", "CVE-2024-20356",
                  "CVE-2017-6739", "CVE-2017-6738", "CVE-2017-6737", "CVE-2017-6736",
                  "CVE-2017-6627", "CVE-2019-1653",
                  "CVE-2025-20316", "CVE-2025-20315", "CVE-2025-20312", "CVE-2025-20293",
                  "CVE-2025-20240", "CVE-2025-20160", "CVE-2025-20149", "CVE-2025-20221",
                  "CVE-2025-20202", "CVE-2025-20196", "CVE-2025-20195"}


# MITIG-REVIEW 3/7 (2026-09-28): the 16 remaining 2025 advisories (SNMP DoS x8, web UI x3,
# WLC x2, DHCP snooping, SNMPv3, ASR 903) + the 4 most recent 2024 ones.
MITIG_REVIEW_3 = {"CVE-2025-20194", "CVE-2025-20193", "CVE-2025-20189", "CVE-2025-20188",
                  "CVE-2025-20186", "CVE-2025-20176", "CVE-2025-20175", "CVE-2025-20174",
                  "CVE-2025-20173", "CVE-2025-20172", "CVE-2025-20171", "CVE-2025-20170",
                  "CVE-2025-20169", "CVE-2025-20162", "CVE-2025-20151", "CVE-2025-20140",
                  "CVE-2024-20510", "CVE-2024-20455", "CVE-2024-20437", "CVE-2024-20436"}

SNMP_DOS_2025 = {"CVE-2025-20169", "CVE-2025-20170", "CVE-2025-20171", "CVE-2025-20172",
                 "CVE-2025-20173", "CVE-2025-20174", "CVE-2025-20175", "CVE-2025-20176"}


# MITIG-REVIEW 4/7 (2026-09-28): 13 `workaround` files 2017-2024 + 7 `mitigation` files.
MITIG_REVIEW_4 = {"CVE-2017-6741", "CVE-2021-27853", "CVE-2021-27854", "CVE-2021-27861",
                  "CVE-2021-27862", "CVE-2023-20186", "CVE-2023-20187", "CVE-2024-20307",
                  "CVE-2024-20308", "CVE-2024-20309", "CVE-2024-20316", "CVE-2024-20373",
                  "CVE-2024-20414", "CVE-2024-20324", "CVE-2024-20313", "CVE-2024-20312",
                  "CVE-2024-20278", "CVE-2024-3596", "CVE-2023-20235", "CVE-2023-20076"}


# MITIG-REVIEW 5/7 (2026-09-28): the last 6 files -> 150/150.
MITIG_REVIEW_5 = {"CVE-2022-20851", "CVE-2023-20065", "CVE-2023-20066", "CVE-2023-20067",
                  "CVE-2023-20227", "CVE-2023-20231"}


@pytest.mark.parametrize("cve", sorted(MITIG_REVIEW_5))
def test_review5_no_template_leftovers(cve):
    d = _mit(cve)
    assert d["steps_reviewed"] == "2026-09-28"
    assert d["review_method"] == "manual-5of7"
    t = _all_text({k: d[k] for k in ("workaround_steps", "acl_mitigation", "recommended_fix", "detection")})
    for bad in ("copy tftp:", "Control Plane Policing", "Review advisory for specific workarounds",
                "Upgrade to patched IOS XE version", "NO PATCH"):
        assert bad not in t, bad


def test_review5_specific_cisco_text_is_reflected():
    assert "no iox" in _all_text(_mit("CVE-2023-20065")["workaround_steps"])
    assert "HTTP TLV Caching" in _all_text(_mit("CVE-2023-20067")["workaround_steps"])
    assert "eq 1701" in _all_text(_mit("CVE-2023-20227")["workaround_steps"])
    assert "Lobby Ambassador" in _all_text(_mit("CVE-2023-20231")["workaround_steps"])
    for cve in ("CVE-2022-20851", "CVE-2023-20066", "CVE-2023-20231"):
        assert _mit(cve)["acl_mitigation"] is None


@pytest.mark.parametrize("cve", sorted(MITIG_REVIEW_4))
def test_review4_no_template_leftovers(cve):
    d = _mit(cve)
    assert d["steps_reviewed"] == "2026-09-28"
    assert d["review_method"] == "manual-4of7"
    t = _all_text({k: d[k] for k in ("workaround_steps", "acl_mitigation", "recommended_fix", "detection")})
    for bad in ("copy tftp:", "Control Plane Policing", "Review advisory for specific workarounds",
                "Upgrade to patched IOS XE version", "NO PATCH", "10.0.0.200", "ISE 3.1+"):
        assert bad not in t, bad


def test_review4_specific_cisco_text_is_reflected():
    t6741 = [c for s in _mit("CVE-2017-6741")["workaround_steps"] for c in s["commands"]]
    assert sum(c.startswith("snmp-server view NO_BAD_SNMP ") for c in t6741) == 16
    assert "mac access-group CSCwa14271 in" in _all_text(_mit("CVE-2021-27853")["workaround_steps"])
    for cve in ("CVE-2021-27854", "CVE-2021-27862"):
        assert "Not a Cisco workaround" in _all_text(_mit(cve)["workaround_steps"])
        assert _mit(cve)["acl_mitigation"] is None
    assert "No mitigations or workarounds" in _all_text(_mit("CVE-2021-27861")["workaround_steps"])
    assert "no ip scp server enable" in _all_text(_mit("CVE-2023-20186")["workaround_steps"])
    assert "platform multicast lre off" in _all_text(_mit("CVE-2023-20187")["workaround_steps"])
    assert "default buffers huge size" in _all_text(_mit("CVE-2024-20307")["workaround_steps"])
    assert "no crypto isakmp fragmentation" in _all_text(_mit("CVE-2024-20308")["workaround_steps"])
    assert "transport input none" in _all_text(_mit("CVE-2024-20309")["workaround_steps"])
    assert "standard named" in _all_text(_mit("CVE-2024-20373")["workaround_steps"])
    assert "no iox" in _all_text(_mit("CVE-2023-20076")["workaround_steps"])
    assert "DTLS" in _all_text(_mit("CVE-2024-3596")["workaround_steps"])
    assert _mit("CVE-2024-20414")["acl_mitigation"] is None


@pytest.mark.parametrize("cve", sorted(MITIG_REVIEW_3))
def test_review3_no_template_leftovers(cve):
    d = _mit(cve)
    assert d["steps_reviewed"] == "2026-09-28"
    assert d["review_method"] == "manual-3of7"
    t = _all_text({k: d[k] for k in ("workaround_steps", "acl_mitigation", "recommended_fix", "detection")})
    for bad in ("copy tftp:", "Control Plane Policing", "Review advisory for specific workarounds",
                "Upgrade to patched IOS XE version", "NO PATCH", "no ap image upgrade"):
        assert bad not in t, bad


@pytest.mark.parametrize("cve", sorted(SNMP_DOS_2025))
def test_review3_snmp_dos_files_carry_ciscos_oid_view(cve):
    """cisco-sa-snmp-dos-sdxnSUcW: Cisco's mitigation is an SNMP view excluding 52 OIDs,
    applied to every community and v3 group. Same error class as C1's CVE-2025-20352."""
    d = _mit(cve)
    cmds = [c for s in d["workaround_steps"] for c in s["commands"]]
    excluded = [c for c in cmds if c.startswith("snmp-server view SNMP_DOS ") and c.endswith(" excluded")]
    assert len(excluded) == 52 + 3, len(excluded)  # 52 OIDs + snmpUsmMIB/snmpVacmMIB/snmpCommunityMIB
    assert "snmp-server view SNMP_DOS ipAddressPrefixEntry.5 excluded" in cmds
    assert "snmp-server community <COMMUNITY> view SNMP_DOS RO" in cmds
    assert "snmp-server group <V3_GROUP> v3 auth read SNMP_DOS write SNMP_DOS" in cmds


def test_review3_specific_cisco_text_is_reflected():
    assert "no wireless ipv6 client" in _all_text(_mit("CVE-2025-20140")["workaround_steps"])
    assert "ip dhcp snooping vlan" in _all_text(_mit("CVE-2025-20162")["workaround_steps"])
    assert "no service internal" in _all_text(_mit("CVE-2024-20437")["workaround_steps"])
    assert "lobby" in _all_text(_mit("CVE-2025-20186")["workaround_steps"])
    assert "uea_mgr" in _all_text(_mit("CVE-2025-20189")["workaround_steps"])
    t188 = _all_text(_mit("CVE-2025-20188")["workaround_steps"])
    assert "deny tcp any any eq 8443" in t188 and "debug wireless bundle client" in t188
    assert "Airespace IPv6 ACL Name" in _all_text(_mit("CVE-2024-20510")["workaround_steps"])
    assert _mit("CVE-2024-20436")["acl_mitigation"] is None
    assert _mit("CVE-2024-20437")["acl_mitigation"] is None


@pytest.mark.parametrize("cve", sorted(MITIG_REVIEW_2))
def test_review2_no_template_leftovers(cve):
    d = _mit(cve)
    assert d["steps_reviewed"] == "2026-09-27"
    t = _all_text({k: d[k] for k in ("workaround_steps", "acl_mitigation", "recommended_fix", "detection")})
    for bad in ("copy tftp:", "Control Plane Policing", "Review advisory for specific workarounds",
                "Upgrade to patched IOS XE version", "NO PATCH"):
        assert bad not in t, bad


def test_review2_wrong_advisories_rehomed():
    expected = {"CVE-2020-3452": "cisco-sa-asaftd-ro-path-KJuQhB86",
                "CVE-2024-20291": "cisco-sa-nxos-po-acl-TkyePgvL",
                "CVE-2024-20356": "cisco-sa-cimc-cmd-inj-bLuPcb"}
    for cve, sa in expected.items():
        d = _mit(cve)
        assert cw.advisory_id(d["cisco_psirt"]) == sa
        assert cw.advisory_id(d["cisco_workaround"]["source"]) == sa
        assert cve in d["cisco_workaround"]["cves"]
    # CVE-2024-20291 was a copy of CVE-2024-20399 (NX-OS CLI command injection).
    t = _all_text(_mit("CVE-2024-20291"))
    assert "command injection" not in t.lower() and "port channel" in t
    assert "ip access-group <ACL_NAME> in" in t
    # Cisco's ASA/FTD table, not the old higher-but-unsourced numbers.
    t = _all_text(_mit("CVE-2020-3452"))
    assert "9.6.4.42" in t and "9.6.4.45" not in t and "6.2.3.16" in t
    # IMC M7: 4.3(2.240009) is not a fix on M7 (Cisco: 4.3(3.240022)).
    fix = _mit("CVE-2024-20356")["recommended_fix"]
    assert "M7: 4.3 -> 4.3(3.240022)" in fix


@pytest.mark.parametrize("cve", ["CVE-2020-3452", "CVE-2024-20356"])
def test_review2_none_means_patch_only(cve):
    d = _mit(cve)
    assert d["cisco_workaround"]["status"] in {"none", "mitigation"}
    assert d["acl_mitigation"] is None
    for step in d["workaround_steps"][:2]:
        assert "Not a Cisco workaround" in step["platform_notes"]


@pytest.mark.parametrize("cve", ["CVE-2017-6736", "CVE-2017-6737", "CVE-2017-6738", "CVE-2017-6739"])
def test_review2_snmp_2017_same_view_as_6740(cve):
    d, ref = _mit(cve), _mit("CVE-2017-6740")
    assert d["workaround_steps"] == ref["workaround_steps"]
    assert "snmp-server view NO_BAD_SNMP ciscoMabMIB excluded" in _all_text(d)


def test_review2_cisco_mitigations_present():
    def cmds(cve):
        return [c for s in _mit(cve)["workaround_steps"] for c in s["commands"]]
    assert " hold-queue 350 in" in cmds("CVE-2017-6627")
    assert " 10 deny udp any any eq 0" in cmds("CVE-2017-6627")
    rv = _mit("CVE-2019-1653")
    assert "1.4.2.22" in rv["recommended_fix"] and "# Web UI: Firewall > General" in cmds("CVE-2019-1653")
    assert "no-patch" not in rv["tags"] and "config.exp" not in _all_text(rv)
    assert "no ip nbar classification tunneled-traffic capwap" in cmds("CVE-2025-20315")
    assert "snmp-server view SNMP_DOS cbQosREDClassStatsEntry excluded" in cmds("CVE-2025-20312")
    assert "crypto pki server <WLC_HOSTNAME>_WLC_CA" in cmds("CVE-2025-20293")
    assert "no shell processing full" in cmds("CVE-2025-20149")
    assert " no cdp" in cmds("CVE-2025-20202")
    assert "no iox" in cmds("CVE-2025-20196")
    assert "ip http access-class ipv4 restrict_ipv4_webui" in cmds("CVE-2025-20195")
    assert "no ip http secure-server" in cmds("CVE-2025-20240")
    assert "show running-config | include interface Vlan|out$" in cmds("CVE-2025-20316")
    tac = _all_text(_mit("CVE-2025-20160"))
    assert "tacacs-server key YOUR-GLOBAL-SECRET" not in tac and "eq 49" not in tac


@pytest.mark.parametrize("cve", sorted(c for c in MITIG_REVIEW_1 if _mit(c)["cisco_workaround"]["status"] == "none"))
def test_review1_none_means_patch_only(cve):
    """Cisco says no workarounds: no ACL block, every step says so, no generic CoPP 'mitigation'."""
    d = _mit(cve)
    assert d["acl_mitigation"] is None
    for step in d["workaround_steps"]:
        assert "Not a Cisco workaround" in (step.get("platform_notes") or ""), step["description"]
        assert "CoPP" not in step["description"]


@pytest.mark.parametrize("cve", ["CVE-2017-6740", "CVE-2017-6742", "CVE-2017-6743", "CVE-2017-6744"])
def test_review1_snmp_2017_carries_ciscos_view_and_no_v3_myth(cve):
    d = _mit(cve)
    cmds = [c for s in d["workaround_steps"] for c in s["commands"]]
    for line in ("snmp-server view NO_BAD_SNMP ciscoMgmt.252 excluded",
                 "snmp-server view NO_BAD_SNMP ciscoMabMIB excluded",
                 "snmp-server view NO_BAD_SNMP ciscoExperiment.997 excluded"):
        assert line in cmds
    text = _all_text({k: d[k] for k in ("workaround_steps", "detection", "verification", "risk_summary")})
    assert "not vulnerable" not in text and "SNMPv3 only" not in text
    assert "EXTRABACON" not in text.upper()


def test_review1_fmc_fixed_releases_follow_cisco():
    for cve in ("CVE-2026-20079", "CVE-2026-20131"):
        d = _mit(cve)
        assert "7.6.0.1 or later" not in _all_text(d)
    assert "7.6 -> 7.6.6" in _mit("CVE-2026-20079")["recommended_fix"]


def test_review1_cisco_mitigations_present():
    def cmds(cve):
        return [c for s in _mit(cve)["workaround_steps"] for c in s["commands"]]
    assert "no vstack" in cmds("CVE-2018-0156")
    assert "feature bfd disable" in cmds("CVE-2018-0155")
    assert any(c.startswith("crypto ikev2 limit queue sa-init") for c in cmds("CVE-2017-12237"))
    rv = _mit("CVE-2019-1652")
    assert "1.4.2.22" in rv["recommended_fix"] and "NO PATCH" not in _all_text(rv)
    assert "# Web UI: Firewall > General" in cmds("CVE-2019-1652")


@pytest.mark.parametrize("cve", ["CVE-2018-0296", "CVE-2024-20353", "CVE-2024-20359"])
def test_where_cisco_says_none_our_steps_say_so(cve):
    d = _mit(cve)
    assert d["cisco_workaround"]["status"] == "none"
    for step in d["workaround_steps"]:
        assert "Not a Cisco workaround" in (step.get("platform_notes") or ""), step["description"]


def test_snmp_2025_20352_has_ciscos_oid_exclusion():
    t = _all_text(_mit("CVE-2025-20352"))
    assert "snmp-server view NO_BAD_SNMP cafSessionMethodsInfoEntry excluded" in t
    assert "before 17.15.4a" not in t


def test_rv_2023_20025_blocks_443_and_60443_on_the_wan():
    t = _all_text(_mit("CVE-2023-20025"))
    assert "60443" in t and "Firewall > General" in t and "WAN" in t


def test_asa_2023_20269_targets_the_right_groups():
    t = _all_text(_mit("CVE-2023-20269"))
    assert "vpn-simultaneous-logins 0" in t and "DefaultADMINGroup" in t and "group-lock" in t
    assert "authentication certificate" not in t and "DefaultRAGroup" not in t


def test_sdwan_2026_20127_uses_ciscos_port_mitigation():
    t = _all_text(_mit("CVE-2026-20127"))
    assert "830" in t and "Patch is the ONLY mitigation" not in t


def test_no_invalid_asa_management_syntax():
    for p in glob.glob(os.path.join(MIT, "CVE-*.json")):
        with open(p, encoding="utf-8") as f:
            t = f.read()
        for bad in ('"no http outside"', '"no ssh outside"', '"no telnet outside"'):
            assert bad not in t, (p, bad)


def test_api_returns_ciscos_text():
    r = client.get("/mitigate/cve/CVE-2025-20352")
    assert r.status_code == 200
    m = r.json()["mitigation"]
    assert m["cisco_workaround"]["status"] == "mitigation"
    assert m["steps_reviewed"] == "2026-09-25"


def test_ui_shows_ciscos_text_as_text_not_html():
    with open(os.path.join(ROOT, "web", "app-network.js"), encoding="utf-8") as f:
        js = f.read()
    block = js[js.index("function renderCiscoWorkaround"):js.index("// Render references")]
    assert 'setText("mitigation-cisco-text", wa.text)' in block
    assert "innerHTML" not in block
    assert "Additional hardening (ours, not a Cisco workaround)" in block
    with open(os.path.join(ROOT, "web", "index.html"), encoding="utf-8") as f:
        html = f.read()
    assert 'id="mitigation-cisco-section"' in html and 'id="mitigation-steps-review"' in html


def test_imports_attach_ciscos_text():
    from services import cisco_sync
    import scripts.import_cisco_to_local as imp
    for mod in (cisco_sync, imp):
        with open(mod.__file__, encoding="utf-8") as f:
            src = f.read()
        assert 'cisco_workaround.fetch_checked(mit_data.get("cisco_psirt"), cve_upper)' in src
