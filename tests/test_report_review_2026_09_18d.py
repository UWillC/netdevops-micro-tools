"""Report review 2026-09-18 (d): the feature classifier and what it drives.

The classifier used to search the whole advisory summary for substrings. Every
Cisco summary ends with an https:// link, so "http" filed unrelated CVEs under
web UI and 87 auto-generated mitigation files told the reader to disable the
HTTP server for bugs in Ethernet frame handling, IKEv1 or ARP.
"""
import glob
import json
import os
import re

import pytest

from services.cisco_sync import _MIT_TEMPLATES, _classify_vuln

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LINK = " This advisory is available at the following link:https://sec.cloudapps.cisco.com/x"


@pytest.mark.parametrize("title,expected", [
    ("Cisco IOS XE Software for Catalyst 9000 Series Switches Denial of Service Vulnerability", "dos"),
    ("Cisco IOS, IOS XE, and IOS XR Software TWAMP Denial of Service Vulnerability", "dos"),
    ("Cisco IOS XE Software Secure Boot Bypass Vulnerabilities", "auth"),
    ("Cisco IOS XE Software Web UI Cross-Site Request Forgery Vulnerability", "webui"),
    ("Cisco IOS XE Software SNMP Denial of Service Vulnerability", "snmp"),
    ("Cisco IOS XE Software DHCP Snooping Denial of Service Vulnerability", "dhcp"),
    ("Multiple Vulnerabilities in OpenSSL Affecting Cisco Products: March 2021", "generic"),
    ("Cisco IOS XE Software for Wireless LAN Controllers HTTP Client Profiling Denial of Service Vulnerability", "dos"),
])
def test_title_decides_and_the_advisory_link_does_not(title, expected):
    summary = "A vulnerability could allow an unauthenticated, remote attacker to do harm." + LINK
    assert _classify_vuln(title, summary) == expected


def test_substrings_inside_words_do_not_count():
    # "unauthenticated" is not "auth"; "windows" is not "dns"; "address" is not "dos"
    assert _classify_vuln("Cisco IOS XE Software Address Handling Vulnerability",
                          "An unauthenticated attacker on Windows could send packets.") == "generic"


def test_privilege_and_aaa_bugs_do_not_get_the_web_ui_workaround():
    for vtype in ("auth", "aaa"):
        assert "no ip http server" not in json.dumps(_MIT_TEMPLATES[vtype])


def test_no_mitigation_file_disables_http_for_a_cve_that_is_not_about_http():
    offenders = []
    for path in glob.glob(os.path.join(ROOT, "cve_mitigations", "*.json")):
        with open(path, encoding="utf-8") as f:
            mit = json.load(f)
        if not isinstance(mit, dict) or "no ip http server" not in json.dumps(mit.get("workaround_steps", "")):
            continue
        rec_path = os.path.join(ROOT, "cve_data", "ios_xe", f"{mit['cve_id'].lower()}.json")
        if not os.path.exists(rec_path):
            continue
        with open(rec_path, encoding="utf-8") as f:
            rec = json.load(f)
        text = (rec.get("title", "") + " " + rec.get("description", "")[:400]).lower()
        if not re.search(r"web|http|lobby", re.sub(r"https?://\S+", " ", text)):
            offenders.append(mit["cve_id"])
    assert offenders == []


def test_sir_counter_in_the_panel_counts_confirmed_matches_only():
    with open(os.path.join(ROOT, "web", "app-security.js"), encoding="utf-8") as f:
        js = f.read()
    block = js[js.index("const sirDistinct"):js.index("const bundleCount")]
    assert "uncertainIds.has" in block
