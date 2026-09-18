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
    ("Cisco IOS XE Software Secure Boot Bypass Vulnerabilities", "secure-boot"),
    ("Cisco IOS XE Software Privilege Escalation Vulnerabilities", "privesc"),
    ("Cisco IOS XE Software Simple Network Management Protocol Denial of Service Vulnerability", "snmp"),
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
    for vtype in ("auth", "aaa", "privesc", "auth-bypass", "secure-boot"):
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


def test_feature_in_the_first_sentence_beats_effect_in_the_title():
    title = "Cisco IOS XE Software SD-Access Fabric Edge Node Denial of Service Vulnerability"
    summary = ("A vulnerability in the DHCP Snooping feature of Cisco IOS XE Software could allow "
               "an unauthenticated, remote attacker to cause high CPU utilization. More text." + LINK)
    assert _classify_vuln(title, summary) == "dhcp"


def test_vpn_routing_and_forwarding_is_not_a_vpn_bug():
    assert _classify_vuln("Cisco IOS Software RSVP Denial of Service Vulnerability",
                          "A vulnerability in RSVP on a device configured with VPN routing and forwarding (VRF) instances.") == "dos"


def test_no_imported_description_ends_mid_word():
    cut = []
    for path in glob.glob(os.path.join(ROOT, "cve_data", "ios_xe", "*.json")):
        with open(path, encoding="utf-8") as f:
            rec = json.load(f)
        if isinstance(rec, dict) and rec.get("source") == "cisco-psirt-import" \
                and rec.get("description", "").rstrip().endswith("..."):
            cut.append(rec["cve_id"])
    assert cut == []


def test_summarizer_repairs_text_cut_by_the_old_importer():
    from services.advisory_text import summarize_advisory_text
    out = summarize_advisory_text("An attacker could run code. This vulnerability is due to improper valida...")
    assert out == "An attacker could run code."
