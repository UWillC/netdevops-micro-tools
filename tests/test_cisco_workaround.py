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
                     "source": cw.CSAF_URL.format(sa="cisco-sa-x"), "fetched": "2026-09-25"}
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
    assert reviewed == {"CVE-2018-0171", "CVE-2018-0296", "CVE-2023-20025", "CVE-2023-20198",
                        "CVE-2023-20269", "CVE-2023-20273", "CVE-2024-20353", "CVE-2024-20359",
                        "CVE-2025-20352", "CVE-2026-20127"}


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
        assert 'cisco_workaround.fetch(mit_data.get("cisco_psirt"))' in src
