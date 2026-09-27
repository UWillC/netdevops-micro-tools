"""MITIG-REVIEW auto (2026-09-27): patch-only only where Cisco says there is no workaround."""
import copy
import glob
import json
import os

import pytest

from scripts import mitig_patch_only as mp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIT = os.path.join(ROOT, "cve_mitigations")
SRC = ("https://sec.cloudapps.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/"
       "cisco-sa-x-AbC123/csaf/cisco-sa-x-AbC123.json")


def _wa(text, status="none"):
    return {"status": status, "text": text, "source": SRC, "fetched": "2026-09-25"}


@pytest.mark.parametrize("wa,expected", [
    (_wa("There are no workarounds that address this vulnerability."), mp.NO_WORKAROUND),
    (_wa("There are no workarounds that address these vulnerabilities."), mp.NO_WORKAROUND),
    (_wa("  There are no  workarounds that address\r\nthis vulnerability. "), mp.NO_WORKAROUND),
    # "no workarounds" next to a real Cisco mitigation is NOT the undisputed case
    (_wa("There are no workarounds that address this vulnerability.\r\n\r\nDisabling the HTTP "
         "Server feature eliminates the attack vector.", "mitigation"), mp.HAS_WORKAROUND),
    (_wa("There is a workaround that addresses this vulnerability. Disable AUX.", "workaround"),
     mp.HAS_WORKAROUND),
    # bare sentence but a status that disagrees -> leave it for a human
    (_wa("There are no workarounds that address this vulnerability.", "mitigation"),
     mp.HAS_WORKAROUND),
    (_wa(""), mp.UNKNOWN),
    (None, mp.UNKNOWN),
])
def test_classifier(wa, expected):
    assert mp.classify(wa) == expected


def _template_record(wa_text="There are no workarounds that address this vulnerability.",
                     status="none"):
    return {
        "cve_id": "CVE-2099-0001",
        "risk_summary": "A vulnerability in Cisco IOS XE Software could allow ...",
        "attack_vector": "See advisory",
        "workaround_steps": [
            {"order": 1, "description": "Check current software version",
             "commands": ["show version"], "platform_notes": "Check advisory."},
            {"order": 2, "description": "Apply Control Plane Policing (CoPP)",
             "commands": ["control-plane", " service-policy input COPP"], "platform_notes": None},
            {"order": 3, "description": "Upgrade to patched version",
             "commands": ["copy tftp: flash:", "reload"], "platform_notes": None},
        ],
        "acl_mitigation": {"description": "x", "acl_name": "A", "commands": ["deny ip any any"],
                           "apply_to": "vty"},
        "recommended_fix": "Upgrade to patched IOS XE version.",
        "upgrade_path": None,
        "detection": {"description": "d", "commands": ["show version"], "vulnerable_if": "v"},
        "verification": {"description": "v", "commands": ["show version"], "expected_output": "e"},
        "cisco_psirt": ("https://sec.cloudapps.cisco.com/security/center/content/"
                        "CiscoSecurityAdvisory/cisco-sa-x-AbC123"),
        "tags": ["cisco-psirt"],
        "last_updated": "2026-01-01",
        "cisco_workaround": _wa(wa_text, status),
    }


def test_transform_is_patch_only():
    rec = _template_record()
    before = copy.deepcopy(rec)
    out = mp.patch_only(rec)
    assert rec == before  # input not mutated
    assert out["acl_mitigation"] is None
    assert out["steps_reviewed"] == "2026-09-27"
    assert out["review_method"] == "auto-patch-only"
    text = json.dumps(out["workaround_steps"])
    for bad in ("CoPP", "control-plane", "copy tftp", "reload", "Review advisory for"):
        assert bad not in text
    for step in out["workaround_steps"]:
        assert "Not a Cisco workaround" in step["platform_notes"]
    assert "cisco-sa-x-AbC123" in out["recommended_fix"]
    assert "Cisco: no workarounds" in out["recommended_fix"]
    assert "IOS XE" not in out["recommended_fix"]  # product wording stays neutral
    # Cisco's text, identity and metadata are untouched
    for k in ("cve_id", "risk_summary", "attack_vector", "cisco_workaround", "cisco_psirt",
              "tags", "last_updated"):
        assert out[k] == before[k]


def test_unknown_product_gets_no_show_version():
    rec = _template_record()
    rec["risk_summary"] = "A vulnerability in Cisco Smart Software Manager On-Prem ..."
    out = mp.patch_only(rec)
    cmds = [c for s in out["workaround_steps"] for c in s["commands"]]
    assert "show version" not in cmds and "show version" not in out["detection"]["commands"]


def _write(tmp_path, name, rec):
    p = tmp_path / f"{name}.json"
    p.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
    return p


def _lists(*cves):
    return lambda sa: set(cves)


def test_run_skips_record_whose_advisory_is_for_another_cve(tmp_path):
    a = _write(tmp_path, "CVE-2099-0001", _template_record())
    before = a.read_text()
    r = mp.run(str(tmp_path), cve_lookup=_lists("CVE-2099-9999"))
    assert r["changed"] == [] and r[mp.NO_WORKAROUND] == []
    assert r[mp.UNKNOWN][0][0] == "CVE-2099-0001" and "does not list" in r[mp.UNKNOWN][0][2]
    r = mp.run(str(tmp_path), cve_lookup=lambda sa: None)  # CSAF fetch failed
    assert r["changed"] == [] and r[mp.UNKNOWN][0][2] == "advisory CVE list not checked"
    assert a.read_text() == before


def test_run_rewrites_only_no_workaround_and_is_idempotent(tmp_path):
    a = _write(tmp_path, "CVE-2099-0001", _template_record())
    b_rec = _template_record("There are no workarounds that address this vulnerability. "
                             "However, administrators may disable the feature.", "mitigation")
    b_rec["cve_id"] = "CVE-2099-0002"
    b = _write(tmp_path, "CVE-2099-0002", b_rec)
    reviewed = _template_record()
    reviewed["cve_id"] = "CVE-2099-0003"
    reviewed["steps_reviewed"] = "2026-09-25"
    c = _write(tmp_path, "CVE-2099-0003", reviewed)
    b_before, c_before = b.read_text(), c.read_text()

    look = _lists("CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003")
    dry = mp.run(str(tmp_path), dry_run=True, cve_lookup=look)
    assert [x[0] for x in dry[mp.NO_WORKAROUND]] == ["CVE-2099-0001"]
    assert dry["changed"] == []
    assert json.loads(a.read_text())["acl_mitigation"] is not None  # dry run wrote nothing

    first = mp.run(str(tmp_path), cve_lookup=look)
    assert first["changed"] == ["CVE-2099-0001"]
    assert [x[0] for x in first[mp.HAS_WORKAROUND]] == ["CVE-2099-0002"]
    assert b.read_text() == b_before and c.read_text() == c_before
    after_first = a.read_text()

    second = mp.run(str(tmp_path), cve_lookup=look)
    assert second["changed"] == [] and second[mp.NO_WORKAROUND] == []
    assert a.read_text() == after_first


# Records whose cisco_psirt points at an advisory for a different CVE (CSAF check 2026-09-27).
ADVISORY_MISMATCH = {"CVE-2020-3452", "CVE-2024-20291", "CVE-2024-20356"}


def test_repo_has_nothing_left_to_auto_review():
    """Offline: every bare 'no workarounds' record left unreviewed is a known mismatch."""
    left = {c for c, _, _ in mp.run(MIT, dry_run=True, cve_lookup=lambda sa: None)[mp.UNKNOWN]}
    assert left == ADVISORY_MISMATCH


def test_auto_reviewed_files_are_patch_only_and_cisco_says_none():
    auto = []
    for p in glob.glob(os.path.join(MIT, "CVE-*.json")):
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        if d.get("review_method") != "auto-patch-only":
            continue
        auto.append(d["cve_id"])
        assert d["cisco_workaround"]["status"] == "none"
        assert mp._NO_WA_RE.match(mp._norm(d["cisco_workaround"]["text"]))
        assert d["acl_mitigation"] is None
        assert d["steps_reviewed"] == "2026-09-27"
        for step in d["workaround_steps"]:
            assert "Not a Cisco workaround" in step["platform_notes"]
            assert "CoPP" not in step["description"]
    assert len(auto) == 54
    assert not set(auto) & ADVISORY_MISMATCH


def test_api_loads_auto_reviewed_record():
    from fastapi.testclient import TestClient
    from api.main import app
    r = TestClient(app).get("/mitigate/cve/CVE-2025-20214")
    assert r.status_code == 200
    m = r.json()["mitigation"]
    assert m["steps_reviewed"] == "2026-09-27"
    assert m["acl_mitigation"] is None
