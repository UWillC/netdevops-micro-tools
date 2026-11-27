"""
PREVIEW-01, version of 22.11: ONE finding with a change plan before the e-mail gate.
Spec (CEO repo) projects/netdevops/specs/2026-11-20_podglad-bez-konta.md, AC-6, AC-18,
AC-19, T12-T14. No network: KEV and openVuln stay offline (conftest), KEV hits come from
the kev_index fixture.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.routers import cve as cve_router
from api.routers import cve_preview as pv
from services import preview_plan as pp
from services.cve_engine import CVEEngine, CVEEngineConfig
from services.mitigation_service import get_mitigation_service

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
PATH = "/analyze/cve/preview"
CVE_IDS = re.compile(r"CVE-\d{4}-\d+", re.I)
SECTION_IDS = ["applies", "workaround", "target", "upgrade", "verify", "sources", "rollback"]


@pytest.fixture(autouse=True)
def _preview_env(monkeypatch):
    monkeypatch.setenv("PREVIEW_ENABLED", "1")
    monkeypatch.setattr(cve_router, "dataset_is_syncing", lambda key: False)
    monkeypatch.setattr(pv, "budget", pv.OpenVulnBudget())


@pytest.fixture
def client():
    return TestClient(app)


def _preview(client, platform, version):
    r = client.post(PATH, json={"platform": platform, "version": version})
    assert r.status_code == 200, r.text
    return r


def _ids(text):
    return {i.upper() for i in CVE_IDS.findall(text)}


@pytest.fixture(scope="module")
def ios_xe_cves():
    e = CVEEngine(config=CVEEngineConfig(engine_version="0.3.7", data_dir="cve_data/ios_xe"))
    e.load_all()
    return {c.cve_id.upper(): c for c in e.cves}


# ------------------------------------------------------------------ AC-6

def test_ac6_exactly_one_cve_id_in_the_whole_json(client):
    r = _preview(client, "IOS XE", "17.9.4")
    d = r.json()
    assert d["state"] == "findings" and d["top_finding"]
    assert _ids(r.text) == {d["top_finding"]["cve_id"].upper()}
    assert d["more_findings"] == d["critical"] + d["high"] - 1


@pytest.mark.parametrize("platform,version", [
    ("IOS XE", "17.6.3"), ("ISE", "3.2 Patch 4"), ("NX-OS", "10.2(6)"), ("IOS", "15.2(7)E8"),
    ("IOS", "15.7(3)M5"), ("Catalyst SD-WAN Manager", "20.12.5"),
    ("Catalyst SD-WAN Controller", "20.12.5"), ("IOS XE", "17.15.4a")])
def test_ac6_never_more_than_one_id(client, platform, version):
    r = _preview(client, platform, version)
    d = r.json()
    top = d.get("top_finding")
    assert _ids(r.text) == ({top["cve_id"].upper()} if top else set())


def test_ac6_sibling_ids_in_cisco_text_are_replaced(ios_xe_cves, monkeypatch):
    # CVE-2023-20273's texts name CVE-2023-20198 (same advisory chain). Since the user
    # decision 23.11 (1) only the first Cisco paragraph is shown, which for this CVE no
    # longer names the sibling, so the shown texts get one on purpose.
    svc = get_mitigation_service()
    m = svc.get_mitigation("CVE-2023-20273").mitigation
    cw = m.cisco_workaround.model_copy(update={
        "text": "Also see CVE-2023-20198 and cve 2023 20199.\r\n\r\nRest names CVE-2023-20200."})
    m = m.model_copy(update={"cisco_workaround": cw, "detection": m.detection.model_copy(
        update={"description": m.detection.description + " Chained with CVE-2023-20198."})})
    real = svc.get_mitigation_for_platform

    def fake(cve_id, platform=None, version=None):
        return real(cve_id, platform, version).model_copy(update={"mitigation": m})
    monkeypatch.setattr(svc, "get_mitigation_for_platform", fake)
    entry = ios_xe_cves["CVE-2023-20273"]
    full = SimpleNamespace(matched=[entry], coverage_uncertain=[])
    tf = pp.build_top_finding(full, "IOS XE", "17.9.4", None, "2026-11-22", eol=False)
    text = tf.model_dump_json()
    assert _ids(text) == {"CVE-2023-20273"}
    assert pp.OTHER_CVE in text


def test_link_filter():
    own = "CVE-2023-20198"
    assert pp._link("x", "https://sec.cloudapps.cisco.com/security/center/x", own)
    assert pp._link("x", "https://www.cisa.gov/known-exploited", own)
    for bad in ["javascript:alert(1)", "http://www.cisco.com/x", "https://evil.example/x",
                "https://cisco.com.evil.example/x", "https://www.cisa.gov/x?q=CVE-2023-20273", None, 7,
                "https://evil.com\\@cisco.com/x", "https://evil.com\\.cisco.com/", "https://u:p@www.cisco.com/x",
                "https://www.cisco.com/x?q=CVE%2D2023%2D20273", "https://www.cisco.com/x cve_2023_20273",
                "https://www.cisco.com/x?q=cve_2023_20273"]:
        assert pp._link("x", bad, own) is None, bad


# ------------------------------------------------------------------ AC-18

def _cve(cid, cvss, kev=False, published="2025-01-01", severity="high"):
    return SimpleNamespace(cve_id=cid, cvss_score=cvss, kev=object() if kev else None,
                           published=published, severity=severity)


def test_ac18_kev_beats_higher_cvss():
    a = _cve("CVE-2025-0001", 10.0)
    b = _cve("CVE-2025-0002", 7.5, kev=True)
    assert pp.pick_top([a, b], []).cve_id == "CVE-2025-0002"


def test_ac18_cvss_tie_newest_publication_wins_then_id():
    old = _cve("CVE-2025-0001", 9.8, published="2024-03-01")
    new = _cve("CVE-2025-0009", 9.8, published="2025-09-24")
    assert pp.pick_top([old, new], []).cve_id == "CVE-2025-0009"
    x = _cve("CVE-2025-0005", 9.8, published="2025-09-24")
    assert pp.pick_top([new, x, old], []).cve_id == "CVE-2025-0005"


def test_ac18_only_uncertain_gets_needs_confirmation(ios_xe_cves):
    entry = ios_xe_cves["CVE-2023-20198"]
    full = SimpleNamespace(matched=[entry], coverage_uncertain=["CVE-2023-20198"])
    tf = pp.build_top_finding(full, "IOS XE", "17.9.4", None, None, eol=False)
    assert tf.needs_confirmation is True and tf.header == "Needs confirmation on your device"
    assert tf.plan[0].id == "applies"


def test_ac18_certain_beats_uncertain_kev():
    sure = _cve("CVE-2025-0001", 7.0)
    unsure = _cve("CVE-2025-0002", 10.0, kev=True)
    assert pp.pick_top([unsure, sure], ["CVE-2025-0002"]).cve_id == "CVE-2025-0001"


def test_ac18_medium_low_never_picked_and_clean_has_no_plan(client, monkeypatch):
    # T4 (AC-18 v24.11): Medium/Low WITHOUT KEV never picked; clean without KEV = no plan.
    assert pp.pick_top([_cve("CVE-2025-0001", 6.0, severity="medium"),
                        _cve("CVE-2025-0002", 3.1, severity="low")], []) is None
    hi = _cve("CVE-2025-0003", 7.0)
    assert pp.pick_top([_cve("CVE-2025-0001", 6.9, severity="medium"), hi], []) is hi
    monkeypatch.setattr(pv, "release_listed", lambda engine, version: True)
    d = _preview(client, "IOS XE", "17.15.4a").json()
    assert d["state"] == "clean" and d["kev"] == 0
    assert d["top_finding"] is None and d["more_findings"] is None


# ------------------------------------------------------------------ AC-18 v24.11 (spec section 10, 24.11)

def test_t2_kev_medium_beats_critical_without_kev():
    crit = _cve("CVE-2025-0001", 9.8, severity="critical")
    kev_med = _cve("CVE-2025-0002", 6.0, kev=True, severity="medium")
    assert pp.pick_top([crit, kev_med], []) is kev_med


def test_t3_kev_medium_vs_kev_high_cvss_decides():
    kev_med = _cve("CVE-2025-0001", 6.0, kev=True, severity="medium")
    kev_high = _cve("CVE-2025-0002", 8.6, kev=True, severity="high")
    assert pp.pick_top([kev_med, kev_high], []) is kev_high


def test_t6_certain_high_beats_uncertain_kev_medium():
    high = _cve("CVE-2025-0001", 7.5)
    kev_med = _cve("CVE-2025-0002", 6.0, kev=True, severity="medium")
    assert pp.pick_top([kev_med, high], ["CVE-2025-0002"]) is high


def test_more_findings_counts_only_other_critical_high():
    top = lambda sev: SimpleNamespace(severity=sev)
    assert pp.count_more_findings(2, 3, None) is None
    assert pp.count_more_findings(2, 3, top("Critical")) == 4
    assert pp.count_more_findings(2, 3, top("Medium")) == 5
    assert pp.count_more_findings(0, 0, top("Low")) == 0
    assert pp.count_more_findings(0, 1, top("High")) == 0


NXOS_KEV = "CVE-2024-20399"


def test_t1_t7_nxos_kev_medium_is_the_plan(client, kev_index):
    kev_index({NXOS_KEV: {"date_added": "2024-07-02"}})
    r = _preview(client, "NX-OS", "10.2(6)")
    d = r.json()
    tf = d["top_finding"]
    assert d["state"] == "findings" and d["kev"] == 1
    assert (tf["cve_id"], tf["kev"], tf["severity"]) == (NXOS_KEV, True, "Medium")
    assert tf["header"] is None   # UI shows the KEV header ("Fix this one first: listed by CISA ...")
    assert d["more_findings"] == d["critical"] + d["high"]
    # T7 (AC-6): exactly one CVE id in the whole JSON.
    assert _ids(r.text) == {NXOS_KEV}


def test_t5_clean_with_kev_medium_has_a_plan(client, kev_index, monkeypatch):
    kev_index({NXOS_KEV: {"date_added": "2024-07-02"}})
    real = cve_router.run_analysis

    def only_medium(req, **kw):
        full = real(req, **kw)
        keep = [c for c in full.matched if c.cve_id == NXOS_KEV]
        assert keep, "fixture: NX-OS 10.2(6) must match CVE-2024-20399"
        full.matched = keep
        full.summary = dict(full.summary or {}, critical=0, high=0, medium=1, low=0)
        return full

    monkeypatch.setattr(cve_router, "run_analysis", only_medium)
    d = _preview(client, "NX-OS", "10.2(6)").json()
    assert d["state"] == "clean" and d["critical"] == 0 and d["high"] == 0 and d["kev"] == 1
    assert d["top_finding"]["cve_id"] == NXOS_KEV and d["top_finding"]["kev"] is True
    assert d["more_findings"] == 0


def _only_nxos_kev_medium(monkeypatch):
    real = cve_router.run_analysis

    def only_medium(req, **kw):
        full = real(req, **kw)
        keep = [c for c in full.matched if c.cve_id == NXOS_KEV]
        assert keep, "fixture: NX-OS 10.2(6) must match CVE-2024-20399"
        full.matched = keep
        full.summary = dict(full.summary or {}, critical=0, high=0, medium=1, low=0)
        return full

    monkeypatch.setattr(cve_router, "run_analysis", only_medium)


def test_r1_unlisted_release_no_cisco_answer_kev_medium_gets_the_plan(client, kev_index,
                                                                        monkeypatch):
    # @ciso R1 (24.11) + AC-18 v24.11 "clean + KEV -> plan": a release outside the
    # Known Affected lists, Cisco silent (release_known -> None), 0 Critical/High but a
    # KEV Medium match is not hidden behind "unknown".
    kev_index({NXOS_KEV: {"date_added": "2024-07-02"}})
    _only_nxos_kev_medium(monkeypatch)
    monkeypatch.setattr(pv, "release_listed", lambda engine, version: False)
    monkeypatch.setattr(pv.csc, "release_known", lambda *a, **kw: None)
    r = _preview(client, "NX-OS", "10.2(6)")
    d = r.json()
    assert d["state"] == "clean" and d["critical"] == 0 and d["high"] == 0 and d["kev"] == 1
    assert d["top_finding"]["cve_id"] == NXOS_KEV and d["top_finding"]["kev"] is True
    assert d["more_findings"] == 0
    assert _ids(r.text) == {NXOS_KEV}


def test_r1_unlisted_release_no_cisco_answer_without_kev_stays_unknown(client, kev_index,
                                                                        monkeypatch):
    kev_index({})
    _only_nxos_kev_medium(monkeypatch)
    monkeypatch.setattr(pv, "release_listed", lambda engine, version: False)
    monkeypatch.setattr(pv.csc, "release_known", lambda *a, **kw: None)
    d = _preview(client, "NX-OS", "10.2(6)").json()
    assert d["state"] == "unknown" and "could not be confirmed" in d["note"]
    assert d["kev"] is None and d["top_finding"] is None


def test_r1_unlisted_release_cisco_says_404_with_kev_stays_unknown(client, kev_index,
                                                                    monkeypatch):
    # Cisco answering "no such release" still wins over any local match (AC-11).
    kev_index({NXOS_KEV: {"date_added": "2024-07-02"}})
    _only_nxos_kev_medium(monkeypatch)
    monkeypatch.setattr(pv, "release_listed", lambda engine, version: False)
    monkeypatch.setattr(cve_router, "_openvuln_ostype", lambda platform, version: "nxos")
    monkeypatch.setattr(pv.csc, "release_known", lambda *a, **kw: False)
    d = _preview(client, "NX-OS", "10.2(6)").json()
    assert d["state"] == "unknown"


def test_ac18_eol_plan_has_sections_1_2_6_only(client):
    d = _preview(client, "IOS", "15.7(3)M5").json()
    assert d["state"] == "eol" and d["upgrade"] is None
    assert [s["id"] for s in d["top_finding"]["plan"]] == ["applies", "workaround", "sources"]


def test_ac18_live_answer_follows_the_rule(client, kev_index):
    kev_index({"CVE-2023-20198": {"date_added": "2023-10-16"}})
    d = _preview(client, "IOS XE", "17.9.4").json()
    assert d["top_finding"]["cve_id"] == "CVE-2023-20198" and d["top_finding"]["kev"] is True


# ------------------------------------------------------------------ AC-19

def _plan(d):
    return {s["id"]: s for s in d["top_finding"]["plan"]}


def _has_content(sec):
    return any(b.get("text") or b.get("commands") for b in sec["blocks"])


def test_ac19a_kev_with_mitigation_file_has_seven_filled_sections(client, kev_index):
    kev_index({"CVE-2023-20198": {"date_added": "2023-10-16"}})
    d = _preview(client, "IOS XE", "17.9.4").json()
    plan = _plan(d)
    assert list(plan) == SECTION_IDS
    for sid, sec in plan.items():
        assert sec["title"] == pp.TITLES[sid] and sec["source"], sid
        assert _has_content(sec), sid
    m = get_mitigation_service().get_mitigation("CVE-2023-20198").mitigation
    assert plan["applies"]["blocks"][0]["commands"] == m.detection.commands
    assert plan["applies"]["blocks"][1]["text"] == m.detection.vulnerable_if
    assert plan["verify"]["blocks"][0]["commands"] == m.verification.commands
    assert plan["verify"]["blocks"][1]["text"] == m.verification.expected_output
    # User decision 23.11 (1): first paragraph of Cisco's text + "Read Cisco's full text".
    excerpt, shortened = pp.cisco_excerpt(m.cisco_workaround.text)
    assert shortened and plan["workaround"]["blocks"][0]["text"] == pp._scrub(excerpt, "CVE-2023-20198")
    assert plan["workaround"]["blocks"][0]["label"] == pp.LABEL_CISCO_EXCERPT == "Excerpt from Cisco's advisory"
    assert plan["workaround"]["links"] == [{"label": pp.LINK_FULL_TEXT, "url": m.cisco_psirt}]
    # User decision 23.11 (3): Upgrade shows the target for all findings, no per-CVE notes.
    assert plan["upgrade"]["blocks"][0] == {"label": pp.TITLES["target"], "text": d["upgrade"]["target"],
                                            "commands": []}
    assert m.upgrade_path and m.upgrade_path not in json.dumps(d)
    assert any(b["label"] and m.steps_reviewed in b["label"] for b in plan["workaround"]["blocks"][1:])
    # Target = the value the counts show (AC-4) and the full report (AC-5).
    assert d["upgrade"]["target"] in plan["target"]["blocks"][0]["text"]
    assert plan["sources"]["links"][0]["url"] == m.cisco_psirt
    assert any(l["url"] == m.cisa_alert for l in plan["sources"]["links"])


@pytest.mark.parametrize("platform,version", [("ISE", "3.2 Patch 4"), ("NX-OS", "10.2(6)")])
def test_ac19b_no_mitigation_file_says_so(client, kev_index, platform, version):
    # T8 (AC-19 v24.11): advisory link in sections 1, 4 and 6 only; 2 and 5 text only.
    kev_index({NXOS_KEV: {"date_added": "2024-07-02"}})
    d = _preview(client, platform, version).json()
    cid = d["top_finding"]["cve_id"]
    assert not get_mitigation_service().get_mitigation(cid).found
    plan = _plan(d)
    assert plan["applies"]["blocks"] == [{"label": None, "text": pp.MSG_NO_STEPS, "commands": []}]
    adv = plan["applies"]["links"]
    assert len(adv) == 1 and adv[0]["label"] == "Cisco advisory" and adv[0]["url"].startswith("https://")
    for sid in ("upgrade", "sources"):
        assert adv[0] in plan[sid]["links"], sid
    for sid in ("workaround", "verify"):
        assert plan[sid]["blocks"] == [{"label": None, "text": pp.MSG_NO_STEPS_SEE_1, "commands": []}]
        assert plan[sid]["links"] == [], sid
    shown = [l for s in d["top_finding"]["plan"] for l in s["links"] if l["url"] == adv[0]["url"]]
    assert len(shown) == 3
    for sid in ("target", "upgrade", "sources", "rollback"):
        assert _has_content(plan[sid]) or plan[sid]["links"], sid


def test_ac19c_cisco_lists_no_workaround(ios_xe_cves):
    svc = get_mitigation_service()
    none_ids = [c for c in svc.list_available()
                if svc.get_mitigation(c).mitigation.cisco_workaround
                and svc.get_mitigation(c).mitigation.cisco_workaround.status == "none"
                and c in ios_xe_cves]
    assert none_ids
    full = SimpleNamespace(matched=[ios_xe_cves[none_ids[0]]], coverage_uncertain=[])
    tf = pp.build_top_finding(full, "IOS XE", "17.9.4", None, None, eol=False)
    wk = next(s for s in tf.plan if s.id == "workaround")
    assert wk.blocks[0].text == "Cisco lists no workaround for this vulnerability. Upgrade is the fix."


def test_ac19_our_steps_hidden_without_review(ios_xe_cves, monkeypatch):
    svc = get_mitigation_service()
    m = svc.get_mitigation("CVE-2023-20198").mitigation.model_copy(update={"steps_reviewed": None})
    real = svc.get_mitigation_for_platform

    def fake(cve_id, platform=None, version=None):
        resp = real(cve_id, platform, version)
        return resp.model_copy(update={"mitigation": m})
    monkeypatch.setattr(svc, "get_mitigation_for_platform", fake)
    full = SimpleNamespace(matched=[ios_xe_cves["CVE-2023-20198"]], coverage_uncertain=[])
    tf = pp.build_top_finding(full, "IOS XE", "17.9.4", None, None, eol=False)
    wk = next(s for s in tf.plan if s.id == "workaround")
    assert len(wk.blocks) == 1 and wk.blocks[0].label == pp.LABEL_CISCO_EXCERPT


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def _data_strings(cid, entry):
    """Every string the plan may carry: data files and the CVE record, with the AC-6 scrub."""
    out = set()
    m = get_mitigation_service().get_mitigation(cid).mitigation
    if m:
        out |= {pp._scrub(s, cid) for s in _strings(json.loads(m.model_dump_json()))}
        if m.cisco_workaround and m.cisco_workaround.text:
            out.add(pp.cisco_excerpt(m.cisco_workaround.text, cid)[0])
    out |= {pp._scrub(s, cid) for s in _strings(json.loads(entry.model_dump_json()))}
    out |= set(_strings(pp.rollback_data()))
    return out


FIXED = ({v for k, v in vars(pp).items() if k.startswith(("MSG_", "HEADER_")) and isinstance(v, str)}
         | set(pp.TITLES.values()) | {"Cisco", "NetDevOps", "Dataset", "Critical", "High", "Medium", "Low",
                                       "Cisco advisory", "CISA alert", pp.LABEL_VULNERABLE_IF,
                                       pp.LABEL_EXPECTED, pp.LABEL_APPLICABILITY,
                                       pp.LINK_FULL_TEXT, pp.LABEL_CISCO_EXCERPT} | set(SECTION_IDS))
FORMATTED = [
    re.compile(r"^Data as of \d{4}-\d{2}-\d{2}\.$"),
    re.compile(r"^Cisco: (mitigation|workaround)$"),
    re.compile(r"^Our (steps|ACL), checked against Cisco's text on \d{4}-\d{2}-\d{2}$"),
    re.compile(r"^Cisco: .+"),                                    # rollback link labels
    re.compile(r"^Rollback: follow Cisco's upgrade guide for .+\.$"),
    re.compile(r"^CVE engine (confirms|does not match) "),        # mitigation_service text
    re.compile(r"^\d{4}-\d{2}-\d{2}$"),
]


@pytest.mark.parametrize("platform,version", [
    ("IOS XE", "17.9.4"), ("ISE", "3.2 Patch 4"), ("NX-OS", "10.2(6)"),
    ("Catalyst SD-WAN Manager", "20.12.5"), ("IOS", "15.7(3)M5")])
def test_ac19d_no_string_from_outside_the_data(client, kev_index, platform, version):
    kev_index({"CVE-2023-20198": {"date_added": "2023-10-16"}})
    d = _preview(client, platform, version).json()
    tf = d["top_finding"]
    full = cve_router.run_analysis(cve_router.CVEAnalyzeRequest(platform=platform, version=version))
    entry = next(c for c in full.matched if c.cve_id == tf["cve_id"])
    allowed = _data_strings(tf["cve_id"], entry) | FIXED | {tf["cve_id"]}
    for s in _strings(tf):
        if s in allowed or any(p.match(s) for p in FORMATTED):
            continue
        up = d.get("upgrade") or {}
        if s in (up.get("note"), up.get("target")):
            continue
        if up.get("target") and re.fullmatch(
                re.escape(up["target"]) + r" \((same train|train change|migration to a supported train)\)\. "
                r"Critical/High left at target: \d+\.", s):
            continue
        raise AssertionError(f"string not from data: {s!r}")


# ------------------------------------------------------------------ T14 rollback

def test_t14_every_rollback_entry_has_a_cisco_source():
    data = pp.rollback_data()
    assert data["checked"]
    for fam in data["families"]:
        assert fam["source"], fam["id"]
        u = urlparse(fam["source"])
        assert u.scheme == "https" and u.hostname == "www.cisco.com", fam["id"]
        assert fam["source_title"] and fam["label"]
        for step in fam["steps"]:
            assert step["text"] and step["commands"] and all(c.strip() for c in step["commands"])


def test_t14_every_preview_platform_has_a_rollback():
    data = pp.rollback_data()
    ids = {f["id"] for f in data["families"]}
    assert set(data["platforms"]) == set(pv.PLATFORMS)
    for platform, fams in data["platforms"].items():
        assert fams and set(fams) <= ids, platform
        sec = pp.rollback_section(platform, "CVE-2023-20198")
        assert sec.links and all(l.url.startswith("https://www.cisco.com/") for l in sec.links)
        assert sec.blocks


def test_t14_family_without_commands_gets_the_fallback_sentence():
    sec = pp.rollback_section("IOS", "CVE-2023-20198")
    assert [b.text for b in sec.blocks] == ["Rollback: follow Cisco's upgrade guide for IOS (classic)."]
    assert all(not b.commands for b in sec.blocks)


def test_t14_rollback_file_is_shipped():
    assert pp.ROLLBACK_FILE.exists()
    ignore = (ROOT / ".dockerignore").read_text() if (ROOT / ".dockerignore").exists() else ""
    assert "cve_rollback" not in ignore


# ------------------------------------------------------------------ T13 frontend

def _js():
    return (WEB / "app-security.js").read_text()


def test_plan_js_writes_text_only():
    js = _js().split("PREVIEW-01", 1)[1]
    for bad in ("innerHTML", "insertAdjacentHTML", "outerHTML", "document.write"):
        assert bad not in js
    assert "—" not in js


PLAN_HARNESS = r"""
const fs = require("fs");
const vm = require("vm");
const sec = fs.readFileSync(process.argv[2], "utf8");
function el(tag) {
  return { tag, className: "", textContent: "", children: [], attrs: {},
           appendChild(c) { this.children.push(c); return c; },
           addEventListener() {},
           set href(v) { this.attrs.href = v; }, get href() { return this.attrs.href; } };
}
const ctx = { String, JSON, Object, Array, Number, document: { createElement: el } };
vm.createContext(ctx);
const fn = sec.slice(sec.indexOf("const PREVIEW_TRAIN_TEXT"), sec.indexOf("(function initPreview()"));
vm.runInContext(fn + "\nthis.previewPlanEl = previewPlanEl;", ctx);
function flat(n, out) { out.push({ tag: n.tag, cls: n.className, text: n.textContent, href: n.attrs.href });
                        n.children.forEach(c => flat(c, out)); return out; }
const data = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
const out = { plan: flat(ctx.previewPlanEl(data), []), none: ctx.previewPlanEl({ state: "clean" }) };
console.log(JSON.stringify(out));
"""

SAMPLE = {
    "state": "findings", "more_findings": 3,
    "top_finding": {
        "cve_id": "CVE-2023-20198", "title": "<img src=x onerror=alert(1)>", "severity": "Critical",
        "cvss": 10.0, "kev": True, "published": "2023-10-16", "needs_confirmation": True,
        "header": "Needs confirmation on your device",
        "plan": [
            {"id": "applies", "title": "Does this apply to you", "source": "NetDevOps",
             "blocks": [{"label": None, "text": "t", "commands": ["show ip http server status", "<b>x</b>"]}],
             "links": [{"label": "bad", "url": "javascript:alert(1)"},
                       {"label": "Cisco advisory", "url": "https://sec.cloudapps.cisco.com/a"}]},
            {"id": "rollback", "title": "Rollback", "source": "Cisco",
             "blocks": [{"label": "IOS XE, install mode", "text": "x", "commands": ["install abort"]}],
             "links": []},
        ],
    },
}


@pytest.fixture(scope="module")
def plan_dom(tmp_path_factory):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    d = tmp_path_factory.mktemp("plan")
    (d / "h.js").write_text(PLAN_HARNESS)
    (d / "sample.json").write_text(json.dumps(SAMPLE))
    res = subprocess.run([node, str(d / "h.js"), str(WEB / "app-security.js"), str(d / "sample.json")],
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout.strip().splitlines()[-1])


def test_plan_dom(plan_dom):
    nodes = plan_dom["plan"]
    assert plan_dom["none"] is None
    texts = [n["text"] for n in nodes]
    assert "Needs confirmation on your device" in texts
    assert "Fix this one first: listed by CISA as exploited in the wild" not in texts
    assert "CVE-2023-20198 | Critical | CVSS 10 | KEV" in texts
    assert "<img src=x onerror=alert(1)>" in texts           # as text, never as markup
    codes = [n["text"] for n in nodes if n["tag"] == "code"]
    assert codes == ["show ip http server status\n<b>x</b>", "install abort"]
    assert sum(1 for n in nodes if n["cls"] and "preview-copy" in n["cls"]) == 2
    hrefs = [n["href"] for n in nodes if n["tag"] == "a"]
    assert hrefs == ["https://sec.cloudapps.cisco.com/a"]     # javascript: dropped
    assert "3 more Critical/High findings for this release are in the full report." in texts
    # User decision 23.11 (1): section 1 open, the others folded in <details><summary>.
    tags = [n["tag"] for n in nodes]
    assert tags.count("section") == 1 and tags.count("details") == 1 and tags.count("summary") == 1
    i = tags.index("summary")
    assert nodes[i - 1]["tag"] == "details" and nodes[i + 1]["text"] == "7. Rollback"
    assert nodes[tags.index("section") + 1]["text"] == "1. Does this apply to you"
    heads = [n for n in nodes if n["tag"] == "h4"]
    assert [h["text"] for h in heads] == ["1. Does this apply to you", "7. Rollback"]
    assert ("Built from Cisco PSIRT data and steps we checked against Cisco's text. "
            "Test in a lab or a maintenance window first.") in texts
    assert sum(1 for n in nodes if n["text"] == "Copy commands") == 2
    assert {"NetDevOps", "Cisco"} <= {n["text"] for n in nodes if n["cls"] == "preview-plan-source"}


def test_copy_v1_strings_in_place():
    # @cmo copy v1, spec section 9 (22.11): strings 1:1.
    js = _js()
    html = (WEB / "index.html").read_text()
    for s in ["Enter your release. See the one vulnerability to fix first and the plan for it: does it "
              "apply, the workaround, the target release, how to verify, how to roll back. No email."]:
        assert s in html
    assert 'id="preview-submit">Show the plan</button>' in html
    for s in ["Fix this one first: listed by CISA as exploited in the wild",
              "Fix this one first: highest CVSS for this release",
              "Copy commands", '"Copied"',
              "Built from Cisco PSIRT data and steps we checked against Cisco's text. "
              "Test in a lab or a maintenance window first.",
              "more Critical/High findings for this release are in the full report.",
              "See every finding with its fix, KEV ids and export. Free with email.",
              "Actively exploited: upgrade now.", "Actively exploited: replace this hardware now."]:
        assert s in js, s
    assert pp.MSG_NO_STEPS == "No reviewed steps for this CVE yet. See the Cisco advisory."
    # T9: AC-19 v24.11, fallback text of sections 2 and 5 (copy section 9, draft @pm).
    assert pp.MSG_NO_STEPS_SEE_1 == "No reviewed steps for this CVE yet. Use the Cisco advisory linked in section 1."
    assert pp.MSG_ROLLBACK_FALLBACK == "Rollback: follow Cisco's upgrade guide for {family}."
    assert "See the full report: CVE list" not in js


@pytest.mark.parametrize("spelling", ["CVE-2023-20273", "cve-2023-20273", "CVE 2023 20273",
                                      "cve_2023_20273", "CVE-2023\u201320273", "CVE2023-20273"])
def test_ac6_loose_spellings_of_other_ids_are_replaced(spelling):
    # @ciso P5
    out = pp._scrub(f"see {spelling} and CVE-2023-20198", "CVE-2023-20198")
    assert out == f"see {pp.OTHER_CVE} and CVE-2023-20198"


def test_ac6_every_mitigation_file_names_only_its_own_cve(ios_xe_cves):
    # @ciso P5: on the real data, not only on the example.
    loose = re.compile(r"CVE[\s_\-\u2010-\u2015]*\d{4}[\s_\-\u2010-\u2015]*\d{4,}", re.I)
    checked = 0
    for cid in get_mitigation_service().list_available():
        entry = ios_xe_cves.get(cid)
        if entry is None:
            continue
        full = SimpleNamespace(matched=[entry], coverage_uncertain=[])
        tf = pp.build_top_finding(full, "IOS XE", "17.9.4", None, "2026-11-22", eol=False)
        if tf is None:   # Medium/Low record: never a top finding
            continue
        checked += 1
        found = {re.sub(r"\D", "", m) for m in loose.findall(tf.model_dump_json())}
        assert found <= {re.sub(r"\D", "", cid)}, (cid, found)
    assert checked > 50


# ------------------------------------------------------------------ user decisions 23.11

def test_cisco_excerpt_first_paragraph_without_raw_links():
    text = ('See bug CSCvc12306 ["https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc12306"]), '
            'then upgrade.\r\n\r\nSecond paragraph.\r\n\r\nThird.')
    assert pp.cisco_excerpt(text) == ("See bug CSCvc12306), then upgrade.", True)
    assert pp.cisco_excerpt("One paragraph only.") == ("One paragraph only.", False)
    assert pp.cisco_excerpt('One ["https://www.cisco.com/x"] link.') == ("One link.", True)
    assert pp.cisco_excerpt(None) == (None, False)


def _shown_cisco_texts():
    """(cve_id, Cisco text) for every mitigation file whose Cisco text the preview shows."""
    svc = get_mitigation_service()
    for cid in svc.list_available():
        cw = svc.get_mitigation(cid).mitigation.cisco_workaround
        if cw and cw.text and cw.status not in ("none", "unknown"):
            yield cid, cw.text


def _intro_next_is_colon_only(text):
    paras = [q for q in (pp.RAW_LINK.sub("", p).strip() for p in
             pp.PARAGRAPH_BREAK.split(text.replace("\r\n", "\n").strip())) if q]
    return len(paras) > 1 and paras[1].endswith(":") and not pp._drop_colon_sentence(paras[1])


def test_every_cisco_text_excerpt_is_short_complete_and_without_links():
    seen = 0
    for cid, text in _shown_cisco_texts():
        excerpt, _ = pp.cisco_excerpt(text, cid)
        paras = excerpt.split("\n\n")
        assert excerpt and len(paras) <= pp.EXCERPT_MAX_PARAS, cid
        assert len(excerpt) <= pp.EXCERPT_MAX_CHARS, (cid, len(excerpt))   # @ciso W2, after _scrub
        assert not re.search(r"https?://", excerpt, re.I), cid          # @ciso D2: any link form
        assert not excerpt.endswith(":"), cid                         # PREVIEW-INTRO-01 / @ciso D1
        if pp.INTRO_ONLY.match(excerpt):   # PREVIEW-INTRO-02: only when the next paragraph
            assert _intro_next_is_colon_only(text), cid   # is a lone colon sentence (2-para limit)
        flat = re.sub(r"\s+", " ", pp._scrub(pp.RAW_LINK.sub("", text), cid))
        assert all(re.sub(r"\s+", " ", p).rstrip(pp.ELLIPSIS) in flat for p in paras), cid   # Cisco's words
        seen += 1
    assert seen >= 50


def test_w2_every_cisco_text_within_the_limit_after_scrub():
    # @ciso W2 (v0.7.21 review): all 150 files, every status, length measured after _scrub.
    svc = get_mitigation_service()
    n = 0
    for cid in svc.list_available():
        cw = svc.get_mitigation(cid).mitigation.cisco_workaround
        if cw and cw.text:
            assert len(pp.cisco_excerpt(cw.text, cid)[0]) <= pp.EXCERPT_MAX_CHARS, cid
            n += 1
    assert n >= 100


def test_w2_cve_2026_20127_long_first_paragraph_is_cut_at_a_sentence():
    text = get_mitigation_service().get_mitigation("CVE-2026-20127").mitigation.cisco_workaround.text
    first = pp.PARAGRAPH_BREAK.split(text.replace("\r\n", "\n").strip())[0]
    assert len(first) > pp.EXCERPT_MAX_CHARS            # the case @ciso found (2004 chars)
    excerpt, shortened = pp.cisco_excerpt(text, "CVE-2026-20127")
    assert shortened and len(excerpt) <= pp.EXCERPT_MAX_CHARS and excerpt[-1] in ".!?"


def test_w2_cap_rules():
    long_sentences = "Short one. " + "word " * 300
    assert pp._cap(long_sentences, 900) == "Short one."
    no_end = "word " * 300
    out = pp._cap(no_end, 900)
    assert len(out) <= 900 and out.endswith(pp.ELLIPSIS) and out[:-1].endswith("word")
    assert pp._cap("x" * 1000, 900) == "x" * 899 + pp.ELLIPSIS
    assert pp._cap("Fits.", 900) == "Fits."
    # Scrub before measuring: OTHER_CVE is longer than the id it replaces.
    text = "A" * 880 + " CVE-2023-20273."
    excerpt, shortened = pp.cisco_excerpt(text, "CVE-2023-20198")
    assert shortened and len(excerpt) <= pp.EXCERPT_MAX_CHARS


def test_cisco_excerpt_colon_and_intro_take_the_next_paragraph():
    assert pp.cisco_excerpt("Do this:\n\nRouter(config)# no x\n\nMore.") == \
        ("Do this:\n\nRouter(config)# no x", True)
    assert pp.cisco_excerpt("There are no workarounds that address this vulnerability.\n\n"
                            "However, disable X.\n\nThird.") == \
        ("There are no workarounds that address this vulnerability.\n\nHowever, disable X.", True)
    # Not only the sentence: stays one paragraph.
    assert pp.cisco_excerpt("There are no workarounds that address this vulnerability. However, "
                            "disable X.\n\nSecond.")[0].count("\n\n") == 0
    # At most two paragraphs; a colon left at the end loses its sentence.
    assert pp.cisco_excerpt("A:\n\nB. Then do this:\n\nC") == ("A:\n\nB.", True)
    # Character limit: the next paragraph does not fit, the colon sentence goes.
    long_next = "x " * pp.EXCERPT_MAX_CHARS
    assert pp.cisco_excerpt(f"Done. Then do this:\n\n{long_next}") == ("Done.", True)
    # Paragraph that is only a link is skipped (@ciso D3).
    assert pp.cisco_excerpt('["https://www.cisco.com/x"]\n\nSecond.') == ("Second.", True)


@pytest.mark.parametrize("cid,starts,ends", [
    ("CVE-2023-20187", "Administrators may disable mLRE", "Router#"),
    ("CVE-2023-20025", "There are no workarounds that address these vulnerabilities. However,",
     "predefined in the services list."),
    ("CVE-2023-20198", "There are no workarounds that address these vulnerabilities.\n\n"
                       "Disabling the HTTP Server feature",
     "both commands are required to disable the HTTP Server feature."),
])
def test_preview_intro_01_real_texts(cid, starts, ends):
    text = get_mitigation_service().get_mitigation(cid).mitigation.cisco_workaround.text
    excerpt, shortened = pp.cisco_excerpt(text)
    assert shortened and excerpt.startswith(starts) and excerpt.endswith(ends), excerpt[-120:]
    assert len(excerpt) <= pp.EXCERPT_MAX_CHARS


@pytest.mark.parametrize("sentence", [
    "There is a workaround that addresses this vulnerability.",
    "There is a workaround and a mitigation that address this vulnerability.",
    "There are workarounds that address this vulnerability.",
    "There are workarounds that address these vulnerabilities.",
    "There are no workarounds that address these vulnerabilities.",
])
def test_preview_intro_02_intro_sentences_take_the_next_paragraph(sentence):
    # PREVIEW-INTRO-02 (user 23.11 "3 tak"): same rule as "There are no workarounds ...".
    assert pp.cisco_excerpt(f"{sentence}\n\nDisable X.\n\nThird.") == \
        (f"{sentence}\n\nDisable X.", True)


@pytest.mark.parametrize("text", [
    "There is a workaround that addresses this vulnerability: Add an IPv4 ACL.",  # CVE-2024-20510
    "There is a workaround that addresses this vulnerability. Disable IKEv1 fragmentation.",
    "There are no workarounds that address this vulnerability. However, there is a mitigation.",
    "There is a workaround that addresses this issue.",
])
def test_preview_intro_02_not_only_the_intro_sentence(text):
    assert not pp.INTRO_ONLY.match(text)
    assert pp.cisco_excerpt(f"{text}\n\nSecond.")[0] == text


@pytest.mark.parametrize("cid,second", [
    ("CVE-2024-20316", "Manage ACLs directly on the device CLI"),
    ("CVE-2024-20373", "There is no support for extended IPv4 ACLs against SNMP."),
    ("CVE-2024-20291", "After performing configuration changes to port channel member ports"),
    ("CVE-2023-20186", "As a workaround for this vulnerability, enable privilege level 0"),
])
def test_preview_intro_02_real_texts(cid, second):
    text = get_mitigation_service().get_mitigation(cid).mitigation.cisco_workaround.text
    excerpt, shortened = pp.cisco_excerpt(text, cid)
    first, nxt = excerpt.split("\n\n")
    assert shortened and pp.INTRO_ONLY.match(first) and nxt.startswith(second), excerpt
    assert len(excerpt) <= pp.EXCERPT_MAX_CHARS


@pytest.mark.parametrize("cid", ["CVE-2024-20309", "CVE-2025-20151", "CVE-2025-20221"])
def test_preview_intro_02_colon_paragraph_after_intro_is_dropped(cid):
    # Intro + a lone "... as shown in the following example:" paragraph: the 2-paragraph
    # limit leaves no room for the example, the colon sentence goes (@ciso D1), the intro stays.
    text = get_mitigation_service().get_mitigation(cid).mitigation.cisco_workaround.text
    excerpt, shortened = pp.cisco_excerpt(text, cid)
    assert shortened and pp.INTRO_ONLY.match(excerpt) and _intro_next_is_colon_only(text)


def test_d2_no_url_in_preview_json_except_the_links(ios_xe_cves):
    # @ciso D2: every https?:// in the top finding is one of its own links, on all files.
    url = re.compile(r"https?://[^\s\"'\])]*", re.I)
    checked = 0
    for cid in get_mitigation_service().list_available():
        entry = ios_xe_cves.get(cid)
        if entry is None:
            continue
        full = SimpleNamespace(matched=[entry], coverage_uncertain=[])
        tf = pp.build_top_finding(full, "IOS XE", "17.9.4", None, "2026-11-22", eol=False)
        if tf is None:
            continue
        d = json.loads(tf.model_dump_json())
        links = {l["url"] for sec in d["plan"] for l in sec["links"]}
        found = set(url.findall(json.dumps(d)))
        # Allowed: the plan's own (filtered) links, which our "Vulnerable if" texts repeat as
        # plain text, and placeholders in our verify steps ("https://<WAN-IP>").
        leaked = {u for u in found if u not in links and not re.match(r"https?://<", u)}
        assert not leaked, (cid, leaked)
        checked += 1
    assert checked > 50


@pytest.mark.parametrize("platform,version", [
    ("IOS XE", "17.9.4"), ("ISE", "3.2 Patch 4"), ("NX-OS", "10.2(6)"), ("IOS", "15.7(3)M5")])
def test_upgrade_section_has_no_per_cve_notes(client, kev_index, platform, version):
    kev_index({"CVE-2023-20198": {"date_added": "2023-10-16"}})
    d = _preview(client, platform, version).json()
    assert "Our notes" not in json.dumps(d)
    if d["state"] == "eol":                                   # AC-18: no upgrade section
        assert "upgrade" not in _plan(d)
        return
    up = _plan(d)["upgrade"]
    assert up["source"] == "Cisco"
    assert up["blocks"][-1]["text"] == pp.MSG_UPGRADE_LINK
    if d["upgrade"] and d["upgrade"].get("target"):
        assert up["blocks"][0]["text"] == d["upgrade"]["target"]


def test_r2_no_advisory_link_no_pointer_to_section_1():
    # @ciso R2 24.11: advisory link dropped by the _link filter + no mitigation file.
    cid = "CVE-2099-0001"
    assert not get_mitigation_service().get_mitigation(cid).found
    top = SimpleNamespace(cve_id=cid, cvss_score=9.8, kev=None, published="2099-01-01",
                          severity="critical", title="Test", advisory_url="https://evil.example/x")
    full = SimpleNamespace(matched=[top], coverage_uncertain=[])
    tf = pp.build_top_finding(full, "NX-OS", "10.2(6)", None, None, eol=False)
    plan = {s.id: s for s in tf.plan}
    assert all(not s.links or s.id == "rollback" for s in tf.plan)
    for sid in ("applies", "workaround", "verify"):
        assert [b.text for b in plan[sid].blocks] == [pp.MSG_NO_STEPS], sid
        assert "linked in section 1" not in json.dumps(plan[sid].model_dump()), sid


def test_w1_preview_pre_fits_on_mobile():
    # @ciso W1 24.11: in the 600 px column layout <pre> must stretch to the card width.
    css = (Path(__file__).resolve().parent.parent / "web" / "style-home.css").read_text()
    blocks = re.findall(r"@media \(max-width: 600px\) \{((?:[^{}]*\{[^{}]*\})*[^{}]*)\}", css)
    assert any(re.search(r"\.preview-plan-pre\s*\{[^}]*(align-self:\s*stretch|max-width:\s*100%)", b)
               for b in blocks)
