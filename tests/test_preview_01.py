"""
PREVIEW-01 "Check your release, no email" (spec 2026-11-20, CEO repo
projects/netdevops/specs/2026-11-20_podglad-bez-konta.md).

No network anywhere in this file: openVuln answers come from fakes installed in
place of services.cisco_software_checker._live_fetch, MailerLite from an
httpx.MockTransport. The suite-wide conftest keeps KEV and the checker offline
unless a test installs a fake.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from api import rate_limit as rl
from api.main import app, CSS_FILES, JS_FILES
from api.routers import cve as cve_router
from api.routers import cve_preview as pv
from api.routers import subscribe as sub
from services import cisco_software_checker as csc

WEB = Path(__file__).resolve().parent.parent / "web"
PATH = "/analyze/cve/preview"

HARDENING = {"advisoryId": "cisco-sa-hardening-iosxe-V8NMuMZJ", "sir": "Critical",
             "firstFixed": [], "cves": ["CVE-2026-20267"]}
XMCP = {"advisoryId": "cisco-sa-ios-xmcp-thbAr34t", "sir": "High",
        "firstFixed": ["17.9.10"], "cves": ["CVE-2026-20301"]}
MEDIUM = {"advisoryId": "cisco-sa-snmpv3-qKEYvzsy", "sir": "Medium",
          "firstFixed": [], "cves": ["CVE-0000-2"]}
# What openVuln answers per release in these tests. Missing key = 404.
OPENVULN = {
    "17.9.4": [XMCP],
    "17.9.10": [MEDIUM],
    "17.6.3": [XMCP],
    "17.15.4a": [MEDIUM],
    "15.2(7)E8": [],
}


class FakeOpenVuln:
    def __init__(self, table=OPENVULN, fail=False):
        self.table = table
        self.fail = fail
        self.calls = []

    def __call__(self, ostype, release):
        self.calls.append((ostype, release))
        if self.fail:
            return None
        return self.table.get(release, csc.UNKNOWN_RELEASE)


@pytest.fixture(autouse=True)
def _preview_env(monkeypatch):
    monkeypatch.setenv("PREVIEW_ENABLED", "1")
    monkeypatch.setattr(cve_router, "dataset_is_syncing", lambda key: False)
    monkeypatch.setattr(pv, "budget", pv.OpenVulnBudget())


@pytest.fixture
def openvuln(monkeypatch):
    fake = FakeOpenVuln()
    monkeypatch.delenv("CISCO_CHECKER_OFFLINE", raising=False)
    monkeypatch.setattr(csc, "_live_fetch", fake)
    return fake


@pytest.fixture
def client():
    return TestClient(app)


def _preview(client, platform, version, headers=None):
    return client.post(PATH, json={"platform": platform, "version": version}, headers=headers)


# ---------------------------------------------------------------- flag (T5)

def test_flag_off_by_default_is_404_and_hidden(client, monkeypatch):
    monkeypatch.delenv("PREVIEW_ENABLED", raising=False)
    r = _preview(client, "IOS XE", "17.9.4")
    assert r.status_code == 404
    assert "cve_preview" not in client.get("/meta/version").json()["feature_flags"]


def test_flag_on_lists_the_feature(client):
    assert "cve_preview" in client.get("/meta/version").json()["feature_flags"]


@pytest.mark.parametrize("value", ["0", "false", "", "no", "off"])
def test_flag_values_that_mean_off(client, monkeypatch, value):
    monkeypatch.setenv("PREVIEW_ENABLED", value)
    assert _preview(client, "IOS XE", "17.9.4").status_code == 404


# ---------------------------------------------------------------- input (AC-3, 9, 10, 15)

@pytest.fixture
def no_engine(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("engine must not run on rejected input")
    monkeypatch.setattr(cve_router, "run_analysis", boom)


@pytest.mark.parametrize("platform", ["FTD", "ios xe", "IOS-XE", "<b>x</b>", "", "ASA"])
def test_platform_outside_the_list_is_400_without_echo(client, no_engine, platform):
    r = _preview(client, platform, "17.9.4")
    assert r.status_code == 400
    assert r.json() == {"detail": pv.MSG_PLATFORM}


@pytest.mark.parametrize("version", ["", "   ", "\t"])
def test_empty_release(client, no_engine, version):
    r = _preview(client, "IOS XE", version)
    assert r.status_code == 400 and r.json() == {"detail": "Enter a software release."}


@pytest.mark.parametrize("version", [
    "1" * 65, "17.9.4 " + "x" * 60, "abc", "no digits here", "17.9.4<script>",
    "17.9\n.4", "17.9.4;rm", "17.9.4'", '17.9.4"', "17.9\u00a0.4", "\uff11\uff17.9.4",
])
def test_bad_release_is_400_without_echo_or_engine(client, no_engine, version):
    r = _preview(client, "IOS XE", version)
    assert r.status_code == 400
    assert r.json() == {"detail": "This does not look like a Cisco release."}
    assert "script" not in r.text and "rm" not in r.text


def test_length_cap_is_64(client):
    line = "Cisco IOS XE Software, Version 17.9.4"
    v64 = " " * (64 - len(line)) + line
    assert len(v64) == 64
    assert _preview(client, "IOS XE", v64).status_code == 200
    assert _preview(client, "IOS XE", " " + v64).status_code == 400
    assert pv.MAX_PREVIEW_VERSION_LENGTH == 64


@pytest.mark.parametrize("body", [{}, {"platform": "IOS XE"}, {"version": "17.9.4"},
                                  {"platform": "IOS XE", "version": 17}])
def test_malformed_body_422_without_echo(client, body):
    r = client.post(PATH, json=body)
    assert r.status_code == 422
    assert "input" not in json.dumps(r.json())


# ---------------------------------------------------------------- main path (AC-4)

@pytest.mark.parametrize("typed", ["17.9.4", "IOS XE 17.9.4", "Cisco IOS XE Software, Version 17.9.4"])
def test_findings_with_cisco_path(client, openvuln, typed):
    r = _preview(client, "IOS XE", typed)
    assert r.status_code == 200
    d = r.json()
    assert d["state"] == "findings"
    assert d["interpreted_as"] == "IOS XE 17.9.4"
    assert d["critical"] + d["high"] > 0
    assert isinstance(d["kev"], int)
    assert d["upgrade"] == {"source": "cisco", "target": "17.9.10", "train": "same",
                            "critical_high_left": 0, "note": None}
    assert d["upgrade_note"] is None
    assert d["data_as_of"] and re.match(r"^\d{4}-\d{2}-\d{2}$", d["data_as_of"])
    assert "openVuln" in d["sources"] and "CISA KEV" in d["sources"]


def test_need_confirmation_counts_only_uncertain_critical_high(client, openvuln):
    d = _preview(client, "IOS", "15.2(7)E8").json()
    full = client.post("/analyze/cve", json={"platform": "IOS", "version": "15.2(7)E8"}).json()
    sev = {c["cve_id"]: (c["severity"] or "").lower() for c in full["matched"]}
    expected = sum(1 for i in full["coverage_uncertain"] if sev.get(i) in ("critical", "high"))
    assert d["need_confirmation"] == expected


def test_kev_is_a_count_from_the_matches(client):
    d = _preview(client, "Catalyst SD-WAN Manager", "20.12.5").json()
    full = client.post("/analyze/cve", json={"platform": "Catalyst SD-WAN Manager",
                                             "version": "20.12.5"}).json()
    assert d["kev"] == sum(1 for c in full["matched"] if c.get("kev")) > 0


# ---------------------------------------------------------------- parity (AC-5)

PARITY_INPUTS = [
    ("IOS XE", "17.9.4"),
    ("IOS XE", "17.6.3"),
    ("ISE", "3.2 Patch 4"),
    ("NX-OS", "10.2(6)"),
    ("IOS XE", "17.15.4a"),   # clean on Critical/High
]


@pytest.mark.parametrize("platform,version", PARITY_INPUTS)
def test_preview_matches_the_full_report(client, openvuln, platform, version):
    full = client.post("/analyze/cve", json={"platform": platform, "version": version}).json()
    d = _preview(client, platform, version).json()
    assert d["state"] in ("findings", "clean"), d
    assert d["critical"] == full["summary"]["critical"]
    assert d["high"] == full["summary"]["high"]
    assert d["medium"] == full["summary"]["medium"]
    assert d["kev"] == sum(1 for c in full["matched"] if c.get("kev"))
    full_model = cve_router.CVEAnalyzeResponse(**full)
    assert (d["upgrade"] or {}).get("target") == pv.preview_target(full_model)


def test_parity_inputs_cover_the_spec_list():
    plats = [p for p, _ in PARITY_INPUTS]
    assert len(PARITY_INPUTS) == 5 and "ISE" in plats and "NX-OS" in plats


# ---------------------------------------------------------------- gated fields (AC-6)

ALLOWED_KEYS = {"state", "interpreted_as", "critical", "high", "medium", "low", "kev",
                "need_confirmation", "upgrade", "upgrade_note", "eol_note", "note",
                "format_hint", "data_as_of", "sources"}
UPGRADE_KEYS = {"source", "target", "train", "critical_high_left", "note"}
LEAKS = re.compile(r"CVE-\d{4}-\d+|cisco-sa-|cvss|https?://|\bsir\b|due_date|directive", re.I)


@pytest.mark.parametrize("platform,version", PARITY_INPUTS + [
    ("Catalyst SD-WAN Manager", "20.12.5"), ("IOS", "15.7(3)M5"), ("IOS", "15.2(7)E8"),
    ("IOS XE", "17.99.1")])
def test_no_gated_field_in_the_json(client, openvuln, platform, version):
    r = _preview(client, platform, version)
    d = r.json()
    assert set(d) == ALLOWED_KEYS
    if d["upgrade"]:
        assert set(d["upgrade"]) == UPGRADE_KEYS
    assert not LEAKS.search(r.text), LEAKS.search(r.text).group(0)
    for key in ("matched", "severity_details", "provenance", "remaining", "remaining_ids",
                "statement", "coverage_uncertain", "bundles", "excluded_not_listed"):
        assert key not in r.text


def test_free_tools_unchanged():
    js = (WEB / "app-gate.js").read_text()
    assert ('const FREE_TOOLS = ["home", "iperf", "subnet", "mtu", "timezone", "kev-watch", '
            '"acl-whatif", "cli-cheat-sheet"];') in js


# ---------------------------------------------------------------- clean / EoL (AC-7, AC-8)

def test_clean_release(client, openvuln):
    d = _preview(client, "IOS XE", "17.15.4a").json()
    assert d["state"] == "clean"
    assert (d["critical"], d["high"]) == (0, 0)
    assert d["note"] == pv.NOTE_CLEAN
    assert "safe" not in json.dumps(d).lower().replace("safe upgrade", "")


def test_eol_banner_instead_of_upgrade(client):
    d = _preview(client, "IOS", "15.7(3)M5").json()
    assert d["state"] == "eol"
    assert d["eol_note"] == "Hardware replacement required, no software fix path."
    assert d["upgrade"] is None
    assert d["critical"] is not None and d["high"] is not None and d["kev"] is not None


# ---------------------------------------------------------------- unknown (AC-11)

def test_unknown_release_cisco_says_404(client, openvuln):
    d = _preview(client, "IOS XE", "17.99.1").json()
    assert d["state"] == "unknown"
    assert d["note"].startswith("NOT EVALUATED: we have no data for this release.")
    assert "could not be confirmed" not in d["note"]
    assert d["format_hint"] and "17.9.4a" in d["format_hint"]
    assert all(d[k] is None for k in ("critical", "high", "medium", "low", "kev"))


@pytest.mark.parametrize("platform,version", [
    ("IOS XE", "17.99.1"), ("IOS XE", "17.15.4a"), ("ISE", "3.9 Patch 1"),
    ("NX-OS", "10.9(9)"), ("Catalyst SD-WAN Manager", "20.99.1")])
def test_unknown_offline_never_zero_zero(client, platform, version):
    d = _preview(client, platform, version).json()
    assert d["state"] != "clean", d
    if d["state"] == "unknown":
        assert "could not be confirmed" in d["note"]
        assert d["critical"] is None and d["high"] is None
    else:   # unlisted, no Cisco answer, yet the engine matched Critical/High: report parity
        assert d["state"] == "findings" and d["critical"] + d["high"] > 0


def test_unknown_even_with_range_hits_when_cisco_says_404(client, openvuln, monkeypatch):
    monkeypatch.setattr(pv, "release_listed", lambda engine, version: False)
    d = _preview(client, "IOS XE", "17.9.44").json()
    assert d["state"] == "unknown"


def test_listed_release_does_not_ask_openvuln_existence(client, openvuln):
    _preview(client, "NX-OS", "10.2(6)")
    assert openvuln.calls == []   # NX-OS: no per-release query at all


# ---------------------------------------------------------------- not covered / syncing (AC-12)

def test_syncing_shows_note_without_numbers(client, monkeypatch):
    monkeypatch.setattr(cve_router, "dataset_is_syncing", lambda key: True)
    d = _preview(client, "IOS XE", "17.9.4").json()
    assert d["state"] == "not_evaluated"
    assert d["note"] == "Dataset is syncing, try again in a minute."
    assert d["critical"] is None and d["upgrade"] is None


def test_not_evaluated_note_passed_through(client, monkeypatch):
    monkeypatch.setattr(cve_router, "platform_coverage_note",
                        lambda p, v=None: "NOT EVALUATED: test note.")
    d = _preview(client, "IOS XE", "17.9.4").json()
    assert d["state"] == "not_evaluated" and d["note"] == "NOT EVALUATED: test note."
    assert d["critical"] is None


# ---------------------------------------------------------------- openVuln down (AC-13)

def test_openvuln_down_falls_back_to_dataset(client, monkeypatch):
    fake = FakeOpenVuln(fail=True)
    monkeypatch.delenv("CISCO_CHECKER_OFFLINE", raising=False)
    monkeypatch.setattr(csc, "_live_fetch", fake)
    d = _preview(client, "IOS XE", "17.9.4").json()
    assert d["state"] == "findings" and d["critical"] is not None
    assert d["upgrade"]["source"] == "dataset" and d["upgrade"]["target"]
    assert d["upgrade_note"] == "Cisco check unavailable right now."


def test_no_path_at_all(client):
    d = _preview(client, "NX-OS", "10.2(6)").json()
    assert d["upgrade"] is None
    assert d["upgrade_note"] == "No upgrade path computed for this release, see the full report."


# ---------------------------------------------------------------- per-IP limit (AC-14)

class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(rl, "ENABLED", True)
    monkeypatch.setattr(rl, "limiter", rl.SlidingWindowLimiter(clock=c))
    return c


def _from(ip, forged="1.2.3.4"):
    return {"X-Forwarded-For": f"{forged}, {ip}, 172.71.0.1"}


@pytest.fixture
def cheap(monkeypatch):
    """The limiter is what is under test: answer 400 before the engine."""
    monkeypatch.setattr(pv, "validate", lambda req: pv._reject(pv.MSG_EMPTY, None))


def test_five_per_minute_then_429(client, clock, cheap):
    for _ in range(5):
        assert _preview(client, "IOS XE", "17.9.4", _from("70.0.0.1")).status_code == 400
    r = _preview(client, "IOS XE", "17.9.4", _from("70.0.0.1"))
    assert r.status_code == 429 and r.headers["retry-after"] == "60"
    assert _preview(client, "IOS XE", "17.9.4", _from("70.0.0.2")).status_code == 400


def test_thirty_per_hour(client, clock, cheap):
    for _ in range(6):
        for _ in range(5):
            assert _preview(client, "IOS XE", "x", _from("70.0.0.1")).status_code == 400
        clock.t += 61
    r = _preview(client, "IOS XE", "x", _from("70.0.0.1"))
    assert r.status_code == 429 and r.headers["retry-after"] == "3600"


def test_forged_first_xff_entry_does_not_reset(client, clock, cheap):
    for i in range(5):
        _preview(client, "IOS XE", "x", _from("70.0.0.1", forged=f"9.9.9.{i}"))
    assert _preview(client, "IOS XE", "x", _from("70.0.0.1", forged="8.8.8.8")).status_code == 429


def test_ipv6_counts_per_64(client, clock, cheap):
    for i in range(5):
        _preview(client, "IOS XE", "x", _from(f"2001:db8:1:2::{i + 1}"))
    assert _preview(client, "IOS XE", "x", _from("2001:db8:1:2:ffff::9")).status_code == 429
    assert _preview(client, "IOS XE", "x", _from("2001:db8:1:3::1")).status_code == 400


def test_preview_limit_does_not_touch_the_full_analyzer(client, clock, cheap):
    for _ in range(6):
        _preview(client, "IOS XE", "x", _from("70.0.0.1"))
    r = client.post("/analyze/cve", json={"platform": "IOS XE", "version": "17.9.4"},
                    headers=_from("70.0.0.1"))
    assert r.status_code == 200


def test_preview_windows_stay_within_an_hour():
    assert rl.PATH_LIMITS[PATH] == ((5, 60), (30, 3600))
    assert rl.RETENTION_SECONDS <= 3600


# ---------------------------------------------------------------- global openVuln budget (AC-16)

def test_budget_caps_uncached_passes_and_keeps_answering(client, openvuln, monkeypatch, capsys):
    monkeypatch.setattr(pv, "budget", pv.OpenVulnBudget(cap=(1, 3600)))
    first = _preview(client, "IOS XE", "17.9.4").json()
    assert first["upgrade"]["source"] == "cisco"
    n = len(openvuln.calls)
    second = _preview(client, "IOS XE", "17.6.3").json()
    assert len(openvuln.calls) == n          # no query over budget
    assert second["state"] == "findings" and second["critical"] is not None
    assert second["upgrade"]["source"] == "dataset"
    assert second["upgrade_note"] == "Cisco check unavailable right now."
    assert "INFO preview openvuln_cap_hit" in capsys.readouterr().out
    # a refused pass is not a failure: the full analyzer still asks Cisco
    assert csc._failed_at is None
    full = client.post("/analyze/cve", json={"platform": "IOS XE", "version": "17.6.3"}).json()
    assert full["cisco_upgrade_path"] is not None


def test_cached_release_costs_no_budget(client, openvuln, monkeypatch):
    monkeypatch.setattr(pv, "budget", pv.OpenVulnBudget(cap=(1, 3600)))
    _preview(client, "IOS XE", "17.9.4")
    again = _preview(client, "IOS XE", "17.9.4").json()
    assert again["upgrade"]["source"] == "cisco"


def test_one_pass_is_one_unit_even_with_several_queries(client, openvuln, monkeypatch):
    monkeypatch.setattr(pv, "budget", pv.OpenVulnBudget(cap=(1, 3600)))
    d = _preview(client, "IOS XE", "17.9.4").json()   # 17.9.4 then 17.9.10: two queries
    assert len(openvuln.calls) == 2 and d["upgrade"]["target"] == "17.9.10"


def test_budget_window():
    c = Clock()
    b = pv.OpenVulnBudget(cap=(2, 3600), clock=c)
    assert b.take() and b.take() and not b.take()
    c.t += 3601
    assert b.take()


def test_default_budget_is_60_per_hour():
    assert pv.OPENVULN_CAP == (60, 3600)


# ---------------------------------------------------------------- logging (T8, AC-17)

def test_log_line_has_state_and_family_only(client, openvuln, capsys):
    _preview(client, "IOS XE", "17.9.4", headers=_from("70.1.2.3"))
    _preview(client, "IOS XE", "abc")
    out = capsys.readouterr().out
    lines = [l for l in out.splitlines() if l.startswith("INFO preview")]
    assert lines == ["INFO preview state=findings family=ios-xe",
                     "INFO preview state=invalid family=ios-xe"]
    assert "17.9.4" not in out and "70.1.2.3" not in out and "abc" not in out


# ---------------------------------------------------------------- subscribe source (T7)

SID = "170000000000000042"


class FakeMailerLite:
    def __init__(self, post_status=201, put_status=200):
        self.requests = []
        self.post_status = post_status
        self.put_status = put_status

    def handler(self, request: httpx.Request):
        self.requests.append(request)
        if request.method == "POST":
            return httpx.Response(self.post_status, json={"data": {"id": SID}})
        if request.method == "PUT":
            return httpx.Response(self.put_status, json={"data": {"id": SID}})
        return httpx.Response(405)

    def client(self):
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


@pytest.fixture
def ml(monkeypatch):
    fake = FakeMailerLite()
    monkeypatch.setattr(sub, "MAILERLITE_API_KEY", "test-key-not-real")
    monkeypatch.setattr(sub, "_client", fake.client)
    return fake


def _puts(fake):
    return [r for r in fake.requests if r.method == "PUT"]


def test_new_subscriber_from_preview_is_tagged(client, ml, capsys):
    r = client.post("/api/subscribe", json={"email": "a@example.com", "source": "preview"})
    assert r.status_code == 200 and r.json()["success"] is True
    (put,) = _puts(ml)
    assert put.url.path == f"/api/subscribers/{SID}"
    assert json.loads(put.content) == {"fields": {"signup_source": "preview"}}
    post = [x for x in ml.requests if x.method == "POST"][0]
    assert "signup_source" not in post.content.decode()   # never in the upsert
    out = capsys.readouterr().out
    assert "INFO subscribe new=1 source=preview" in out and "a@example.com" not in out


def test_existing_subscriber_is_never_overwritten(client, ml):
    ml.post_status = 200
    client.post("/api/subscribe", json={"email": "a@example.com", "source": "preview"})
    assert _puts(ml) == []


@pytest.mark.parametrize("body", [{"email": "a@example.com"},
                                  {"email": "a@example.com", "source": "landing"},
                                  {"email": "a@example.com", "source": "preview2"},
                                  {"email": "a@example.com", "source": None}])
def test_other_sources_are_ignored(client, ml, capsys, body):
    r = client.post("/api/subscribe", json=body)
    assert r.status_code == 200
    assert _puts(ml) == []
    assert "INFO subscribe new=1 source=none" in capsys.readouterr().out


def test_failed_tag_still_subscribes(client, ml):
    ml.put_status = 500
    r = client.post("/api/subscribe", json={"email": "a@example.com", "source": "preview"})
    assert r.json()["success"] is True


def test_same_answer_new_or_existing(client, ml):
    a = client.post("/api/subscribe", json={"email": "a@example.com", "source": "preview"}).json()
    ml.post_status = 200
    b = client.post("/api/subscribe", json={"email": "a@example.com", "source": "preview"}).json()
    assert a == b


# ---------------------------------------------------------------- frontend (AC-1, AC-6, T6)

def test_no_new_asset_files_needed():
    assert "app-security" in JS_FILES and "style-home" in CSS_FILES
    html = (WEB / "index.html").read_text()
    for src in re.findall(r'<script src="([\w-]+)\.js', html):
        assert src in JS_FILES
    for href in re.findall(r'<link rel="stylesheet" href="([\w-]+)\.css', html):
        assert href in CSS_FILES


def test_card_is_hidden_until_the_flag_and_above_quickstart():
    html = (WEB / "index.html").read_text()
    home = html.split('<section id="tab-home"', 1)[1].split("</section>", 1)[0]
    assert '<div class="preview-card" id="preview" hidden>' in home
    assert home.index('id="preview"') < home.index('id="quickstart-card"')
    card = home.split('id="preview"', 1)[1].split('id="quickstart-card"', 1)[0]
    assert "gate-lock" not in card and "🔒" not in card
    opts = re.findall(r'<option value="([^"]+)"', card)
    assert set(opts) == set(pv.PLATFORMS)
    assert 'maxlength="64"' in card


def _preview_js():
    js = (WEB / "app-security.js").read_text()
    return js.split("PREVIEW-01", 1)[1]


def test_preview_js_writes_text_only():
    js = _preview_js()
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js and "outerHTML" not in js
    assert 'showGateModal("cve"' in js
    assert "/analyze/cve/preview" in js and '"cve_preview"' in js


def test_no_em_dash_in_new_copy():
    assert "\u2014" not in _preview_js()
    html = (WEB / "index.html").read_text()
    card = html.split('id="preview"', 1)[1].split('id="quickstart-card"', 1)[0]
    assert "\u2014" not in card


NODE_HARNESS = r"""
const fs = require("fs");
const vm = require("vm");
const gate = fs.readFileSync(process.argv[2], "utf8");
const sec = fs.readFileSync(process.argv[3], "utf8");

function sandbox(store, search) {
  const bodies = [];
  const storage = {
    getItem: k => (k in store ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); },
  };
  const document = { readyState: "complete", querySelector: () => null,
                     querySelectorAll: () => [], getElementById: () => null,
                     addEventListener: () => {} };
  const loc = new URL("https://netdevops-tools.thebackroom.ai/" + (search || ""));
  const ctx = { document, localStorage: storage, Headers, URL, URLSearchParams, Request, console,
                setTimeout, Promise, JSON, Date, Object, String, Array, Number, parseInt,
                location: loc,
                fetch: async (u, init) => { bodies.push(init && init.body ? JSON.parse(init.body) : null);
                                            return { ok: true, json: async () => ({ success: true, token: null }) }; } };
  ctx.window = ctx;
  vm.createContext(ctx);
  vm.runInContext(gate, ctx);
  return { ctx, bodies, store };
}

(async () => {
  const out = {};
  const now = Date.now();
  let s = sandbox({ netdevops_preview_at: String(now - 3600e3) });
  await vm.runInContext("submitEmail('a@b.co')", s.ctx);
  out.recent = s.bodies.pop();
  s = sandbox({ netdevops_preview_at: String(now - 8 * 86400e3) });
  await vm.runInContext("submitEmail('a@b.co')", s.ctx);
  out.old = s.bodies.pop();
  s = sandbox({});
  await vm.runInContext("submitEmail('a@b.co')", s.ctx);
  out.none = s.bodies.pop();
  s = sandbox({ netdevops_preview_at: String(now) }, "?internal=1");
  await vm.runInContext("submitEmail('a@b.co')", s.ctx);
  out.internal = { body: s.bodies.pop(), flag: s.store.netdevops_internal || null };

  // previewLines from app-security.js: run only the pure function
  const fn = sec.slice(sec.indexOf("const PREVIEW_TRAIN_TEXT"), sec.indexOf("(function initPreview()"));
  const c2 = { String, JSON, Object, Array, document: { createElement: () => ({}) } };
  vm.createContext(c2);
  vm.runInContext(fn + "\nthis.previewLines = previewLines;", c2);
  const base = { interpreted_as: "IOS XE 17.9.4", data_as_of: "2026-11-20", sources: "S" };
  out.findings = c2.previewLines(Object.assign({ state: "findings", critical: 2, high: 44, kev: 1,
    need_confirmation: 3, upgrade: { source: "cisco", target: "17.9.10", train: "same",
    critical_high_left: 0 } }, base)).map(l => l.text);
  out.clean = c2.previewLines(Object.assign({ state: "clean", critical: 0, high: 0, medium: 5, low: 0,
    kev: 0, note: "Our dataset covers Cisco PSIRT advisories; it is not a full scan of your device." }, base)).map(l => l.text);
  out.unknown = c2.previewLines({ state: "unknown", note: "NOT EVALUATED: x", format_hint: "e.g. 17.9.4a" }).map(l => l.text);
  out.eol = c2.previewLines(Object.assign({ state: "eol", critical: 1, high: 2, kev: 0,
    eol_note: "Hardware replacement required, no software fix path.",
    upgrade: { source: "dataset", target: "X" } }, base)).map(l => l.text);
  console.log(JSON.stringify(out));
})().catch(e => { console.error(e); process.exit(1); });
"""


@pytest.fixture(scope="module")
def node_out(tmp_path_factory):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    script = tmp_path_factory.mktemp("preview") / "harness.js"
    script.write_text(NODE_HARNESS)
    res = subprocess.run([node, str(script), str(WEB / "app-gate.js"), str(WEB / "app-security.js")],
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout.strip().splitlines()[-1])


def test_source_sent_only_within_7_days_and_not_from_internal(node_out):
    assert node_out["recent"] == {"email": "a@b.co", "source": "preview"}
    assert node_out["old"] == {"email": "a@b.co"}
    assert node_out["none"] == {"email": "a@b.co"}
    assert node_out["internal"] == {"body": {"email": "a@b.co"}, "flag": "1"}


def test_rendered_lines(node_out):
    f = node_out["findings"]
    assert f[0] == "Interpreted as: IOS XE 17.9.4"
    assert "Critical: 2" in f and "High: 44 (3 of them need confirmation)" in f
    assert "KEV: 1, listed by CISA as exploited in the wild" in f
    assert any("Safe upgrade path: 17.9.10 (same train). Critical/High left at target: 0." in l for l in f)
    assert any(l.startswith("Data as of 2026-11-20.") for l in f)
    c = node_out["clean"]
    assert "0 Critical, 0 High in our dataset for this release" in c
    assert "Medium: 5, Low: 0" in c
    assert not any("safe" in l.lower() for l in c)
    assert node_out["unknown"] == ["NOT EVALUATED: x", "e.g. 17.9.4a"]
    e = node_out["eol"]
    assert "Hardware replacement required, no software fix path." in e
    assert not any("upgrade path" in l for l in e)
