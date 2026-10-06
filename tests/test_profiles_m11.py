"""
M11 (v0.6.66): profile names are file names, so they are validated, and
server-side profile storage is off during the public beta.

Covers:
- name allowlist + "resolves inside profiles/" on load / save / delete
- POST /profiles/save and DELETE /profiles/delete/{name} refuse (403) and
  write nothing
- the demo profiles (branch, dc, lab) stay readable, and the endpoints that
  aggregate profiles only ever see files inside profiles/
- regression for the PoC: a save aimed at a CVE record cannot touch it, and the
  analyzer still reports CVE-2018-0171
- the advisories feed rejects a platform filter that is not a plain slug
"""

import hashlib
import json
import os
import shutil

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.routers import cve as cve_router
from api.routers import export as export_router
from api.routers import profiles as profiles_router
from models.profile_model import DeviceProfile
from services.profile_service import (
    PROFILE_STORAGE_DISABLED_MESSAGE,
    InvalidProfileName,
    ProfileService,
    ProfileStorageDisabled,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CVE_0171 = os.path.join(REPO, "cve_data", "ios_xe", "cve-2018-0171.json")
DEMO = ["branch", "dc", "lab"]

BAD_NAMES = [
    "../x",
    "../../etc/passwd",
    "../cve_data/ios_xe/cve-2018-0171",
    "..",
    ".",
    "..json",
    ".hidden",
    "branch.json",
    "a/b",
    "a\\b",
    "/tmp/x",
    "/etc/passwd",
    "C:\\x",
    "..%2fx",
    "%2e%2e%2fx",
    "name with space",
    "x\x00y",
    "x\n",
    "",
    "a" * 65,
    "caf\u00e9",
    "\uff0e\uff0e\uff0fx",  # fullwidth "../x"
    "\u2024\u2024/x",  # one-dot leaders
    "a\u200bb",  # zero-width space
]

client = TestClient(app)


def _sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _tree(root):
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(dirpath, f)
            out[os.path.relpath(p, root)] = _sha(p)
    return out


@pytest.fixture
def sandbox(tmp_path):
    """tmp/profiles (demo copies) next to tmp/cve_data/ios_xe/cve-2018-0171.json."""
    prof = tmp_path / "profiles"
    prof.mkdir()
    for name in DEMO:
        shutil.copy(os.path.join(REPO, "profiles", f"{name}.json"), prof / f"{name}.json")
    cve_dir = tmp_path / "cve_data" / "ios_xe"
    cve_dir.mkdir(parents=True)
    shutil.copy(CVE_0171, cve_dir / "cve-2018-0171.json")
    return tmp_path


# ------------------------------------------------------------------
# Service: name validation (independent of the write switch)
# ------------------------------------------------------------------

@pytest.mark.parametrize("name", BAD_NAMES)
@pytest.mark.parametrize("allow_writes", [False, True])
def test_service_rejects_bad_names_everywhere(sandbox, name, allow_writes):
    svc = ProfileService(str(sandbox / "profiles"), allow_writes=allow_writes)
    before = _tree(str(sandbox))
    with pytest.raises(InvalidProfileName):
        svc.load_profile(name)
    with pytest.raises(InvalidProfileName):
        svc.save_profile(DeviceProfile(name=name))
    with pytest.raises(InvalidProfileName):
        svc.delete_profile(name)
    assert _tree(str(sandbox)) == before


@pytest.mark.parametrize("name", ["branch", "dc", "lab", "a", "A-b_9", "x" * 64])
def test_service_accepts_allowlisted_names(sandbox, name):
    svc = ProfileService(str(sandbox / "profiles"))
    path = svc._path(name)
    assert os.path.dirname(path) == os.path.realpath(str(sandbox / "profiles"))
    assert path.endswith(f"{name}.json")


def test_symlink_out_of_profiles_is_not_followed(sandbox):
    prof = sandbox / "profiles"
    os.symlink(str(sandbox / "cve_data" / "ios_xe" / "cve-2018-0171.json"), str(prof / "evil.json"))
    svc = ProfileService(str(prof), allow_writes=True)
    with pytest.raises(InvalidProfileName):
        svc.load_profile("evil")
    with pytest.raises(InvalidProfileName):
        svc.save_profile(DeviceProfile(name="evil"))
    assert "evil" not in svc.list_profiles()
    assert _sha(str(sandbox / "cve_data" / "ios_xe" / "cve-2018-0171.json")) == _sha(CVE_0171)


def test_list_ignores_files_with_disallowed_names(sandbox):
    prof = sandbox / "profiles"
    (prof / "bad name.json").write_text("{}")
    (prof / "x.y.json").write_text("{}")
    (prof / "notes.txt").write_text("x")
    svc = ProfileService(str(prof))
    assert svc.list_profiles() == DEMO


# ------------------------------------------------------------------
# Service: writes are off by default
# ------------------------------------------------------------------

def test_service_save_disabled_by_default_writes_nothing(sandbox):
    svc = ProfileService(str(sandbox / "profiles"))
    before = _tree(str(sandbox))
    with pytest.raises(ProfileStorageDisabled):
        svc.save_profile(DeviceProfile(name="newprofile", snmp={"auth_password": "s3cret"}))
    with pytest.raises(ProfileStorageDisabled):
        svc.save_profile(DeviceProfile(name="branch"))
    assert _tree(str(sandbox)) == before


def test_service_delete_disabled_by_default_keeps_demo(sandbox):
    svc = ProfileService(str(sandbox / "profiles"))
    with pytest.raises(ProfileStorageDisabled):
        svc.delete_profile("branch")
    assert svc.list_profiles() == DEMO


def test_service_write_path_still_works_when_enabled(sandbox):
    """The switch, not a broken code path, is what stops writes."""
    svc = ProfileService(str(sandbox / "profiles"), allow_writes=True)
    svc.save_profile(DeviceProfile(name="tmp-1"))
    assert "tmp-1" in svc.list_profiles()
    svc.delete_profile("tmp-1")
    assert "tmp-1" not in svc.list_profiles()


# ------------------------------------------------------------------
# API: refusal codes, nothing on disk
# ------------------------------------------------------------------

@pytest.fixture
def api_sandbox(sandbox, monkeypatch):
    """Point the profile endpoints at the sandbox, writes off (production default)."""
    svc = ProfileService(str(sandbox / "profiles"))
    monkeypatch.setattr(profiles_router, "svc", svc)
    monkeypatch.setattr(export_router, "svc", svc)
    return sandbox


@pytest.mark.parametrize("name", [n for n in BAD_NAMES if "\x00" not in n])
def test_api_save_bad_name_400(api_sandbox, name):
    before = _tree(str(api_sandbox))
    r = client.post("/profiles/save", json={"name": name})
    assert r.status_code == 400
    assert _tree(str(api_sandbox)) == before


def test_api_save_valid_name_403(api_sandbox):
    before = _tree(str(api_sandbox))
    r = client.post("/profiles/save", json={"name": "mine", "snmp": {"auth_password": "s3cret"}})
    assert r.status_code == 403
    assert r.json()["detail"] == PROFILE_STORAGE_DISABLED_MESSAGE
    assert "public beta" in r.json()["detail"]
    r = client.post("/profiles/save", json={"name": "branch"})
    assert r.status_code == 403
    assert _tree(str(api_sandbox)) == before


@pytest.mark.parametrize("name", DEMO + ["missing"])
def test_api_delete_403(api_sandbox, name):
    before = _tree(str(api_sandbox))
    r = client.delete(f"/profiles/delete/{name}")
    assert r.status_code == 403
    assert _tree(str(api_sandbox)) == before


@pytest.mark.parametrize("path", [
    "/profiles/delete/..",
    "/profiles/delete/..json",
    "/profiles/delete/branch.json",
    "/profiles/delete/..%2fx",
    "/profiles/delete/%2e%2e",
    "/profiles/load/..",
    "/profiles/load/..json",
    "/profiles/load/branch.json",
    "/profiles/load/..%2fcve_data",
    "/profiles/load/%2e%2e%5cx",
    "/profiles/load/caf%C3%A9",
])
def test_api_traversal_in_url_is_4xx(api_sandbox, path):
    before = _tree(str(api_sandbox))
    r = client.request("DELETE" if "/delete/" in path else "GET", path)
    assert 400 <= r.status_code < 500
    assert _tree(str(api_sandbox)) == before


def test_api_demo_profiles_readable(api_sandbox):
    assert client.get("/profiles/list").json() == {"profiles": DEMO}
    for name in DEMO:
        r = client.get(f"/profiles/load/{name}")
        assert r.status_code == 200
        assert r.json()["name"] == name


def test_api_aggregates_only_see_profiles_dir(api_sandbox):
    # A stray file next to profiles/ must never show up.
    (api_sandbox / "outside.json").write_text(json.dumps({"name": "outside"}))
    vulns = client.get("/profiles/vulnerabilities")
    assert vulns.status_code == 200
    assert sorted(r["profile_name"] for r in vulns.json()["results"]) == DEMO
    scores = client.get("/profiles/security-scores")
    assert scores.status_code == 200
    assert sorted(r["profile_name"] for r in scores.json()["results"]) == DEMO
    exp = client.get("/export/security-report", params={"format": "json"})
    assert exp.status_code == 200
    assert "outside" not in exp.text


def test_production_router_has_writes_off():
    assert profiles_router.svc.allow_writes is False
    assert export_router.svc.allow_writes is False


# ------------------------------------------------------------------
# Regression: the @ciso PoC (save aimed at a CVE record)
# ------------------------------------------------------------------

def _analyzer_ids():
    r = client.post("/analyze/cve", json={"platform": "Catalyst 9300", "version": "16.3.1"})
    assert r.status_code == 200
    return {m["cve_id"] for m in r.json()["matched"]}


def test_poc_save_over_cve_record_refused_production_router():
    """Real router, real profiles/ dir: the exact PoC body is refused."""
    before = _sha(CVE_0171)
    r = client.post("/profiles/save", json={"name": "../cve_data/ios_xe/cve-2018-0171"})
    assert r.status_code == 400
    r = client.post("/profiles/save", json={"name": CVE_0171[:-len(".json")]})
    assert r.status_code == 400
    assert _sha(CVE_0171) == before
    assert "CVE-2018-0171" in _analyzer_ids()


def test_poc_refused_even_with_writes_enabled(sandbox, monkeypatch):
    """Validation alone (writes switched on) keeps the CVE record intact."""
    svc = ProfileService(str(sandbox / "profiles"), allow_writes=True)
    monkeypatch.setattr(profiles_router, "svc", svc)
    target = sandbox / "cve_data" / "ios_xe" / "cve-2018-0171.json"
    before = _sha(str(target))
    for name in ("../cve_data/ios_xe/cve-2018-0171", str(target)[:-len(".json")]):
        r = client.post("/profiles/save", json={"name": name})
        assert r.status_code == 400
    assert _sha(str(target)) == before
    assert "CVE-2018-0171" in _analyzer_ids()


# ------------------------------------------------------------------
# Advisories feed: platform filter becomes a cache file name
# ------------------------------------------------------------------

@pytest.mark.parametrize("platform", [
    "../cve_data/ios_xe/cve-2018-0171",
    "..",
    "/etc/passwd",
    "a/b",
    "IOSXE",
    "ios xe",
    "x" * 33,
    "caf\u00e9",
])
def test_feed_rejects_non_slug_platform(platform, monkeypatch):
    called = []
    monkeypatch.setattr(cve_router, "_get_advisories_feed", lambda p="all": called.append(p))
    for route in ("/analyze/advisories", "/analyze/critical-feed"):
        r = client.get(route, params={"platform": platform})
        assert r.status_code == 400
    assert called == []


@pytest.mark.parametrize("platform", ["all", "iosxe", "ios", "nxos", "asa", "ftd", "ise"])
def test_feed_accepts_ui_platforms(platform):
    assert cve_router._validated_feed_platform(platform) == platform
