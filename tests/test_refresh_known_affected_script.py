"""The repo-copy refresher: refresh-only, exact dry-run, honest exit codes."""
import importlib.util
import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location(
    "refresh_known_affected", os.path.join(ROOT, "scripts", "refresh_known_affected.py"))
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)


def _record(tmp_path, cve="CVE-2026-0001", adv_id="cisco-sa-test-1", listed=("17.9.1",)):
    path = tmp_path / f"{cve.lower()}.json"
    path.write_text(json.dumps({
        "cve_id": cve,
        "title": "curated title",
        "severity": "high",
        "advisory_url": f"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{adv_id}",
        "known_affected": {"ios-xe": list(listed)},
        "known_affected_as_of": "2026-01-01",
    }), encoding="utf-8")
    return path


def _adv(adv_id="cisco-sa-test-1", cves=("CVE-2026-0001",), versions=("17.9.1", "17.9.2")):
    return {"advisoryId": adv_id, "cves": list(cves),
            "productNames": [f"Cisco IOS XE Software {v}" for v in versions]}


def test_revised_list_is_written_and_curated_fields_survive(tmp_path):
    path = _record(tmp_path)
    seen, changed = script.refresh_platform("iosxe", [_adv()], str(tmp_path))
    rec = json.loads(path.read_text(encoding="utf-8"))
    assert (seen, changed) == (1, 1)
    assert rec["known_affected"]["ios-xe"] == ["17.9.1", "17.9.2"]
    assert rec["known_affected_as_of"] != "2026-01-01"
    assert rec["title"] == "curated title" and rec["severity"] == "high"


def test_never_creates_a_record(tmp_path):
    seen, changed = script.refresh_platform("iosxe", [_adv(cves=("CVE-2026-9999",))], str(tmp_path))
    assert (seen, changed) == (0, 0) and os.listdir(tmp_path) == []


def test_dry_run_reports_the_same_number_and_writes_nothing(tmp_path):
    path = _record(tmp_path)
    before = path.read_bytes()
    assert script.refresh_platform("iosxe", [_adv()], str(tmp_path), dry_run=True) == (1, 1)
    assert path.read_bytes() == before


def test_unchanged_list_is_not_touched(tmp_path):
    path = _record(tmp_path, listed=("17.9.1", "17.9.2"))
    before = path.read_bytes()
    assert script.refresh_platform("iosxe", [_adv()], str(tmp_path)) == (1, 0)
    assert path.read_bytes() == before


def test_another_advisory_for_the_same_cve_does_not_overwrite(tmp_path):
    path = _record(tmp_path)
    before = path.read_bytes()
    other = _adv(adv_id="cisco-sa-other-9", versions=("16.12.1",))
    assert script.refresh_platform("iosxe", [other], str(tmp_path)) == (1, 0)
    assert path.read_bytes() == before


def test_exit_2_when_nothing_could_be_fetched(capsys):
    assert script.main(["--dry-run"], fetch=lambda platform: []) == 2
    assert "could not look" in capsys.readouterr().out


def test_exit_0_and_every_sync_platform_has_a_dataset(monkeypatch, tmp_path):
    from services.cve_sources import AUTO_SYNC_PLATFORMS
    assert set(script.DATA_DIR_FOR) == set(AUTO_SYNC_PLATFORMS)
    monkeypatch.setattr(script, "DATA_DIR_FOR", {p: str(tmp_path) for p in AUTO_SYNC_PLATFORMS})
    assert script.main(["--dry-run"], fetch=lambda platform: [_adv()]) == 0


# ---------- the "ios" platform query (found while building this script) ----------

def test_ios_query_uses_a_name_the_api_can_match():
    from services.cve_sources import CiscoAdvisoryProvider
    # classic IOS releases are "Cisco IOS 15.x"; "Cisco IOS Software" never matched
    assert CiscoAdvisoryProvider.PLATFORM_PRODUCTS["ios"] == "Cisco IOS"


def test_ios_fetch_drops_xe_only_and_xr_advisories(monkeypatch):
    from services.cve_sources import CiscoAdvisoryProvider
    page = {"advisories": [
        {"advisoryId": "a-classic", "productNames": ["Cisco IOS 15.2(4)E", "Cisco IOS XE Software 17.9.1"]},
        {"advisoryId": "a-xe-only", "productNames": ["Cisco IOS XE Software 17.9.1"]},
        {"advisoryId": "a-xr-only", "productNames": ["Cisco IOS XR Software 7.1.1"]},
    ]}
    p = CiscoAdvisoryProvider(platform="ios")
    monkeypatch.setattr(p, "_load_credentials", lambda: {"client_id": "x", "client_secret": "y"})
    monkeypatch.setattr(p, "_api_get", lambda url: page)
    monkeypatch.setattr(p, "_write_cache", lambda advs: None)
    assert [a["advisoryId"] for a in p.fetch_advisories(use_cache=False)] == ["a-classic"]


def test_ios_only_advisory_is_not_filed_as_ios_xe():
    from services.cisco_sync import _build_cve_json
    adv = {"advisoryId": "cisco-sa-x", "sir": "High", "advisoryTitle": "t", "summary": "s",
           "productNames": ["Cisco IOS 15.2(4)E"], "cves": ["CVE-2026-0002"]}
    assert _build_cve_json("CVE-2026-0002", adv, "", "")["platforms"] == ["IOS"]
    adv["productNames"].append("Cisco IOS XE Software 17.9.1")
    assert _build_cve_json("CVE-2026-0002", adv, "", "")["platforms"] == ["IOS XE", "IOS"]
    adv["productNames"] = []
    assert _build_cve_json("CVE-2026-0002", adv, "", "")["platforms"] == ["IOS XE"]
