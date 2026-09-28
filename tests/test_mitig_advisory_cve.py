"""MITIG-WRONG-CVE (2026-09-27): a mitigation must sit under an advisory that lists its CVE.

Three hand-written records (CVE-2020-3452, CVE-2024-20291, CVE-2024-20356) pointed at the
advisory of a different CVE, so Cisco's Workarounds text (and, for 20291, the whole record)
described another vulnerability. Fixed in MITIG-REVIEW 2/7. Two guards keep it that way:
  * importer gate: `cisco_workaround.fetch_checked` rejects an advisory whose CSAF does not
    list the CVE, and both importers then do not write the mitigation;
  * data check: every file stores the CVE list of its advisory (`cisco_workaround.cves`)
    and must be listed there (offline, all 150 files).
"""
import glob
import io
import json
import os
from unittest.mock import patch

import pytest

import scripts.mitig_patch_only as mp
import services.cisco_sync as cisco_sync
from services import cisco_workaround as cw
from services.cisco_workaround import fetch_checked as real_fetch_checked

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIT = os.path.join(ROOT, "cve_mitigations")
URL = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"


def _csaf(*cves):
    return json.dumps({
        "document": {"notes": [{"title": "Workarounds",
                                "text": "There are no workarounds that address this vulnerability."}]},
        "vulnerabilities": [{"cve": c} for c in cves],
    }).encode()


class _R(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _serve(*cves):
    return patch.object(cw.urllib.request, "urlopen", side_effect=lambda *a, **k: _R(_csaf(*cves)))


# ---- gate -------------------------------------------------------------------------------

def test_gate_accepts_advisory_that_lists_the_cve():
    with _serve("CVE-2099-0001", "CVE-2099-0002"):
        wa, rejected = real_fetch_checked(URL + "cisco-sa-test", "CVE-2099-0002")
    assert rejected is False
    assert wa["status"] == "none" and wa["cves"] == ["CVE-2099-0001", "CVE-2099-0002"]


def test_gate_rejects_advisory_of_another_cve(capsys):
    with _serve("CVE-2020-3187"):
        wa, rejected = real_fetch_checked(URL + "cisco-sa-asaftd-path-JE3azWw43", "CVE-2020-3452")
    assert wa is None and rejected is True
    assert "REJECTED CVE-2020-3452" in capsys.readouterr().out


def test_gate_network_failure_is_not_a_rejection():
    with patch.object(cw.urllib.request, "urlopen", side_effect=TimeoutError("t")):
        assert real_fetch_checked(URL + "cisco-sa-test", "CVE-2099-0001") == (None, False)
    assert real_fetch_checked(None, "CVE-2099-0001") == (None, False)


def _adv(cves=("CVE-2099-0001",)):
    return {"advisoryId": "cisco-sa-test-1", "advisoryTitle": "Cisco IOS XE Software Test Vulnerability",
            "sir": "High", "cvssBaseScore": "8.6", "cves": list(cves), "cwe": ["CWE-20"],
            "summary": "s", "firstPublished": "2026-01-01", "lastUpdated": "2026-01-01",
            "publicationUrl": URL + "cisco-sa-test-1",
            "productNames": ["Cisco IOS XE Software 17.9.4"]}


@pytest.fixture
def sync_dirs(tmp_path, monkeypatch):
    data, mit = tmp_path / "cve", tmp_path / "mit"
    data.mkdir(); mit.mkdir()
    monkeypatch.setattr(cisco_sync, "CVE_DATA_DIR", str(data))
    monkeypatch.setattr(cisco_sync, "MITIGATION_DIR", str(mit))
    monkeypatch.setattr(cw, "fetch_checked", real_fetch_checked)  # conftest stubs it offline
    return data, mit


def test_importer_rejects_mitigation_when_advisory_does_not_list_cve(sync_dirs):
    data, mit = sync_dirs
    with _serve("CVE-2099-9999"):
        cisco_sync.auto_sync_new_cves([_adv()])
    assert (data / "cve-2099-0001.json").exists()        # the CVE record still follows PSIRT
    assert not (mit / "CVE-2099-0001.json").exists()     # no mitigation under a foreign advisory


def test_importer_writes_mitigation_with_cve_list_when_listed(sync_dirs):
    _, mit = sync_dirs
    with _serve("CVE-2099-0001"):
        cisco_sync.auto_sync_new_cves([_adv()])
    rec = json.loads((mit / "CVE-2099-0001.json").read_text(encoding="utf-8"))
    assert rec["cisco_workaround"]["cves"] == ["CVE-2099-0001"]


def test_all_writers_use_the_gate():
    import scripts.import_cisco_to_local as imp
    import scripts.fetch_cisco_workarounds as fw
    for mod in (cisco_sync, imp):
        src = open(mod.__file__, encoding="utf-8").read()
        assert "fetch_checked(" in src and "rejected" in src
    src = open(fw.__file__, encoding="utf-8").read()
    assert 'cve not in (wa.get("cves") or [])' in src


# ---- data: 150/150 ----------------------------------------------------------------------

def _files():
    out = []
    for p in sorted(glob.glob(os.path.join(MIT, "CVE-*.json"))):
        with open(p, encoding="utf-8") as f:
            out.append(json.load(f))
    return out


def test_every_mitigation_sits_under_an_advisory_that_lists_its_cve():
    files = _files()
    assert len(files) == 150
    wrong = []
    for d in files:
        wa = d["cisco_workaround"]
        sa = cw.advisory_id(d["cisco_psirt"])
        if sa != cw.advisory_id(wa["source"]):
            wrong.append((d["cve_id"], "cisco_psirt and CSAF source differ"))
        elif d["cve_id"] not in (wa.get("cves") or []):
            wrong.append((d["cve_id"], sa, wa.get("cves")))
    assert wrong == []


def test_patch_only_classifier_sees_no_advisory_mismatch_offline():
    """Same check through mitig_patch_only's gate, fed from the stored CVE lists."""
    lists = {}
    for d in _files():
        sa = mp._SA_RE.search(d["cisco_workaround"]["source"]).group(1)
        lists.setdefault(sa, set()).update(d["cisco_workaround"]["cves"])
    res = mp.run(MIT, dry_run=True, cve_lookup=lambda sa: lists.get(sa))
    assert [x for x in res[mp.UNKNOWN] if "does not list" in x[2]] == []
