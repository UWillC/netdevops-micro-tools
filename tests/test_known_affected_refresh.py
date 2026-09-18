"""
Known Affected lists stay current on their own (LISTS-01, 2026-09-18).

MATCH-01 made the Known Affected list decide whether a release matches at all.
But auto_sync_new_cves() skips CVEs that already exist locally, so a list was
frozen at import time and would go quietly wrong the day Cisco revised the
advisory. The interim answer — "remember to run the migration script" — is the
mechanism by which the IOS XE platform cache had reached 189 days.

Two halves: the sync refreshes lists on existing records, and the analyzer
itself starts that sync in the background when the platform cache is stale.
"""

import datetime
import json
import os
import time

import pytest

import services.cisco_sync as cisco_sync
from api.routers import cve as cve_router
from services.cisco_sync import auto_sync_new_cves, refresh_known_affected

URL = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
TODAY = datetime.date.today().isoformat()


def adv(adv_id="cisco-sa-test-1", cves=("CVE-2026-1",), versions=("17.9.4", "17.9.5")):
    return {"advisoryId": adv_id, "advisoryTitle": "Cisco IOS XE Software Test Vulnerability",
            "sir": "High", "cvssBaseScore": "8.6", "cves": list(cves), "cwe": ["CWE-20"],
            "summary": "s", "firstPublished": "2026-01-01", "lastUpdated": "2026-01-01",
            "publicationUrl": URL + adv_id,
            "productNames": ["Cisco IOS XE Software " + v for v in versions]}


def curated(adv_id="cisco-sa-test-1", lists=None, as_of="2026-01-01"):
    return {"cve_id": "CVE-2026-1", "title": "CURATED TITLE", "severity": "critical",
            "platforms": ["IOS XE"], "affected": {"min": "17.1.1", "max": "17.9.5"},
            "fixed_in": "17.9.6", "tags": ["hand-picked"], "description": "curated words",
            "advisory_url": URL + adv_id, "source": "local-json",
            "known_affected": lists if lists is not None else {"ios-xe": ["17.9.4"]},
            "known_affected_as_of": as_of}


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    data, mit = tmp_path / "cve", tmp_path / "mit"
    data.mkdir(); mit.mkdir()
    monkeypatch.setattr(cisco_sync, "CVE_DATA_DIR", str(data))
    monkeypatch.setattr(cisco_sync, "MITIGATION_DIR", str(mit))
    return data


def write(dirs, rec):
    path = dirs / (rec["cve_id"].lower() + ".json")
    path.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    return path


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


class TestRefreshOneRecord:
    def test_revised_list_replaces_the_old_one(self, dirs):
        path = write(dirs, curated())
        assert refresh_known_affected(str(path), adv(versions=("17.9.4", "17.9.5", "17.12.1"))) == 1
        rec = read(path)
        assert rec["known_affected"]["ios-xe"] == ["17.12.1", "17.9.4", "17.9.5"]
        assert rec["known_affected_as_of"] == TODAY

    def test_cisco_removing_a_release_is_followed_too(self, dirs):
        path = write(dirs, curated(lists={"ios-xe": ["17.9.4", "17.9.5"]}))
        refresh_known_affected(str(path), adv(versions=("17.9.5",)))
        assert read(path)["known_affected"]["ios-xe"] == ["17.9.5"]

    def test_curated_fields_are_never_touched(self, dirs):
        path = write(dirs, curated())
        before = read(path)
        refresh_known_affected(str(path), adv(versions=("17.12.1",)))
        after = read(path)
        for key in before:
            if key not in ("known_affected", "known_affected_as_of"):
                assert after[key] == before[key], key

    def test_unchanged_list_writes_nothing_and_keeps_its_date(self, dirs):
        path = write(dirs, curated(lists={"ios-xe": ["17.9.4", "17.9.5"]}))
        mtime = os.path.getmtime(path)
        time.sleep(0.01)
        assert refresh_known_affected(str(path), adv()) == 0
        assert os.path.getmtime(path) == mtime
        assert read(path)["known_affected_as_of"] == "2026-01-01"

    def test_other_advisory_for_the_same_cve_does_not_flip_the_list(self, dirs):
        """One CVE can sit in several advisories with different release lists."""
        path = write(dirs, curated(adv_id="cisco-sa-test-1"))
        other = adv(adv_id="cisco-sa-OTHER", versions=("16.1.1",))
        assert refresh_known_affected(str(path), other) == 0
        assert read(path)["known_affected"] == {"ios-xe": ["17.9.4"]}

    def test_a_list_is_never_replaced_by_nothing(self, dirs):
        """'Cisco IOS XE Software ' with no release = not told, not 'none affected'."""
        path = write(dirs, curated())
        nameless = adv()
        nameless["productNames"] = ["Cisco IOS XE Software "]
        assert refresh_known_affected(str(path), nameless) == 0
        assert read(path)["known_affected"] == {"ios-xe": ["17.9.4"]}

    def test_a_family_missing_from_the_revision_is_kept(self, dirs):
        path = write(dirs, curated(lists={"ios-xe": ["17.9.4"], "ios": ["15.2(7)E8"]}))
        refresh_known_affected(str(path), adv(versions=("17.9.4", "17.9.5")))
        assert read(path)["known_affected"]["ios"] == ["15.2(7)E8"]

    def test_record_without_a_list_gains_one(self, dirs):
        rec = curated()
        del rec["known_affected"], rec["known_affected_as_of"]
        path = write(dirs, rec)
        assert refresh_known_affected(str(path), adv()) == 1
        assert read(path)["known_affected"]["ios-xe"] == ["17.9.4", "17.9.5"]

    def test_unreadable_record_is_skipped_not_fatal(self, dirs):
        path = dirs / "cve-2026-1.json"
        path.write_text("{broken", encoding="utf-8")
        assert refresh_known_affected(str(path), adv()) == 0


class TestAutoSync:
    def test_existing_record_is_refreshed_not_reimported(self, dirs):
        path = write(dirs, curated())
        imported = auto_sync_new_cves([adv(versions=("17.9.4", "17.12.1"))])
        rec = read(path)
        assert imported == 0                                  # not a new CVE
        assert rec["title"] == "CURATED TITLE"                # curated data kept
        assert "17.12.1" in rec["known_affected"]["ios-xe"]    # list followed Cisco

    def test_new_cve_is_still_imported_with_its_list(self, dirs):
        assert auto_sync_new_cves([adv(cves=("CVE-2026-9",))]) == 1
        assert read(dirs / "cve-2026-9.json")["known_affected"]["ios-xe"] == ["17.9.4", "17.9.5"]

    def test_the_effect_reaches_the_matcher(self, dirs):
        """The point of all this: a revision changes who is told they are affected."""
        from services.cve_engine import CVEEngine, CVEEngineConfig
        rec = curated(lists={"ios-xe": ["17.9.4"]})
        rec["description"] = "A vulnerability in Cisco IOS XE Software."
        write(dirs, rec)

        def matched(version):
            e = CVEEngine(config=CVEEngineConfig(data_dir=str(dirs)))
            e.load_all()
            return [c.cve_id for c in e.match("IOS XE", version)]

        assert matched("17.12.1") == []
        auto_sync_new_cves([adv(versions=("17.9.4", "17.12.1"))])
        assert matched("17.12.1") == ["CVE-2026-1"]


class TestAnalyzerStartsTheSync:
    @pytest.fixture
    def spawned(self, monkeypatch):
        calls = []
        monkeypatch.setattr(cve_router, "_spawn", lambda target, *args: calls.append(args))
        return calls

    def analyze(self, platform, version):
        from api.routers.cve import CVEAnalyzeRequest, analyze_cve
        return analyze_cve(CVEAnalyzeRequest(platform=platform, version=version))

    def test_stale_platform_cache_triggers_a_background_sync(self, spawned, monkeypatch):
        monkeypatch.setattr(cve_router, "_platform_cache_age_hours", lambda p: 24 * 30)
        self.analyze("IOS XE", "17.9.4")
        assert spawned == [("iosxe",)]

    def test_missing_platform_cache_triggers_it_too(self, spawned, monkeypatch):
        monkeypatch.setattr(cve_router, "_platform_cache_age_hours", lambda p: None)
        self.analyze("ISR4451-X", "17.5.1")
        assert spawned == [("iosxe",)]

    def test_fresh_cache_does_not(self, spawned, monkeypatch):
        monkeypatch.setattr(cve_router, "_platform_cache_age_hours", lambda p: 1.0)
        self.analyze("IOS XE", "17.9.4")
        assert spawned == []

    def test_ise_does_too_since_it_became_a_synced_dataset(self, spawned, monkeypatch):
        """Until ISE-04 cve_data/ise was a curated seed with no sync behind it."""
        monkeypatch.setattr(cve_router, "_platform_cache_age_hours", lambda p: None)
        self.analyze("ISE", "3.4 Patch 3")
        assert spawned == [("ise",)]

    def test_the_request_is_answered_without_waiting(self, spawned, monkeypatch):
        monkeypatch.setattr(cve_router, "_platform_cache_age_hours", lambda p: None)
        r = self.analyze("IOS XE", "17.9.4")
        assert len(r.matched) == 71

    def test_report_states_how_current_the_lists_are(self):
        r = self.analyze("IOS XE", "17.9.4")
        assert r.known_affected_as_of["oldest"] <= r.known_affected_as_of["newest"]
        assert self.analyze("ISE", "3.4 Patch 3").known_affected_as_of is not None
