"""
Cisco hardening-release CVEs, end to end (CVE-007 stage 2, 2026-09-18).

Stage 1 detected these on the fly. Stage 2 makes the fact durable: both PSIRT
importers stamp a typed `bundled` block at import time, the per-CVE CWE is no
longer fabricated from cwe_list[0], the fix-path contract on CVEFirstFixed is
documented and has an accessor, and the threat feed says "N CVEs · class".
"""

import importlib.util
import json
import os

import pytest

from models.cve_model import CVEAffectedRange, CVEBundledInfo, CVEEntry, CVEFirstFixed
from services.hardening_release import (
    advisory_id_from_url,
    bundled_info_from_advisory,
    is_bundled_cve,
    is_hardening_advisory,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Shapes copied from the PSIRT cache on 2026-09-18 (ids, counts, CWE lists).
REAL_HARDENING = [
    ("cisco-sa-hardening-crosswork-UzDTU9Vh", 4,
     ["CWE-306", "CWE-522", "CWE-73", "CWE-89"]),
    ("cisco-sa-hardening-iosxr-qg64NcM", 7,
     ["CWE-284", "CWE-664", "CWE-682", "CWE-691", "CWE-693", "CWE-703", "CWE-707"]),
    ("cisco-sa-hardening-esa-dfCrfXkm", 5,
     ["CWE-1284", "CWE-23", "CWE-284", "CWE-664", "CWE-707"]),
    ("cisco-sa-hardening-ise-XU5EwX5T", 6,
     ["CWE-20", "CWE-269", "CWE-284", "CWE-522", "CWE-669", "CWE-74"]),
    ("cisco-sa-hardening-ndw1-psFvnrg", 6,
     ["CWE-200", "CWE-22", "CWE-284", "CWE-306", "CWE-77", "CWE-89"]),
    ("cisco-sa-hardening-iosxe-V8NMuMZJ", 7,
     ["CWE-119", "CWE-20", "CWE-284", "CWE-664", "CWE-682", "CWE-691", "CWE-74"]),
    ("cisco-sa-hardening-asaftdfmc-uvpPROhN", 8,
     ["CWE-284", "CWE-664", "CWE-682", "CWE-693", "CWE-697", "CWE-703", "CWE-707", "CWE-710"]),
]


def hardening_adv(adv_id="cisco-sa-hardening-ise-XU5EwX5T", n=6, cwes=None):
    cwes = cwes or ["CWE-20", "CWE-269", "CWE-284", "CWE-522", "CWE-669", "CWE-74"]
    return {
        "advisoryId": adv_id,
        "advisoryTitle": "Cisco Something Hardening Release: September 2026",
        "sir": "Critical", "cvssBaseScore": "10.0",
        "cves": ["CVE-2026-%05d" % (20000 + i) for i in range(n)],
        "cwe": cwes,
        "productNames": ["Cisco Identity Services Engine Software 3.4"],
        "firstPublished": "2026-09-16T16:00:00", "lastUpdated": "2026-09-16T16:00:00",
        "publicationUrl": "https://sec.cloudapps.cisco.com/security/center/content/"
                          "CiscoSecurityAdvisory/" + adv_id,
        "summary": "hardening",
    }


def ordinary_adv():
    return {
        "advisoryId": "cisco-sa-ISE-ABP-VNSW7Tn5",
        "advisoryTitle": "Cisco Identity Services Engine Authentication Bypass Vulnerability",
        "sir": "Critical", "cvssBaseScore": "10.0",
        "cves": ["CVE-2026-76460"], "cwe": ["CWE-648"],
        "productNames": ["Cisco Identity Services Engine Software 3.4"],
        "firstPublished": "2026-09-16T16:00:00", "lastUpdated": "2026-09-16T16:00:00",
        "publicationUrl": "https://sec.cloudapps.cisco.com/security/center/content/"
                          "CiscoSecurityAdvisory/cisco-sa-ISE-ABP-VNSW7Tn5",
        "summary": "auth bypass",
    }


class TestSignature:
    @pytest.mark.parametrize("adv_id,n,cwes", REAL_HARDENING,
                             ids=[r[0].split("-")[3] for r in REAL_HARDENING])
    def test_every_real_hardening_advisory_is_one_cve_per_cwe(self, adv_id, n, cwes):
        info = bundled_info_from_advisory(hardening_adv(adv_id, n, cwes))
        assert info is not None
        assert info.one_cve_per_cwe is True
        assert len(info.sibling_cves) == len(info.cwe_categories) == n

    def test_detected_by_id_alone(self):
        adv = hardening_adv()
        adv["advisoryTitle"] = "Untitled"
        assert is_hardening_advisory(adv)

    def test_detected_by_title_alone(self):
        adv = hardening_adv(adv_id="cisco-sa-something-else")
        assert is_hardening_advisory(adv)

    def test_ordinary_advisory_is_not(self):
        assert not is_hardening_advisory(ordinary_adv())
        assert bundled_info_from_advisory(ordinary_adv()) is None

    def test_count_mismatch_is_flagged_not_hidden(self):
        """Matched on id/title but not one-CVE-per-CWE -> deserves a second look."""
        info = bundled_info_from_advisory(hardening_adv(n=6, cwes=["CWE-20", "CWE-284"]))
        assert info is not None and info.one_cve_per_cwe is False

    def test_na_placeholders_are_dropped(self):
        adv = hardening_adv()
        adv["cves"] = adv["cves"] + ["NA"]
        adv["cwe"] = adv["cwe"] + ["NA"]
        info = bundled_info_from_advisory(adv)
        assert "NA" not in info.sibling_cves and "NA" not in info.cwe_categories

    def test_advisory_id_from_url(self):
        assert advisory_id_from_url(hardening_adv()["publicationUrl"]) == \
            "cisco-sa-hardening-ise-XU5EwX5T"
        assert advisory_id_from_url(None) is None


class TestIsBundledCve:
    def entry(self, **kw):
        base = dict(cve_id="CVE-T", title="Some Vulnerability", severity="high",
                    description="d", affected=CVEAffectedRange(min="1", max="2"))
        base.update(kw)
        return CVEEntry(**base)

    def test_typed_block_is_the_strongest_signal(self):
        e = self.entry(bundled=CVEBundledInfo(advisory_id="cisco-sa-hardening-x"))
        assert is_bundled_cve(e)

    def test_legacy_records_without_the_block_still_detect(self):
        """Records imported before CVE-007 must not need a re-import."""
        assert is_bundled_cve(self.entry(tags=["bundled-cve"]))
        assert is_bundled_cve(self.entry(
            advisory_url="https://x/CiscoSecurityAdvisory/cisco-sa-hardening-iosxr-qg64NcM"))

    def test_publication_bundle_is_not_a_bundled_cve(self):
        assert not is_bundled_cve(self.entry(bundle="2026-09"))


class TestProviderImport:
    @pytest.fixture
    def provider(self):
        from services.cve_sources import CiscoAdvisoryProvider
        return CiscoAdvisoryProvider(platform="ise")

    def test_every_cve_of_a_hardening_advisory_gets_the_block(self, provider):
        entries = provider._parse_advisory(hardening_adv())
        assert len(entries) == 6
        assert all(e.bundled is not None and e.bundled.one_cve_per_cwe for e in entries)
        assert all(len(e.bundled.sibling_cves) == 6 for e in entries)

    def test_per_cve_cwe_is_not_fabricated(self, provider):
        """cwe_list[0] stamped the same (alphabetically first) CWE on all six."""
        entries = provider._parse_advisory(hardening_adv())
        assert all(e.cwe is None for e in entries)
        assert entries[0].bundled.cwe_categories[0] == "CWE-20"

    def test_tags(self, provider):
        e = provider._parse_advisory(hardening_adv())[0]
        assert "hardening-release" in e.tags and "bundled-cve" in e.tags

    def test_ordinary_advisory_is_unchanged(self, provider):
        e = provider._parse_advisory(ordinary_adv())[0]
        assert e.bundled is None and e.cwe == "CWE-648"
        assert "bundled-cve" not in e.tags


class TestScriptImport:
    @pytest.fixture(scope="class")
    def mod(self):
        spec = importlib.util.spec_from_file_location(
            "import_cisco_to_local", os.path.join(ROOT, "scripts", "import_cisco_to_local.py"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    def test_hardening_record_shape(self, mod):
        d = mod.build_cve_data("CVE-2026-20000", hardening_adv(), "0.0.0", "99.0.0")
        assert d["cwe"] is None
        assert d["bundled"]["one_cve_per_cwe"] is True
        assert "bundled-cve" in d["tags"]
        CVEEntry(**d)  # still a valid record

    def test_ordinary_record_shape(self, mod):
        d = mod.build_cve_data("CVE-2026-76460", ordinary_adv(), "0.0.0", "99.0.0")
        assert d["cwe"] == "CWE-648" and d["bundled"] is None
        CVEEntry(**d)


class TestRuntimeAutoSyncImport:
    """services.cisco_sync._build_cve_json — the importer that runs in production.

    v0.6.34 claimed "both importers" were patched. There are three: this one is
    called by auto_sync_new_cves() on every PSIRT refresh and was missed.
    """

    def test_hardening_record_shape(self):
        from services.cisco_sync import _build_cve_json
        d = _build_cve_json("CVE-2026-20000", hardening_adv(), "0.0.0", "99.0.0")
        assert d["cwe"] is None
        assert d["bundled"]["one_cve_per_cwe"] is True
        assert "bundled-cve" in d["tags"] and "hardening-release" in d["tags"]
        CVEEntry(**d)

    def test_ordinary_record_shape(self):
        from services.cisco_sync import _build_cve_json
        d = _build_cve_json("CVE-2026-76460", ordinary_adv(), "0.0.0", "99.0.0")
        assert d["cwe"] == "CWE-648" and d["bundled"] is None
        CVEEntry(**d)

    def test_all_three_importers_agree(self):
        """One advisory, three code paths, one answer."""
        import importlib.util
        from services.cisco_sync import _build_cve_json
        from services.cve_sources import CiscoAdvisoryProvider
        spec = importlib.util.spec_from_file_location(
            "import_cisco_to_local", os.path.join(ROOT, "scripts", "import_cisco_to_local.py"))
        script = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(script)

        adv = hardening_adv()
        a = _build_cve_json(adv["cves"][0], adv, "0", "9")["bundled"]
        b = script.build_cve_data(adv["cves"][0], adv, "0", "9")["bundled"]
        c = CiscoAdvisoryProvider(platform="ise")._parse_advisory(adv)[0].bundled.model_dump()
        assert a == b == c


class TestFixPathContract:
    F = CVEFirstFixed(fixes={"ise-3.3": "3.3 Patch 12", "ise-3.4": "3.4 Patch 7",
                             "ios-xe": "17.9.4a"})

    def test_train_path_wins(self):
        assert self.F.fix_for("ise", "3.4") == "3.4 Patch 7"

    def test_bare_family(self):
        assert self.F.fix_for("ios-xe") == "17.9.4a"

    def test_unknown_train_falls_back_to_family_or_none(self):
        assert self.F.fix_for("ise", "3.9") is None
        assert self.F.fix_for("ios-xe", "17.9") == "17.9.4a"

    def test_trains(self):
        assert self.F.trains("ise") == ["3.3", "3.4"]
        assert self.F.trains("ios-xe") == []


class TestFeed:
    def test_psirt_hardening_row_carries_count_and_categories(self):
        from api.routers.cve import _advisories_to_feed
        row = _advisories_to_feed([hardening_adv()], "ise")[0]
        assert row.bundled["cve_count"] == 6
        assert "CWE-284" in row.bundled["cwe_categories"]

    def test_ordinary_row_has_no_bundled_block(self):
        from api.routers.cve import _advisories_to_feed
        assert _advisories_to_feed([ordinary_adv()], "ise")[0].bundled is None

    def test_local_rows_carry_it_too(self):
        from api.routers.cve import _local_records_to_feed
        rows = {r.cve_id: r for r in _local_records_to_feed("ise")}
        assert rows["CVE-2026-20192"].bundled["cve_count"] == 6
        assert rows["CVE-2026-76460"].bundled is None


class TestDatasetAgainstNvd:
    """Regression for an error shipped in v0.6.31.

    Two CWE values in cve_data/ise were inferred from advisory titles instead
    of read from NVD: CVE-2026-20130 was CWE-707 (NVD: CWE-74) and
    CVE-2026-20352 had none (NVD: CWE-119). Values below are NVD API 2.0,
    source psirt@cisco.com, read 2026-09-18.
    """

    NVD = {
        "CVE-2026-76460": ("CWE-648", 10.0), "CVE-2026-20130": ("CWE-74", 10.0),
        "CVE-2026-20192": ("CWE-284", 10.0), "CVE-2026-20194": ("CWE-669", 9.1),
        "CVE-2026-20234": ("CWE-522", 9.9), "CVE-2026-20237": ("CWE-20", 9.1),
        "CVE-2026-20287": ("CWE-269", 6.5), "CVE-2026-20352": ("CWE-119", 8.6),
    }

    @pytest.mark.parametrize("cve_id", sorted(NVD))
    def test_cwe_score_and_vector(self, cve_id):
        with open(os.path.join(ROOT, "cve_data", "ise", cve_id.lower() + ".json")) as f:
            d = json.load(f)
        cwe, score = self.NVD[cve_id]
        assert d["cwe"] == cwe
        assert d["cvss_score"] == score
        assert (d["cvss_vector"] or "").startswith("CVSS:3.1/")

    def test_bundled_categories_equal_the_per_cve_cwes(self):
        """Six CVEs, six categories, and they are the same six."""
        per_cve, categories = set(), None
        for cve_id in self.NVD:
            with open(os.path.join(ROOT, "cve_data", "ise", cve_id.lower() + ".json")) as f:
                d = json.load(f)
            if d.get("bundled"):
                per_cve.add(d["cwe"])
                categories = set(d["bundled"]["cwe_categories"])
        assert per_cve == categories and len(per_cve) == 6
