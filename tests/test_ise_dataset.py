"""
Integrity tests for cve_data/ise/ (ISE-01, 2026-09-18).

These do not re-test the model; they guard the things that actually rot in a
hand-seeded dataset: fix versions that stop parsing, a KEV block that drifts
from the catalog snapshot it claims, and records whose confidence silently
degrades to "max-bound" because someone dropped first_fixed_version.
"""

import glob
import json
import os

import pytest

from models.cve_model import CVEEntry
from services.cisco_version import CiscoIseVersion, cisco_compare
from services.cve_engine import data_confidence

ISE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "cve_data", "ise")
PATHS = sorted(glob.glob(os.path.join(ISE_DIR, "*.json")))


def load(path):
    with open(path, encoding="utf-8") as f:
        return CVEEntry(**json.load(f))


def test_dataset_is_not_empty():
    assert PATHS, "cve_data/ise/ is empty — run scripts/seed_ise_cve_data.py"


@pytest.mark.parametrize("path", PATHS, ids=[os.path.basename(p) for p in PATHS])
class TestRecord:
    def test_parses_into_model(self, path):
        assert load(path).cve_id.startswith("CVE-")

    def test_filename_matches_cve_id(self, path):
        assert os.path.basename(path) == load(path).cve_id.lower() + ".json"

    def test_family_is_ise(self, path):
        e = load(path)
        assert e.product_families == ["ise"]
        assert "ISE" in e.platforms

    def test_every_fix_version_parses(self, path):
        """A fix string the comparator cannot read is a silent match failure."""
        e = load(path)
        assert e.first_fixed_version and e.first_fixed_version.fixes
        for train_key, fix in e.first_fixed_version.fixes.items():
            assert train_key.startswith("ise-"), train_key
            assert CiscoIseVersion.parse(fix) is not None, (train_key, fix)

    def test_fix_belongs_to_its_train_key(self, path):
        """fixes["ise-3.4"] must be a 3.4 version, not 3.5."""
        for train_key, fix in load(path).first_fixed_version.fixes.items():
            train = train_key.split("-", 1)[1]
            parsed = CiscoIseVersion.parse(fix)
            assert "%d.%d" % (parsed.major, parsed.minor) == train, (train_key, fix)

    def test_confidence_is_verified(self, path):
        assert data_confidence(load(path))["confidence"] == "verified"

    def test_advisory_url_is_cisco(self, path):
        assert load(path).advisory_url.startswith(
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/")

    def test_bundle_tagged(self, path):
        e = load(path)
        assert e.bundle == "2026-09"
        assert "bundle-2026-09" in e.tags


class TestKevRecord:
    """CVE-2026-76460 is the actively exploited one; it must stay distinguishable."""

    def kev_records(self):
        return [e for e in (load(p) for p in PATHS) if e.kev is not None]

    def test_exactly_one_kev_record(self):
        ids = [e.cve_id for e in self.kev_records()]
        assert ids == ["CVE-2026-76460"], ids

    def test_kev_dates_and_directive(self):
        kev = self.kev_records()[0].kev
        assert kev.date_added == "2026-09-16"
        assert kev.due_date == "2026-09-19"
        assert kev.catalog_version == "2026.09.16"
        assert kev.directive == "BOD 26-04"

    def test_kev_record_is_tagged_for_triage(self):
        e = self.kev_records()[0]
        assert "kev" in e.tags and "actively-exploited" in e.tags

    def test_non_kev_records_carry_no_kev_block(self):
        """Absence must mean 'not in KEV', never 'nobody filled it in'."""
        others = [e for e in (load(p) for p in PATHS) if e.cve_id != "CVE-2026-76460"]
        assert others and all(e.kev is None for e in others)


class TestRadiusDosLowerBound:
    """CVE-2026-20352: releases 3.1 and earlier are NOT vulnerable."""

    def record(self):
        return load(os.path.join(ISE_DIR, "cve-2026-20352.json"))

    def test_affected_range_starts_at_32(self):
        assert self.record().affected.min == "3.2"

    def test_no_fix_offered_for_31(self):
        assert "ise-3.1" not in self.record().first_fixed_version.fixes

    def test_differs_from_full_bundle_shape(self):
        """Guards against someone pasting the shared FIXES map over it."""
        full = load(os.path.join(ISE_DIR, "cve-2026-76460.json"))
        assert set(self.record().first_fixed_version.fixes) < set(full.first_fixed_version.fixes)


class TestBundledCveShape:
    """Hardening-release CVEs are CWE classes, not single bugs (see CVE-007)."""

    def hardening(self):
        return [e for e in (load(p) for p in PATHS) if "hardening-release" in e.tags]

    def test_hardening_set_present(self):
        assert len(self.hardening()) == 6

    def test_all_hardening_share_one_advisory(self):
        urls = {e.advisory_url for e in self.hardening()}
        assert len(urls) == 1 and "hardening-ise" in urls.pop()

    def test_all_hardening_flagged_as_bundled(self):
        assert all("bundled-cve" in e.tags for e in self.hardening())

    def test_sir_cvss_divergence_is_flagged_not_hidden(self):
        """CVE-2026-20287 is CVSS 6.5 under a Critical-SIR advisory."""
        odd = [e for e in self.hardening() if e.cisco_sir == "Critical" and e.severity != "critical"]
        assert [e.cve_id for e in odd] == ["CVE-2026-20287"]
        assert "sir-cvss-divergence" in odd[0].tags


def test_seed_script_has_no_drift():
    """cve_data/ise/ must match scripts/seed_ise_cve_data.py output."""
    import subprocess
    import sys
    root = os.path.dirname(ISE_DIR.rstrip("/").rstrip("ise").rstrip("/"))
    r = subprocess.run([sys.executable, "scripts/seed_ise_cve_data.py", "--check"],
                       cwd=root, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
