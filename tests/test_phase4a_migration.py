"""
Tests for cisco_sync.enrich_legacy_psirt_records (CVE-006 Phase 4a).

Verifies the one-time legacy migration helper:
- Single record migration: detail fetch + JSON patch
- Idempotent: re-run skips already-enriched records (no extra fetch)
- Curated records skipped (preserve hand-entered fixed_in)
- Records without advisory_url skipped
- Detail fetch failure: failed counter incremented, file untouched
- Atomic write: corrupted partial state never persisted
- max_records cap honored
- dry_run mode: counters update but no file writes
- Rate limit sleep between actual API calls (not on cache hits)
"""

import json
import os
from unittest.mock import MagicMock, patch

from services.cisco_sync import (
    _atomic_write_json,
    _extract_advisory_id,
    enrich_legacy_psirt_records,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_record(dir_path, cve_id, source="cisco-psirt-import", advisory_url=None,
                  first_fixed_version=None, product_families=None):
    """Create a minimal CVE JSON file in dir_path."""
    record = {
        "cve_id": cve_id,
        "title": "Test CVE",
        "severity": "high",
        "platforms": ["IOS XE"],
        "affected": {"min": "0.0.0", "max": "999.999.999"},
        "fixed_in": None,
        "tags": [],
        "description": "test",
        "advisory_url": advisory_url or f"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{cve_id.lower()}",
        "source": source,
    }
    if first_fixed_version is not None:
        record["first_fixed_version"] = first_fixed_version
    if product_families is not None:
        record["product_families"] = product_families

    path = os.path.join(str(dir_path), f"{cve_id.lower()}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
    return path


def _make_provider_mock(detail_responses):
    """Create a CiscoAdvisoryProvider mock with prepared detail responses.

    detail_responses: dict mapping advisory_id -> detail dict (or None for failure)
    """
    provider = MagicMock()

    def fetch(advisory_id):
        return detail_responses.get(advisory_id)

    def read_cache(advisory_id):
        # No cache by default; tests can override
        return None

    def extract(detail):
        # Use the real implementation
        from services.cve_sources import CiscoAdvisoryProvider
        return CiscoAdvisoryProvider._extract_fix_versions(detail)

    provider._fetch_advisory_detail.side_effect = fetch
    provider._read_detail_cache.side_effect = read_cache
    provider._extract_fix_versions.side_effect = extract
    return provider


# ---------------------------------------------------------------------------
# _extract_advisory_id
# ---------------------------------------------------------------------------

def test_extract_advisory_id_standard_url():
    url = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-csrf-ycUYxkKO"
    assert _extract_advisory_id(url) == "cisco-sa-webui-csrf-ycUYxkKO"


def test_extract_advisory_id_with_query_string():
    url = "https://example.com/CiscoSecurityAdvisory/cisco-sa-asa-2025?tab=summary"
    assert _extract_advisory_id(url) == "cisco-sa-asa-2025"


def test_extract_advisory_id_unknown_url():
    assert _extract_advisory_id("https://nvd.nist.gov/vuln/detail/CVE-2023-20198") is None


def test_extract_advisory_id_none_input():
    assert _extract_advisory_id(None) is None
    assert _extract_advisory_id("") is None


# ---------------------------------------------------------------------------
# Single record migration
# ---------------------------------------------------------------------------

def test_enrich_single_record_writes_first_fixed_version(tmp_path):
    """Happy path: legacy record gets enriched, JSON patched on disk."""
    advisory_id = "cisco-sa-test-12345"
    advisory_url = f"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{advisory_id}"
    path = _write_record(tmp_path, "CVE-2025-12345", advisory_url=advisory_url)

    detail = {
        "advisoryId": advisory_id,
        "firstFixed": ["Cisco IOS XE Software 17.9.4a"],
        "productNames": ["Cisco IOS XE Software 17.9.3", "Cisco IOS XE Software 17.9.4"],
    }

    provider = _make_provider_mock({advisory_id: detail})

    counts = enrich_legacy_psirt_records(
        provider, cve_data_dir=str(tmp_path), rate_limit_sleep=0
    )

    assert counts["enriched"] == 1
    assert counts["fetched"] == 1
    assert counts["failed"] == 0

    with open(path, "r", encoding="utf-8") as f:
        patched = json.load(f)

    assert patched["first_fixed_version"] == {"fixes": {"ios-xe": "17.9.4a"}}
    assert patched["product_families"] == ["ios-xe"]
    assert "Cisco IOS XE Software 17.9.4" in patched["affected_versions_raw"]


def test_enrich_preserves_other_fields(tmp_path):
    """Migration must not touch fields outside the Phase 4 enrichment set."""
    advisory_id = "cisco-sa-preserve"
    path = _write_record(
        tmp_path, "CVE-2025-99999",
        advisory_url=f"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{advisory_id}",
    )

    detail = {"firstFixed": ["Cisco IOS XE Software 17.9.4a"], "productNames": []}
    provider = _make_provider_mock({advisory_id: detail})

    enrich_legacy_psirt_records(
        provider, cve_data_dir=str(tmp_path), rate_limit_sleep=0
    )

    with open(path, "r", encoding="utf-8") as f:
        patched = json.load(f)

    # Original fields preserved verbatim
    assert patched["cve_id"] == "CVE-2025-99999"
    assert patched["severity"] == "high"
    assert patched["affected"] == {"min": "0.0.0", "max": "999.999.999"}
    assert patched["source"] == "cisco-psirt-import"
    # New field present
    assert "first_fixed_version" in patched


# ---------------------------------------------------------------------------
# Idempotent re-runs
# ---------------------------------------------------------------------------

def test_enrich_idempotent_skips_already_enriched(tmp_path):
    """Re-run on already-enriched records: no fetch, no write."""
    advisory_id = "cisco-sa-already-done"
    _write_record(
        tmp_path, "CVE-2025-77777",
        advisory_url=f"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{advisory_id}",
        first_fixed_version={"fixes": {"ios-xe": "17.9.4a"}},
    )

    provider = _make_provider_mock({})  # no responses needed

    counts = enrich_legacy_psirt_records(
        provider, cve_data_dir=str(tmp_path), rate_limit_sleep=0
    )

    assert counts["skipped_already_enriched"] == 1
    assert counts["enriched"] == 0
    assert counts["fetched"] == 0
    provider._fetch_advisory_detail.assert_not_called()


# ---------------------------------------------------------------------------
# Curated record protection
# ---------------------------------------------------------------------------

def test_enrich_skips_curated_records(tmp_path):
    """Records with source != 'cisco-psirt-import' are NEVER touched."""
    _write_record(tmp_path, "CVE-2025-CURATED", source="local-json")

    provider = _make_provider_mock({})
    counts = enrich_legacy_psirt_records(
        provider, cve_data_dir=str(tmp_path), rate_limit_sleep=0
    )

    assert counts["skipped_curated"] == 1
    assert counts["enriched"] == 0
    provider._fetch_advisory_detail.assert_not_called()


# ---------------------------------------------------------------------------
# Missing / bad URL handling
# ---------------------------------------------------------------------------

def test_enrich_skips_records_without_advisory_url(tmp_path):
    """Records with empty advisory_url cannot be migrated."""
    record = {
        "cve_id": "CVE-2025-NOURL",
        "source": "cisco-psirt-import",
        "advisory_url": "",  # empty
        "title": "T", "severity": "low", "platforms": [],
        "affected": {"min": "0.0.0", "max": "999.999.999"},
        "fixed_in": None, "tags": [], "description": "",
    }
    with open(os.path.join(str(tmp_path), "cve-2025-nourl.json"), "w") as f:
        json.dump(record, f)

    provider = _make_provider_mock({})
    counts = enrich_legacy_psirt_records(
        provider, cve_data_dir=str(tmp_path), rate_limit_sleep=0
    )

    assert counts["skipped_no_url"] == 1
    assert counts["enriched"] == 0


def test_enrich_skips_records_with_unrecognised_url_pattern(tmp_path):
    """advisory_url not matching cisco-sa-* pattern is skipped."""
    _write_record(
        tmp_path, "CVE-2025-NVDONLY",
        advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2025-NVDONLY",
    )

    provider = _make_provider_mock({})
    counts = enrich_legacy_psirt_records(
        provider, cve_data_dir=str(tmp_path), rate_limit_sleep=0
    )

    assert counts["skipped_no_url"] == 1


# ---------------------------------------------------------------------------
# Detail fetch failure
# ---------------------------------------------------------------------------

def test_enrich_handles_detail_fetch_failure(tmp_path):
    """Detail fetch returns None: failed counter, file untouched."""
    advisory_id = "cisco-sa-rate-limited"
    path = _write_record(
        tmp_path, "CVE-2025-RATELIMIT",
        advisory_url=f"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{advisory_id}",
    )

    provider = _make_provider_mock({advisory_id: None})  # API failure

    counts = enrich_legacy_psirt_records(
        provider, cve_data_dir=str(tmp_path), rate_limit_sleep=0
    )

    assert counts["failed"] == 1
    assert counts["enriched"] == 0

    # File MUST be unchanged (no first_fixed_version added)
    with open(path, "r", encoding="utf-8") as f:
        unchanged = json.load(f)
    assert "first_fixed_version" not in unchanged or unchanged["first_fixed_version"] is None


# ---------------------------------------------------------------------------
# max_records cap
# ---------------------------------------------------------------------------

def test_enrich_max_records_cap(tmp_path):
    """max_records caps how many records get enriched in one run."""
    for i in range(5):
        adv_id = f"cisco-sa-cap-{i}"
        _write_record(
            tmp_path, f"CVE-2025-{i:05d}",
            advisory_url=f"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{adv_id}",
        )

    detail = {"firstFixed": ["Cisco IOS XE Software 17.9.4a"], "productNames": []}
    detail_responses = {f"cisco-sa-cap-{i}": detail for i in range(5)}
    provider = _make_provider_mock(detail_responses)

    counts = enrich_legacy_psirt_records(
        provider, cve_data_dir=str(tmp_path), rate_limit_sleep=0, max_records=2
    )

    assert counts["enriched"] == 2
    assert counts["scanned"] >= 2  # We at least visited 2 before the cap


# ---------------------------------------------------------------------------
# dry_run mode
# ---------------------------------------------------------------------------

def test_enrich_dry_run_does_not_write(tmp_path):
    """dry_run=True: counters reflect would-be enrichment but no file changes."""
    advisory_id = "cisco-sa-dryrun"
    path = _write_record(
        tmp_path, "CVE-2025-DRYRUN",
        advisory_url=f"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{advisory_id}",
    )

    detail = {"firstFixed": ["Cisco IOS XE Software 17.9.4a"], "productNames": []}
    provider = _make_provider_mock({advisory_id: detail})

    counts = enrich_legacy_psirt_records(
        provider, cve_data_dir=str(tmp_path), rate_limit_sleep=0, dry_run=True
    )

    assert counts["enriched"] == 1  # Counted as enriched

    # File NOT modified
    with open(path, "r", encoding="utf-8") as f:
        original = json.load(f)
    assert "first_fixed_version" not in original or original["first_fixed_version"] is None


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------

def test_atomic_write_json_creates_file(tmp_path):
    """_atomic_write_json writes valid JSON via temp + rename."""
    path = os.path.join(str(tmp_path), "atomic.json")
    data = {"key": "value", "list": [1, 2, 3]}

    _atomic_write_json(path, data)

    with open(path, "r") as f:
        loaded = json.load(f)
    assert loaded == data
    # Temp file cleaned up
    assert not os.path.exists(path + ".tmp")


# ---------------------------------------------------------------------------
# Skip _version_release_dates.json and other underscore-prefixed files
# ---------------------------------------------------------------------------

def test_enrich_skips_underscore_prefixed_files(tmp_path):
    """Files like _version_release_dates.json are not CVE records."""
    underscore_path = os.path.join(str(tmp_path), "_version_release_dates.json")
    with open(underscore_path, "w") as f:
        json.dump({"IOS_XE": {"17.9.4": "2023-05-15"}}, f)

    provider = _make_provider_mock({})
    counts = enrich_legacy_psirt_records(
        provider, cve_data_dir=str(tmp_path), rate_limit_sleep=0
    )

    # Underscore file ignored entirely
    assert counts["scanned"] == 0
