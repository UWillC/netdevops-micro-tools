"""
XCUT-002 provenance tests (v0.6.19).

Anchors the structure of the provenance block: required keys, source
shape, deterministic ruleset_version, source distribution counts.
"""
import os
import tempfile

from models.cve_model import CVEAffectedRange, CVEEntry
from services.provenance import (
    cve_provenance,
    _hours_since,
    _newest_mtime,
    _source_block,
)


def _make(cve_id="CVE-X", source="local-json"):
    return CVEEntry(
        cve_id=cve_id,
        title="t",
        severity="high",
        platforms=["IOS XE"],
        affected=CVEAffectedRange(min="", max=""),
        description="d",
        source=source,
    )


def test_provenance_top_level_keys():
    p = cve_provenance(tool_version="0.6.19", cve_engine_version="0.3.7", matched_cves=[])
    for key in (
        "tool_version",
        "cve_engine_version",
        "ruleset_version",
        "report_generated",
        "sources",
        "source_distribution",
        "policy_note",
    ):
        assert key in p, f"missing key: {key}"
    assert p["tool_version"] == "0.6.19"
    assert p["cve_engine_version"] == "0.3.7"


def test_sources_have_uniform_shape():
    p = cve_provenance(tool_version="x", cve_engine_version="y", matched_cves=[])
    assert isinstance(p["sources"], list)
    assert len(p["sources"]) >= 3  # local-json, cisco-psirt-import, nvd-enrichment
    for s in p["sources"]:
        for k in ("name", "description", "available", "last_refreshed", "age_hours", "file_count"):
            assert k in s, f"source {s.get('name')} missing {k}"
        if s["available"]:
            assert s["last_refreshed"] is not None
            assert s["last_refreshed"].endswith("Z")
            assert s["age_hours"] is not None
            assert s["file_count"] >= 0


def test_source_distribution_counts_per_provider():
    cves = [
        _make("CVE-2023-A", source="local-json"),
        _make("CVE-2023-B", source="local-json"),
        _make("CVE-2023-C", source="cisco-psirt-import"),
        _make("CVE-2023-D", source="cisco-psirt-import"),
        _make("CVE-2023-E", source="cisco-psirt-import"),
    ]
    p = cve_provenance(tool_version="x", cve_engine_version="y", matched_cves=cves)
    assert p["source_distribution"] == {"local-json": 2, "cisco-psirt-import": 3}


def test_unknown_source_bucketed():
    cves = [_make("CVE-X", source=None)]
    p = cve_provenance(tool_version="x", cve_engine_version="y", matched_cves=cves)
    assert p["source_distribution"] == {"unknown": 1}


def test_ruleset_version_format():
    """Ruleset version is deterministic — derived from local-json mtime."""
    p = cve_provenance(tool_version="x", cve_engine_version="y", matched_cves=[])
    rv = p["ruleset_version"]
    # Either "local-json-YYYYMMDD" or "unknown" (if cve_data dir missing).
    assert rv == "unknown" or (rv.startswith("local-json-") and len(rv) == len("local-json-YYYYMMDD"))


def test_source_block_missing_path():
    """A source whose path doesn't exist returns available=False with nulls."""
    s = _source_block(name="test", path="/nonexistent/path/xyz", description="x")
    assert s["available"] is False
    assert s["last_refreshed"] is None
    assert s["age_hours"] is None
    assert s["file_count"] == 0
    # Required keys still present so UI rendering doesn't break.
    assert s["name"] == "test"
    assert s["description"] == "x"


def test_source_block_existing_file():
    with tempfile.NamedTemporaryFile() as f:
        f.write(b"x")
        f.flush()
        s = _source_block(name="t", path=f.name, description="d")
        assert s["available"] is True
        assert s["last_refreshed"].endswith("Z")
        assert s["age_hours"] >= 0
        assert s["file_count"] == 1


def test_newest_mtime_recursive():
    """Walks subdirectories to find the newest file."""
    with tempfile.TemporaryDirectory() as d:
        sub = os.path.join(d, "sub")
        os.makedirs(sub)
        with open(os.path.join(sub, "deep.txt"), "w") as f:
            f.write("x")
        result = _newest_mtime(d)
        assert result is not None
        assert result > 0


def test_report_generated_is_iso_utc():
    p = cve_provenance(tool_version="x", cve_engine_version="y", matched_cves=[])
    rg = p["report_generated"]
    assert rg.endswith("Z")
    assert "T" in rg
    # Should be parseable.
    import datetime
    datetime.datetime.fromisoformat(rg.rstrip("Z"))


def test_policy_note_mentions_audit_use():
    """Footer is for audit / compliance evidence — text must say so."""
    p = cve_provenance(tool_version="x", cve_engine_version="y", matched_cves=[])
    note = p["policy_note"].lower()
    assert "chain of custody" in note or "audit" in note or "compliance" in note
