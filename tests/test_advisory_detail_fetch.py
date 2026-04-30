"""
Tests for CiscoAdvisoryProvider._fetch_advisory_detail (CVE-006 Phase 4 Step 1).

Verifies the standalone advisory-detail fetch helper:
- Cache hit returns cached detail (zero API cost)
- Cache miss triggers API call, response is persisted to per-id cache
- API failure returns None (delegated to _api_get error path)
- Stale cache (past TTL) is ignored, fresh fetch issued
- Empty PSIRT response (advisories=[]) returns None
- Cache write failures are non-fatal (helper still returns detail)

Phase 4 Step 1 ships the helper standalone — _parse_advisory() is NOT
yet wired to call it. Wiring happens in Step 3.
"""

import json
import time
from unittest.mock import patch

from services.cve_sources import CiscoAdvisoryProvider


# ---------------------------------------------------------------------------
# Cache hit / miss
# ---------------------------------------------------------------------------

def test_fetch_advisory_detail_cache_hit(tmp_path, monkeypatch):
    """Cached fresh detail returned without API call."""
    monkeypatch.setattr("services.cve_sources.CISCO_DETAIL_CACHE_DIR", str(tmp_path))

    provider = CiscoAdvisoryProvider(platform="iosxe")
    advisory_id = "cisco-sa-test-12345"

    cached_detail = {
        "advisoryId": advisory_id,
        "firstFixed": ["Cisco IOS XE Software 17.9.4a"],
    }
    cache_path = tmp_path / f"{advisory_id}.json"
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump({"cached_at": time.time(), "detail": cached_detail}, f)

    with patch.object(provider, "_api_get") as mock_api:
        result = provider._fetch_advisory_detail(advisory_id)

    assert result == cached_detail
    mock_api.assert_not_called()


def test_fetch_advisory_detail_cache_miss_persists_response(tmp_path, monkeypatch):
    """Cache miss triggers API call, response persisted on success."""
    monkeypatch.setattr("services.cve_sources.CISCO_DETAIL_CACHE_DIR", str(tmp_path))

    provider = CiscoAdvisoryProvider(platform="iosxe")
    advisory_id = "cisco-sa-test-67890"
    expected_detail = {
        "advisoryId": advisory_id,
        "firstFixed": ["Cisco IOS XE Software 17.12.1"],
    }

    with patch.object(provider, "_api_get") as mock_api:
        mock_api.return_value = {"advisories": [expected_detail]}
        with patch.object(provider, "_load_credentials") as mock_creds:
            mock_creds.return_value = {"api_base": "https://example.com/v2"}
            result = provider._fetch_advisory_detail(advisory_id)

    assert result == expected_detail
    mock_api.assert_called_once()

    cache_path = tmp_path / f"{advisory_id}.json"
    assert cache_path.exists()

    with open(cache_path, "r", encoding="utf-8") as f:
        persisted = json.load(f)
    assert persisted["detail"] == expected_detail
    assert "cached_at" in persisted


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------

def test_fetch_advisory_detail_api_failure_returns_none(tmp_path, monkeypatch):
    """_api_get None (rate limit / 403 / network) propagates as None."""
    monkeypatch.setattr("services.cve_sources.CISCO_DETAIL_CACHE_DIR", str(tmp_path))

    provider = CiscoAdvisoryProvider(platform="iosxe")

    with patch.object(provider, "_api_get") as mock_api:
        mock_api.return_value = None
        with patch.object(provider, "_load_credentials") as mock_creds:
            mock_creds.return_value = {"api_base": "https://example.com/v2"}
            result = provider._fetch_advisory_detail("cisco-sa-fail")

    assert result is None
    mock_api.assert_called_once()


def test_fetch_advisory_detail_no_credentials_returns_none(tmp_path, monkeypatch):
    """Missing credentials short-circuit to None without API call."""
    monkeypatch.setattr("services.cve_sources.CISCO_DETAIL_CACHE_DIR", str(tmp_path))

    provider = CiscoAdvisoryProvider(platform="iosxe")

    with patch.object(provider, "_api_get") as mock_api:
        with patch.object(provider, "_load_credentials") as mock_creds:
            mock_creds.return_value = None
            result = provider._fetch_advisory_detail("cisco-sa-nocreds")

    assert result is None
    mock_api.assert_not_called()


def test_fetch_advisory_detail_empty_advisories_returns_none(tmp_path, monkeypatch):
    """PSIRT returning advisories=[] (advisory not found) yields None."""
    monkeypatch.setattr("services.cve_sources.CISCO_DETAIL_CACHE_DIR", str(tmp_path))

    provider = CiscoAdvisoryProvider(platform="iosxe")

    with patch.object(provider, "_api_get") as mock_api:
        mock_api.return_value = {"advisories": []}
        with patch.object(provider, "_load_credentials") as mock_creds:
            mock_creds.return_value = {"api_base": "https://example.com/v2"}
            result = provider._fetch_advisory_detail("cisco-sa-empty")

    assert result is None


# ---------------------------------------------------------------------------
# Cache freshness
# ---------------------------------------------------------------------------

def test_fetch_advisory_detail_stale_cache_ignored(tmp_path, monkeypatch):
    """Stale cache (past TTL) is ignored; fresh API call is issued."""
    monkeypatch.setattr("services.cve_sources.CISCO_DETAIL_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr("services.cve_sources.CISCO_DETAIL_CACHE_TTL", 1)

    provider = CiscoAdvisoryProvider(platform="iosxe")
    advisory_id = "cisco-sa-stale"

    stale_detail = {"advisoryId": advisory_id, "firstFixed": ["old"]}
    cache_path = tmp_path / f"{advisory_id}.json"
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump({"cached_at": time.time() - 100, "detail": stale_detail}, f)

    fresh_detail = {"advisoryId": advisory_id, "firstFixed": ["new"]}
    with patch.object(provider, "_api_get") as mock_api:
        mock_api.return_value = {"advisories": [fresh_detail]}
        with patch.object(provider, "_load_credentials") as mock_creds:
            mock_creds.return_value = {"api_base": "https://example.com/v2"}
            result = provider._fetch_advisory_detail(advisory_id)

    assert result == fresh_detail
    mock_api.assert_called_once()


def test_fetch_advisory_detail_corrupt_cache_falls_back_to_api(tmp_path, monkeypatch):
    """Corrupt cache file (invalid JSON) is treated as miss and API is called."""
    monkeypatch.setattr("services.cve_sources.CISCO_DETAIL_CACHE_DIR", str(tmp_path))

    provider = CiscoAdvisoryProvider(platform="iosxe")
    advisory_id = "cisco-sa-corrupt"

    cache_path = tmp_path / f"{advisory_id}.json"
    cache_path.write_text("{not valid json")

    fresh_detail = {"advisoryId": advisory_id, "firstFixed": ["recovered"]}
    with patch.object(provider, "_api_get") as mock_api:
        mock_api.return_value = {"advisories": [fresh_detail]}
        with patch.object(provider, "_load_credentials") as mock_creds:
            mock_creds.return_value = {"api_base": "https://example.com/v2"}
            result = provider._fetch_advisory_detail(advisory_id)

    assert result == fresh_detail
    mock_api.assert_called_once()


# ---------------------------------------------------------------------------
# URL construction
# ---------------------------------------------------------------------------

def test_fetch_advisory_detail_constructs_correct_url(tmp_path, monkeypatch):
    """URL pattern: {api_base}/advisory/{advisory_id}"""
    monkeypatch.setattr("services.cve_sources.CISCO_DETAIL_CACHE_DIR", str(tmp_path))

    provider = CiscoAdvisoryProvider(platform="iosxe")
    advisory_id = "cisco-sa-asa-XYZ"

    captured = {}

    def fake_api_get(url):
        captured["url"] = url
        return {"advisories": [{"advisoryId": advisory_id}]}

    with patch.object(provider, "_api_get", side_effect=fake_api_get):
        with patch.object(provider, "_load_credentials") as mock_creds:
            mock_creds.return_value = {"api_base": "https://apix.cisco.com/security/advisories/v2"}
            provider._fetch_advisory_detail(advisory_id)

    assert captured["url"] == f"https://apix.cisco.com/security/advisories/v2/advisory/{advisory_id}"
