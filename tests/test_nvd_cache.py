import json
import os
import tempfile
import time

import pytest

from services.cve_sources import NvdEnricherProvider, NVD_CACHE_TTL


class TestNvdCache:
    """Tests for NVD API response caching."""

    def setup_method(self):
        """Create a temporary cache directory for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.original_cache_dir = None
        # We'll patch the cache dir in the provider

    def teardown_method(self):
        """Clean up temporary files."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_cache_path_generation(self):
        """Test that cache paths are generated correctly."""
        provider = NvdEnricherProvider(cve_ids=[])

        path = provider._get_cache_path("CVE-2023-20198")
        assert "CVE-2023-20198.json" in path

        # Test normalization
        path_lower = provider._get_cache_path("cve-2023-20198")
        assert "CVE-2023-20198.json" in path_lower

    def test_cache_write_and_read(self):
        """Test that data can be written to and read from cache."""
        provider = NvdEnricherProvider(cve_ids=[])

        # Create temp cache dir
        import services.cve_sources as cve_sources
        original_dir = cve_sources.NVD_CACHE_DIR
        cve_sources.NVD_CACHE_DIR = self.temp_dir

        try:
            test_data = {"test": "data", "cve_id": "CVE-2023-20198"}

            # Write to cache
            provider._write_cache("CVE-2023-20198", test_data)

            # Read from cache
            cached = provider._read_cache("CVE-2023-20198")

            assert cached is not None
            assert cached["test"] == "data"
            assert cached["cve_id"] == "CVE-2023-20198"
        finally:
            cve_sources.NVD_CACHE_DIR = original_dir

    def test_cache_miss(self):
        """Test that cache miss returns None."""
        provider = NvdEnricherProvider(cve_ids=[])

        import services.cve_sources as cve_sources
        original_dir = cve_sources.NVD_CACHE_DIR
        cve_sources.NVD_CACHE_DIR = self.temp_dir

        try:
            # Try to read non-existent cache
            cached = provider._read_cache("CVE-9999-99999")
            assert cached is None
        finally:
            cve_sources.NVD_CACHE_DIR = original_dir

    def test_cache_expiry(self):
        """Test that expired cache entries are not returned."""
        provider = NvdEnricherProvider(cve_ids=[])

        import services.cve_sources as cve_sources
        original_dir = cve_sources.NVD_CACHE_DIR
        cve_sources.NVD_CACHE_DIR = self.temp_dir

        try:
            # Manually create an expired cache file
            cache_path = os.path.join(self.temp_dir, "CVE-2023-20198.json")
            expired_data = {
                "cached_at": time.time() - NVD_CACHE_TTL - 3600,  # 1 hour past TTL
                "data": {"test": "expired"}
            }
            with open(cache_path, "w") as f:
                json.dump(expired_data, f)

            # Should return None for expired cache
            cached = provider._read_cache("CVE-2023-20198")
            assert cached is None
        finally:
            cve_sources.NVD_CACHE_DIR = original_dir

    def test_cache_valid_within_ttl(self):
        """Test that cache entries within TTL are returned."""
        provider = NvdEnricherProvider(cve_ids=[])

        import services.cve_sources as cve_sources
        original_dir = cve_sources.NVD_CACHE_DIR
        cve_sources.NVD_CACHE_DIR = self.temp_dir

        try:
            # Manually create a valid cache file
            cache_path = os.path.join(self.temp_dir, "CVE-2023-20198.json")
            valid_data = {
                "cached_at": time.time() - 3600,  # 1 hour ago (within 24h TTL)
                "data": {"test": "valid"}
            }
            with open(cache_path, "w") as f:
                json.dump(valid_data, f)

            # Should return data for valid cache
            cached = provider._read_cache("CVE-2023-20198")
            assert cached is not None
            assert cached["test"] == "valid"
        finally:
            cve_sources.NVD_CACHE_DIR = original_dir


def test_cache_ttl_is_24_hours():
    """Verify cache TTL is set to 24 hours."""
    assert NVD_CACHE_TTL == 24 * 3600  # 86400 seconds
