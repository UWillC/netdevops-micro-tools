"""FTD-PSIRT (2026-10-18): the FTD feed asks PSIRT for the exact product name.

Before the fix `PLATFORM_PRODUCTS` had no "ftd" key, so the provider sent
product=ftd verbatim and the API answered with a fuzzy match (same class of
bug as ISE-02). Every platform the feed allowlist accepts must now map to a
real PSIRT product name.
"""
import urllib.parse

from api.routers.cve import FEED_PLATFORMS
from services.cve_sources import CiscoAdvisoryProvider

FTD_PRODUCT = "Cisco Secure Firewall Threat Defense (FTD) Software"


def test_ftd_maps_to_psirt_product_name():
    assert CiscoAdvisoryProvider.PLATFORM_PRODUCTS["ftd"] == FTD_PRODUCT


def test_every_feed_platform_has_a_psirt_product_name():
    missing = [p for p in FEED_PLATFORMS
               if p != "all" and p not in CiscoAdvisoryProvider.PLATFORM_PRODUCTS]
    assert missing == []


def test_ftd_fetch_sends_exact_product_not_slug(monkeypatch):
    provider = CiscoAdvisoryProvider(platform="ftd", max_pages=1)
    urls = []
    monkeypatch.setattr(provider, "_load_credentials",
                        lambda: {"api_base": "https://psirt.example/v2"})
    monkeypatch.setattr(provider, "_api_get",
                        lambda url: urls.append(url) or {"advisories": []})
    assert provider.fetch_advisories(use_cache=False) == []
    assert urls, "PSIRT was not called"
    query = urllib.parse.parse_qs(urllib.parse.urlparse(urls[0]).query)
    assert query["product"] == [FTD_PRODUCT]
