"""
SDWAN-01 (2026-09-30): Catalyst SD-WAN Manager / Controller / Validator are
their own family, not cEdge (IOS XE in SD-WAN mode).

Before: "Catalyst SD-WAN Manager" 20.12.5 matched the "catalyst sd-wan" alias,
got 99 IOS / NGWC / glibc CVEs, no coverage note, and not CVE-2026-76504
(CISA KEV 2026-09-30). There is no controller dataset yet, so the honest
answer is NOT EVALUATED, never an IOS XE answer.
"""
import pytest
from fastapi.testclient import TestClient

from api.main import app
from services.platform_taxonomy import ProductFamily, normalize_user_platform, detect_primary_family

client = TestClient(app)


@pytest.mark.parametrize("platform", [
    "Catalyst SD-WAN Manager", "Cisco Catalyst SD-WAN Manager", "vManage",
    "SD-WAN Controller", "Catalyst SD-WAN Validator", "vSmart", "vBond",
])
def test_controllers_are_their_own_family(platform):
    assert normalize_user_platform(platform) == ProductFamily.SDWAN_CONTROLLERS


@pytest.mark.parametrize("platform", ["Catalyst SD-WAN", "cEdge", "Cisco IOS XE SD-WAN"])
def test_cedge_unchanged(platform):
    assert normalize_user_platform(platform) == ProductFamily.IOS_XE_SDWAN


def test_title_detection():
    assert detect_primary_family(
        "Cisco Catalyst SD-WAN Manager API Authentication Bypass Vulnerability"
    ) == ProductFamily.SDWAN_CONTROLLERS
    assert detect_primary_family(
        "Cisco IOS XE Catalyst SD-WAN Command Injection Vulnerability"
    ) == ProductFamily.IOS_XE_SDWAN


def test_manager_query_is_not_answered_from_ios_xe():
    """SDWAN-02.1 replaced NOT EVALUATED with the controller dataset; the
    SDWAN-01 guarantee that remains is: never an IOS XE answer."""
    r = client.post("/analyze/cve", json={"platform": "Catalyst SD-WAN Manager", "version": "20.12.5"})
    assert r.status_code == 200
    body = r.json()
    assert body["matched"]
    assert all("sd-wan-controllers" in m["product_families"] for m in body["matched"])
    assert body["coverage_note"].startswith("Catalyst SD-WAN Manager/Controller/Validator coverage")
    assert "never assumed clean" in body["coverage_note"]
