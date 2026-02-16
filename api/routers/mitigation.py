"""
CVE Mitigation Advisor API Router
Provides endpoints for fetching mitigation recommendations.
"""

from fastapi import APIRouter, HTTPException
from typing import List

from models.mitigation_model import (
    CVEMitigation,
    MitigationRequest,
    MitigationResponse
)
from services.mitigation_service import get_mitigation_service


router = APIRouter(prefix="/mitigate", tags=["CVE Mitigation Advisor"])


@router.get(
    "/cve/{cve_id}",
    response_model=MitigationResponse,
    summary="Get mitigation for a specific CVE",
    description="Returns workaround commands, ACL mitigation, upgrade path, and verification steps for a CVE."
)
async def get_mitigation(cve_id: str) -> MitigationResponse:
    """
    Get mitigation recommendations for a specific CVE.

    - **cve_id**: CVE identifier (e.g., CVE-2023-20198)

    Returns complete mitigation package including:
    - Workaround commands
    - ACL-based mitigation
    - Recommended upgrade version
    - Detection and verification commands
    """
    service = get_mitigation_service()
    return service.get_mitigation(cve_id)


@router.post(
    "/cve",
    response_model=MitigationResponse,
    summary="Get mitigation with optional platform/version filtering",
    description="Get mitigation for a CVE with optional platform and version context."
)
async def get_mitigation_filtered(request: MitigationRequest) -> MitigationResponse:
    """
    Get mitigation with optional platform/version filtering.

    Future: Will filter workarounds based on platform and version.
    Currently returns full mitigation regardless of filters.
    """
    service = get_mitigation_service()
    response = service.get_mitigation(request.cve_id)

    # TODO: Filter workarounds based on platform/version
    # if request.platform and response.found:
    #     response.mitigation = filter_by_platform(response.mitigation, request.platform)

    return response


@router.get(
    "/list",
    response_model=List[str],
    summary="List all CVEs with available mitigations"
)
async def list_mitigations() -> List[str]:
    """List all CVE IDs that have mitigation data available."""
    service = get_mitigation_service()
    return service.list_available()


@router.get(
    "/critical",
    response_model=List[CVEMitigation],
    summary="Get all critical CVE mitigations"
)
async def get_critical_mitigations() -> List[CVEMitigation]:
    """Get all mitigations tagged as critical."""
    service = get_mitigation_service()
    return service.get_critical()


@router.get(
    "/tag/{tag}",
    response_model=List[CVEMitigation],
    summary="Get mitigations by tag"
)
async def get_mitigations_by_tag(tag: str) -> List[CVEMitigation]:
    """
    Get all mitigations with a specific tag.

    Common tags: critical, high, web-ui, privilege-escalation, zero-day
    """
    service = get_mitigation_service()
    return service.get_by_tag(tag)


@router.post(
    "/reload",
    summary="Reload mitigation database",
    description="Reload all mitigation data from disk. Returns count of loaded mitigations."
)
async def reload_mitigations() -> dict:
    """Reload mitigation database from disk."""
    service = get_mitigation_service()
    count = service.reload()
    return {"status": "reloaded", "count": count}
