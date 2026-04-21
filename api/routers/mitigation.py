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
    summary="Get mitigation with platform/version applicability check",
    description=(
        "Get mitigation for a CVE with optional platform and version "
        "context. When both are supplied, the response includes an "
        "`applicability` field (`applicable` / `not_applicable` / "
        "`unknown`) derived from the CVE engine, so the UI can flag "
        "whether the mitigation actually applies to the target device."
    )
)
async def get_mitigation_filtered(request: MitigationRequest) -> MitigationResponse:
    """
    Get mitigation with platform/version applicability check.

    v0.6.22: Cross-references the CVE engine to determine whether the
    CVE actually affects the target (platform, version). Full mitigation
    is always returned when found, but with `applicability` annotation:

    - `applicable`: CVE engine confirms the target is vulnerable → act.
    - `not_applicable`: CVE engine does NOT match → informational only.
    - `unknown`: engine call failed / no context supplied → treat as info.

    Rationale: operators sometimes look up a mitigation for a CVE that
    applies to a different platform than theirs (e.g., Cat 9300 operator
    looking up an ASA CVE for reference). Without applicability, they may
    apply the ACL to their device and create more problems. With the
    annotation, the UI can render "NOT APPLICABLE" prominently.
    """
    service = get_mitigation_service()
    return service.get_mitigation_for_platform(
        cve_id=request.cve_id,
        platform=request.platform,
        version=request.version,
    )


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
