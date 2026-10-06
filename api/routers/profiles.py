from fastapi import APIRouter, HTTPException

from services.profile_service import (
    InvalidProfileName,
    ProfileService,
    ProfileStorageDisabled,
)
from models.profile_model import DeviceProfile, ProfileVulnerabilitiesResponse
from models.security_score import SecurityScoreResponse

router = APIRouter()
svc = ProfileService()


# List profiles
@router.get("/profiles/list")
def list_profiles():
    return {"profiles": svc.list_profiles()}


# Load profile
@router.get("/profiles/load/{name}")
def load_profile(name: str):
    try:
        data = svc.load_profile(name)
        return data
    except InvalidProfileName as e:
        raise HTTPException(status_code=400, detail=str(e))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Profile not found")


# Save profile
# M11 (v0.6.66): server-side storage is off. Name is validated first (400),
# then the request is refused (403); nothing is written to disk.
@router.post("/profiles/save")
def save_profile(profile: DeviceProfile):
    try:
        svc.save_profile(profile)
    except InvalidProfileName as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ProfileStorageDisabled as e:
        raise HTTPException(status_code=403, detail=str(e))
    return {"status": "ok", "saved_as": profile.name}


# Delete profile
@router.delete("/profiles/delete/{name}")
def delete_profile(name: str):
    try:
        svc.delete_profile(name)
        return {"status": "deleted", "name": name}
    except InvalidProfileName as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ProfileStorageDisabled as e:
        raise HTTPException(status_code=403, detail=str(e))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Profile not found")


# ------------------------------------------
# v0.3.5: Profiles × CVE integration
# ------------------------------------------
@router.get("/profiles/vulnerabilities", response_model=ProfileVulnerabilitiesResponse)
def check_vulnerabilities():
    """
    Check all profiles against CVE database.

    Returns vulnerability status for each profile with platform/version info.
    Profiles without platform/version are marked as 'unknown'.
    """
    return svc.check_all_vulnerabilities()


# ------------------------------------------
# v0.4.0: Security Score
# ------------------------------------------
@router.get("/profiles/security-scores", response_model=SecurityScoreResponse)
def get_security_scores():
    """
    Calculate security scores (0-100) for all profiles.

    Score algorithm:
    - Base score: 100
    - Penalties per CVE based on severity (critical: -25, high: -15, medium: -8, low: -3)
    - Modifiers: exploited-in-wild (×1.5), patch-available (×0.7), aged >365d (×1.2)

    Returns per-profile scores with full CVE breakdown.
    """
    return svc.calculate_all_security_scores()
