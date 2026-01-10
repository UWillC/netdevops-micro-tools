from fastapi import APIRouter, HTTPException

from services.profile_service import ProfileService
from models.profile_model import DeviceProfile, ProfileVulnerabilitiesResponse

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
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Profile not found")


# Save profile
@router.post("/profiles/save")
def save_profile(profile: DeviceProfile):
    svc.save_profile(profile)
    return {"status": "ok", "saved_as": profile.name}


# Delete profile
@router.delete("/profiles/delete/{name}")
def delete_profile(name: str):
    try:
        svc.delete_profile(name)
        return {"status": "deleted", "name": name}
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
