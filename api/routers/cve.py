from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional
import datetime

from services.cve_engine import CVEEngine
from models.cve_model import CVEEntry


router = APIRouter()


# -----------------------------
# Request / Response models
# -----------------------------
class CVEAnalyzeRequest(BaseModel):
    platform: str
    version: str
    include_suggestions: bool = True


class CVEAnalyzeResponse(BaseModel):
    platform: str
    version: str
    matched: List[CVEEntry]
    summary: dict
    recommended_upgrade: Optional[str]
    timestamp: str


# -----------------------------
# Endpoint
# -----------------------------
@router.post("/cve", response_model=CVEAnalyzeResponse)
def analyze_cve(req: CVEAnalyzeRequest):

    engine = CVEEngine()
    engine.load_all()
    matched = engine.match(req.platform, req.version)

    summary = engine.summary(matched)
    recommendation = None

    if req.include_suggestions:
        recommendation = engine.recommended_upgrade(matched)

    return CVEAnalyzeResponse(
        platform=req.platform,
        version=req.version,
        matched=matched,
        summary=summary,
        recommended_upgrade=recommendation,
        timestamp=datetime.datetime.utcnow().isoformat() + "Z",
    )
