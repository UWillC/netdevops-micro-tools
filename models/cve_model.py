from pydantic import BaseModel
from typing import List, Optional


class CVEAffectedRange(BaseModel):
    min: str
    max: str


class CVEEntry(BaseModel):
    cve_id: str
    title: str
    severity: str  # critical/high/medium/low
    platforms: List[str]
    affected: CVEAffectedRange
    fixed_in: Optional[str] = None
    tags: List[str] = []
    description: str
    workaround: Optional[str] = None
    advisory_url: Optional[str] = None
    confidence: str = "demo"  # demo | validated | partial
