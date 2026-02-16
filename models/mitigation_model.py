"""
CVE Mitigation Advisor - Data Models
Defines structure for mitigation recommendations.
"""

from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MitigationStep(BaseModel):
    """Single mitigation step with commands."""
    order: int
    description: str
    commands: List[str]
    platform_notes: Optional[str] = None


class DetectionMethod(BaseModel):
    """How to detect if device is vulnerable."""
    description: str
    commands: List[str]
    vulnerable_if: str


class VerificationMethod(BaseModel):
    """How to verify mitigation was successful."""
    description: str
    commands: List[str]
    expected_output: str


class ACLMitigation(BaseModel):
    """ACL-based mitigation config."""
    description: str
    acl_name: str
    commands: List[str]
    apply_to: str  # e.g., "ip http access-class"


class CVEMitigation(BaseModel):
    """Complete mitigation package for a CVE."""

    cve_id: str = Field(..., description="CVE identifier, e.g., CVE-2023-20198")

    risk_summary: str = Field(..., description="Brief explanation of the risk")
    attack_vector: str = Field(..., description="How the attack works")

    workaround_steps: List[MitigationStep] = Field(
        default_factory=list,
        description="Step-by-step workaround commands"
    )

    acl_mitigation: Optional[ACLMitigation] = Field(
        None,
        description="ACL-based mitigation if applicable"
    )

    recommended_fix: str = Field(..., description="Recommended IOS version to upgrade")
    upgrade_path: Optional[str] = Field(None, description="Upgrade path notes")

    detection: DetectionMethod = Field(..., description="How to detect vulnerability")
    verification: VerificationMethod = Field(..., description="How to verify mitigation")

    cisco_psirt: Optional[str] = Field(None, description="Cisco PSIRT advisory URL")
    field_notice: Optional[str] = Field(None, description="Field Notice ID if exists")
    cisa_alert: Optional[str] = Field(None, description="CISA alert URL if exists")

    tags: List[str] = Field(default_factory=list)
    last_updated: str = Field(..., description="ISO date of last update")


class MitigationRequest(BaseModel):
    """API request for mitigation lookup."""
    cve_id: str
    platform: Optional[str] = None
    version: Optional[str] = None


class MitigationResponse(BaseModel):
    """API response with full mitigation data."""
    found: bool
    cve_id: str
    mitigation: Optional[CVEMitigation] = None
    message: Optional[str] = None
