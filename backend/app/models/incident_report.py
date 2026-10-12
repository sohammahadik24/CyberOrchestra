"""Structured report generated from existing incident analysis artifacts."""

from enum import Enum
from typing import List

from pydantic import BaseModel, ConfigDict, Field

from app.models.policy_decision import PolicyDecision
from app.models.recovery_plan import RecoveryAction


class FindingStatus(str, Enum):
    CONFIRMED = "confirmed"
    INFERRED = "inferred"
    UNCERTAIN = "uncertain"


class FinalRiskLevel(str, Enum):
    UNKNOWN = "unknown"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReportFinding(BaseModel):
    finding: str
    status: FindingStatus = Field(description="Clearly distinguishes confirmed findings from inferences and uncertainty")
    supporting_evidence_ids: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class EvidenceSummary(BaseModel):
    evidence_id: str
    summary: str

    model_config = ConfigDict(extra="forbid")


class IncidentReport(BaseModel):
    incident_id: str
    executive_summary: ReportFinding
    threat_assessment: List[ReportFinding] = Field(default_factory=list)
    malware_findings: List[ReportFinding] = Field(default_factory=list)
    log_findings: List[ReportFinding] = Field(default_factory=list)
    vulnerability_findings: List[ReportFinding] = Field(default_factory=list)
    recovery_recommendations: List[RecoveryAction] = Field(default_factory=list)
    policy_decisions: List[PolicyDecision] = Field(default_factory=list)
    evidence_summary: List[EvidenceSummary] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)
    final_risk_level: FinalRiskLevel

    model_config = ConfigDict(extra="forbid")
