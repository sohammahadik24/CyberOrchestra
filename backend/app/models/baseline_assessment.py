"""Structured complete assessment produced by the single-LLM baseline."""

from typing import List

from pydantic import BaseModel, ConfigDict, Field

from app.models.threat_assessment import ThreatClassification, ThreatSeverity


class BaselineFinding(BaseModel):
    finding: str
    supporting_evidence_ids: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class BaselineRecommendation(BaseModel):
    recommendation: str
    rationale: str
    supporting_evidence_ids: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class BaselineAssessment(BaseModel):
    incident_id: str
    threat_classification: ThreatClassification
    severity: ThreatSeverity
    malware_findings: List[BaselineFinding] = Field(default_factory=list)
    log_findings: List[BaselineFinding] = Field(default_factory=list)
    vulnerability_findings: List[BaselineFinding] = Field(default_factory=list)
    recovery_recommendations: List[BaselineRecommendation] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)
    supporting_evidence_ids: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")
