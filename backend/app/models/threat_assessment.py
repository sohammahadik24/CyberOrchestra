"""Structured Threat Detection Agent output."""

from enum import Enum
from typing import List

from pydantic import BaseModel, ConfigDict, Field


class ThreatClassification(str, Enum):
    UNKNOWN = "unknown"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class ThreatSeverity(str, Enum):
    UNKNOWN = "unknown"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NextAnalysis(str, Enum):
    MALWARE_ANALYSIS = "malware_analysis"
    LOG_ANALYSIS = "log_analysis"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    ADDITIONAL_TELEMETRY = "additional_telemetry"
    HUMAN_REVIEW = "human_review"
    NONE = "none"


class ThreatAssessment(BaseModel):
    """Agent assessment; confidence is internal assessment confidence (0–1)."""

    incident_id: str
    threat_classification: ThreatClassification
    severity: ThreatSeverity
    confidence: float = Field(ge=0.0, le=1.0, description="Agent assessment confidence, not an external score")
    reasoning: str
    observed_facts: List[str] = Field(default_factory=list)
    inferences: List[str] = Field(default_factory=list)
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    related_cves: List[str] = Field(default_factory=list)
    recommended_next_analysis: List[NextAnalysis] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")
