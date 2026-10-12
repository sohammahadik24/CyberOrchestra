"""Strict structured output for the Log Analysis Agent."""

from enum import Enum
from typing import List

from pydantic import BaseModel, ConfigDict, Field


class LogSeverity(str, Enum):
    UNKNOWN = "unknown"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LogFinding(BaseModel):
    finding: str
    supporting_evidence_ids: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class AttackIndicator(BaseModel):
    indicator_type: str
    value: str
    supporting_evidence_ids: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class TimelineFinding(BaseModel):
    event: str
    timestamp: str = Field(description="Use the supplied event time, or an empty string if none is recorded")
    supporting_evidence_ids: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class LogAssessment(BaseModel):
    incident_id: str
    suspicious_events: List[LogFinding] = Field(default_factory=list)
    attack_indicators: List[AttackIndicator] = Field(default_factory=list)
    timeline_findings: List[TimelineFinding] = Field(default_factory=list)
    severity: LogSeverity
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, description="Agent assessment confidence, not an external score")
    uncertainties: List[str] = Field(default_factory=list)
    recommended_next_analysis: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")
