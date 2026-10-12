"""Structured, auditable recovery recommendations for human review."""

from enum import Enum
from typing import List

from pydantic import BaseModel, ConfigDict, Field


class ActionPriority(str, Enum):
    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RecoveryAction(BaseModel):
    recovery_action: str = Field(description="A specific proposed recovery recommendation; never execute it")
    action_priority: ActionPriority
    rationale: str
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    expected_outcome: str
    risks: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class RecoveryPlan(BaseModel):
    incident_id: str
    recovery_actions: List[RecoveryAction] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")
