"""Deterministic policy decisions for proposed recovery actions."""

from enum import Enum
from typing import List

from pydantic import BaseModel, ConfigDict, Field


class PolicyDecisionValue(str, Enum):
    APPROVED = "APPROVED"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"
    REJECTED = "REJECTED"


class PolicyDecision(BaseModel):
    incident_id: str
    action: str = Field(description="The proposed recovery action being evaluated")
    decision: PolicyDecisionValue
    reason: str
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    policy_rule_id: str

    model_config = ConfigDict(extra="forbid")
