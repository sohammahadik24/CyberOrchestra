"""Unit tests for deterministic recovery action policy decisions."""

import pytest

from app.core.policy_engine import PolicyEngine
from app.models.incident import Evidence, Incident
from app.models.incident_state import IncidentState
from app.models.policy_decision import PolicyDecisionValue
from app.models.recovery_plan import ActionPriority, RecoveryAction, RecoveryPlan
from app.models.threat_assessment import ThreatAssessment, ThreatClassification, ThreatSeverity


def make_state(severity=ThreatSeverity.LOW, confidence=0.95):
    incident = Incident(
        incident_id="INC-POL-1", incident_type="security_event", description="Test event.",
        source="test", severity="low",
        evidence=[Evidence(
            evidence_id="E-POL-1", evidence_type="observation", source="sensor",
            description="Observed event supporting the recommendation.",
        )],
    )
    state = IncidentState(incident_id=incident.incident_id, normalized_incident=incident)
    state.add_threat_detection_result(ThreatAssessment(
        incident_id=incident.incident_id,
        threat_classification=ThreatClassification.SUSPICIOUS,
        severity=severity,
        confidence=confidence,
        reasoning="Assessment based on the recorded event.",
        supporting_evidence_ids=["E-POL-1"],
    ))
    return state


def action(text="Review the recorded event with the system owner.", evidence_ids=None, priority=ActionPriority.LOW, risks=None):
    return RecoveryAction(
        recovery_action=text,
        action_priority=priority,
        rationale="The cited event supports reviewing the affected system.",
        supporting_evidence_ids=["E-POL-1"] if evidence_ids is None else evidence_ids,
        expected_outcome="Confirm the event and determine an appropriate response.",
        risks=risks or [],
    )


def plan(*actions, incident_id="INC-POL-1"):
    return RecoveryPlan(incident_id=incident_id, recovery_actions=list(actions))


def test_supported_lower_risk_action_is_approved():
    result = PolicyEngine().evaluate(plan(action()), make_state())
    assert len(result) == 1
    assert result[0].decision == PolicyDecisionValue.APPROVED
    assert result[0].policy_rule_id == "PE-004"
    assert result[0].supporting_evidence_ids == ["E-POL-1"]
    assert result[0].reason


def test_high_risk_action_requires_approval():
    result = PolicyEngine().evaluate(plan(action("Disable the account associated with this event.")), make_state())
    assert result[0].decision == PolicyDecisionValue.REQUIRES_APPROVAL
    assert result[0].policy_rule_id == "PE-002"


def test_unsupported_or_insufficient_evidence_is_rejected():
    decisions = PolicyEngine().evaluate(
        plan(action(evidence_ids=[]), action(evidence_ids=["E-FAKE"])), make_state()
    )
    assert [item.decision for item in decisions] == [
        PolicyDecisionValue.REJECTED,
        PolicyDecisionValue.REJECTED,
    ]
    assert all(item.policy_rule_id == "PE-001" for item in decisions)


def test_high_severity_or_low_confidence_requires_approval():
    high_severity = PolicyEngine().evaluate(plan(action()), make_state(ThreatSeverity.HIGH, 0.95))
    low_confidence = PolicyEngine().evaluate(plan(action()), make_state(ThreatSeverity.LOW, 0.5))
    assert high_severity[0].decision == PolicyDecisionValue.REQUIRES_APPROVAL
    assert low_confidence[0].decision == PolicyDecisionValue.REQUIRES_APPROVAL
    assert high_severity[0].policy_rule_id == "PE-003"


def test_plan_and_state_incident_ids_must_match():
    with pytest.raises(ValueError, match="same incident_id"):
        PolicyEngine().evaluate(plan(action(), incident_id="INC-OTHER"), make_state())


def test_each_action_is_evaluated_independently():
    results = PolicyEngine().evaluate(
        plan(action(), action("Wipe the host and rebuild it.")), make_state()
    )
    assert [result.decision for result in results] == [
        PolicyDecisionValue.APPROVED,
        PolicyDecisionValue.REQUIRES_APPROVAL,
    ]
