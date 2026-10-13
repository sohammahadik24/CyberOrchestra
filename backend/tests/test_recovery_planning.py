"""Mocked tests for the Recovery Planning Agent."""

import json
from unittest.mock import Mock

import pytest

from app.core.config import settings
from app.agents.recovery_planning import RecoveryPlanningAgent, RecoveryPlanningError
from app.models.incident import Evidence, Incident
from app.models.incident_state import IncidentState
from app.models.threat_assessment import ThreatAssessment, ThreatClassification, ThreatSeverity


def make_state(with_evidence=True):
    incident = Incident(
        incident_id="INC-REC-1",
        incident_type="suspicious_activity",
        description="Suspicious access detected.",
        source="test",
        evidence=[Evidence(
            evidence_id="E-REC-1", evidence_type="authentication_log", source="identity",
            description="Repeated failed logins followed by one successful login.",
        )] if with_evidence else [],
    )
    state = IncidentState(incident_id=incident.incident_id, normalized_incident=incident)
    if with_evidence:
        state.add_threat_detection_result(ThreatAssessment(
            incident_id=incident.incident_id,
            threat_classification=ThreatClassification.SUSPICIOUS,
            severity=ThreatSeverity.MEDIUM,
            confidence=0.7,
            reasoning="Authentication evidence shows unusual access.",
            supporting_evidence_ids=["E-REC-1"],
            uncertainties=["The account owner has not confirmed the login."],
        ))
    return state


def output_json(**updates):
    payload = {
        "incident_id": "INC-REC-1",
        "recovery_actions": [{
            "recovery_action": "Review the successful login with the account owner and reset credentials if unauthorized.",
            "action_priority": "high",
            "rationale": "The authentication record shows repeated failures before a successful login.",
            "supporting_evidence_ids": ["E-REC-1"],
            "expected_outcome": "Confirm whether access was legitimate and reduce risk from compromised credentials.",
            "risks": ["A credential reset may interrupt the user's access."],
        }],
        "uncertainties": ["The account owner has not confirmed the login."]
    }
    payload.update(updates)
    return json.dumps(payload)


def test_plan_is_structured_and_uses_shared_incident_state():
    llm = Mock()
    llm.generate.return_value = output_json()
    state = make_state()
    result = RecoveryPlanningAgent(llm).plan(state)
    assert result.incident_id == state.incident_id
    assert result.recovery_actions[0].action_priority.value == "high"
    assert result.recovery_actions[0].supporting_evidence_ids == ["E-REC-1"]
    assert result.uncertainties == ["The account owner has not confirmed the login."]
    request = llm.generate.call_args.kwargs["structured_input"]
    assert request["shared_incident_state"]["aggregated_evidence_ids"] == ["E-REC-1"]
    assert llm.generate.call_args.kwargs["provider"] == "groq"
    assert llm.generate.call_args.kwargs["model"] == settings.RECOVERY_LLM_MODEL


def test_no_evidence_must_not_produce_unsupported_actions():
    llm = Mock()
    llm.generate.return_value = output_json(recovery_actions=[])
    result = RecoveryPlanningAgent(llm).plan(make_state(with_evidence=False))
    assert result.recovery_actions == []


def test_action_cannot_omit_or_fabricate_evidence_citations():
    llm = Mock()
    llm.generate.return_value = output_json(recovery_actions=[{
        "recovery_action": "Take an action.", "action_priority": "medium", "rationale": "Reason.",
        "supporting_evidence_ids": [], "expected_outcome": "Outcome.", "risks": [],
    }])
    with pytest.raises(RecoveryPlanningError, match="must cite"):
        RecoveryPlanningAgent(llm).plan(make_state())

    llm.generate.return_value = output_json(recovery_actions=[{
        "recovery_action": "Take an action.", "action_priority": "medium", "rationale": "Reason.",
        "supporting_evidence_ids": ["E-FAKE"], "expected_outcome": "Outcome.", "risks": [],
    }])
    with pytest.raises(RecoveryPlanningError, match="not aggregated"):
        RecoveryPlanningAgent(llm).plan(make_state())


def test_mismatched_incident_and_malformed_response_fail_safely():
    llm = Mock()
    llm.generate.return_value = output_json(incident_id="INC-OTHER")
    with pytest.raises(RecoveryPlanningError, match="incident_id"):
        RecoveryPlanningAgent(llm).plan(make_state())

    llm.generate.return_value = "not json"
    with pytest.raises(RecoveryPlanningError, match="could not be generated or validated"):
        RecoveryPlanningAgent(llm).plan(make_state())
