"""Mocked tests for report generation and input preservation."""

import json
from unittest.mock import Mock

import pytest

from app.agents.report_generation import ReportGenerationAgent, ReportGenerationError
from app.models.incident import Evidence, Incident
from app.models.incident_state import IncidentState
from app.models.policy_decision import PolicyDecision, PolicyDecisionValue
from app.models.recovery_plan import ActionPriority, RecoveryAction, RecoveryPlan
from app.models.threat_assessment import ThreatAssessment, ThreatClassification, ThreatSeverity


def inputs():
    incident = Incident(
        incident_id="INC-REPORT-1", incident_type="suspicious_login",
        description="A suspicious login was reported.", source="test",
        evidence=[Evidence(
            evidence_id="E-REPORT-1", evidence_type="authentication_log", source="identity",
            description="Failed logins preceded a successful login.",
        )],
    )
    state = IncidentState(incident_id=incident.incident_id, normalized_incident=incident)
    state.add_threat_detection_result(ThreatAssessment(
        incident_id=incident.incident_id,
        threat_classification=ThreatClassification.SUSPICIOUS,
        severity=ThreatSeverity.MEDIUM,
        confidence=0.8,
        reasoning="The login pattern is unusual.",
        observed_facts=["Failed logins preceded a successful login."],
        supporting_evidence_ids=["E-REPORT-1"],
        uncertainties=["Account owner confirmation is pending."],
    ))
    action = RecoveryAction(
        recovery_action="Review the login with the account owner.",
        action_priority=ActionPriority.MEDIUM,
        rationale="The authentication evidence is unusual.",
        supporting_evidence_ids=["E-REPORT-1"],
        expected_outcome="Confirm whether the login was authorized.",
        risks=[],
    )
    recovery = RecoveryPlan(incident_id=incident.incident_id, recovery_actions=[action])
    decision = PolicyDecision(
        incident_id=incident.incident_id,
        action=action.recovery_action,
        decision=PolicyDecisionValue.APPROVED,
        reason="Evidence is supported and thresholds are met.",
        supporting_evidence_ids=["E-REPORT-1"],
        policy_rule_id="PE-004",
    )
    return state, recovery, [decision]


def report_payload(state, recovery, decisions, **updates):
    payload = {
        "incident_id": state.incident_id,
        "executive_summary": {
            "finding": "A suspicious login pattern was recorded.",
            "status": "confirmed",
            "supporting_evidence_ids": ["E-REPORT-1"],
        },
        "threat_assessment": [{
            "finding": "The login pattern is suspicious.", "status": "inferred",
            "supporting_evidence_ids": ["E-REPORT-1"],
        }],
        "malware_findings": [],
        "log_findings": [],
        "vulnerability_findings": [],
        "recovery_recommendations": [item.model_dump(mode="json") for item in recovery.recovery_actions],
        "policy_decisions": [item.model_dump(mode="json") for item in decisions],
        "evidence_summary": [{"evidence_id": "E-REPORT-1", "summary": "Failed logins preceded a successful login."}],
        "uncertainties": ["Account owner confirmation is pending."],
        "final_risk_level": "medium",
    }
    payload.update(updates)
    return json.dumps(payload)


def test_generates_structured_report_from_all_inputs_and_uses_expected_model():
    state, recovery, decisions = inputs()
    llm = Mock()
    llm.generate.return_value = report_payload(state, recovery, decisions)
    report = ReportGenerationAgent(llm).generate(state, recovery, decisions)
    assert report.incident_id == state.incident_id
    assert report.executive_summary.supporting_evidence_ids == ["E-REPORT-1"]
    assert report.recovery_recommendations == recovery.recovery_actions
    assert report.policy_decisions == decisions
    assert report.final_risk_level.value == "medium"
    request = llm.generate.call_args.kwargs["structured_input"]
    assert request["shared_incident_state"]["incident_id"] == state.incident_id
    assert request["recovery_plan"]["incident_id"] == state.incident_id
    assert llm.generate.call_args.kwargs["provider"] == "groq"
    assert llm.generate.call_args.kwargs["model"] == "qwen/qwen3-32b"


def test_policy_decisions_must_be_reproduced_exactly():
    state, recovery, decisions = inputs()
    llm = Mock()
    altered = decisions[0].model_copy(update={"reason": "Changed reason"})
    llm.generate.return_value = report_payload(state, recovery, decisions, policy_decisions=[altered.model_dump(mode="json")])
    with pytest.raises(ReportGenerationError, match="changed or omitted supplied policy decisions"):
        ReportGenerationAgent(llm).generate(state, recovery, decisions)


def test_unsupported_evidence_and_missing_summary_citations_are_rejected():
    state, recovery, decisions = inputs()
    llm = Mock()
    llm.generate.return_value = report_payload(state, recovery, decisions, evidence_summary=[{
        "evidence_id": "E-FABRICATED", "summary": "Invented event."
    }])
    with pytest.raises(ReportGenerationError, match="not present in the incident"):
        ReportGenerationAgent(llm).generate(state, recovery, decisions)

    llm.generate.return_value = report_payload(state, recovery, decisions, executive_summary={
        "finding": "An unsupported claim.", "status": "confirmed", "supporting_evidence_ids": []
    })
    with pytest.raises(ReportGenerationError, match="Executive summary must cite"):
        ReportGenerationAgent(llm).generate(state, recovery, decisions)


def test_incident_mismatches_and_malformed_output_fail_safely():
    state, recovery, decisions = inputs()
    llm = Mock()
    wrong_recovery = recovery.model_copy(update={"incident_id": "INC-OTHER"})
    with pytest.raises(ReportGenerationError, match="Recovery plan incident_id"):
        ReportGenerationAgent(llm).generate(state, wrong_recovery, decisions)

    wrong_decisions = [decisions[0].model_copy(update={"incident_id": "INC-OTHER"})]
    with pytest.raises(ReportGenerationError, match="Policy decision incident_id"):
        ReportGenerationAgent(llm).generate(state, recovery, wrong_decisions)

    llm.generate.return_value = "not json"
    with pytest.raises(ReportGenerationError, match="could not be generated or validated"):
        ReportGenerationAgent(llm).generate(state, recovery, decisions)
