"""Mocked tests for the one-call single-LLM baseline."""

import json
from unittest.mock import Mock

import pytest

from app.baseline.single_llm_baseline import SingleLLMBaseline, SingleLLMBaselineError
from app.models.incident import Evidence, Incident
from app.models.threat_assessment import ThreatClassification, ThreatSeverity


def make_incident(with_evidence=True):
    return Incident(
        incident_id="INC-BASE-1",
        incident_type="security_observation",
        description="A host generated a suspicious authentication event.",
        source="test",
        evidence=[Evidence(
            evidence_id="E-BASE-1", evidence_type="authentication_log", source="identity",
            description="Multiple failed logins preceded a successful login.",
        )] if with_evidence else [],
    )


def output_json(**updates):
    payload = {
        "incident_id": "INC-BASE-1",
        "threat_classification": "suspicious",
        "severity": "medium",
        "malware_findings": [],
        "log_findings": [{
            "finding": "Failed logins preceded a successful login.",
            "supporting_evidence_ids": ["E-BASE-1"],
        }],
        "vulnerability_findings": [],
        "recovery_recommendations": [{
            "recommendation": "Review the successful login with the account owner.",
            "rationale": "The login pattern is unusual.",
            "supporting_evidence_ids": ["E-BASE-1"],
        }],
        "uncertainties": ["The account owner has not confirmed the login."],
        "supporting_evidence_ids": ["E-BASE-1"],
    }
    payload.update(updates)
    return json.dumps(payload)


def test_complete_baseline_is_returned_in_one_groq_call():
    llm = Mock()
    llm.generate.return_value = output_json()
    incident = make_incident()
    assessment = SingleLLMBaseline(llm).analyze(incident)
    assert assessment.incident_id == incident.incident_id
    assert assessment.threat_classification == ThreatClassification.SUSPICIOUS
    assert assessment.severity == ThreatSeverity.MEDIUM
    assert assessment.log_findings[0].supporting_evidence_ids == ["E-BASE-1"]
    assert len(assessment.recovery_recommendations) == 1
    llm.generate.assert_called_once()
    kwargs = llm.generate.call_args.kwargs
    assert kwargs["provider"] == "groq"
    assert kwargs["model"] == "openai/gpt-oss-120b"
    assert kwargs["structured_input"]["normalized_incident"]["incident_id"] == incident.incident_id
    assert len(kwargs["structured_input"]["available_evidence"]) == 1


def test_external_evidence_is_combined_and_duplicate_ids_deduplicated():
    incident = make_incident()
    extra = Evidence(
        evidence_id="E-BASE-2", evidence_type="observation", source="sensor", description="Additional observation."
    )
    llm = Mock()
    llm.generate.return_value = output_json(
        log_findings=[],
        recovery_recommendations=[],
        supporting_evidence_ids=["E-BASE-2"],
    )
    assessment = SingleLLMBaseline(llm).analyze(incident, [extra, incident.evidence[0]])
    assert assessment.supporting_evidence_ids == ["E-BASE-2"]
    passed = llm.generate.call_args.kwargs["structured_input"]["available_evidence"]
    assert [item["evidence_id"] for item in passed] == ["E-BASE-1", "E-BASE-2"]


def test_unsupported_evidence_and_uncited_findings_are_rejected():
    llm = Mock()
    llm.generate.return_value = output_json(supporting_evidence_ids=["E-FAKE"])
    with pytest.raises(SingleLLMBaselineError, match="not supplied"):
        SingleLLMBaseline(llm).analyze(make_incident())

    llm.generate.return_value = output_json(log_findings=[{"finding": "Unsupported claim."}])
    with pytest.raises(SingleLLMBaselineError, match="must cite supporting evidence"):
        SingleLLMBaseline(llm).analyze(make_incident())


def test_malformed_output_and_incident_mismatch_fail_safely():
    llm = Mock()
    llm.generate.return_value = "not json"
    with pytest.raises(SingleLLMBaselineError, match="could not be generated or validated"):
        SingleLLMBaseline(llm).analyze(make_incident())

    llm.generate.return_value = output_json(incident_id="INC-OTHER")
    with pytest.raises(SingleLLMBaselineError, match="incident_id"):
        SingleLLMBaseline(llm).analyze(make_incident())
