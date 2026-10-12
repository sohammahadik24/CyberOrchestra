"""Mocked tests for the evidence-grounded Threat Detection Agent."""

import json
from unittest.mock import Mock

import pytest

from app.agents.threat_detection import ThreatDetectionAgent, ThreatDetectionError
from app.models.incident import Evidence, Incident, Indicator
from app.models.threat_assessment import ThreatAssessment


def fixture_incident():
    return Incident(
        incident_id="INC-STEP3",
        incident_type="suspicious_network_activity",
        description="Outbound connection to an IP observed in a firewall event.",
        source="firewall",
        indicators=[Indicator(indicator_type="ip", value="203.0.113.7", source="firewall")],
    )


def fixture_evidence():
    return Evidence(
        evidence_id="EVID-ABUSE-203.0.113.7",
        evidence_type="network_reputation",
        source="AbuseIPDB",
        description="External reports exist for this IP.",
        metadata={"provenance": "AbuseIPDB API v2", "abuse_confidence_score": 42},
    )


def valid_output(**overrides):
    payload = {
        "incident_id": "INC-STEP3",
        "threat_classification": "suspicious",
        "severity": "medium",
        "confidence": 0.72,
        "reasoning": "Observed: a firewall event records an outbound connection. Inference: additional review may clarify its significance.",
        "observed_facts": ["The incident contains an outbound connection observation."],
        "inferences": ["The activity may warrant further investigation."],
        "supporting_evidence_ids": ["EVID-ABUSE-203.0.113.7"],
        "mitre_techniques": [],
        "related_cves": [],
        "recommended_next_analysis": ["log_analysis"],
        "uncertainties": ["The provided evidence does not establish intent."],
    }
    payload.update(overrides)
    return json.dumps(payload)


def test_valid_incident_and_evidence_returns_structured_assessment():
    llm = Mock()
    llm.generate.return_value = valid_output()
    assessment = ThreatDetectionAgent(llm).assess(fixture_incident(), [fixture_evidence()])
    assert isinstance(assessment, ThreatAssessment)
    assert assessment.incident_id == "INC-STEP3"
    assert assessment.threat_classification.value == "suspicious"
    assert assessment.confidence == 0.72
    llm.generate.assert_called_once()
    kwargs = llm.generate.call_args.kwargs
    assert "never invent" in kwargs["system_prompt"].lower()
    assert kwargs["structured_input"]["external_evidence"][0]["source"] == "AbuseIPDB"


def test_evidence_ids_are_preserved_and_unknown_ids_rejected():
    llm = Mock()
    llm.generate.return_value = valid_output()
    assessed = ThreatDetectionAgent(llm).assess(fixture_incident(), [fixture_evidence()])
    assert assessed.supporting_evidence_ids == ["EVID-ABUSE-203.0.113.7"]

    llm.generate.return_value = valid_output(supporting_evidence_ids=["made-up-id"])
    with pytest.raises(ThreatDetectionError, match="not supplied"):
        ThreatDetectionAgent(llm).assess(fixture_incident(), [fixture_evidence()])


@pytest.mark.parametrize("raw", ["not json", "{}", json.dumps({"confidence": 5})])
def test_invalid_or_malformed_output_fails_safely(raw):
    llm = Mock()
    llm.generate.return_value = raw
    with pytest.raises(ThreatDetectionError):
        ThreatDetectionAgent(llm).assess(fixture_incident(), [fixture_evidence()])


def test_no_evidence_is_passed_as_empty_and_can_report_uncertainty():
    llm = Mock()
    llm.generate.return_value = valid_output(
        supporting_evidence_ids=[],
        threat_classification="unknown",
        severity="unknown",
        confidence=0.2,
        observed_facts=[],
        inferences=[],
        uncertainties=["No external evidence was supplied."],
    )
    assessment = ThreatDetectionAgent(llm).assess(fixture_incident(), [])
    assert assessment.supporting_evidence_ids == []
    assert assessment.threat_classification.value == "unknown"
    assert llm.generate.call_args.kwargs["structured_input"]["external_evidence"] == []


def test_llm_failure_is_wrapped_without_returning_unvalidated_assessment():
    llm = Mock()
    llm.generate.side_effect = RuntimeError("provider unavailable")
    with pytest.raises(ThreatDetectionError, match="could not be generated"):
        ThreatDetectionAgent(llm).assess(fixture_incident(), [fixture_evidence()])
