"""Mocked tests for the Log Analysis Agent."""

import json
from unittest.mock import Mock

import pytest

from app.agents.log_analysis import LogAnalysisAgent, LogAnalysisError
from app.models.incident import Evidence, Incident, Indicator
from app.models.log_assessment import LogAssessment


def make_incident():
    return Incident(
        incident_id="INC-LOG-1",
        incident_type="suspicious_network_activity",
        description="Firewall log records connections to a remote host.",
        source="firewall",
        indicators=[
            Indicator(indicator_type="ip", value="203.0.113.20", source="firewall"),
            Indicator(indicator_type="cve", value="CVE-2025-12345", source="scanner"),
        ],
        evidence=[Evidence(
            evidence_id="E-LOG-1",
            evidence_type="network_log",
            source="firewall",
            description="Connection from host 10.0.0.5 to 203.0.113.20 at 2026-10-08T10:30:00Z was denied.",
            timestamp="2026-10-08T10:30:00Z",
            metadata={"provenance": "firewall-export"},
        ), Evidence(
            evidence_id="E-URL-1",
            evidence_type="url_reputation",
            source="URLhaus",
            description="External URL reputation context.",
        )],
    )


def response_json(**updates):
    payload = {
        "incident_id": "INC-LOG-1",
        "suspicious_events": [{"finding": "The firewall denied an outbound connection.", "supporting_evidence_ids": ["E-LOG-1"]}],
        "attack_indicators": [{"indicator_type": "ip", "value": "203.0.113.20", "supporting_evidence_ids": ["E-LOG-1"]}],
        "timeline_findings": [{"event": "Firewall denied the connection.", "timestamp": "2026-10-08T10:30:00Z", "supporting_evidence_ids": ["E-LOG-1"]}],
        "severity": "medium",
        "supporting_evidence_ids": ["E-LOG-1"],
        "confidence": 0.73,
        "uncertainties": ["The available record does not establish the remote host's intent."],
        "recommended_next_analysis": ["review_additional_firewall_logs"],
    }
    payload.update(updates)
    return json.dumps(payload)


def test_valid_incident_parses_structured_response_and_preserves_evidence_ids():
    llm = Mock()
    llm.generate.return_value = response_json()
    assessment = LogAnalysisAgent(llm).analyze(make_incident())
    assert isinstance(assessment, LogAssessment)
    assert assessment.incident_id == "INC-LOG-1"
    assert assessment.supporting_evidence_ids == ["E-LOG-1"]
    assert assessment.timeline_findings[0].supporting_evidence_ids == ["E-LOG-1"]
    request = llm.generate.call_args.kwargs["structured_input"]
    assert [item["evidence_id"] for item in request["log_evidence"]] == ["E-LOG-1"]
    assert [item["value"] for item in request["relevant_indicators"]] == ["203.0.113.20"]
    assert request["incident"]["evidence"] == []
    assert "never invent log events" in llm.generate.call_args.kwargs["system_prompt"].lower()


def test_no_log_evidence_uses_empty_context():
    llm = Mock()
    llm.generate.return_value = response_json(
        suspicious_events=[], attack_indicators=[], timeline_findings=[],
        supporting_evidence_ids=[], severity="unknown", confidence=0.15,
        uncertainties=["No log evidence was supplied."],
    )
    incident = make_incident().model_copy(update={"evidence": []})
    unrelated = Evidence(evidence_id="E-URL-1", evidence_type="url_reputation", source="URLhaus", description="Reputation only.")
    assessment = LogAnalysisAgent(llm).analyze(incident, [unrelated])
    assert assessment.supporting_evidence_ids == []
    assert llm.generate.call_args.kwargs["structured_input"]["log_evidence"] == []


@pytest.mark.parametrize("raw", ["not json", "{}", json.dumps({"incident_id": "INC-LOG-1", "confidence": 2})])
def test_malformed_llm_output_fails_safely(raw):
    llm = Mock()
    llm.generate.return_value = raw
    with pytest.raises(LogAnalysisError):
        LogAnalysisAgent(llm).analyze(make_incident())


def test_llm_failure_is_wrapped():
    llm = Mock()
    llm.generate.side_effect = RuntimeError("provider unavailable")
    with pytest.raises(LogAnalysisError, match="could not be generated"):
        LogAnalysisAgent(llm).analyze(make_incident())


def test_fabricated_evidence_id_is_rejected():
    llm = Mock()
    llm.generate.return_value = response_json(supporting_evidence_ids=["E-FABRICATED"])
    with pytest.raises(LogAnalysisError, match="not supplied"):
        LogAnalysisAgent(llm).analyze(make_incident())
