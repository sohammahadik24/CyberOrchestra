"""Tests for shared incident state and its evidence/result validation."""

import pytest

from app.models.incident import Evidence, Incident
from app.models.incident_state import IncidentState
from app.models.log_assessment import LogAssessment, LogFinding, LogSeverity
from app.models.malware_assessment import MalwareAssessment, BehavioralFinding, BehavioralStatus
from app.models.threat_assessment import ThreatAssessment, ThreatClassification, ThreatSeverity
from app.models.vulnerability_assessment import VulnerabilityAssessment, VulnerabilitySeverity
from app.services.incident_state import IncidentStateService


def make_incident():
    return Incident(
        incident_id="INC-STATE-1",
        incident_type="security_event",
        description="Test incident",
        source="test",
        evidence=[
            Evidence(evidence_id="E-1", evidence_type="observation", source="sensor", description="Observed."),
            Evidence(evidence_id="E-2", evidence_type="system_log", source="host", description="Log record."),
        ],
    )


def make_threat(evidence_ids=None, incident_id="INC-STATE-1", uncertainty="Needs review"):
    return ThreatAssessment(
        incident_id=incident_id,
        threat_classification=ThreatClassification.SUSPICIOUS,
        severity=ThreatSeverity.MEDIUM,
        confidence=0.7,
        reasoning="Evidence indicates suspicious activity.",
        supporting_evidence_ids=evidence_ids or [],
        uncertainties=[uncertainty],
    )


def test_create_state_and_add_all_structured_result_types():
    service = IncidentStateService()
    state = service.create(make_incident())
    threat = make_threat(["E-1"])
    malware = MalwareAssessment(
        incident_id="INC-STATE-1", malware_detected=False, confidence=0.3,
        behavioral_findings=[BehavioralFinding(finding="No behavior established", status=BehavioralStatus.SUSPECTED, supporting_evidence_ids=["E-2"])],
        uncertainties=["Sample not available."],
    )
    logs = LogAssessment(
        incident_id="INC-STATE-1", severity=LogSeverity.LOW, confidence=0.5,
        suspicious_events=[LogFinding(finding="Record seen", supporting_evidence_ids=["E-1"])],
        uncertainties=["Limited logs."],
    )
    vuln = VulnerabilityAssessment(
        incident_id="INC-STATE-1", severity=VulnerabilitySeverity.UNKNOWN,
        exploitability_assessment="Unknown", confidence=0.2,
        supporting_evidence_ids=["E-2"], uncertainties=["No CVE data."],
    )
    service.add_threat_detection_result(state, threat)
    service.add_malware_analysis_result(state, malware)
    service.add_log_analysis_result(state, logs)
    service.add_vulnerability_assessment_result(state, vuln)

    assert state.threat_detection_result == threat
    assert state.malware_analysis_result == malware
    assert state.log_analysis_result == logs
    assert state.vulnerability_assessment_result == vuln
    assert state.aggregated_evidence_ids == ["E-1", "E-2"]
    assert state.overall_uncertainties == ["Needs review", "Sample not available.", "Limited logs.", "No CVE data."]


def test_updating_result_replaces_value_and_rebuilds_aggregates():
    state = IncidentStateService().create(make_incident())
    state.add_threat_detection_result(make_threat(["E-1"]))
    newer = make_threat(["E-2"], uncertainty="Additional records needed")
    state.add_threat_detection_result(newer)
    assert state.threat_detection_result == newer
    assert state.aggregated_evidence_ids == ["E-2"]
    assert state.overall_uncertainties == ["Additional records needed"]


def test_result_for_another_incident_is_rejected_without_mutating_state():
    state = IncidentStateService().create(make_incident())
    with pytest.raises(ValueError, match="same incident"):
        state.add_threat_detection_result(make_threat(incident_id="INC-OTHER"))
    assert state.threat_detection_result is None


def test_unsupported_top_level_or_nested_evidence_id_is_rejected():
    state = IncidentState(normalized_incident=make_incident(), incident_id="INC-STATE-1")
    with pytest.raises(ValueError, match="unsupported evidence"):
        state.add_threat_detection_result(make_threat(["E-UNKNOWN"]))

    malware = MalwareAssessment(
        incident_id="INC-STATE-1", malware_detected=False, confidence=0.1,
        behavioral_findings=[BehavioralFinding(finding="Finding", status=BehavioralStatus.OBSERVED, supporting_evidence_ids=["E-UNKNOWN"])],
    )
    with pytest.raises(ValueError, match="unsupported evidence"):
        state.add_malware_analysis_result(malware)


def test_constructor_checks_incident_and_result_consistency():
    with pytest.raises(ValueError, match="normalized incident"):
        IncidentState(incident_id="INC-OTHER", normalized_incident=make_incident())
    with pytest.raises(ValueError, match="same incident"):
        IncidentState(
            incident_id="INC-STATE-1",
            normalized_incident=make_incident(),
            threat_detection_result=make_threat(incident_id="INC-OTHER"),
        )
