"""Fixed-label tests for deterministic two-system evaluation."""

from app.evaluation.evaluator import (
    EvaluationCase,
    EvaluationGroundTruth,
    EvaluationRunner,
    ExpectedPolicyDecision,
    MultiAgentPrediction,
)
from app.evaluation.metrics import MetricStatus
from app.models.baseline_assessment import BaselineAssessment, BaselineFinding, BaselineRecommendation
from app.models.incident import Evidence, Incident
from app.models.incident_report import (
    EvidenceSummary, FinalRiskLevel, FindingStatus, IncidentReport, ReportFinding,
)
from app.models.incident_state import IncidentState
from app.models.log_assessment import LogAssessment, LogFinding, LogSeverity
from app.models.malware_assessment import MalwareAssessment
from app.models.policy_decision import PolicyDecision, PolicyDecisionValue
from app.models.recovery_plan import ActionPriority, RecoveryAction, RecoveryPlan
from app.models.threat_assessment import ThreatAssessment, ThreatClassification, ThreatSeverity
from app.models.vulnerability_assessment import VulnerabilityAssessment, VulnerabilitySeverity


def case(incident_id, classification, severity, techniques, cves, recommendation, evidence_id, policy=None):
    incident = Incident(
        incident_id=incident_id, incident_type="simulated", description="Fixed test input.", source="test",
        evidence=[Evidence(evidence_id=evidence_id, evidence_type="observation", source="test", description="Known test evidence.")],
    )
    truth = EvaluationGroundTruth(
        source="fixed unit-test ground truth",
        threat_classification=classification,
        severity=severity,
        malware_detected=False,
        mitre_techniques=techniques,
        related_cves=cves,
        recovery_recommendations=recommendation,
        policy_decisions=policy,
    )
    return EvaluationCase(incident=incident, ground_truth=truth)


def multi_prediction(test_case, *, bad_citation=False):
    incident_id = test_case.incident.incident_id
    evidence_id = test_case.incident.evidence[0].evidence_id
    state = IncidentState(incident_id=incident_id, normalized_incident=test_case.incident)
    state.add_threat_detection_result(ThreatAssessment(
        incident_id=incident_id, threat_classification=ThreatClassification.SUSPICIOUS,
        severity=ThreatSeverity.HIGH, confidence=0.9, reasoning="Test result.",
        mitre_techniques=["T1566.002"], related_cves=["CVE-2026-20002"],
        supporting_evidence_ids=[evidence_id],
    ))
    state.add_malware_analysis_result(MalwareAssessment(
        incident_id=incident_id, malware_detected=False, confidence=0.8,
        supporting_evidence_ids=[evidence_id],
    ))
    state.add_log_analysis_result(LogAssessment(
        incident_id=incident_id, severity=LogSeverity.HIGH, confidence=0.9,
        suspicious_events=[LogFinding(finding="Known event", supporting_evidence_ids=[evidence_id])],
    ))
    state.add_vulnerability_assessment_result(VulnerabilityAssessment(
        incident_id=incident_id, severity=VulnerabilitySeverity.HIGH,
        vulnerabilities=["Known simulated CVE"], related_cves=["CVE-2026-20002"],
        exploitability_assessment="Not assessed", confidence=0.9,
        supporting_evidence_ids=[evidence_id],
    ))
    recovery_action = RecoveryAction(
        recovery_action="Review the recorded event.", action_priority=ActionPriority.LOW,
        rationale="Fixed test rationale.", supporting_evidence_ids=[evidence_id],
        expected_outcome="Confirm the event.", risks=[],
    )
    recovery = RecoveryPlan(incident_id=incident_id, recovery_actions=[recovery_action])
    decision = PolicyDecision(
        incident_id=incident_id, action=recovery_action.recovery_action,
        decision=PolicyDecisionValue.APPROVED, reason="Test rule.",
        supporting_evidence_ids=[evidence_id], policy_rule_id="PE-004",
    )
    decisions = [decision] if test_case.ground_truth.policy_decisions else []
    report = IncidentReport(
        incident_id=incident_id,
        executive_summary=ReportFinding(finding="Known event.", status=FindingStatus.CONFIRMED, supporting_evidence_ids=[evidence_id]),
        threat_assessment=[ReportFinding(finding="Suspicious.", status=FindingStatus.INFERRED, supporting_evidence_ids=[evidence_id])],
        malware_findings=[ReportFinding(finding="No malware confirmed.", status=FindingStatus.CONFIRMED, supporting_evidence_ids=[evidence_id])],
        log_findings=[ReportFinding(finding="Known log event.", status=FindingStatus.CONFIRMED, supporting_evidence_ids=[evidence_id])],
        vulnerability_findings=[ReportFinding(finding="CVE present.", status=FindingStatus.CONFIRMED, supporting_evidence_ids=[evidence_id])],
        recovery_recommendations=[recovery_action], policy_decisions=decisions,
        evidence_summary=[EvidenceSummary(evidence_id=evidence_id, summary="Known test evidence.")],
        uncertainties=[], final_risk_level=FinalRiskLevel.HIGH,
    )
    if bad_citation:
        # Pydantic state prohibits unsupported IDs, so the bad reference is introduced in report.
        report.executive_summary.supporting_evidence_ids.append("E-OTHER-CASE")
    return MultiAgentPrediction(incident_state=state, recovery_plan=recovery, policy_decisions=decisions, report=report)


def baseline_prediction(test_case):
    evidence_id = test_case.incident.evidence[0].evidence_id
    return BaselineAssessment(
        incident_id=test_case.incident.incident_id,
        threat_classification=ThreatClassification.SUSPICIOUS,
        severity=ThreatSeverity.HIGH,
        malware_findings=[],
        log_findings=[BaselineFinding(finding="Technique T1566.002 observed.", supporting_evidence_ids=[evidence_id])],
        vulnerability_findings=[BaselineFinding(finding="CVE-2026-20002 relevant.", supporting_evidence_ids=[evidence_id])],
        recovery_recommendations=[BaselineRecommendation(
            recommendation="Review the recorded event.", rationale="Known evidence.", supporting_evidence_ids=[evidence_id]
        )],
        uncertainties=[], supporting_evidence_ids=[evidence_id],
    )


def test_runner_calculates_known_metrics_for_both_systems_on_same_incidents():
    policy = [ExpectedPolicyDecision(action="Review the recorded event.", decision=PolicyDecisionValue.APPROVED)]
    first = case("INC-EVAL-1", ThreatClassification.SUSPICIOUS, ThreatSeverity.HIGH,
                 ["T1566.002"], ["CVE-2026-20002"], ["Review the recorded event."], "E-1", policy)
    second = case("INC-EVAL-2", ThreatClassification.BENIGN, ThreatSeverity.LOW,
                  [], [], [], "E-2", [])
    multi = {
        first.incident.incident_id: multi_prediction(first),
        second.incident.incident_id: multi_prediction(second),
    }
    baseline = {
        first.incident.incident_id: baseline_prediction(first),
        second.incident.incident_id: baseline_prediction(second),
    }
    result = EvaluationRunner().evaluate([first, second], multi, baseline)
    assert result.multi_agent.metrics["threat_classification_accuracy"].value == 0.5
    assert result.multi_agent.metrics["severity_accuracy"].value == 0.5
    assert result.multi_agent.metrics["precision"].value == 0.5
    assert result.multi_agent.metrics["recall"].value == 1.0
    assert abs(result.multi_agent.metrics["f1_score"].value - (2 / 3)) < 1e-9
    assert result.multi_agent.metrics["mitre_technique_mapping_accuracy"].value == 0.5
    assert result.multi_agent.metrics["cve_relevance_accuracy"].value == 0.5
    assert result.multi_agent.metrics["recovery_recommendation_correctness"].value == 0.5
    assert result.multi_agent.metrics["policy_compliance_rate"].value == 1.0
    assert result.multi_agent.metrics["evidence_grounding_rate"].value == 1.0
    assert result.multi_agent.metrics["report_completeness"].value == 1.0
    assert result.multi_agent.metrics["cross_agent_consistency"].value == 1.0
    assert result.single_llm_baseline.metrics["policy_compliance_rate"].status == MetricStatus.NOT_APPLICABLE
    assert result.single_llm_baseline.metrics["cross_agent_consistency"].status == MetricStatus.NOT_APPLICABLE
    assert result.multi_agent.ground_truth_incident_ids == ["INC-EVAL-1", "INC-EVAL-2"]


def test_missing_invalid_prediction_is_counted_as_missing_not_filled_in():
    test_case = case("INC-MISSING", ThreatClassification.MALICIOUS, ThreatSeverity.HIGH,
                     [], [], [], "E-MISSING")
    result = EvaluationRunner().evaluate([test_case], {"INC-MISSING": {"invalid": True}}, {})
    assert result.multi_agent.invalid_or_missing_prediction_ids == ["INC-MISSING"]
    assert result.multi_agent.metrics["threat_classification_accuracy"].value == 0.0
    assert result.single_llm_baseline.invalid_or_missing_prediction_ids == ["INC-MISSING"]
    assert result.single_llm_baseline.metrics["severity_accuracy"].value == 0.0


def test_ground_truth_is_separate_and_unlabeled_fields_are_not_scored():
    incident = Incident(incident_id="INC-UNLABELED", incident_type="test", description="x", source="unit")
    test_case = EvaluationCase(incident=incident, ground_truth=EvaluationGroundTruth(source="no labels"))
    result = EvaluationRunner().evaluate([test_case], {}, {})
    metric = result.multi_agent.metrics["threat_classification_accuracy"]
    assert metric.value is None
    assert metric.status == MetricStatus.NO_GROUND_TRUTH
    assert result.ground_truth_source_by_incident["INC-UNLABELED"] == "no labels"


def test_grounding_is_measured_per_incident_and_invalid_predictions_are_safe():
    first = case("INC-GROUND-1", ThreatClassification.SUSPICIOUS, ThreatSeverity.HIGH,
                 [], [], [], "E-LOCAL-1")
    second = case("INC-GROUND-2", ThreatClassification.SUSPICIOUS, ThreatSeverity.HIGH,
                  [], [], [], "E-LOCAL-2")
    result = EvaluationRunner().evaluate(
        [first, second],
        {"INC-GROUND-1": multi_prediction(first, bad_citation=True), "INC-GROUND-2": "malformed"},
        {},
    )
    assert result.multi_agent.metrics["evidence_grounding_rate"].value is not None
    assert result.multi_agent.metrics["evidence_grounding_rate"].value < 1.0
    assert result.multi_agent.invalid_or_missing_prediction_ids == ["INC-GROUND-2"]


def test_existing_simulated_incidents_load_without_fabricated_ground_truth():
    cases = EvaluationRunner().load_simulated_cases({})
    assert len(cases) == 5
    assert all(case.ground_truth.source == "ground_truth_not_provided" for case in cases)
    assert all(case.ground_truth.threat_classification is None for case in cases)
