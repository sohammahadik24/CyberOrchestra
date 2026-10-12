"""Evaluation contracts and a deterministic runner for both CyberOrchestra systems."""

import json
import re
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Set, Union

from pydantic import BaseModel, ConfigDict, Field

from app.models.baseline_assessment import BaselineAssessment
from app.models.incident import Incident
from app.models.incident_report import IncidentReport
from app.models.incident_state import IncidentState
from app.models.policy_decision import PolicyDecision, PolicyDecisionValue
from app.models.recovery_plan import RecoveryPlan
from app.models.threat_assessment import ThreatClassification, ThreatSeverity
from app.services.normalizer import DataNormalizer
from app.evaluation.metrics import (
    MetricResult,
    accuracy_metric,
    binary_classification_metrics,
    exact_set_metric,
    not_applicable_metric,
    ratio_metric,
)


class ExpectedPolicyDecision(BaseModel):
    action: str
    decision: PolicyDecisionValue

    model_config = ConfigDict(extra="forbid")


class EvaluationGroundTruth(BaseModel):
    """Explicit dataset labels; absent fields are unlabelled and are not scored."""

    source: str = Field(description="Provenance of these labels, such as a curated dataset manifest")
    threat_classification: Optional[ThreatClassification] = None
    severity: Optional[ThreatSeverity] = None
    malware_detected: Optional[bool] = None
    mitre_techniques: Optional[List[str]] = None
    related_cves: Optional[List[str]] = None
    recovery_recommendations: Optional[List[str]] = None
    policy_decisions: Optional[List[ExpectedPolicyDecision]] = None

    model_config = ConfigDict(extra="forbid")


class EvaluationCase(BaseModel):
    incident: Incident
    ground_truth: EvaluationGroundTruth

    model_config = ConfigDict(extra="forbid")


class MultiAgentPrediction(BaseModel):
    incident_state: IncidentState
    recovery_plan: Optional[RecoveryPlan] = None
    policy_decisions: List[PolicyDecision] = Field(default_factory=list)
    report: Optional[IncidentReport] = None

    model_config = ConfigDict(extra="forbid")


SystemPrediction = Union[MultiAgentPrediction, BaselineAssessment]


class SystemEvaluationResult(BaseModel):
    system_name: str
    metrics: Dict[str, MetricResult]
    ground_truth_incident_ids: List[str]
    invalid_or_missing_prediction_ids: List[str]

    model_config = ConfigDict(extra="forbid")


class EvaluationComparison(BaseModel):
    """Calculated results for two systems evaluated on identical incident IDs."""

    ground_truth_source_by_incident: Dict[str, str]
    multi_agent: SystemEvaluationResult
    single_llm_baseline: SystemEvaluationResult

    model_config = ConfigDict(extra="forbid")


class _NormalizedPrediction(BaseModel):
    threat_classification: Optional[ThreatClassification] = None
    severity: Optional[ThreatSeverity] = None
    malware_detected: Optional[bool] = None
    techniques: Set[str] = Field(default_factory=set)
    cves: Set[str] = Field(default_factory=set)
    recommendations: Set[str] = Field(default_factory=set)
    citations: List[str] = Field(default_factory=list)
    policies: Dict[str, PolicyDecisionValue] = Field(default_factory=dict)
    report_completeness: Optional[tuple[int, int]] = None
    consistency: Optional[tuple[int, int]] = None


_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_TECHNIQUE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def _normalized_text(values: Sequence[str]) -> Set[str]:
    return {" ".join(value.casefold().split()) for value in values if value.strip()}


def _collect_citations(value) -> List[str]:
    citations: List[str] = []
    if isinstance(value, dict):
        ids = value.get("supporting_evidence_ids", [])
        if isinstance(ids, list):
            citations.extend(item for item in ids if isinstance(item, str))
        for child in value.values():
            citations.extend(_collect_citations(child))
    elif isinstance(value, list):
        for child in value:
            citations.extend(_collect_citations(child))
    return citations


def _parse_prediction(value, expected_type):
    if value is None:
        return None
    try:
        if isinstance(value, expected_type):
            return value
        return expected_type.model_validate(value)
    except Exception:
        return None


def _normalize_multi(prediction: MultiAgentPrediction, incident_id: str) -> Optional[_NormalizedPrediction]:
    state = prediction.incident_state
    if state.incident_id != incident_id:
        return None
    related_objects = [prediction.recovery_plan, prediction.report, *prediction.policy_decisions]
    if any(item is not None and item.incident_id != incident_id for item in related_objects):
        return None
    threat = state.threat_detection_result
    malware = state.malware_analysis_result
    techniques: Set[str] = set(threat.mitre_techniques if threat else [])
    cves: Set[str] = set(threat.related_cves if threat else [])
    if state.log_analysis_result:
        for indicator in state.log_analysis_result.attack_indicators:
            if "mitre" in indicator.indicator_type.lower():
                techniques.add(indicator.value)
    vulnerability = state.vulnerability_assessment_result
    if vulnerability:
        cves.update(vulnerability.related_cves)
    recommendations = {
        action.recovery_action
        for action in (prediction.recovery_plan.recovery_actions if prediction.recovery_plan else [])
    }
    policies = {" ".join(item.action.casefold().split()): item.decision for item in prediction.policy_decisions}
    citations: List[str] = []
    citations.extend(_collect_citations(prediction.model_dump(mode="python")))

    report_shape: Optional[tuple[int, int]] = None
    if prediction.report is not None:
        report = prediction.report
        requirements = [
            bool(report.executive_summary.finding.strip()),
            bool(report.threat_assessment) if threat else True,
            bool(report.malware_findings) if malware else True,
            bool(report.log_findings) if state.log_analysis_result else True,
            bool(report.vulnerability_findings) if vulnerability else True,
            bool(report.recovery_recommendations) if recommendations else True,
            bool(report.policy_decisions) if prediction.policy_decisions else True,
            bool(report.evidence_summary) if state.normalized_incident.evidence else True,
            report.final_risk_level.value != "unknown",
        ]
        report_shape = (sum(requirements), len(requirements))
    else:
        report_shape = (0, 9)

    severity_values = [
        item.severity.value for item in (
            threat,
            state.log_analysis_result,
            vulnerability,
        ) if item is not None and hasattr(item, "severity")
    ]
    # Cross-agent checks are explicit contradictions only: IDs agree and malware-positive
    # cannot coexist with an explicitly benign threat classification.
    checks = 1
    passed = 1
    if malware and malware.malware_detected and threat and threat.threat_classification == ThreatClassification.BENIGN:
        passed -= 1
    for left_index in range(len(severity_values)):
        for right_index in range(left_index + 1, len(severity_values)):
            checks += 1
            passed += int(severity_values[left_index] == severity_values[right_index])

    return _NormalizedPrediction(
        threat_classification=threat.threat_classification if threat else None,
        severity=threat.severity if threat else None,
        malware_detected=malware.malware_detected if malware else None,
        techniques=techniques,
        cves=cves,
        recommendations=_normalized_text(list(recommendations)),
        citations=citations,
        policies=policies,
        report_completeness=report_shape,
        consistency=(passed, checks),
    )


def _normalize_baseline(prediction: BaselineAssessment, incident_id: str) -> Optional[_NormalizedPrediction]:
    if prediction.incident_id != incident_id:
        return None
    finding_text = [item.finding for item in (
        prediction.malware_findings + prediction.log_findings + prediction.vulnerability_findings
    )]
    recommendations = [item.recommendation for item in prediction.recovery_recommendations]
    all_text = " ".join(finding_text + recommendations)
    citations = _collect_citations(prediction.model_dump(mode="python"))
    return _NormalizedPrediction(
        threat_classification=prediction.threat_classification,
        severity=prediction.severity,
        malware_detected=bool(prediction.malware_findings),
        techniques={value.upper() for value in _TECHNIQUE_PATTERN.findall(all_text)},
        cves={value.upper() for value in _CVE_PATTERN.findall(all_text)},
        recommendations=_normalized_text(recommendations),
        citations=citations,
        policies={},
        report_completeness=None,
        consistency=None,
    )


def _metric_result(numerator: int, denominator: int, definition: str) -> MetricResult:
    return ratio_metric(numerator, denominator, definition)


class EvaluationRunner:
    """Compare provided multi-agent and baseline predictions on the same labeled cases.

    This runner never invokes either production system. Supply their predictions keyed by
    incident ID and explicit ground-truth cases; missing/invalid prediction payloads score as
    missing predictions rather than generating replacement values.
    """

    def evaluate(
        self,
        cases: Sequence[EvaluationCase],
        multi_agent_predictions: Mapping[str, object],
        baseline_predictions: Mapping[str, object],
    ) -> EvaluationComparison:
        incident_ids = [case.incident.incident_id for case in cases]
        if len(incident_ids) != len(set(incident_ids)):
            raise ValueError("evaluation cases must have unique incident IDs")

        multi = {}
        baseline = {}
        invalid_multi: List[str] = []
        invalid_baseline: List[str] = []
        for incident_id in incident_ids:
            multi_raw = multi_agent_predictions.get(incident_id)
            multi_value = _parse_prediction(multi_raw, MultiAgentPrediction)
            multi_normalized = _normalize_multi(multi_value, incident_id) if multi_value else None
            if multi_normalized is None:
                invalid_multi.append(incident_id)
            multi[incident_id] = multi_normalized

            baseline_raw = baseline_predictions.get(incident_id)
            baseline_value = _parse_prediction(baseline_raw, BaselineAssessment)
            baseline_normalized = _normalize_baseline(baseline_value, incident_id) if baseline_value else None
            if baseline_normalized is None:
                invalid_baseline.append(incident_id)
            baseline[incident_id] = baseline_normalized

        source_map = {case.incident.incident_id: case.ground_truth.source for case in cases}
        return EvaluationComparison(
            ground_truth_source_by_incident=source_map,
            multi_agent=self._evaluate_system("multi_agent", cases, multi, invalid_multi, is_multi=True),
            single_llm_baseline=self._evaluate_system("single_llm_baseline", cases, baseline, invalid_baseline, is_multi=False),
        )

    def load_simulated_cases(
        self,
        ground_truth_by_incident: Mapping[str, EvaluationGroundTruth],
        dataset_directory: Optional[Path] = None,
    ) -> List[EvaluationCase]:
        """Load the repository's synthetic incidents and attach explicitly supplied labels.

        The committed raw scenarios contain telemetry and source severity but no complete
        evaluation-label manifest. Missing labels are represented as unlabelled; none are
        inferred from the scenario text.
        """
        directory = dataset_directory or Path(__file__).resolve().parents[2] / "data" / "raw" / "incidents"
        cases = []
        normalizer = DataNormalizer()
        for path in sorted(directory.glob("*.json")):
            raw = json.loads(path.read_text(encoding="utf-8"))
            incident = normalizer.normalize(raw)
            truth = ground_truth_by_incident.get(incident.incident_id)
            if truth is None:
                truth = EvaluationGroundTruth(source="ground_truth_not_provided")
            cases.append(EvaluationCase(incident=incident, ground_truth=truth))
        return cases

    @staticmethod
    def _evaluate_system(name, cases, predictions, invalid_ids, *, is_multi):
        labeled_classification = [case for case in cases if case.ground_truth.threat_classification is not None]
        labeled_severity = [case for case in cases if case.ground_truth.severity is not None]
        classification_expected = [case.ground_truth.threat_classification for case in labeled_classification]
        classification_predicted = [
            predictions[case.incident.incident_id].threat_classification
            if predictions[case.incident.incident_id] else None for case in labeled_classification
        ]
        severity_expected = [case.ground_truth.severity for case in labeled_severity]
        severity_predicted = [
            predictions[case.incident.incident_id].severity
            if predictions[case.incident.incident_id] else None for case in labeled_severity
        ]
        precision, recall, f1 = binary_classification_metrics(
            [value in {ThreatClassification.SUSPICIOUS, ThreatClassification.MALICIOUS} for value in classification_expected],
            [value in {ThreatClassification.SUSPICIOUS, ThreatClassification.MALICIOUS} if value is not None else None for value in classification_predicted],
        )
        metrics: Dict[str, MetricResult] = {
            "threat_classification_accuracy": accuracy_metric(classification_expected, classification_predicted, "Exact threat-classification matches / labeled incidents"),
            "severity_accuracy": accuracy_metric(severity_expected, severity_predicted, "Exact severity matches / labeled incidents"),
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
        }

        for key, truth_attr, prediction_attr, definition in (
            ("mitre_technique_mapping_accuracy", "mitre_techniques", "techniques", "Per-incident exact-set match rate for MITRE technique IDs"),
            ("cve_relevance_accuracy", "related_cves", "cves", "Per-incident exact-set match rate for relevant CVE IDs"),
            ("recovery_recommendation_correctness", "recovery_recommendations", "recommendations", "Per-incident exact-set match after whitespace/case normalization"),
        ):
            selected = [case for case in cases if getattr(case.ground_truth, truth_attr) is not None]
            truth_sets = [
                _normalized_text(getattr(case.ground_truth, truth_attr)) if truth_attr == "recovery_recommendations"
                else {value.upper() for value in getattr(case.ground_truth, truth_attr)} for case in selected
            ]
            predicted_sets = [predictions[case.incident.incident_id].__getattribute__(prediction_attr) if predictions[case.incident.incident_id] else None for case in selected]
            metrics[key] = exact_set_metric(truth_sets, predicted_sets, definition)

        grounded_citations = total_citations = 0
        for case in cases:
            valid_evidence_ids = {item.evidence_id for item in case.incident.evidence}
            prediction = predictions[case.incident.incident_id]
            if prediction:
                total_citations += len(prediction.citations)
                grounded_citations += sum(1 for citation in prediction.citations if citation in valid_evidence_ids)
        metrics["evidence_grounding_rate"] = ratio_metric(
            grounded_citations, total_citations, "Supplied evidence citations / all evidence citations"
        )

        malware_cases = [case for case in cases if case.ground_truth.malware_detected is not None]
        malware_correct = 0
        for case in malware_cases:
            prediction = predictions[case.incident.incident_id]
            if prediction and prediction.malware_detected is not None and prediction.malware_detected == case.ground_truth.malware_detected:
                malware_correct += 1
        metrics["malware_detection_accuracy"] = ratio_metric(malware_correct, len(malware_cases), "Correct malware-detected labels / incidents with malware ground truth")

        policy_pairs = []
        for case in cases:
            expected = case.ground_truth.policy_decisions
            if expected is not None:
                prediction = predictions[case.incident.incident_id]
                predicted_policies = prediction.policies if prediction else {}
                expected_map = {" ".join(item.action.casefold().split()): item.decision for item in expected}
                for action_key in set(expected_map) | set(predicted_policies):
                    policy_pairs.append(action_key in expected_map and predicted_policies.get(action_key) == expected_map[action_key])
        if not is_multi:
            metrics["policy_compliance_rate"] = not_applicable_metric("Baseline produces no policy-engine decisions by design")
        else:
            metrics["policy_compliance_rate"] = ratio_metric(sum(policy_pairs), len(policy_pairs), "Policy decisions matching explicit dataset action/decision labels")

        if not is_multi:
            metrics["report_completeness"] = not_applicable_metric("Single-LLM baseline does not produce the multi-agent incident report")
            metrics["cross_agent_consistency"] = not_applicable_metric("Single-LLM baseline has no specialized agents to compare")
        else:
            report_total = report_complete = 0
            consistency_total = consistency_passed = 0
            for case in cases:
                prediction = predictions[case.incident.incident_id]
                if prediction and prediction.report_completeness:
                    report_complete += prediction.report_completeness[0]
                    report_total += prediction.report_completeness[1]
                elif not prediction:
                    report_total += 9
                if prediction and prediction.consistency:
                    consistency_passed += prediction.consistency[0]
                    consistency_total += prediction.consistency[1]
            metrics["report_completeness"] = ratio_metric(report_complete, report_total, "Completed required incident-report sections / applicable sections")
            metrics["cross_agent_consistency"] = ratio_metric(consistency_passed, consistency_total, "Consistent cross-agent identity/claim/severity checks / checks")

        labeled_ids = sorted({
            case.incident.incident_id for case in cases
            if any(value is not None for value in case.ground_truth.model_dump(exclude={"source"}).values())
        })
        return SystemEvaluationResult(
            system_name=name,
            metrics=metrics,
            ground_truth_incident_ids=labeled_ids,
            invalid_or_missing_prediction_ids=sorted(invalid_ids),
        )


evaluation_runner = EvaluationRunner()
