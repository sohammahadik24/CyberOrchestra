"""Pure deterministic policy evaluation for recovery recommendations.

Modify the rule IDs, thresholds, or term lists below to adjust policy behavior.
The engine only returns decisions; it never executes or authorizes an operation.
"""

from typing import List, Optional, Set

from app.models.incident_state import IncidentState
from app.models.policy_decision import PolicyDecision, PolicyDecisionValue
from app.models.recovery_plan import RecoveryPlan


# Explicit policy controls. Keep rule IDs stable for audit trails.
POLICY_RULES = {
    "PE-001": "Reject actions with missing, unsupported, or unaggregated evidence citations.",
    "PE-002": "Require human approval for destructive or operationally high-risk actions.",
    "PE-003": "Require human approval when severity is high/critical/unknown or confidence is low/unknown.",
    "PE-004": "Approve evidence-supported, lower-risk actions when context meets auto-approval thresholds.",
}
AUTO_APPROVAL_MAX_SEVERITY_RANK = 2  # informational=0, low=1, medium=2
AUTO_APPROVAL_MIN_CONFIDENCE = 0.75
HIGH_RISK_ACTION_TERMS = (
    "wipe", "destroy", "delete", "format", "purge", "erase", "drop database",
    "reimage", "rebuild", "reset credentials", "revoke", "disable", "terminate",
    "shut down", "shutdown", "isolate", "quarantine", "block",
)
HIGH_RISK_IMPACT_TERMS = (
    "irreversible", "data loss", "downtime", "business interruption",
    "service impact", "production impact", "disrupt", "outage",
)
SEVERITY_RANKS = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
    "unknown": 5,
}


def _enum_value(value) -> str:
    return str(getattr(value, "value", value)).lower()


def _overall_severity(state: IncidentState) -> str:
    values = []
    if state.normalized_incident.severity:
        values.append(_enum_value(state.normalized_incident.severity))
    for result in state.results():
        severity = getattr(result, "severity", None)
        if severity is not None:
            values.append(_enum_value(severity))
    if not values:
        return "unknown"
    return max(values, key=lambda value: SEVERITY_RANKS.get(value, SEVERITY_RANKS["unknown"]))


def _overall_confidence(state: IncidentState) -> Optional[float]:
    confidences = [float(result.confidence) for result in state.results() if result.confidence is not None]
    return min(confidences) if confidences else None


def _is_high_risk(action_text: str, risk_text: str) -> bool:
    combined = f"{action_text} {risk_text}".lower()
    return any(term in combined for term in HIGH_RISK_ACTION_TERMS + HIGH_RISK_IMPACT_TERMS)


class PolicyEngine:
    """Evaluate every recovery action independently using fixed local rules."""

    def evaluate(self, recovery_plan: RecoveryPlan, state: IncidentState) -> List[PolicyDecision]:
        if recovery_plan.incident_id != state.incident_id:
            raise ValueError("recovery plan and shared state must have the same incident_id")

        valid_ids: Set[str] = {item.evidence_id for item in state.normalized_incident.evidence}
        aggregated_ids = set(state.aggregated_evidence_ids)
        severity = _overall_severity(state)
        confidence = _overall_confidence(state)
        decisions: List[PolicyDecision] = []

        for proposed in recovery_plan.recovery_actions:
            action_text = proposed.recovery_action.strip()
            cited = list(dict.fromkeys(proposed.supporting_evidence_ids))
            cited_set = set(cited)
            if (
                not cited_set
                or not cited_set.issubset(valid_ids)
                or not cited_set.issubset(aggregated_ids)
                or not proposed.rationale.strip()
                or not proposed.expected_outcome.strip()
            ):
                decision = PolicyDecisionValue.REJECTED
                rule_id = "PE-001"
                reason = "Action lacks complete rationale/outcome or valid evidence citations aggregated in shared state."
            elif _is_high_risk(action_text, " ".join(proposed.risks)):
                decision = PolicyDecisionValue.REQUIRES_APPROVAL
                rule_id = "PE-002"
                reason = "Action or stated impact is high risk; human approval is required before any execution."
            elif (
                SEVERITY_RANKS.get(severity, SEVERITY_RANKS["unknown"]) > AUTO_APPROVAL_MAX_SEVERITY_RANK
                or confidence is None
                or confidence < AUTO_APPROVAL_MIN_CONFIDENCE
            ):
                decision = PolicyDecisionValue.REQUIRES_APPROVAL
                rule_id = "PE-003"
                reason = (
                    f"Incident severity is {severity} and overall assessment confidence is "
                    f"{'unknown' if confidence is None else f'{confidence:.2f}'}; human approval is required."
                )
            else:
                decision = PolicyDecisionValue.APPROVED
                rule_id = "PE-004"
                reason = "Evidence is supported and incident severity/confidence meet the configured auto-approval thresholds."

            decisions.append(PolicyDecision(
                incident_id=state.incident_id,
                action=proposed.recovery_action,
                decision=decision,
                reason=reason,
                supporting_evidence_ids=cited,
                policy_rule_id=rule_id,
            ))
        return decisions


policy_engine = PolicyEngine()
