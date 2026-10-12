"""Central in-memory repository for CyberOrchestra incidents, executions, and artifacts.

Maintains normalized incidents, execution stages, shared state, recovery plans,
policy decisions, and incident reports. Seeds on startup from raw benchmark scenarios.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

from app.models.incident import Incident
from app.models.incident_report import IncidentReport
from app.models.incident_state import IncidentState
from app.models.policy_decision import PolicyDecision, PolicyDecisionValue
from app.models.recovery_plan import RecoveryPlan
from app.services.normalizer import default_normalizer

logger = logging.getLogger(__name__)


class PolicyReviewRecord:
    """Tracks a policy engine decision and subsequent human analyst action."""

    def __init__(self, decision: PolicyDecision):
        self.decision_id = f"POL-{uuid.uuid4().hex[:8].upper()}"
        self.incident_id = decision.incident_id
        self.action = decision.action
        self.decision = decision.decision  # APPROVED, REQUIRES_APPROVAL, REJECTED
        self.reason = decision.reason
        self.supporting_evidence_ids = decision.supporting_evidence_ids
        self.policy_rule_id = decision.policy_rule_id
        self.human_status: str = "Pending" if decision.decision == PolicyDecisionValue.REQUIRES_APPROVAL else (
            "Approved" if decision.decision == PolicyDecisionValue.APPROVED else "Rejected"
        )
        self.analyst_notes: Optional[str] = None
        self.decided_at: Optional[datetime] = None
        self.created_at: datetime = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.decision_id,
            "incident": self.incident_id,
            "action": self.action,
            "decision": self.decision.value if hasattr(self.decision, "value") else str(self.decision),
            "status": self.human_status,
            "policy_rule_id": self.policy_rule_id,
            "reason": self.reason,
            "supporting_evidence_ids": self.supporting_evidence_ids,
            "analyst_notes": self.analyst_notes,
            "created_at": self.created_at.isoformat(),
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
        }


class IncidentRecord:
    """Wrapper holding an incident, its workflow state, and associated artifacts."""

    def __init__(self, incident: Incident, raw_payload: Optional[Dict[str, Any]] = None):
        self.incident = incident
        self.raw_payload = raw_payload or {}
        self.pipeline_stage: str = "Normalized"
        self.status: str = "New"
        self.created_at: datetime = incident.timestamp or datetime.now(timezone.utc)
        self.updated_at: datetime = datetime.now(timezone.utc)
        self.execution_history: List[Dict[str, Any]] = []
        self.state: Optional[IncidentState] = None
        self.recovery_plan: Optional[RecoveryPlan] = None
        self.policy_reviews: List[PolicyReviewRecord] = []
        self.report: Optional[IncidentReport] = None
        self.last_error: Optional[str] = None

    def update_stage(self, stage: str, status: Optional[str] = None):
        self.pipeline_stage = stage
        if status:
            self.status = status
        self.updated_at = datetime.now(timezone.utc)

    def to_summary_dict(self) -> Dict[str, Any]:
        iocs = [ind.value for ind in self.incident.indicators]
        tags = [ind.indicator_type for ind in self.incident.indicators]
        if self.incident.incident_type:
            tags.append(self.incident.incident_type)

        severity_map = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "informational": "Info",
            "info": "Info",
        }
        raw_sev = (self.incident.severity or "Medium").lower()
        formatted_sev = severity_map.get(raw_sev, "Medium")

        return {
            "id": self.incident.incident_id,
            "title": self.incident.description[:80] + ("..." if len(self.incident.description) > 80 else ""),
            "description": self.incident.description,
            "severity": formatted_sev,
            "status": self.status,
            "assignee": "CyberOrchestra AI",
            "source": self.incident.source,
            "affectedAssets": len(set(iocs)) or 1,
            "createdAt": self.created_at.isoformat(),
            "updatedAt": self.updated_at.isoformat(),
            "pipelineStage": self.pipeline_stage,
            "iocs": iocs[:6],
            "tags": list(dict.fromkeys(tags))[:5],
            "indicatorCount": len(self.incident.indicators),
            "evidenceCount": len(self.incident.evidence),
            "hasRecoveryPlan": self.recovery_plan is not None,
            "hasPolicyReviews": len(self.policy_reviews) > 0,
            "hasReport": self.report is not None,
        }


class IncidentRepository:
    """Thread-safe, stateful in-memory store for CyberOrchestra."""

    def __init__(self):
        self._incidents: Dict[str, IncidentRecord] = {}
        self._activity_log: List[Dict[str, Any]] = []
        self._evaluation_results: Optional[Dict[str, Any]] = None
        self._seed_default_scenarios()

    def _seed_default_scenarios(self):
        """Loads and normalizes the 5 raw scenario files from backend/data/raw/incidents/."""
        possible_dirs = [
            Path(__file__).resolve().parent.parent.parent / "data" / "raw" / "incidents",
            Path("backend/data/raw/incidents"),
            Path("data/raw/incidents"),
        ]
        scenarios_dir = next((d for d in possible_dirs if d.is_dir()), None)
        if not scenarios_dir:
            logger.warning("Scenarios directory not found for repository seeding.")
            return

        for filepath in sorted(scenarios_dir.glob("*.json")):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
                normalized = default_normalizer.normalize(raw_data)
                record = IncidentRecord(normalized, raw_payload=raw_data)
                record.pipeline_stage = "Ingested"
                record.status = "Investigating"
                self._incidents[normalized.incident_id] = record
                self.log_activity(
                    agent="Data Normalizer",
                    action=f"Normalized {len(normalized.indicators)} indicators and {len(normalized.evidence)} evidence items from {filepath.name}",
                    incident_id=normalized.incident_id,
                    severity="System",
                )
            except Exception as err:
                logger.error(f"Failed to load scenario {filepath.name}: {err}")

    def log_activity(
        self,
        agent: str,
        action: str,
        incident_id: Optional[str] = None,
        severity: str = "System",
    ):
        entry = {
            "id": f"al-{uuid.uuid4().hex[:8]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": agent,
            "action": action,
            "incidentId": incident_id,
            "severity": severity,
        }
        self._activity_log.insert(0, entry)
        if len(self._activity_log) > 100:
            self._activity_log = self._activity_log[:100]

    def get_all(self) -> List[IncidentRecord]:
        return list(self._incidents.values())

    def get(self, incident_id: str) -> Optional[IncidentRecord]:
        return self._incidents.get(incident_id)

    def add(self, incident: Incident, raw_payload: Optional[Dict[str, Any]] = None) -> IncidentRecord:
        record = IncidentRecord(incident, raw_payload=raw_payload)
        self._incidents[incident.incident_id] = record
        self.log_activity(
            agent="Data Normalizer",
            action=f"New incident {incident.incident_id} normalized and registered ({len(incident.indicators)} indicators)",
            incident_id=incident.incident_id,
            severity="Info",
        )
        return record

    def get_all_policy_reviews(self) -> List[Dict[str, Any]]:
        reviews = []
        for record in self._incidents.values():
            for review in record.policy_reviews:
                reviews.append(review.to_dict())
        reviews.sort(key=lambda r: r["created_at"], reverse=True)
        return reviews

    def update_policy_review_status(self, decision_id: str, human_status: str, notes: Optional[str] = None) -> bool:
        for record in self._incidents.values():
            for review in record.policy_reviews:
                if review.decision_id == decision_id:
                    review.human_status = human_status
                    review.analyst_notes = notes
                    review.decided_at = datetime.now(timezone.utc)
                    self.log_activity(
                        agent="Human Analyst",
                        action=f"Analyst {human_status.lower()} policy action '{review.action[:50]}' on {review.incident_id}",
                        incident_id=review.incident_id,
                        severity="High" if human_status == "Approved" else "Medium",
                    )
                    return True
        return False

    def get_all_reports(self) -> List[Dict[str, Any]]:
        reports = []
        for record in self._incidents.values():
            if record.report:
                rep = record.report
                reports.append({
                    "id": f"RPT-{record.incident.incident_id}",
                    "incident": record.incident.incident_id,
                    "title": f"Incident Report: {record.incident.description[:60]}",
                    "status": "Final",
                    "analyst": "Report Generation Agent",
                    "generatedAt": record.updated_at.isoformat(),
                    "riskLevel": rep.final_risk_level.value if hasattr(rep.final_risk_level, "value") else str(rep.final_risk_level),
                    "executiveSummary": rep.executive_summary.finding,
                    "findingsCount": len(rep.threat_assessment) + len(rep.malware_findings) + len(rep.log_findings) + len(rep.vulnerability_findings),
                    "recommendationsCount": len(rep.recovery_recommendations),
                    "reportObject": rep.model_dump(mode="json"),
                })
        return reports

    def get_activity_log(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self._activity_log[:limit]

    def set_evaluation_results(self, results: Dict[str, Any]):
        self._evaluation_results = results

    def get_evaluation_results(self) -> Optional[Dict[str, Any]]:
        return self._evaluation_results


incident_repository = IncidentRepository()
