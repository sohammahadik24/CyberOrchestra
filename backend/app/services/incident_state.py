"""Service helpers for creating and updating shared incident state."""

from app.models.incident import Incident
from app.models.incident_state import IncidentState
from app.models.log_assessment import LogAssessment
from app.models.malware_assessment import MalwareAssessment
from app.models.threat_assessment import ThreatAssessment
from app.models.vulnerability_assessment import VulnerabilityAssessment


class IncidentStateService:
    """Create state from a normalized incident and store validated agent results."""

    def create(self, incident: Incident) -> IncidentState:
        return IncidentState(incident_id=incident.incident_id, normalized_incident=incident)

    def add_threat_detection_result(self, state: IncidentState, result: ThreatAssessment) -> IncidentState:
        return state.add_threat_detection_result(result)

    def add_malware_analysis_result(self, state: IncidentState, result: MalwareAssessment) -> IncidentState:
        return state.add_malware_analysis_result(result)

    def add_log_analysis_result(self, state: IncidentState, result: LogAssessment) -> IncidentState:
        return state.add_log_analysis_result(result)

    def add_vulnerability_assessment_result(self, state: IncidentState, result: VulnerabilityAssessment) -> IncidentState:
        return state.add_vulnerability_assessment_result(result)


incident_state_service = IncidentStateService()
