"""Shared, validated state for analysis results belonging to one incident."""

from typing import List, Optional, Set, Type

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.incident import Incident
from app.models.log_assessment import LogAssessment
from app.models.malware_assessment import MalwareAssessment
from app.models.threat_assessment import ThreatAssessment
from app.models.vulnerability_assessment import VulnerabilityAssessment


AgentResult = ThreatAssessment | MalwareAssessment | LogAssessment | VulnerabilityAssessment


def result_evidence_ids(result: AgentResult) -> Set[str]:
    """Collect evidence citations from top-level and nested result findings."""
    ids: Set[str] = set()

    def visit(value):
        if isinstance(value, dict):
            citations = value.get("supporting_evidence_ids", [])
            if isinstance(citations, list):
                ids.update(item for item in citations if isinstance(item, str))
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(result.model_dump(mode="python"))
    return ids


class IncidentState(BaseModel):
    """Normalized incident plus unchanged structured outputs from analysis agents."""

    incident_id: str
    normalized_incident: Incident
    threat_detection_result: Optional[ThreatAssessment] = None
    malware_analysis_result: Optional[MalwareAssessment] = None
    log_analysis_result: Optional[LogAssessment] = None
    vulnerability_assessment_result: Optional[VulnerabilityAssessment] = None
    aggregated_evidence_ids: List[str] = Field(default_factory=list)
    overall_uncertainties: List[str] = Field(default_factory=list)

    model_config = ConfigDict(validate_assignment=True)

    @model_validator(mode="after")
    def validate_state_consistency(self):
        if self.incident_id != self.normalized_incident.incident_id:
            raise ValueError("normalized incident incident_id must match shared state")
        allowed = {item.evidence_id for item in self.normalized_incident.evidence}
        all_ids: Set[str] = set()
        uncertainties: List[str] = []
        for result in self.results():
            if result.incident_id != self.incident_id:
                raise ValueError("all agent results must have the same incident_id as shared state")
            cited = result_evidence_ids(result)
            unsupported = cited - allowed
            if unsupported:
                raise ValueError("agent result cites unsupported evidence IDs: " + ", ".join(sorted(unsupported)))
            all_ids.update(cited)
            uncertainties.extend(result.uncertainties)
        object.__setattr__(self, "aggregated_evidence_ids", sorted(all_ids))
        object.__setattr__(self, "overall_uncertainties", list(dict.fromkeys(uncertainties)))
        return self

    def results(self) -> List[AgentResult]:
        return [
            item for item in (
                self.threat_detection_result,
                self.malware_analysis_result,
                self.log_analysis_result,
                self.vulnerability_assessment_result,
            ) if item is not None
        ]

    def add_or_update_result(self, field_name: str, result: AgentResult) -> "IncidentState":
        expected: dict[str, Type[BaseModel]] = {
            "threat_detection_result": ThreatAssessment,
            "malware_analysis_result": MalwareAssessment,
            "log_analysis_result": LogAssessment,
            "vulnerability_assessment_result": VulnerabilityAssessment,
        }
        if field_name not in expected:
            raise ValueError(f"unsupported result field: {field_name}")
        if not isinstance(result, expected[field_name]):
            raise TypeError(f"{field_name} requires {expected[field_name].__name__}")
        if result.incident_id != self.incident_id:
            raise ValueError("all agent results must have the same incident_id as shared state")
        allowed = {item.evidence_id for item in self.normalized_incident.evidence}
        unsupported = result_evidence_ids(result) - allowed
        if unsupported:
            raise ValueError("agent result cites unsupported evidence IDs: " + ", ".join(sorted(unsupported)))

        # Build a fully validated replacement so failures leave the current state untouched.
        values = self.model_dump()
        values[field_name] = result
        values["aggregated_evidence_ids"] = []
        values["overall_uncertainties"] = []
        replacement = type(self).model_validate(values)
        for name in self.__class__.model_fields:
            setattr(self, name, getattr(replacement, name))
        return self

    def add_threat_detection_result(self, result: ThreatAssessment) -> "IncidentState":
        return self.add_or_update_result("threat_detection_result", result)

    def add_malware_analysis_result(self, result: MalwareAssessment) -> "IncidentState":
        return self.add_or_update_result("malware_analysis_result", result)

    def add_log_analysis_result(self, result: LogAssessment) -> "IncidentState":
        return self.add_or_update_result("log_analysis_result", result)

    def add_vulnerability_assessment_result(self, result: VulnerabilityAssessment) -> "IncidentState":
        return self.add_or_update_result("vulnerability_assessment_result", result)
