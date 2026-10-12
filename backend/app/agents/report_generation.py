"""Generate an evidence-linked incident report from existing workflow artifacts."""

from typing import List, Optional, Set

from app.core.config import settings
from app.models.incident_report import IncidentReport
from app.models.incident_state import IncidentState
from app.models.policy_decision import PolicyDecision
from app.models.recovery_plan import RecoveryPlan
from app.services.llm_service import LLMService, llm_service


REPORT_GENERATION_SYSTEM_PROMPT = """You are CyberOrchestra's report generation analyst.
Summarize only information present in the supplied shared incident state, recovery plan, and
policy decisions. Do not invent evidence IDs, CVEs, events, findings, or recovery actions. Every
important finding, including the executive summary, must include supporting evidence IDs present
in the input evidence. Clearly label findings as confirmed, inferred, or uncertain. Preserve
recovery recommendations from the supplied recovery plan; do not add, remove, or modify them.
Reproduce every policy decision exactly as supplied, including action, decision, reason,
supporting evidence IDs, and policy_rule_id; do not make new policy decisions. If inputs do not
support a conclusion, express that uncertainty. Return only JSON matching IncidentReport, without
markdown or additional text."""


class ReportGenerationError(Exception):
    """Raised when a report cannot be generated or validated safely."""


class ReportGenerationAgent:
    def __init__(self, llm: Optional[LLMService] = None):
        self.llm = llm or llm_service

    def generate(
        self,
        state: IncidentState,
        recovery_plan: RecoveryPlan,
        policy_decisions: List[PolicyDecision],
    ) -> IncidentReport:
        """Create a report without adding analysis, recommendations, or policy decisions."""
        if recovery_plan.incident_id != state.incident_id:
            raise ReportGenerationError("Recovery plan incident_id did not match shared state.")
        if any(item.incident_id != state.incident_id for item in policy_decisions):
            raise ReportGenerationError("Policy decision incident_id did not match shared state.")

        request = {
            "shared_incident_state": state.model_dump(mode="json"),
            "recovery_plan": recovery_plan.model_dump(mode="json"),
            "policy_decisions": [item.model_dump(mode="json") for item in policy_decisions],
            "required_output_schema": IncidentReport.model_json_schema(),
        }
        try:
            raw = self.llm.generate(
                system_prompt=REPORT_GENERATION_SYSTEM_PROMPT,
                structured_input=request,
                response_model=IncidentReport,
                provider=settings.REPORT_LLM_PROVIDER,
                model=settings.REPORT_LLM_MODEL,
                api_key=settings.REPORT_LLM_API_KEY,
                base_url=settings.REPORT_LLM_BASE_URL,
            )
            report = IncidentReport.model_validate_json(raw)
        except Exception as err:
            raise ReportGenerationError(f"Incident report could not be generated or validated: {err}") from err

        if report.incident_id != state.incident_id:
            raise ReportGenerationError("LLM response incident_id did not match shared state.")
        if report.policy_decisions != policy_decisions:
            raise ReportGenerationError("LLM response changed or omitted supplied policy decisions.")
        if report.recovery_recommendations != recovery_plan.recovery_actions:
            raise ReportGenerationError("LLM response changed or omitted supplied recovery recommendations.")

        allowed_ids: Set[str] = {item.evidence_id for item in state.normalized_incident.evidence}
        cited: Set[str] = set()

        def collect(value):
            if isinstance(value, dict):
                ids = value.get("supporting_evidence_ids", [])
                if isinstance(ids, list):
                    cited.update(item for item in ids if isinstance(item, str))
                for child in value.values():
                    collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)

        collect(report.model_dump(mode="python"))
        cited.update(item.evidence_id for item in report.evidence_summary)
        unknown_ids = cited - allowed_ids
        if unknown_ids:
            raise ReportGenerationError(
                "LLM response cited evidence IDs not present in the incident: " + ", ".join(sorted(unknown_ids))
            )
        if not report.executive_summary.supporting_evidence_ids:
            raise ReportGenerationError("Executive summary must cite supporting evidence.")
        return report


report_generation_agent = ReportGenerationAgent()
