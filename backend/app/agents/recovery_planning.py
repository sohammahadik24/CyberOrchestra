"""Generate evidence-grounded recovery recommendations for review only."""

from typing import Optional, Set

from app.core.config import settings
from app.models.incident_state import IncidentState
from app.models.recovery_plan import RecoveryPlan
from app.services.llm_service import LLMService, llm_service


RECOVERY_PLANNING_SYSTEM_PROMPT = """You are CyberOrchestra's recovery planning analyst.
Use only facts and evidence contained in the supplied shared incident state. Recommendations
must be evidence-grounded, specific, structured, and auditable. Every proposed recovery action
must cite one or more supporting_evidence_ids present in aggregated_evidence_ids. Do not invent
evidence, evidence IDs, or incident facts. If there is not enough evidence to support an action,
return no action and describe the uncertainty. These are recommendations for authorized human
review only: never execute, authorize, or claim approval of any action. Do not make policy
decisions or propose bypassing policy. Include rationale, priority, expected outcome, and risks
for each action. Return only a JSON object matching the required RecoveryPlan schema, with no
markdown or additional text."""


class RecoveryPlanningError(Exception):
    """Raised when a recovery plan cannot be safely generated or validated."""


class RecoveryPlanningAgent:
    def __init__(self, llm: Optional[LLMService] = None):
        self.llm = llm or llm_service

    def plan(self, state: IncidentState) -> RecoveryPlan:
        """Create recommendations from shared state; performs no action or authorization."""
        request = {
            "shared_incident_state": state.model_dump(mode="json"),
            "required_output_schema": RecoveryPlan.model_json_schema(),
        }
        try:
            raw = self.llm.generate(
                system_prompt=RECOVERY_PLANNING_SYSTEM_PROMPT,
                structured_input=request,
                response_model=RecoveryPlan,
                provider=settings.RECOVERY_LLM_PROVIDER,
                model=settings.RECOVERY_LLM_MODEL,
                api_key=settings.RECOVERY_LLM_API_KEY,
                base_url=settings.RECOVERY_LLM_BASE_URL,
            )
            recovery_plan = RecoveryPlan.model_validate_json(raw)
        except Exception as err:
            raise RecoveryPlanningError(f"Recovery plan could not be generated or validated: {err}") from err

        if recovery_plan.incident_id != state.incident_id:
            raise RecoveryPlanningError("LLM response incident_id did not match the supplied shared state.")
        allowed_ids: Set[str] = set(state.aggregated_evidence_ids)
        for action in recovery_plan.recovery_actions:
            if not action.supporting_evidence_ids:
                raise RecoveryPlanningError("Every recovery action must cite supporting evidence.")
            unknown_ids = set(action.supporting_evidence_ids) - allowed_ids
            if unknown_ids:
                raise RecoveryPlanningError(
                    "LLM response cited evidence IDs that were not aggregated in shared state: "
                    + ", ".join(sorted(unknown_ids))
                )
        return recovery_plan


recovery_planning_agent = RecoveryPlanningAgent()
