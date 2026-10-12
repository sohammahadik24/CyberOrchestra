"""Incident reports endpoints."""

from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException, status

from app.services.incident_repository import incident_repository
from app.services.pipeline_orchestrator import pipeline_orchestrator

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    summary="List all generated incident reports",
)
def list_reports() -> List[Dict[str, Any]]:
    return incident_repository.get_all_reports()


@router.get(
    "/{report_id}",
    status_code=status.HTTP_200_OK,
    summary="Get full report details and structured findings",
)
def get_report(report_id: str) -> Dict[str, Any]:
    # Support lookup by report ID (RPT-INC-...) or by raw incident ID
    incident_id = report_id.replace("RPT-", "")
    rec = incident_repository.get(incident_id)
    if not rec or not rec.report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report {report_id} not found.")

    rep = rec.report
    return {
        "id": f"RPT-{rec.incident.incident_id}",
        "incident": rec.incident.incident_id,
        "title": f"Incident Report: {rec.incident.description[:60]}",
        "status": "Final",
        "analyst": "Report Generation Agent",
        "generatedAt": rec.updated_at.isoformat(),
        "riskLevel": rep.final_risk_level.value if hasattr(rep.final_risk_level, "value") else str(rep.final_risk_level),
        "executiveSummary": rep.executive_summary.finding,
        "threatAssessment": [f.model_dump(mode="json") for f in rep.threat_assessment],
        "malwareFindings": [f.model_dump(mode="json") for f in rep.malware_findings],
        "logFindings": [f.model_dump(mode="json") for f in rep.log_findings],
        "vulnerabilityFindings": [f.model_dump(mode="json") for f in rep.vulnerability_findings],
        "recoveryRecommendations": [r.model_dump(mode="json") for r in rep.recovery_recommendations],
        "policyDecisions": [d.model_dump(mode="json") for d in rep.policy_decisions],
        "evidenceSummary": [e.model_dump(mode="json") for e in rep.evidence_summary],
        "uncertainties": rep.uncertainties,
    }


@router.post(
    "/generate/{incident_id}",
    status_code=status.HTTP_200_OK,
    summary="Generate or re-generate an incident report",
)
def generate_report(incident_id: str) -> Dict[str, Any]:
    rec = incident_repository.get(incident_id)
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_id} not found.")

    if not rec.recovery_plan or not rec.state or not rec.policy_reviews:
        # Run pipeline to generate up to report
        pipeline_orchestrator.execute_pipeline(incident_id)
        rec = incident_repository.get(incident_id)

    if not rec or not rec.report:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Report generation failed.")

    return get_report(f"RPT-{incident_id}")
