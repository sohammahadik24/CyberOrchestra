"""Incident management, pipeline execution, and scenario endpoints."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.models.incident import Incident
from app.services.incident_repository import incident_repository
from app.services.normalizer import NormalizationError, default_normalizer
from app.services.pipeline_orchestrator import pipeline_orchestrator

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    summary="List all incidents with optional filtering",
)
def list_incidents(
    severity: Optional[str] = Query(None, description="Filter by severity (Critical, High, Medium, Low, Info)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (New, Investigating, Policy Review, Resolved)"),
    search: Optional[str] = Query(None, description="Search term matching ID or description"),
) -> List[Dict[str, Any]]:
    records = incident_repository.get_all()
    summaries = [rec.to_summary_dict() for rec in records]

    if severity:
        summaries = [s for s in summaries if s["severity"].lower() == severity.lower()]
    if status_filter:
        summaries = [s for s in summaries if s["status"].lower() == status_filter.lower()]
    if search:
        q = search.lower()
        summaries = [
            s for s in summaries
            if q in s["id"].lower() or q in s["title"].lower() or q in s["description"].lower() or any(q in ioc.lower() for ioc in s["iocs"])
        ]

    return summaries


@router.get(
    "/scenarios",
    status_code=status.HTTP_200_OK,
    summary="List available built-in test scenarios",
)
def list_scenarios() -> List[Dict[str, Any]]:
    possible_dirs = [
        Path(__file__).resolve().parent.parent.parent / "data" / "raw" / "incidents",
        Path("backend/data/raw/incidents"),
        Path("data/raw/incidents"),
    ]
    scenarios_dir = next((d for d in possible_dirs if d.is_dir()), None)
    if not scenarios_dir:
        return []

    scenarios = []
    for f in sorted(scenarios_dir.glob("*.json")):
        try:
            with open(f, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            scenarios.append({
                "filename": f.name,
                "incident_id": data.get("incident_id", f.stem),
                "incident_type": data.get("incident_type", "Unknown"),
                "description": data.get("description", ""),
                "severity": data.get("severity", "medium"),
                "source": data.get("source", "simulated"),
                "indicatorsCount": len(data.get("indicators", [])),
                "evidenceCount": len(data.get("evidence", [])),
                "rawData": data,
            })
        except Exception:
            continue

    return scenarios


@router.get(
    "/{incident_id}",
    status_code=status.HTTP_200_OK,
    summary="Get full incident details, pipeline stages, and artifacts",
)
def get_incident(incident_id: str) -> Dict[str, Any]:
    rec = incident_repository.get(incident_id)
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_id} not found.")

    return {
        "summary": rec.to_summary_dict(),
        "incident": rec.incident.model_dump(mode="json"),
        "raw_payload": rec.raw_payload,
        "pipeline_stage": rec.pipeline_stage,
        "status": rec.status,
        "execution_history": rec.execution_history,
        "state": rec.state.model_dump(mode="json") if rec.state else None,
        "recovery_plan": rec.recovery_plan.model_dump(mode="json") if rec.recovery_plan else None,
        "policy_reviews": [p.to_dict() for p in rec.policy_reviews],
        "report": rec.report.model_dump(mode="json") if rec.report else None,
    }


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Ingest and normalize raw incident telemetry",
)
def create_incident(payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        normalized = default_normalizer.normalize(payload)
    except NormalizationError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Normalization failed: {err}") from err
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid incident payload: {err}") from err

    record = incident_repository.add(normalized, raw_payload=payload)
    return record.to_summary_dict()


@router.post(
    "/load-scenario/{scenario_filename}",
    status_code=status.HTTP_201_CREATED,
    summary="Load a built-in scenario into active incidents",
)
def load_scenario(scenario_filename: str) -> Dict[str, Any]:
    possible_dirs = [
        Path(__file__).resolve().parent.parent.parent / "data" / "raw" / "incidents",
        Path("backend/data/raw/incidents"),
        Path("data/raw/incidents"),
    ]
    scenarios_dir = next((d for d in possible_dirs if d.is_dir()), None)
    if not scenarios_dir:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scenarios directory not found.")

    filepath = scenarios_dir / scenario_filename
    if not filepath.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scenario {scenario_filename} not found.")

    try:
        with open(filepath, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        normalized = default_normalizer.normalize(data)
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to load scenario: {err}") from err

    record = incident_repository.add(normalized, raw_payload=data)
    return record.to_summary_dict()


@router.post(
    "/{incident_id}/run-pipeline",
    status_code=status.HTTP_200_OK,
    summary="Execute the complete CyberOrchestra pipeline on an incident",
)
def run_pipeline(incident_id: str) -> Dict[str, Any]:
    rec = incident_repository.get(incident_id)
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_id} not found.")

    try:
        result = pipeline_orchestrator.execute_pipeline(incident_id)
        return result
    except Exception as err:
        rec.update_stage("Error")
        rec.last_error = str(err)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Pipeline execution failed: {err}") from err


@router.post(
    "/{incident_id}/enrich",
    status_code=status.HTTP_200_OK,
    summary="Enrich an incident using configured live threat intelligence feeds",
)
def enrich_incident(incident_id: str) -> Dict[str, Any]:
    rec = incident_repository.get(incident_id)
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_id} not found.")

    result = pipeline_orchestrator.enrich_threat_intelligence(rec.incident)
    incident_repository.log_activity(
        agent="Threat Intelligence",
        action=f"Enriched {incident_id} with {len(result['new_evidence'])} new threat intelligence records",
        incident_id=incident_id,
        severity="Info",
    )
    return result
