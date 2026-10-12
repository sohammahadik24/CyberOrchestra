"""Policy reviews and human analyst approval workflow endpoints."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Query, status

from app.services.incident_repository import incident_repository

router = APIRouter(prefix="/policy", tags=["Policy Engine & Reviews"])


class AnalystActionRequest(BaseModel):
    notes: Optional[str] = None


@router.get(
    "/reviews",
    status_code=status.HTTP_200_OK,
    summary="List all policy engine decisions and human approval queue items",
)
def list_policy_reviews(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by review status (Pending, Approved, Rejected)"),
) -> List[Dict[str, Any]]:
    reviews = incident_repository.get_all_policy_reviews()
    if status_filter:
        reviews = [r for r in reviews if r["status"].lower() == status_filter.lower()]
    return reviews


@router.post(
    "/reviews/{decision_id}/approve",
    status_code=status.HTTP_200_OK,
    summary="Record human analyst approval of a flagged action",
)
def approve_policy_review(decision_id: str, request: Optional[AnalystActionRequest] = None) -> Dict[str, Any]:
    notes = request.notes if request else None
    success = incident_repository.update_policy_review_status(decision_id, "Approved", notes)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy decision {decision_id} not found.")

    return {
        "status": "success",
        "decision_id": decision_id,
        "human_status": "Approved",
        "message": "Human approval recorded. Note: recovery action is verified and documented for authorized operations.",
    }


@router.post(
    "/reviews/{decision_id}/reject",
    status_code=status.HTTP_200_OK,
    summary="Record human analyst rejection of a flagged action",
)
def reject_policy_review(decision_id: str, request: Optional[AnalystActionRequest] = None) -> Dict[str, Any]:
    notes = request.notes if request else None
    success = incident_repository.update_policy_review_status(decision_id, "Rejected", notes)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy decision {decision_id} not found.")

    return {
        "status": "success",
        "decision_id": decision_id,
        "human_status": "Rejected",
        "message": "Action rejected by human analyst. Recovery action will not be executed.",
    }
