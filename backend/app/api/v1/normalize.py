"""Normalization API endpoints."""

from typing import Any, Dict
from fastapi import APIRouter, HTTPException, status

from app.models.incident import Incident
from app.services.normalizer import NormalizationError, default_normalizer

router = APIRouter(prefix="/normalize", tags=["Normalization"])


@router.post(
    "",
    response_model=Incident,
    status_code=status.HTTP_200_OK,
    summary="Normalize raw incident telemetry",
    description=(
        "Accepts a heterogeneous raw incident payload, standardizes its schema, "
        "normalizes indicator types, preserves evidence provenance, and returns "
        "a canonical Incident model representation."
    ),
)
def normalize_endpoint(payload: Dict[str, Any]) -> Incident:
    """Normalize raw incident payload into canonical Incident representation.

    Thin endpoint pattern:
    API route -> Data Normalizer service -> Pydantic model -> response
    """
    try:
        normalized = default_normalizer.normalize(payload)
        return normalized
    except NormalizationError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Normalization failed: {err}",
        ) from err
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal error processing normalization: {err}",
        ) from err
