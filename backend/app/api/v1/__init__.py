from fastapi import APIRouter
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.evaluation import router as evaluation_router
from app.api.v1.incidents import router as incidents_router
from app.api.v1.intelligence import router as intelligence_router
from app.api.v1.normalize import router as normalize_router
from app.api.v1.policy import router as policy_router
from app.api.v1.reports import router as reports_router
from app.api.v1.system import router as system_router

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(system_router)
api_v1_router.include_router(dashboard_router)
api_v1_router.include_router(incidents_router)
api_v1_router.include_router(normalize_router)
api_v1_router.include_router(intelligence_router)
api_v1_router.include_router(policy_router)
api_v1_router.include_router(reports_router)
api_v1_router.include_router(evaluation_router)

__all__ = ["api_v1_router"]
