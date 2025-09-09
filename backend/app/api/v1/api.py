"""
API Router Configuration
"""

from fastapi import APIRouter
from app.api.v1.endpoints import upload, vulnerabilities, reports, dashboard, risk_analysis

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(upload.router, prefix="/upload", tags=["upload"])
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(risk_analysis.router, prefix="/risk-analysis", tags=["risk-analysis"])
