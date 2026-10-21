"""
api/routes/investigations.py — /api/investigations endpoints
Owner: Vedika

List all investigations + get status of a specific one.
"""

from fastapi import APIRouter
from api.models import InvestigationStatus
from db import get_db, InvestigationRepo

router = APIRouter(prefix="/api/investigations", tags=["investigations"])


@router.get("", response_model=list[InvestigationStatus])
async def list_investigations(limit: int = 50):
    repo = InvestigationRepo(get_db())
    return await repo.list_all(limit=limit)


@router.get("/{inv_id}/status", response_model=InvestigationStatus)
async def get_status(inv_id: str):
    repo = InvestigationRepo(get_db())
    return await repo.get_or_404(inv_id)
