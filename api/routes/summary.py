"""
api/routes/summary.py — GET /api/investigations/{inv_id}/summary
Owner: Vedika

Returns the full investigation summary — all agent results, decision log,
confidence evolution, and investigation metadata in one payload.
"""

from fastapi import APIRouter
from api.models import FullSummary
from db import get_db, InvestigationRepo

router = APIRouter(prefix="/api/investigations", tags=["summary"])


@router.get("/{inv_id}/summary", response_model=FullSummary)
async def get_summary(inv_id: str):
    repo = InvestigationRepo(get_db())
    return await repo.get_full_summary(inv_id)
