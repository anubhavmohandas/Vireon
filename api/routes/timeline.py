"""
api/routes/timeline.py — GET /api/investigations/{inv_id}/timeline
Owner: Vedika

Returns timeline events. Supports incremental polling via ?since_id=
so the frontend only fetches new events since the last request.
"""

from fastapi import APIRouter
from api.models import TimelineEvent
from db import get_db, InvestigationRepo

router = APIRouter(prefix="/api/investigations", tags=["timeline"])


@router.get("/{inv_id}/timeline", response_model=list[TimelineEvent])
async def get_timeline(inv_id: str, since_id: int = 0):
    repo = InvestigationRepo(get_db())
    return await repo.get_timeline(inv_id, since_id=since_id)
