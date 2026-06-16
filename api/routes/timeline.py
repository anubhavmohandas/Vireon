"""
api/routes/timeline.py — GET /api/investigations/{inv_id}/timeline
Owner: Vedika

Returns timeline events. Supports incremental polling via ?since_id=
so the frontend only fetches new events since the last request.
"""

from fastapi import APIRouter, HTTPException
from api.models import TimelineEvent

router = APIRouter(prefix="/api/investigations", tags=["timeline"])


@router.get("/{inv_id}/timeline", response_model=list[TimelineEvent])
async def get_timeline(inv_id: str, since_id: int = 0):
    """
    Returns timeline events for this investigation.
    Pass ?since_id=<last_seen_id> for incremental updates (live polling).

    TODO (Vedika):
      1. Call InvestigationRepo.get_timeline(inv_id, since_id=since_id)
      2. Return events
    """
    raise HTTPException(status_code=501, detail="Not implemented yet")
