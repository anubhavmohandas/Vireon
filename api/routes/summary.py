"""
api/routes/summary.py — GET /api/investigations/{inv_id}/summary
Owner: Vedika

Returns the full investigation summary — all agent results, decision log,
confidence evolution, and investigation metadata in one payload.
"""

from fastapi import APIRouter, HTTPException
from api.models import FullSummary

router = APIRouter(prefix="/api/investigations", tags=["summary"])


@router.get("/{inv_id}/summary", response_model=FullSummary)
async def get_summary(inv_id: str):
    """
    Full summary page data — one call for everything the UI needs.

    TODO (Vedika):
      1. Call InvestigationRepo.get_full_summary(inv_id)
      2. Return result
    """
    raise HTTPException(status_code=501, detail="Not implemented yet")
