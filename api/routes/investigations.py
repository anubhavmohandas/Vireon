"""
api/routes/investigations.py — /api/investigations endpoints
Owner: Vedika

List all investigations + get status of a specific one.
"""

from fastapi import APIRouter, HTTPException
from api.models import InvestigationStatus

router = APIRouter(prefix="/api/investigations", tags=["investigations"])


@router.get("", response_model=list[InvestigationStatus])
async def list_investigations(limit: int = 50):
    """
    List all past and current investigations, most recent first.

    TODO (Vedika):
      1. Call InvestigationRepo.list_all(limit=limit)
      2. Return list
    """
    raise HTTPException(status_code=501, detail="Not implemented yet")


@router.get("/{inv_id}/status", response_model=InvestigationStatus)
async def get_status(inv_id: str):
    """
    Get current status of an investigation.
    Frontend polls this every few seconds while status == "running".

    TODO (Vedika):
      1. Call InvestigationRepo.get_or_404(inv_id)
      2. Return row
    """
    raise HTTPException(status_code=501, detail="Not implemented yet")
