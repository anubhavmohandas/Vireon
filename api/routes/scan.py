"""
api/routes/scan.py — POST /api/scan
Owner: Vedika

Starts a new investigation as a background asyncio task.
Returns inv_id immediately so the frontend can start polling /status.
"""

from fastapi import APIRouter, HTTPException
from api.models import ScanRequest, ScanResponse

router = APIRouter(prefix="/api", tags=["scan"])


@router.post("/scan", response_model=ScanResponse)
async def start_scan(body: ScanRequest):
    """
    Start a new Vireon investigation.

    TODO (Vedika):
      1. Validate that body.repo_path exists on disk
      2. Create investigation row in DB (via InvestigationRepo)
      3. Launch coordinator.run() as asyncio background task
      4. Register task in _active_tasks dict keyed by inv_id
      5. Return inv_id + status="running"
    """
    raise HTTPException(status_code=501, detail="Not implemented yet")
