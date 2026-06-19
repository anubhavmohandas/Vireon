"""
api/routes/scan.py — POST /api/scan
Starts a new investigation as an asyncio background task.
Returns inv_id immediately so the frontend can start polling /status.
"""

import asyncio
import subprocess
import tempfile

from fastapi import APIRouter, HTTPException
from api.models import ScanRequest, ScanResponse
from db import get_db

router = APIRouter(prefix="/api", tags=["scan"])

# Active tasks — keyed by inv_id so api/main.py can cancel on shutdown
_active_tasks: dict[str, asyncio.Task] = {}


def _clone_if_needed(repo_input: str) -> str:
    """Clone GitHub URL to temp dir, or return local path as-is."""
    if repo_input.startswith("https://") or repo_input.startswith("git@"):
        tmp = tempfile.mkdtemp(prefix="vireon-api-")
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_input, tmp],
            check=True, capture_output=True, timeout=120,
        )
        return tmp
    return repo_input


@router.post("/scan", response_model=ScanResponse)
async def start_scan(body: ScanRequest):
    """
    Start a new Vireon investigation.
    Accepts a GitHub URL or local path. Clones automatically if URL.
    Returns inv_id immediately — frontend polls /status for live progress.
    """
    db = get_db()

    try:
        repo_path = _clone_if_needed(body.repo_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to clone repo: {e}")

    # Create SharedState to get the inv_id, then persist the row
    from memory.shared_state import SharedState
    state = SharedState(repo_path=repo_path, db=db)
    inv_id = state.inv_id
    await db.insert_investigation(inv_id, body.repo_path, body.days)

    async def _task():
        from coordinator.coordinator import Coordinator
        coordinator = Coordinator(repo_path=repo_path, days=body.days, db=db)
        coordinator.state = state  # reuse — inv_id already in DB
        try:
            await coordinator.run()
        except Exception as e:
            await db.update_investigation_status(inv_id, "failed", error=str(e))
        finally:
            _active_tasks.pop(inv_id, None)

    task = asyncio.create_task(_task())
    _active_tasks[inv_id] = task

    return ScanResponse(
        inv_id=inv_id,
        status="running",
        message=f"Investigation {inv_id} started",
    )
