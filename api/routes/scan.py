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
    """Clone a remote URL to a temp dir, or return a local path as-is."""
    url = (repo_input or "").strip()
    if url.startswith("https://") or url.startswith("http://") or url.startswith("git@"):
        tmp = tempfile.mkdtemp(prefix="vireon-api-")
        # "--" terminates option parsing so a hostile URL can't be read as a flag.
        subprocess.run(
            ["git", "clone", "--depth", "1", "--", url, tmp],
            check=True, capture_output=True, timeout=120,
        )
        return tmp
    return repo_input


def _extract_github_repo(repo_input: str) -> str:
    """
    Parse 'owner/repo' from a GitHub URL so the delivery agent can raise
    the PR against the exact repo that was scanned, not whatever is set in .env.

    Handles:
      https://github.com/owner/repo
      https://github.com/owner/repo.git
      git@github.com:owner/repo.git
    Returns "" for local paths (falls back to GITHUB_REPO env var).
    """
    import re
    m = re.match(r"https?://github\.com/([^/]+/[^/\s]+?)(?:\.git)?/?$", repo_input.strip())
    if m:
        return m.group(1)
    m = re.match(r"git@github\.com:([^/]+/[^/\s]+?)(?:\.git)?$", repo_input.strip())
    if m:
        return m.group(1)
    return ""


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

    # Auto-derive target GitHub repo from the submitted URL so the delivery
    # agent raises the PR against the right repo without any manual .env change.
    state.github_repo = _extract_github_repo(body.repo_path)
    if state.github_repo:
        print(f"[scan] Auto-derived GITHUB_REPO={state.github_repo} from submitted URL")

    # Store the original URL so the coordinator/UI shows it instead of the temp clone path.
    state.original_repo_path = body.repo_path

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
