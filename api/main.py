"""
api/main.py — Vireon FastAPI application entry point
Owner: Vedika

Run with:
    uvicorn api.main:app --reload --port 8000

All routes are registered here. DB init happens in lifespan.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import scan, investigations, timeline, summary, graph


# ── Active scan tasks (inv_id → asyncio.Task) ─────────────────────────────────
# Vedika: import this dict in scan.py to register/cancel tasks
active_tasks: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: initialise DB.
    Shutdown: cancel any running scan tasks cleanly.

    TODO (Vedika):
      - from db.database import get_db
      - await get_db().init()
    """
    # ── startup ───────────────────────────────────────────────────────────────
    # TODO: await get_db().init()
    print("[Vireon API] Starting up...")

    yield

    # ── shutdown ──────────────────────────────────────────────────────────────
    print("[Vireon API] Shutting down — cancelling active scans...")
    for inv_id, task in active_tasks.items():
        task.cancel()
        print(f"  Cancelled: {inv_id}")


app = FastAPI(
    title="Vireon API",
    description="Autonomous Multi-Agent Security Investigation Platform",
    version="0.1.0",
    lifespan=lifespan,
)

# ── CORS — allow Harsh's frontend dev server ──────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # tighten for production
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Register routers ──────────────────────────────────────────────────────────
app.include_router(scan.router)
app.include_router(investigations.router)
app.include_router(timeline.router)
app.include_router(summary.router)
app.include_router(graph.router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "vireon-api"}
