"""
api/routes/graph.py — GET /api/investigations/{inv_id}/graph
Owner: Vedika

Returns dependency/CVE knowledge graph as {nodes, edges} JSON.
Harsh's frontend uses this to render the interactive graph visualization.
"""

from fastapi import APIRouter
from api.models import GraphData
from db import get_db, InvestigationRepo

router = APIRouter(prefix="/api/investigations", tags=["graph"])


@router.get("/{inv_id}/graph", response_model=GraphData)
async def get_graph(inv_id: str):
    repo = InvestigationRepo(get_db())
    return await repo.get_graph_data(inv_id)


@router.get("/{inv_id}/confidence", response_model=list[dict])
async def get_confidence_evolution(inv_id: str):
    return await get_db().get_confidence_evolution(inv_id)
