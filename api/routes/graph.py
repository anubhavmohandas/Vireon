"""
api/routes/graph.py — GET /api/investigations/{inv_id}/graph
Owner: Vedika

Returns dependency/CVE knowledge graph as {nodes, edges} JSON.
Harsh's frontend uses this to render the interactive graph visualization.
"""

from fastapi import APIRouter, HTTPException
from api.models import GraphData

router = APIRouter(prefix="/api/investigations", tags=["graph"])


@router.get("/{inv_id}/graph", response_model=GraphData)
async def get_graph(inv_id: str):
    """
    Returns graph as {nodes: [...], edges: [...]} — ready for D3/vis.js/Cytoscape.

    TODO (Vedika):
      1. Call InvestigationRepo.get_graph_data(inv_id)
      2. Return result
    """
    raise HTTPException(status_code=501, detail="Not implemented yet")


@router.get("/{inv_id}/confidence", response_model=list[dict])
async def get_confidence_evolution(inv_id: str):
    """
    Returns confidence snapshots in order — used by Harsh's confidence timeline graph.

    TODO (Vedika):
      1. Call db.get_confidence_evolution(inv_id)
      2. Return list
    """
    raise HTTPException(status_code=501, detail="Not implemented yet")
