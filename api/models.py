"""
api/models.py — Pydantic request/response schemas.
Owner: Vedika

Add/edit schemas here as endpoints are implemented.
"""

from pydantic import BaseModel
from typing import Any, Optional


# ── Request bodies ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    repo_path: str
    days: int = 7


# ── Response schemas ──────────────────────────────────────────────────────────

class ScanResponse(BaseModel):
    inv_id: str
    status: str
    message: str


class InvestigationStatus(BaseModel):
    inv_id: str
    repo_path: str
    status: str          # "running" | "completed" | "aborted" | "failed"
    started_at: str
    completed_at: Optional[str] = None
    fused_confidence: Optional[float] = None
    error: Optional[str] = None


class TimelineEvent(BaseModel):
    id: int
    inv_id: str
    ts: str
    agent: str
    event: str
    detail: Optional[str] = None
    confidence: Optional[float] = None


class AgentResult(BaseModel):
    inv_id: str
    agent: str
    verdict: str
    confidence: float
    evidence: list[dict]
    metadata: dict[str, Any]
    duration_ms: Optional[int] = None
    created_at: str


class DecisionEntry(BaseModel):
    id: int
    inv_id: str
    ts: str
    agent: str
    action: str
    reason: Optional[str] = None
    metadata: dict[str, Any]


class ConfidenceSnapshot(BaseModel):
    id: int
    inv_id: str
    ts: str
    agent: str
    confidence: float
    label: Optional[str] = None


class GraphNode(BaseModel):
    id: str
    type: str       # "cve" | "package" | "file"
    label: str
    severity: Optional[str] = None


class GraphEdge(BaseModel):
    source: str
    target: str
    label: str


class GraphData(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class FullSummary(BaseModel):
    investigation: InvestigationStatus
    agent_results: list[AgentResult]
    decision_log: list[DecisionEntry]
    confidence_evolution: list[ConfidenceSnapshot]
