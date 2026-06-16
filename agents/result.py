"""
agents/result.py — AgentResult data model

Standard result schema returned by every Vireon agent.
Moved here from memory/shared_state.py so the contract lives
next to the agents that produce and consume it.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class AgentResult:
    """Standard result schema — every agent returns this."""
    agent: str
    verdict: str                  # "confirmed" | "rejected" | "inconclusive"
    confidence: float             # 0.0–1.0
    evidence: list[dict]          # raw findings
    metadata: dict[str, Any]      # agent-specific extras (patch path, CVE list, etc.)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    duration_ms: int = 0          # wall-clock time for this agent's execute()
    depends_on: list[str] = field(default_factory=list)  # agent names this result depended on
