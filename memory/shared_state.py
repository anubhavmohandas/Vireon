"""
memory/shared_state.py — Vireon shared evidence store

Single source of truth for the investigation. All agents read/write here.
Thread-safe via asyncio.Lock — agents run concurrently.

Timeline events are append-only. Evidence is keyed by agent name.
"""

import asyncio
import random
import string
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from agents.result import AgentResult  # noqa: F401 — re-exported for backward compat


def _generate_inv_id() -> str:
    """Generate a unique investigation ID, e.g. INV-2026-04821"""
    year = datetime.now().year
    suffix = "".join(random.choices(string.digits, k=5))
    return f"INV-{year}-{suffix}"


@dataclass
class TimelineEvent:
    timestamp: str
    agent: str
    event: str        # "started" | "finished" | "objected" | "approved" | "rejected"
    detail: str = ""
    confidence: Optional[float] = None
    inv_id: str = ""


class SharedState:
    """
    Central evidence store for one Vireon investigation run.

    Usage:
        state = SharedState(repo_path="/path/to/repo")
        await state.post_result("threat", result)
        await state.add_event("static", "finished", "3 findings", confidence=0.72)
        results = await state.get_results()
    """

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.inv_id = _generate_inv_id()
        self._lock = asyncio.Lock()

        # Evidence keyed by agent name
        self._results: dict[str, AgentResult] = {}

        # Append-only investigation timeline
        self._timeline: list[TimelineEvent] = []

        # Shared data blobs passed between agents
        self.stack: dict[str, str] = {}             # package → version
        self.cves: list[dict] = []                  # raw CVE entries from NVD
        self.graph = None                           # NetworkX graph from synapse
        self.findings: list[dict] = []              # semgrep findings
        self.confirmed: list[dict] = []             # analyzer-confirmed vulns
        self.reach_results: dict = {}               # reachability analysis
        self.patch_result: dict = {}                # patcher output
        self.test_results: dict = {}                # test runner output
        self.verify_results: dict = {}              # verifier output
        self.pr_result: dict = {}                   # GitHub PR output

        # Challenger/compliance loop state
        self.challenger_objection: Optional[str] = None
        self.compliance_approved: Optional[bool] = None
        self.remediation_attempts: int = 0
        from config import MAX_REMEDIATION_ATTEMPTS
        self.max_remediation_attempts: int = MAX_REMEDIATION_ATTEMPTS

        # Decision log — append-only audit trail of every key decision
        self._decision_log: list[dict] = []

        # Confidence evolution — ordered list of (agent, confidence) snapshots
        # Used for the "confidence rising/falling" demo visualization
        self._confidence_evolution: list[dict] = []

    # ── Results ───────────────────────────────────────────────────────────────

    async def post_result(self, agent: str, result: AgentResult):
        async with self._lock:
            self._results[agent] = result

    async def get_result(self, agent: str) -> Optional[AgentResult]:
        async with self._lock:
            return self._results.get(agent)

    async def get_results(self) -> dict[str, AgentResult]:
        async with self._lock:
            return dict(self._results)

    # ── Timeline ──────────────────────────────────────────────────────────────

    async def add_event(
        self,
        agent: str,
        event: str,
        detail: str = "",
        confidence: Optional[float] = None,
    ):
        async with self._lock:
            ev = TimelineEvent(
                timestamp=datetime.now().strftime("%H:%M:%S"),
                agent=agent,
                event=event,
                detail=detail,
                confidence=confidence,
                inv_id=self.inv_id,
            )
            self._timeline.append(ev)
            conf_str = f" [{confidence:.2f}]" if confidence is not None else ""
            print(f"[{self.inv_id}] [{ev.timestamp}] {agent.upper():22s} {event.upper():12s}{conf_str}  {detail}")

    async def get_timeline(self) -> list[TimelineEvent]:
        async with self._lock:
            return list(self._timeline)

    # ── Decision log ──────────────────────────────────────────────────────────

    async def log_decision(self, agent: str, action: str, reason: str = "", metadata: dict = None):
        """
        Append a structured decision to the audit trail.

        Examples:
            await state.log_decision("compliance", "PATCH_REJECTED", "Authentication check removed")
            await state.log_decision("challenger", "FINDING_DISMISSED", "Input sanitized via ORM")
            await state.log_decision("coordinator", "INVESTIGATION_ABORTED", "Fused confidence too low")
        """
        async with self._lock:
            entry = {
                "timestamp": datetime.now().isoformat(),
                "inv_id": self.inv_id,
                "agent": agent,
                "action": action,
                "reason": reason,
                "metadata": metadata or {},
            }
            self._decision_log.append(entry)
            print(f"[DECISION] {agent.upper():20s} {action:30s}  {reason}")

    async def get_decision_log(self) -> list[dict]:
        async with self._lock:
            return list(self._decision_log)

    # ── Confidence evolution ──────────────────────────────────────────────────

    async def record_confidence(self, agent: str, confidence: float, label: str = ""):
        """
        Record a confidence snapshot for the evolution timeline.
        Call after each agent finishes so the UI can show confidence rising/falling.
        """
        async with self._lock:
            self._confidence_evolution.append({
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "agent": agent,
                "confidence": round(confidence, 3),
                "label": label or agent,
            })

    async def get_confidence_evolution(self) -> list[dict]:
        async with self._lock:
            return list(self._confidence_evolution)

    # ── Confidence fusion ─────────────────────────────────────────────────────

    async def fused_confidence(self) -> float:
        """
        Weighted average across agent confidences.
        Challenger reduces the score (negative weight).
        """
        from config import CHALLENGER_WEIGHT
        weights = {
            "threat":          0.25,
            "static":          0.25,
            "exploitability":  0.35,
            "challenger":      CHALLENGER_WEIGHT,   # tunable via config/env
        }
        async with self._lock:
            total_w = 0.0
            score = 0.0
            for agent, w in weights.items():
                r = self._results.get(agent)
                if r is None:
                    continue
                if w < 0:
                    # Challenger: higher confidence means more doubt → subtract
                    score += w * r.confidence
                else:
                    score += w * r.confidence
                total_w += abs(w)
            if total_w == 0:
                return 0.0
            return max(0.0, min(1.0, score / total_w))

    # ── Summary for Band room / UI ────────────────────────────────────────────

    async def war_room_summary(self) -> str:
        """Human-readable status for posting to Band room."""
        async with self._lock:
            lines = ["── Vireon War Room ──────────────────────"]
            lines.append(f"Investigation: {self.inv_id}")
            lines.append(f"Repo: {self.repo_path}")
            lines.append(f"CVEs found: {len(self.cves)}")
            lines.append(f"Findings:   {len(self.findings)}")
            lines.append(f"Confirmed:  {len(self.confirmed)}")
            lines.append("")
            lines.append("Agent Results:")
            for agent, r in self._results.items():
                conf = f"{r.confidence:.2f}"
                lines.append(f"  {agent:22s} {r.verdict:14s} conf={conf}")
            lines.append("─────────────────────────────────────────")
            return "\n".join(lines)
