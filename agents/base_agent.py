"""
agents/base_agent.py — Band SDK base wrapper

All Vireon agents inherit from BandAgent.
Handles:
  - Band WebSocket connection via thenvoi SDK
  - Posting messages to the Band room
  - Lifecycle (connect → run → disconnect)

Each agent overrides `execute()` — the actual SAGE work.
Band connectivity is purely for the hackathon demo layer;
the real logic lives in the SAGE imports inside each agent.
"""

import asyncio
import os
import time
from abc import ABC, abstractmethod
from typing import Optional

from memory.shared_state import SharedState, AgentResult


class BandAgent(ABC):
    """
    Base class for all Vireon agents.

    Subclasses must implement:
        name          — short identifier used in timeline + Band messages
        system_prompt — passed to Band's AnthropicAdapter
        depends_on    — list of agent names this agent needs results from
        execute()     — the actual work; returns AgentResult
    """

    name: str = "base"
    system_prompt: str = "You are a Vireon security agent."
    depends_on: list[str] = []   # declare in subclass, e.g. ["threat", "static"]

    def __init__(self, state: SharedState, agent_id: str, api_key: str):
        self.state = state
        self.agent_id = agent_id
        self.api_key = api_key
        self._band_agent = None
        self._start_ms: float = 0

    # ── Band connection ───────────────────────────────────────────────────────

    async def connect_band(self):
        """
        Connect to Band room via thenvoi SDK.
        If agent_id/api_key are empty (dev mode), skip silently.
        """
        if not self.agent_id or not self.api_key:
            print(f"[{self.name}] Band credentials not set — running in local mode")
            return

        try:
            from thenvoi import Agent
            from thenvoi.adapters import AnthropicAdapter

            adapter = AnthropicAdapter(
                model="claude-sonnet-4-6",
                custom_section=self.system_prompt,
                enable_execution_reporting=True,
            )
            self._band_agent = Agent.create(
                adapter=adapter,
                agent_id=self.agent_id,
                api_key=self.api_key,
                ws_url=os.getenv("BAND_WS_URL", "wss://app.band.ai/api/v1/socket/websocket"),
                rest_url=os.getenv("BAND_REST_URL", "https://app.band.ai/"),
            )
        except ImportError:
            print(f"[{self.name}] thenvoi not installed — running in local mode")
        except Exception as e:
            print(f"[{self.name}] Band connection failed: {e} — continuing in local mode")

    async def post_to_room(self, message: str):
        """Post a message to the Band room (best-effort)."""
        if self._band_agent is None:
            print(f"[{self.name}→Band] {message}")
            return
        try:
            # thenvoi agents post via the adapter's message queue
            # For hackathon: just print; Band UI shows it via websocket
            print(f"[{self.name}→Band] {message}")
        except Exception as e:
            print(f"[{self.name}] Failed to post to Band: {e}")

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def run(self) -> AgentResult:
        """
        Full lifecycle: connect → announce → execute → post result → return.
        Automatically tracks duration_ms and injects depends_on into result.
        """
        await self.connect_band()
        await self.state.add_event(self.name, "started")
        await self.post_to_room(f"🔍 [{self.state.inv_id}] {self.name} agent starting...")

        self._start_ms = time.monotonic() * 1000

        try:
            result = await self.execute()

            # Inject timing + dependency metadata
            result.duration_ms = int(time.monotonic() * 1000 - self._start_ms)
            result.depends_on = list(self.depends_on)

            await self.state.post_result(self.name, result)
            await self.state.add_event(
                self.name, "finished",
                detail=f"{result.verdict} | {len(result.evidence)} items | {result.duration_ms}ms",
                confidence=result.confidence,
            )
            # Auto-record in decision log + confidence evolution
            await self.state.log_decision(
                self.name,
                f"VERDICT_{result.verdict.upper()}",
                reason=str(result.metadata.get("reason", ""))[:120],
            )
            await self.state.record_confidence(self.name, result.confidence)
            await self.post_to_room(
                f"✅ [{self.state.inv_id}] {self.name} finished — verdict: {result.verdict} "
                f"(confidence: {result.confidence:.2f}, {result.duration_ms}ms)\n"
                f"{self._summarize(result)}"
            )
            return result

        except Exception as e:
            await self.state.add_event(self.name, "error", detail=str(e))
            await self.post_to_room(f"❌ [{self.state.inv_id}] {self.name} error: {e}")
            raise

    def _summarize(self, result: AgentResult) -> str:
        """Short human-readable summary of result for Band room."""
        if not result.evidence:
            return "No evidence collected."
        lines = []
        for item in result.evidence[:3]:
            lines.append(f"  • {item}")
        if len(result.evidence) > 3:
            lines.append(f"  … and {len(result.evidence) - 3} more")
        return "\n".join(lines)

    # ── Override in subclass ──────────────────────────────────────────────────

    @abstractmethod
    async def execute(self) -> AgentResult:
        """Do the actual SAGE work. Must return AgentResult."""
        ...
