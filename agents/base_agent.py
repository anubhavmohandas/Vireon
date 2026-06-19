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

from memory.shared_state import SharedState
from agents.result import AgentResult


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
        Validate Band credentials and mark this agent as Band-connected.

        Vireon agents are task-driven (run once, return result) — they only POST
        messages to Band, never receive them.  Starting the full WebSocket listener
        via agent.run() would block forever, so we skip it.  All communication
        happens via REST in post_to_room().

        Package: band-sdk[anthropic]  (import namespace: `band`, not `thenvoi`)
        """
        if not self.agent_id or not self.api_key:
            print(f"[{self.name}] Band credentials not set — running in local mode")
            return

        room_id = os.getenv("BAND_ROOM_ID", "")
        if not room_id:
            print(f"[{self.name}] BAND_ROOM_ID not set — Band posting disabled")
            return

        try:
            # Verify the SDK is importable (catches missing install early)
            from band import Agent  # noqa: F401
            self._band_agent = True  # sentinel — means "credentials OK, use REST"
            print(f"[{self.name}] Band ready (REST mode) ✓")
        except ImportError:
            print(f"[{self.name}] band-sdk not installed — run: pip install 'band-sdk[anthropic]'")
        except Exception as e:
            print(f"[{self.name}] Band init failed: {e} — continuing in local mode")

    async def _disconnect_band(self):
        """No persistent connection to tear down (REST-only mode)."""
        self._band_agent = None

    async def post_to_room(self, message: str):
        """
        Post a message to the shared Band investigation room via REST API.

        Uses POST /api/v1/agent/chats/{BAND_ROOM_ID}/messages with the agent's
        own API key so messages appear under the correct agent identity in Band.

        Always prints locally too so the terminal log stays complete.
        """
        print(f"[{self.name}→Band] {message}")

        room_id = os.getenv("BAND_ROOM_ID", "")
        if not room_id or not self.api_key or not self._band_agent:
            return  # No room configured or Band not initialised — local mode only

        rest_url = os.getenv("BAND_REST_URL", "https://app.band.ai/").rstrip("/")
        endpoint = f"{rest_url}/api/v1/agent/chats/{room_id}/messages"

        try:
            import asyncio
            import functools
            import requests as _req

            payload = {"text": f"[{self.name}] {message}"}
            headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}

            # Run the blocking requests call off the event loop
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(
                None,
                functools.partial(
                    _req.post, endpoint,
                    json=payload, headers=headers, timeout=10,
                ),
            )
            if resp.status_code not in (200, 201):
                print(f"[{self.name}] Band post returned {resp.status_code}: {resp.text[:100]}")
        except Exception as e:
            print(f"[{self.name}] Band post failed: {e}")

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
            rich = self._rich_detail(result)
            await self.state.add_event(
                self.name, "finished",
                detail=rich,
                confidence=result.confidence,
            )
            # Auto-record in decision log + confidence evolution
            await self.state.log_decision(
                self.name,
                f"VERDICT_{result.verdict.upper()}",
                reason=str(result.metadata.get("reason", ""))[:120],
            )
            await self.state.record_confidence(self.name, result.confidence)

            # Snapshot the running fused value so ConfidenceGraph can plot
            # the fused line rising/falling over the investigation, not just
            # individual agent dots.
            fused = await self.state.fused_confidence()
            await self.state.record_confidence(
                "fused", fused, label=f"after_{self.name}"
            )

            await self.post_to_room(
                f"✅ [{self.state.inv_id}] {self.name} finished — verdict: {result.verdict} "
                f"(confidence: {result.confidence:.2f}, {result.duration_ms}ms)\n"
                f"  {rich}\n"
                f"{self._summarize(result)}"
            )
            return result

        except Exception as e:
            await self.state.add_event(self.name, "error", detail=str(e))
            await self.post_to_room(f"❌ [{self.state.inv_id}] {self.name} error: {e}")
            raise

        finally:
            await self._disconnect_band()

    def _rich_detail(self, result: AgentResult) -> str:
        """
        One-line human-readable summary shown in the timeline.
        Override in subclasses to add agent-specific reasoning.
        Default: verdict + item count + duration.
        """
        return (
            f"{result.verdict} | {len(result.evidence)} items | "
            f"conf={result.confidence:.2f} | {result.duration_ms}ms"
        )

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
