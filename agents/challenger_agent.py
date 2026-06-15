"""
agents/challenger_agent.py — Challenger Agent (Counter Evidence)

Security role: Red Team Reviewer
No SAGE module — this is Vireon's original IP.

Responsibilities:
  1. Actively attempt to disprove ExploitabilityAgent's verdict
  2. Look for: sanitization, auth requirements, mitigating controls, unreachable paths
  3. Reduce confidence if mitigating factors found
  4. If it can't disprove → confidence stays high (good signal)

This is the "disagreement" that makes Vireon a real war room, not a pipeline.
Band room will show this as a visible debate between agents.
"""

import sys
import os

_SAGE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "SAGE")
if _SAGE_DIR not in sys.path:
    sys.path.insert(0, _SAGE_DIR)

from agents.base_agent import BandAgent
from memory.shared_state import SharedState, AgentResult
from config import make_llm_client


_CHALLENGER_PROMPT = """
You are a Red Team security reviewer challenging a vulnerability assessment.

You have been given:
- A list of confirmed vulnerabilities from a static analysis + LLM review
- The repo path and reachability data

Your job is to ACTIVELY try to disprove or reduce the severity of these findings.
Look for:
1. Is there input sanitization present in calling functions?
2. Does the vulnerable path require authentication that an external attacker can't bypass?
3. Is the sink actually reachable from external entry points?
4. Are there framework-level protections (ORM, template auto-escaping, etc.)?
5. Is this a false positive from Semgrep's pattern matching?

For each finding, output:
{
  "cve_id": "...",
  "challenge": "UPHELD" | "REDUCED" | "DISMISSED",
  "confidence_adjustment": -0.3 to 0.0,
  "reason": "one sentence"
}

Return a JSON array.
If you cannot find mitigating factors, say so clearly — that strengthens the case.
"""


class ChallengerAgent(BandAgent):
    name = "challenger"
    depends_on = ["exploitability"]
    system_prompt = (
        "You are Vireon's Challenger Agent. You are a red team reviewer whose job is to "
        "DISAGREE with vulnerability assessments and find reasons they might be wrong. "
        "You look for sanitization, authentication controls, unreachable code paths, "
        "and framework-level protections. You are skeptical and precise."
    )

    async def execute(self) -> AgentResult:
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> AgentResult:
        confirmed = self.state.confirmed
        reach_results = self.state.reach_results

        if not confirmed:
            return AgentResult(
                agent=self.name,
                verdict="inconclusive",
                confidence=0.0,
                evidence=[],
                metadata={"reason": "Nothing to challenge — no confirmed vulnerabilities"},
            )

        # Build context for LLM challenge
        findings_summary = []
        for c in confirmed[:10]:  # Limit to avoid token explosion
            findings_summary.append({
                "cve_id": c.get("cve_id", "?"),
                "reason": c.get("reason", ""),
                "attack_vector": c.get("attack_vector", ""),
                "affected_functions": c.get("affected_functions", []),
                "confidence": c.get("confidence", 0.5),
            })

        reachability_summary = {}
        for k, v in list(reach_results.items())[:10]:
            reachability_summary[k] = {
                "reachable": v.get("reachable", False),
                "paths": v.get("paths", [])[:2],
            }

        prompt = f"""
{_CHALLENGER_PROMPT}

Confirmed vulnerabilities to challenge:
{findings_summary}

Reachability data:
{reachability_summary}

Repo: {self.state.repo_path}
"""
        client = make_llm_client()
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        )

        raw = response.content[0].text.strip()
        self.state.challenger_objection = raw

        # Parse JSON response
        import json
        import re
        challenges = []
        try:
            # Extract JSON array from response
            match = re.search(r'\[.*\]', raw, re.DOTALL)
            if match:
                challenges = json.loads(match.group())
        except Exception:
            challenges = []

        # Calculate confidence adjustment
        total_adjustment = 0.0
        evidence = []
        dismissed_count = 0

        for ch in challenges:
            adj = ch.get("confidence_adjustment", 0.0)
            total_adjustment += adj
            verdict = ch.get("challenge", "UPHELD")
            if verdict == "DISMISSED":
                dismissed_count += 1
            evidence.append({
                "cve_id": ch.get("cve_id", "?"),
                "challenge": verdict,
                "adjustment": adj,
                "reason": ch.get("reason", "")[:150],
            })

        # Challenger's own confidence = how strongly it challenged
        challenger_confidence = min(0.9, abs(total_adjustment) + 0.1) if challenges else 0.1

        # Post objection to Band room for drama
        objection_summary = f"⚔️ Challenger reviewed {len(confirmed)} findings. "
        if dismissed_count:
            objection_summary += f"DISMISSED {dismissed_count}. "
        reductions = [c for c in challenges if c.get("challenge") == "REDUCED"]
        if reductions:
            objection_summary += f"REDUCED {len(reductions)}. "
        upheld = [c for c in challenges if c.get("challenge") == "UPHELD"]
        if upheld:
            objection_summary += f"UPHELD {len(upheld)} (confirmed real)."

        # Store for coordinator
        self.state.challenger_objection = objection_summary

        return AgentResult(
            agent=self.name,
            verdict="confirmed" if dismissed_count > 0 else "rejected",
            confidence=challenger_confidence,
            evidence=evidence,
            metadata={
                "challenges_raised": len(challenges),
                "dismissed": dismissed_count,
                "reduced": len(reductions),
                "upheld": len(upheld),
                "total_confidence_adjustment": total_adjustment,
                "objection_summary": objection_summary,
            },
        )
