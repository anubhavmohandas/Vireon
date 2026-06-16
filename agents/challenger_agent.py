"""
agents/challenger_agent.py — Challenger Agent (Counter Evidence)

Security role: Red Team Reviewer
No engine module — this is Vireon's original IP.

Responsibilities:
  1. Actively attempt to disprove ExploitabilityAgent's verdict
  2. Look for: sanitization, auth requirements, mitigating controls, unreachable paths
  3. Reduce confidence if mitigating factors found
  4. If it can't disprove → that strengthens the case

Verdict semantics (distinct from other agents):
  "counter_evidence_found"  — Challenger found mitigating factors (≥1 finding dismissed/reduced)
  "no_counter_evidence"     — Challenger tried but couldn't disprove anything (strengthens case)
  "inconclusive"            — Nothing to challenge, or hard failure

Status field in metadata:
  "SUCCESS"             — LLM responded + JSON parsed correctly
  "NO_COUNTER_EVIDENCE" — LLM responded but found nothing to challenge
  "PARSE_ERROR"         — LLM responded but JSON extraction failed
  "API_ERROR"           — LLM call itself failed

This is the "disagreement" that makes Vireon a real war room, not a pipeline.
"""

import json
import re

from agents.base_agent import BandAgent
from agents.result import AgentResult
from config import llm_call


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
                metadata={
                    "status": "NO_COUNTER_EVIDENCE",
                    "reason": "Nothing to challenge — no confirmed vulnerabilities",
                },
            )

        # Build context for LLM challenge
        findings_summary = [
            {
                "cve_id": c.get("cve_id", "?"),
                "reason": c.get("reason", ""),
                "attack_vector": c.get("attack_vector", ""),
                "affected_functions": c.get("affected_functions", []),
                "confidence": c.get("confidence", 0.5),
            }
            for c in confirmed[:10]
        ]

        reachability_summary = {
            k: {"reachable": v.get("reachable", False), "paths": v.get("paths", [])[:2]}
            for k, v in list(reach_results.items())[:10]
        }

        prompt = f"""
{_CHALLENGER_PROMPT}

Confirmed vulnerabilities to challenge:
{findings_summary}

Reachability data:
{reachability_summary}

Repo: {self.state.repo_path}
"""

        # ── LLM call ──────────────────────────────────────────────────────────
        try:
            raw = llm_call(prompt, system=self.system_prompt, max_tokens=2000)
        except Exception as e:
            self.state.challenger_objection = f"API_ERROR: {e}"
            return AgentResult(
                agent=self.name,
                verdict="inconclusive",
                confidence=0.0,
                evidence=[],
                metadata={
                    "status": "API_ERROR",
                    "error": str(e)[:200],
                    "reason": "LLM call failed — pipeline continues with reduced confidence",
                },
            )

        # ── JSON parse ────────────────────────────────────────────────────────
        challenges = []
        parse_error = None
        try:
            match = re.search(r'\[.*\]', raw, re.DOTALL)
            if match:
                challenges = json.loads(match.group())
            else:
                parse_error = "No JSON array found in LLM response"
        except Exception as e:
            parse_error = str(e)[:200]

        if parse_error:
            self.state.challenger_objection = f"PARSE_ERROR: {parse_error}"
            return AgentResult(
                agent=self.name,
                verdict="inconclusive",
                confidence=0.1,
                evidence=[{"raw_response": raw[:500]}],
                metadata={
                    "status": "PARSE_ERROR",
                    "error": parse_error,
                    "reason": "LLM responded but JSON extraction failed — treating as no counter evidence",
                },
            )

        # ── Tally results ─────────────────────────────────────────────────────
        total_adjustment = 0.0
        evidence = []
        dismissed_count = 0
        reductions = []
        upheld = []

        for ch in challenges:
            adj = float(ch.get("confidence_adjustment", 0.0))
            total_adjustment += adj
            challenge_verdict = ch.get("challenge", "UPHELD")

            if challenge_verdict == "DISMISSED":
                dismissed_count += 1
            elif challenge_verdict == "REDUCED":
                reductions.append(ch)
            else:
                upheld.append(ch)

            evidence.append({
                "cve_id": ch.get("cve_id", "?"),
                "challenge": challenge_verdict,
                "adjustment": adj,
                "reason": ch.get("reason", "")[:150],
            })

        # If LLM returned an empty array → no counter evidence found
        if not challenges:
            self.state.challenger_objection = "LLM returned empty challenge list — no counter evidence"
            return AgentResult(
                agent=self.name,
                verdict="no_counter_evidence",
                confidence=0.1,
                evidence=[],
                metadata={
                    "status": "NO_COUNTER_EVIDENCE",
                    "reason": "LLM found no mitigating factors — strengthens the case against",
                    "challenges_raised": 0,
                    "dismissed": 0,
                    "reduced": 0,
                    "upheld": 0,
                    "total_confidence_adjustment": 0.0,
                },
            )

        # Challenger confidence = magnitude of adjustments it made
        challenger_confidence = min(0.9, abs(total_adjustment) + 0.1)

        # ── Verdict: describes what the Challenger found, not whether vuln exists ──
        # "counter_evidence_found" = Challenger successfully reduced/dismissed ≥1 finding
        # "no_counter_evidence"    = Challenger tried, couldn't disprove anything
        if dismissed_count > 0 or reductions:
            verdict = "counter_evidence_found"
            status = "SUCCESS"
        else:
            verdict = "no_counter_evidence"
            status = "SUCCESS"

        objection_parts = [f"⚔️ Challenger reviewed {len(confirmed)} findings."]
        if dismissed_count:
            objection_parts.append(f"DISMISSED {dismissed_count}.")
        if reductions:
            objection_parts.append(f"REDUCED {len(reductions)}.")
        if upheld:
            objection_parts.append(f"UPHELD {len(upheld)} (confirmed real).")
        objection_summary = " ".join(objection_parts)

        self.state.challenger_objection = objection_summary

        return AgentResult(
            agent=self.name,
            verdict=verdict,
            confidence=challenger_confidence,
            evidence=evidence,
            metadata={
                "status": status,
                "challenges_raised": len(challenges),
                "dismissed": dismissed_count,
                "reduced": len(reductions),
                "upheld": len(upheld),
                "total_confidence_adjustment": total_adjustment,
                "objection_summary": objection_summary,
            },
        )
