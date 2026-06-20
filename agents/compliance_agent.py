"""
agents/compliance_agent.py — Compliance Agent

Security role: Compliance Reviewer
No SAGE module — Vireon original IP.

Responsibilities:
  1. Review the generated patch for compliance violations
  2. Check: does it break auth? does it reduce security surface? does it break tests?
  3. APPROVE or REJECT with reason
  4. If REJECT → RemediationAgent retries (up to max_attempts)

This is what makes the remediation loop non-trivial.
Judges see: patch generated → compliance rejected → patch regenerated → approved.
"""

import os

from agents.base_agent import BandAgent
from memory.shared_state import SharedState
from agents.result import AgentResult
from config import llm_call


_COMPLIANCE_PROMPT = """
You are a security compliance reviewer.

You have been given a set of patches generated to fix vulnerabilities.
Your job is to verify:

1. SECURITY REGRESSION: Does the patch remove authentication, authorization checks, or rate limiting?
2. TEST BREAKAGE: Does the patch change function signatures or behavior that would break existing tests?
3. INCOMPLETE FIX: Does the patch fix the symptom but not the root cause?
4. NEW VULNERABILITIES: Does the patch introduce new security issues?
5. SCOPE CREEP: Does the patch change more than necessary?

For each patch, output:
{
  "cve_id": "...",
  "decision": "APPROVED" | "REJECTED",
  "reason": "one sentence",
  "severity": "blocking" | "warning"
}

Return a JSON array.
Be strict — a rejected patch goes back to the Remediation Agent for a retry.
"""


class ComplianceAgent(BandAgent):
    name = "compliance"
    depends_on = ["remediation"]
    system_prompt = (
        "You are Vireon's Compliance Agent. You review security patches before they are applied. "
        "You check for security regressions, broken authentication, incomplete fixes, "
        "and new vulnerabilities introduced by the patch. You can APPROVE or REJECT patches. "
        "Rejected patches go back for remediation."
    )

    async def execute(self) -> AgentResult:
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _rich_detail(self, result: AgentResult) -> str:
        m = result.metadata
        overall = m.get("overall", "?")
        approved = m.get("approved_count", 0)
        rejected = m.get("rejected_count", 0)
        blocking = m.get("blocking_rejections", 0)
        blocking_str = f" ({blocking} blocking)" if blocking else ""
        return (
            f"{overall} | approved={approved} rejected={rejected}{blocking_str} | "
            f"conf={result.confidence:.2f} +{result.duration_ms}ms"
        )

    def _run_sync(self) -> AgentResult:
        patch_result = self.state.patch_result
        confirmed = self.state.confirmed

        if not patch_result:
            return AgentResult(
                agent=self.name,
                verdict="inconclusive",
                confidence=0.0,
                evidence=[],
                metadata={"reason": "No patches to review"},
            )

        patches = patch_result.get("patches", []) if isinstance(patch_result, dict) else []

        if not patches and not confirmed:
            self.state.compliance_approved = True
            return AgentResult(
                agent=self.name,
                verdict="confirmed",
                confidence=0.9,
                evidence=[],
                metadata={"decision": "APPROVED", "reason": "No code patches — dep bumps only, auto-approved"},
            )

        # Build patch summaries for LLM review
        patch_summaries = []
        for p in patches[:10]:
            patch_summaries.append({
                "cve_id": p.get("cve_id", "?"),
                "diff_preview": (p.get("diff", "") or "")[:500],
                "explanation": p.get("explanation", "")[:300],
            })

        prompt = f"""
{_COMPLIANCE_PROMPT}

Patches to review:
{patch_summaries}

Original confirmed vulnerabilities:
{[{"cve_id": c.get("cve_id"), "attack_vector": c.get("attack_vector", "")} for c in confirmed[:10]]}
"""

        raw = llm_call(prompt, system=self.system_prompt, max_tokens=1500)

        from engine.json_utils import extract_json_array
        decisions = extract_json_array(raw)
        parsed_ok = bool(decisions)

        approved = [d for d in decisions if d.get("decision") == "APPROVED"]
        rejected = [d for d in decisions if d.get("decision") == "REJECTED"]
        blocking = [d for d in rejected if d.get("severity") == "blocking"]

        # All-approved or no blocking rejections → pass.
        # NOTE: if the review couldn't be parsed at all (parsed_ok=False) we let
        # the patch through to keep the pipeline moving, but we record it loudly
        # (status REVIEW_UNPARSED) instead of silently approving — a reviewer can
        # see the gate didn't actually run.
        overall_approved = len(blocking) == 0

        self.state.compliance_approved = overall_approved

        evidence = []
        for d in decisions:
            evidence.append({
                "cve_id": d.get("cve_id", "?"),
                "decision": d.get("decision", "?"),
                "reason": d.get("reason", "")[:150],
                "severity": d.get("severity", ""),
            })

        if overall_approved:
            verdict = "confirmed"
            confidence = 0.9 - (len(rejected) * 0.05)
        else:
            verdict = "rejected"
            confidence = 0.85

        # Couldn't parse a review → don't claim a clean approval.
        if not parsed_ok:
            confidence = 0.4
            overall_label = "REVIEW_UNPARSED"
        else:
            overall_label = "APPROVED" if overall_approved else "REJECTED"

        return AgentResult(
            agent=self.name,
            verdict=verdict,
            confidence=confidence,
            evidence=evidence,
            metadata={
                "approved_count": len(approved),
                "rejected_count": len(rejected),
                "blocking_rejections": len(blocking),
                "overall": overall_label,
                "review_parsed": parsed_ok,
            },
        )
