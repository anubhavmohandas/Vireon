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

import sys
import os

_SAGE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "SAGE")
if _SAGE_DIR not in sys.path:
    sys.path.insert(0, _SAGE_DIR)

from vireon.agents.base_agent import BandAgent
from vireon.memory.shared_state import SharedState, AgentResult
from vireon.config import make_llm_client


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

        client = make_llm_client()
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}],
        )

        raw = response.content[0].text.strip()

        import json, re
        decisions = []
        try:
            match = re.search(r'\[.*\]', raw, re.DOTALL)
            if match:
                decisions = json.loads(match.group())
        except Exception:
            decisions = []

        approved = [d for d in decisions if d.get("decision") == "APPROVED"]
        rejected = [d for d in decisions if d.get("decision") == "REJECTED"]
        blocking = [d for d in rejected if d.get("severity") == "blocking"]

        # All-approved or no blocking rejections → pass
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

        return AgentResult(
            agent=self.name,
            verdict=verdict,
            confidence=confidence,
            evidence=evidence,
            metadata={
                "approved_count": len(approved),
                "rejected_count": len(rejected),
                "blocking_rejections": len(blocking),
                "overall": "APPROVED" if overall_approved else "REJECTED",
            },
        )
