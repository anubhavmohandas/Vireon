"""
agents/remediation_agent.py — Remediation Agent

Security role: Security Engineer (Fix Generation)
Internally uses: scanner.patcher (standalone, no SAGE dependency)

Responsibilities:
  1. Generate patches for confirmed + upheld vulnerabilities
  2. Produce: patched file, diff, explanation
  3. Support retry if ComplianceAgent rejects the patch

Runs after ChallengerAgent confirms findings are real.
"""

import os

from agents.base_agent import BandAgent
from memory.shared_state import SharedState
from agents.result import AgentResult


class RemediationAgent(BandAgent):
    name = "remediation"
    depends_on = ["exploitability", "challenger"]
    system_prompt = (
        "You are Vireon's Remediation Agent. "
        "You generate security patches for confirmed vulnerabilities. "
        "Each patch must: fix the root cause (not just add a check), "
        "preserve existing functionality, pass existing tests, "
        "and not introduce new security issues. "
        "Produce clean, minimal diffs with clear explanations."
    )

    async def execute(self) -> AgentResult:
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> AgentResult:
        from engine.patcher import run_patcher

        confirmed = self.state.confirmed
        repo_path = self.state.repo_path
        G = self.state.graph

        if not confirmed:
            return AgentResult(
                agent=self.name,
                verdict="rejected",
                confidence=0.0,
                evidence=[],
                metadata={"reason": "No confirmed vulnerabilities to patch"},
            )

        # Get all CVEs from graph for dep bump
        all_cves = []
        if G is not None:
            seen = set()
            for node, data in G.nodes(data=True):
                if node.startswith("cve:"):
                    cve_id = data.get("cve_id", node.replace("cve:", ""))
                    if cve_id not in seen:
                        seen.add(cve_id)
                        all_cves.append({
                            "cve_id": cve_id,
                            "package": data.get("package", ""),
                            "affected_range": data.get("affected_range", ""),
                            "severity": data.get("severity", "UNKNOWN"),
                        })

        self.state.remediation_attempts += 1

        patch_result = run_patcher(confirmed, repo_path, all_cves=all_cves)
        self.state.patch_result = patch_result

        patches = patch_result.get("patches", []) if isinstance(patch_result, dict) else []
        dep_bumps = patch_result.get("dep_bumps", []) if isinstance(patch_result, dict) else []

        evidence = []
        for p in patches[:10]:
            evidence.append({
                "cve_id": p.get("cve_id", "?"),
                "type": "code_patch",
                "file": p.get("patched_file", "?"),
                "has_diff": bool(p.get("diff")),
            })
        for b in dep_bumps[:10]:
            evidence.append({
                "package": b.get("package", "?"),
                "type": "dep_bump",
                "from": b.get("current", "?"),
                "to": b.get("safe_version", "?"),
            })

        confidence = 0.8 if patches else (0.6 if dep_bumps else 0.2)

        return AgentResult(
            agent=self.name,
            verdict="confirmed" if (patches or dep_bumps) else "inconclusive",
            confidence=confidence,
            evidence=evidence,
            metadata={
                "code_patches": len(patches),
                "dep_bumps": len(dep_bumps),
                "attempt": self.state.remediation_attempts,
            },
        )
