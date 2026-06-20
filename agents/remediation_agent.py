"""
agents/remediation_agent.py — Remediation Agent

Security role: Security Engineer (Fix Generation)
Internally uses: engine.patcher (standalone, no SAGE dependency)

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

    def _rich_detail(self, result: AgentResult) -> str:
        m = result.metadata
        patches = m.get("code_patches", 0)
        bumps = m.get("dep_bumps", 0)
        attempt = m.get("attempt", 1)
        return (
            f"attempt {attempt} | code patches={patches} dep bumps={bumps} | "
            f"conf={result.confidence:.2f} +{result.duration_ms}ms"
        )

    def _run_sync(self) -> AgentResult:
        from engine.patcher import run_patcher
        from engine.graph import cves_from_graph

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
        # Graph nodes are keyed by raw CVE ID (e.g. "CVE-2024-1234"), not "cve:..."
        # NOTE: carry fixed_version / installed_version through. OSV already
        # resolved the exact version that fixes each CVE; dropping it here forced
        # the patcher to fall back to "latest" for every bump.
        all_cves = cves_from_graph(G)

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
