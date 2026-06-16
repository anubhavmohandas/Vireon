"""
agents/delivery_agent.py — Delivery Agent

Security role: Delivery Engineer
Internally uses: engine.github_pr (standalone)

Responsibilities:
  1. Create GitHub PR with the verified patch
  2. PR body includes: CVE list, attack vectors, patch explanation, confidence scores
  3. Falls back to output/pr_draft.md if GITHUB_TOKEN not set
  4. Only runs after VerificationAgent confirms

This is the terminal action — visible artifact that judges can check.
Renamed from pr_agent.py to delivery_agent.py for extensibility
(GitLab, Azure DevOps, Bitbucket support can be added here later).
"""

import os

from agents.base_agent import BandAgent
from memory.shared_state import SharedState
from agents.result import AgentResult


class DeliveryAgent(BandAgent):
    name = "pr"
    system_prompt = (
        "You are Vireon's Delivery Agent. "
        "After a patch is verified, you create a GitHub pull request. "
        "The PR must include: a full list of CVEs addressed, the attack vectors patched, "
        "the confidence scores from the investigation, "
        "and a clear explanation of what changed and why. "
        "The PR is the final artifact — make it detailed enough for a human reviewer."
    )

    async def execute(self) -> AgentResult:
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> AgentResult:
        from engine.github_pr import run_github_pr, save_pr_result

        patch_result = self.state.patch_result
        confirmed = self.state.confirmed
        test_results = self.state.test_results
        verify_results = self.state.verify_results
        repo_path = self.state.repo_path
        G = self.state.graph

        if not patch_result:
            return AgentResult(
                agent=self.name,
                verdict="inconclusive",
                confidence=0.0,
                evidence=[],
                metadata={"reason": "No verified patch to submit"},
            )

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

        pr_result = run_github_pr(
            patch_result=patch_result,
            confirmed=confirmed,
            all_cves=all_cves,
            test_results=test_results,
            verify_results=verify_results,
            repo_path=repo_path,
        )
        save_pr_result(pr_result)
        self.state.pr_result = pr_result

        pr_url = pr_result.get("url", "") if isinstance(pr_result, dict) else ""
        pr_number = pr_result.get("number", "") if isinstance(pr_result, dict) else ""
        skipped = pr_result.get("skipped", False) if isinstance(pr_result, dict) else False

        evidence = [{"pr_url": pr_url, "pr_number": pr_number, "skipped": skipped}]
        verdict = "confirmed" if pr_url and not skipped else "inconclusive"
        confidence = 1.0 if pr_url and not skipped else 0.5

        return AgentResult(
            agent=self.name,
            verdict=verdict,
            confidence=confidence,
            evidence=evidence,
            metadata={
                "pr_url": pr_url,
                "pr_number": pr_number,
                "skipped": skipped,
                "cves_addressed": len(all_cves),
            },
        )
