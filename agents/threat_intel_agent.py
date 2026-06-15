"""
agents/threat_intel_agent.py — Threat Intelligence Agent

Security role: Threat Researcher
Internally uses: sage.fetcher.*, sage.reachability, sage.synapse.*

Responsibilities:
  1. Detect repo stack (languages, packages, versions)
  2. Fetch CVEs from NVD matching the stack
  3. Build Synapse knowledge graph + attach CVEs
  4. Run reachability analysis
  5. Report: which CVEs are reachable vs. theoretical

This is the widest net — every other agent narrows from here.
"""

import sys
import os

# Ensure SAGE is importable (sibling directory)
_SAGE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "SAGE")
if _SAGE_DIR not in sys.path:
    sys.path.insert(0, _SAGE_DIR)

from vireon.agents.base_agent import BandAgent
from vireon.memory.shared_state import SharedState, AgentResult


class ThreatIntelAgent(BandAgent):
    name = "threat"
    system_prompt = (
        "You are Vireon's Threat Intelligence Agent. "
        "Your job is to identify which CVEs from NVD are relevant to the scanned repository "
        "and determine their reachability within the codebase. "
        "You use NVD data, package dependency analysis, and call-graph reachability. "
        "Report your findings to the team with confidence scores."
    )

    def __init__(self, state: SharedState, agent_id: str, api_key: str, days: int = 7):
        super().__init__(state, agent_id, api_key)
        self.days = days

    async def execute(self) -> AgentResult:
        import asyncio
        # SAGE imports — these are sync; run in executor to not block event loop
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self._run_sync)
        return result

    def _run_sync(self) -> AgentResult:
        from sage.config import cfg
        from sage.fetcher.nvd import fetch_cves_since
        from sage.fetcher.filter import detect_stack, filter_relevant_cves
        from sage.fetcher.store import init_db, save_cves
        from sage.synapse.parser import parse_repo
        from sage.synapse.mapper import attach_cves, seed_libraries
        from sage.synapse.export import export_graph
        from sage.reachability import analyze_reachability, save_reachability

        repo_path = self.state.repo_path
        cfg.set_repo(repo_path)
        init_db()

        # Step 1: Detect stack
        stack = detect_stack(repo_path)
        self.state.stack = stack

        if not stack:
            return AgentResult(
                agent=self.name,
                verdict="inconclusive",
                confidence=0.0,
                evidence=[],
                metadata={"reason": "No dependencies detected in repo"},
            )

        # Step 2: Fetch CVEs
        raw_cves = fetch_cves_since(days=self.days)
        relevant = filter_relevant_cves(raw_cves, stack)
        save_cves(relevant)
        self.state.cves = relevant

        # Step 3: Build knowledge graph
        G = parse_repo(repo_path)
        G = seed_libraries(G, repo_path)
        G = attach_cves(G)

        # Step 4: Reachability
        reach_results = analyze_reachability(G)
        save_reachability(reach_results)
        export_graph(G, repo_path=repo_path, reach_results=reach_results)

        self.state.graph = G
        self.state.reach_results = reach_results

        # Score: ratio of reachable CVEs to total
        reachable = [r for r in reach_results.values() if r.get("reachable")]
        confidence = len(reachable) / max(len(relevant), 1)
        confidence = min(0.95, max(0.1, confidence))

        evidence = [
            {
                "cve_id": c.get("sage_match", {}).get("cve_id", "?"),
                "package": c.get("sage_match", {}).get("package", "?"),
                "severity": c.get("sage_match", {}).get("severity", "?"),
            }
            for c in relevant[:20]
        ]

        verdict = "confirmed" if relevant else "rejected"

        return AgentResult(
            agent=self.name,
            verdict=verdict,
            confidence=confidence,
            evidence=evidence,
            metadata={
                "stack_packages": len(stack),
                "cves_fetched": len(raw_cves),
                "cves_relevant": len(relevant),
                "reachable_cves": len(reachable),
                "graph_nodes": G.number_of_nodes(),
            },
        )
