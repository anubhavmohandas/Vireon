"""
agents/threat_intel_agent.py — Threat Intelligence Agent

Security role: Threat Researcher
Internally uses: engine.stack, engine.osv, engine.nvd, engine.graph (standalone)

Responsibilities:
  1. Detect repo stack (languages, packages, versions)
  2. Fetch CVEs from NVD matching the stack
  3. Build Synapse knowledge graph + attach CVEs
  4. Run reachability analysis
  5. Report: which CVEs are reachable vs. theoretical

This is the widest net — every other agent narrows from here.
"""

import os

from agents.base_agent import BandAgent
from memory.shared_state import SharedState
from agents.result import AgentResult


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
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self._run_sync)
        return result

    def _rich_detail(self, result: AgentResult) -> str:
        m = result.metadata
        return (
            f"stack={m.get('stack_packages', '?')} pkgs | "
            f"CVEs fetched={m.get('cves_fetched', '?')} "
            f"(OSV={m.get('osv_cves', '?')} NVD={m.get('nvd_cves', '?')}) | "
            f"reachable={m.get('reachable_cves', '?')} | "
            f"conf={result.confidence:.2f} +{result.duration_ms}ms"
        )

    def _run_sync(self) -> AgentResult:
        from engine.stack import detect_stack
        from engine.osv import fetch_osv_for_stack
        from engine.nvd import fetch_nvd_for_stack
        from engine.graph import build_graph

        repo_path = self.state.repo_path

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

        # Step 2: Fetch CVEs — OSV first (reliable), NVD as supplement
        osv_cves = fetch_osv_for_stack(stack)
        nvd_cves = fetch_nvd_for_stack(stack, days=self.days)

        # Merge, deduplicate by CVE ID
        seen_ids = set()
        relevant = []
        for cve in osv_cves + nvd_cves:
            cve_id = cve.get("sage_match", {}).get("cve_id", "")
            if cve_id not in seen_ids:
                seen_ids.add(cve_id)
                relevant.append(cve)

        self.state.cves = relevant

        # Step 3: Build lightweight dependency graph
        G = build_graph(repo_path, stack, relevant)
        self.state.graph = G

        # Step 4: Reachability — combine attack_vector with graph connectivity.
        # A CVE is reachable only if:
        #   (a) its attack_vector is NETWORK or ADJACENT (not LOCAL / PHYSICAL / UNKNOWN), AND
        #   (b) the vulnerable package is actually present in the dependency graph
        #       (reachable from the "repo" root via BFS).
        #
        # Using the graph avoids inflating reachability for packages that appear
        # in the NVD/OSV response but are not in this repo's actual dependency tree.
        try:
            import networkx as nx
            _graph_available = True
        except ImportError:
            _graph_available = False

        def _in_graph(pkg: str) -> bool:
            """Return True if pkg node exists and is connected to 'repo'."""
            if not _graph_available or G is None:
                return True  # can't prove absence — assume present
            if pkg not in G:
                return False
            if "repo" not in G:
                return pkg in G  # no repo node — just check existence
            try:
                return nx.has_path(G.to_undirected(), "repo", pkg)
            except (nx.NetworkXError, nx.exception.NodeNotFound):
                return pkg in G

        NETWORK_VECTORS = {"NETWORK", "ADJACENT"}

        reach_dict = {}
        for cve in relevant:
            m = cve.get("sage_match", {})
            cve_id = m.get("cve_id", "")
            pkg = m.get("package", "")
            av = m.get("attack_vector", "UNKNOWN")
            vector_reachable = av in NETWORK_VECTORS
            graph_reachable = _in_graph(pkg)
            reachable = vector_reachable and graph_reachable
            reach_dict[cve_id] = {
                "cve_id":           cve_id,
                "package":          pkg,
                "reachable":        reachable,
                "attack_vector":    av,
                "in_dep_graph":     graph_reachable,
                "paths": [{"entry": "external", "path": ["external", pkg], "depth": 1}] if reachable else [],
            }
        self.state.reach_results = reach_dict

        reachable = [r for r in reach_dict.values() if r.get("reachable")]
        confidence = min(0.95, max(0.1, len(reachable) / max(len(relevant), 1)))

        evidence = [
            {
                "cve_id":   c.get("sage_match", {}).get("cve_id", "?"),
                "package":  c.get("sage_match", {}).get("package", "?"),
                "severity": c.get("sage_match", {}).get("severity", "?"),
                "source":   c.get("sage_match", {}).get("source", "NVD"),
            }
            for c in relevant[:20]
        ]

        return AgentResult(
            agent=self.name,
            verdict="confirmed" if relevant else "rejected",
            confidence=confidence,
            evidence=evidence,
            metadata={
                "stack_packages":  len(stack),
                "osv_cves":        len(osv_cves),
                "nvd_cves":        len(nvd_cves),
                "cves_fetched":    len(osv_cves) + len(nvd_cves),
                "cves_relevant":   len(relevant),
                "reachable_cves":  len(reachable),
                "graph_nodes":     G.number_of_nodes() if G else 0,
            },
        )
