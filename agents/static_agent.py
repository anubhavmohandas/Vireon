"""
agents/static_agent.py — Static Analysis Agent

Security role: Code Analyst
Internally uses: scanner.semgrep (standalone, no SAGE dependency)

Responsibilities:
  1. Run Semgrep on the blast radius of CVE-exposed functions
  2. Save raw findings
  3. Report pattern-level evidence (SQL injection, command injection, etc.)

Runs in parallel with ThreatIntelAgent during the evidence-gathering phase.
Requires: state.graph must be populated (ThreatIntelAgent must finish first).
"""

import os

from agents.base_agent import BandAgent
from memory.shared_state import SharedState, AgentResult


class StaticAgent(BandAgent):
    name = "static"
    system_prompt = (
        "You are Vireon's Static Analysis Agent. "
        "You run Semgrep on vulnerable code regions exposed by CVE blast radius analysis. "
        "Your job is to find concrete code-level evidence of vulnerability patterns "
        "(SQL injection, command injection, path traversal, XSS, etc.). "
        "Report findings with file paths, line numbers, and CWE classifications."
    )

    async def execute(self) -> AgentResult:
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> AgentResult:
        from scanner.semgrep import run_semgrep, normalize_findings

        repo_path = self.state.repo_path
        cves = self.state.cves

        findings_raw = run_semgrep(repo_path, cves=cves)
        findings = normalize_findings(findings_raw)
        self.state.findings = findings

        if not findings:
            return AgentResult(
                agent=self.name,
                verdict="rejected",
                confidence=0.85,  # High confidence that nothing was found
                evidence=[],
                metadata={"semgrep_rules_run": True, "findings_count": 0},
            )

        # Build evidence list
        evidence = []
        for f in findings[:20]:
            evidence.append({
                "file": f.get("path", "?"),
                "line": f.get("start", {}).get("line", "?"),
                "rule": f.get("check_id", "?"),
                "message": f.get("extra", {}).get("message", "")[:120],
            })

        # Confidence: more findings → more confident something is wrong
        confidence = min(0.9, 0.4 + len(findings) * 0.05)

        return AgentResult(
            agent=self.name,
            verdict="confirmed",
            confidence=confidence,
            evidence=evidence,
            metadata={
                "findings_count": len(findings),
                "unique_files": len({f.get("path") for f in findings}),
            },
        )
