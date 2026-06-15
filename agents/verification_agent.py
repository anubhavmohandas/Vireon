"""
agents/verification_agent.py — Verification Agent

Security role: QA / Security Verifier
Internally uses: scanner.verifier (standalone, no SAGE dependency)

Responsibilities:
  1. Run existing tests against patched code
  2. Run final Semgrep pass to confirm vulnerability is gone
  3. Compare before/after findings
  4. Report: patch verified ✓ or regression found ✗

This is the closed loop — patch doesn't ship until verification passes.
"""

import os

from agents.base_agent import BandAgent
from memory.shared_state import SharedState, AgentResult


class VerificationAgent(BandAgent):
    name = "verification"
    depends_on = ["remediation", "compliance"]
    system_prompt = (
        "You are Vireon's Verification Agent. "
        "After patches are generated and compliance-approved, you run the test suite "
        "and a final Semgrep scan to confirm: "
        "(1) existing tests still pass, "
        "(2) the vulnerability pattern is no longer detectable in the patched code. "
        "Only report success if both conditions are met."
    )

    async def execute(self) -> AgentResult:
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> AgentResult:
        from scanner.verifier import run_tests, save_test_results, run_verifier, save_verifier_results

        patch_result = self.state.patch_result
        confirmed = self.state.confirmed
        repo_path = self.state.repo_path

        if not patch_result:
            return AgentResult(
                agent=self.name,
                verdict="inconclusive",
                confidence=0.0,
                evidence=[],
                metadata={"reason": "No patch to verify"},
            )

        # Run tests
        test_results = run_tests(patch_result, confirmed, repo_path)
        save_test_results(test_results)
        self.state.test_results = test_results

        # Run verifier
        verify_results = run_verifier(patch_result, confirmed, repo_path)
        save_verifier_results(verify_results)
        self.state.verify_results = verify_results

        # Parse results
        tests_passed = test_results.get("passed", 0) if isinstance(test_results, dict) else 0
        tests_failed = test_results.get("failed", 0) if isinstance(test_results, dict) else 0
        vuln_cleared = verify_results.get("vulnerabilities_cleared", 0) if isinstance(verify_results, dict) else 0
        vuln_remaining = verify_results.get("vulnerabilities_remaining", 0) if isinstance(verify_results, dict) else 0

        overall_pass = tests_failed == 0 and vuln_remaining == 0

        evidence = [
            {"check": "tests_passed", "value": tests_passed},
            {"check": "tests_failed", "value": tests_failed},
            {"check": "vulns_cleared", "value": vuln_cleared},
            {"check": "vulns_remaining", "value": vuln_remaining},
        ]

        confidence = 0.95 if overall_pass else (0.3 if tests_failed > 0 else 0.5)

        return AgentResult(
            agent=self.name,
            verdict="confirmed" if overall_pass else "rejected",
            confidence=confidence,
            evidence=evidence,
            metadata={
                "tests_passed": tests_passed,
                "tests_failed": tests_failed,
                "vulns_cleared": vuln_cleared,
                "vulns_remaining": vuln_remaining,
                "overall": "VERIFIED" if overall_pass else "FAILED",
            },
        )
