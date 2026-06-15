"""
coordinator/coordinator.py — Vireon War Room Coordinator

Orchestrates the full investigation:

Phase 1 — Parallel Evidence Gathering:
  ThreatIntelAgent + StaticAgent run concurrently
  (ThreatIntelAgent must complete before StaticAgent can use the graph)

Phase 2 — Exploitability Review:
  ExploitabilityAgent confirms which findings are real

Phase 3 — Debate:
  ChallengerAgent tries to disprove the findings
  Confidence fusion calculates final risk score

Phase 4 — Remediation Loop (up to max_attempts):
  RemediationAgent generates patch
  ComplianceAgent reviews it
  If REJECTED → RemediationAgent retries

Phase 5 — Verification + Delivery:
  VerificationAgent runs tests + final Semgrep
  PRAgent creates GitHub PR

The coordinator posts live updates to the Band room throughout.
"""

import asyncio
from datetime import datetime

from memory.shared_state import SharedState
from agents.threat_intel_agent import ThreatIntelAgent
from agents.static_agent import StaticAgent
from agents.exploitability_agent import ExploitabilityAgent
from agents.challenger_agent import ChallengerAgent
from agents.remediation_agent import RemediationAgent
from agents.compliance_agent import ComplianceAgent
from agents.verification_agent import VerificationAgent
from agents.pr_agent import PRAgent
from config import vcfg
from coordinator.summary import generate_summary


class Coordinator:
    """
    Vireon War Room Coordinator.

    Usage:
        coordinator = Coordinator(repo_path="/path/to/repo", days=7)
        await coordinator.run()
    """

    def __init__(self, repo_path: str, days: int = 7):
        self.repo_path = repo_path
        self.days = days
        self.state = SharedState(repo_path=repo_path)
        self.start_time = None

    def _make_agent(self, cls, id_key: str, key_key: str, **kwargs):
        agent_id = getattr(vcfg, id_key, "")
        api_key = getattr(vcfg, key_key, "")
        return cls(self.state, agent_id, api_key, **kwargs)

    async def run(self):
        self.start_time = datetime.now()
        state = self.state

        print("\n" + "═" * 60)
        print("  VIREON — Autonomous Security Investigation Platform")
        print(f"  Investigation: {state.inv_id}")
        print(f"  Repo:          {self.repo_path}")
        print(f"  Started:       {self.start_time.strftime('%H:%M:%S')}")
        print("═" * 60 + "\n")

        await state.add_event("coordinator", "started", f"[{state.inv_id}] repo={self.repo_path}")
        print(f"  Investigation ID: {state.inv_id}\n")

        # ── Phase 1: Threat Intel must run first (builds the graph) ───────────
        print("\n[Phase 1] Threat Intelligence + Knowledge Graph\n")
        threat_agent = self._make_agent(
            ThreatIntelAgent,
            "THREAT_AGENT_ID", "THREAT_AGENT_KEY",
            days=self.days,
        )
        await threat_agent.run()

        if not state.graph:
            await state.add_event("coordinator", "aborted", "No knowledge graph — cannot proceed")
            print("\n[Vireon] No graph built — is the repo path correct and does it have dependencies?")
            return

        # ── Phase 1b: Static analysis runs immediately after graph is ready ───
        # In a full parallel system, Static would subscribe to graph-ready event.
        # For the hackathon: sequential but fast — graph is in memory already.
        print("\n[Phase 1b] Static Analysis\n")
        static_agent = self._make_agent(StaticAgent, "STATIC_AGENT_ID", "STATIC_AGENT_KEY")
        await static_agent.run()

        await state.add_event(
            "coordinator", "evidence_gathered",
            detail=f"threat+static complete | findings={len(state.findings)} CVEs={len(state.cves)}",
        )

        if not state.findings:
            await state.add_event("coordinator", "completed", "No findings — repo appears clean")
            print("\n[Vireon] No Semgrep findings. Repo looks clean for this CVE window.")
            await self._print_summary()
            return

        # ── Phase 2: Exploitability ───────────────────────────────────────────
        print("\n[Phase 2] Exploitability Review\n")
        exploit_agent = self._make_agent(
            ExploitabilityAgent, "EXPLOITABILITY_AGENT_ID", "EXPLOITABILITY_AGENT_KEY"
        )
        await exploit_agent.run()

        if not state.confirmed:
            await state.add_event("coordinator", "completed", "No exploitable findings confirmed")
            print("\n[Vireon] Static findings exist but none confirmed exploitable.")
            await self._print_summary()
            return

        # ── Phase 3: Challenger Debate ────────────────────────────────────────
        print("\n[Phase 3] Challenger Debate\n")
        challenger = self._make_agent(
            ChallengerAgent, "CHALLENGER_AGENT_ID", "CHALLENGER_AGENT_KEY"
        )
        await challenger.run()

        # Confidence fusion
        fused = await state.fused_confidence()
        await state.add_event(
            "coordinator", "confidence_fusion",
            detail=f"fused_confidence={fused:.2f}",
            confidence=fused,
        )
        print(f"\n[Coordinator] Fused confidence: {fused:.2f}")

        if fused < 0.3:
            await state.add_event("coordinator", "aborted", f"Fused confidence too low ({fused:.2f}) — investigation inconclusive")
            print(f"\n[Vireon] Fused confidence {fused:.2f} below threshold — not proceeding to patch.")
            await self._print_summary()
            return

        # ── Phase 4: Remediation Loop ─────────────────────────────────────────
        print("\n[Phase 4] Remediation + Compliance Loop\n")
        remediation_approved = False

        while state.remediation_attempts < state.max_remediation_attempts:
            attempt = state.remediation_attempts + 1
            print(f"  [Remediation attempt {attempt}/{state.max_remediation_attempts}]")

            remediation_agent = self._make_agent(
                RemediationAgent, "REMEDIATION_AGENT_ID", "REMEDIATION_AGENT_KEY"
            )
            await remediation_agent.run()

            compliance_agent = self._make_agent(
                ComplianceAgent, "COMPLIANCE_AGENT_ID", "COMPLIANCE_AGENT_KEY"
            )
            compliance_result = await compliance_agent.run()

            if state.compliance_approved:
                remediation_approved = True
                await state.add_event("coordinator", "compliance_approved", f"attempt={attempt}")
                print(f"\n  ✅ Compliance approved on attempt {attempt}")
                break
            else:
                await state.add_event(
                    "coordinator", "compliance_rejected",
                    detail=f"attempt={attempt} — retrying",
                )
                print(f"\n  ❌ Compliance rejected — retrying...")
                # Clear patch so RemediationAgent regenerates fresh
                state.patch_result = {}

        if not remediation_approved:
            await state.add_event("coordinator", "remediation_failed", "Max attempts reached")
            print(f"\n[Vireon] Remediation failed after {state.max_remediation_attempts} attempts.")
            await self._print_summary()
            return

        # ── Phase 5: Verification + PR ────────────────────────────────────────
        print("\n[Phase 5] Verification\n")
        verification_agent = self._make_agent(
            VerificationAgent, "VERIFICATION_AGENT_ID", "VERIFICATION_AGENT_KEY"
        )
        verify_result = await verification_agent.run()

        if verify_result.verdict == "rejected":
            await state.add_event("coordinator", "verification_failed")
            print("\n[Vireon] Verification failed — patch not submitted.")
            await self._print_summary()
            return

        print("\n[Phase 5b] GitHub PR\n")
        pr_agent = self._make_agent(PRAgent, "PR_AGENT_ID", "PR_AGENT_KEY")
        await pr_agent.run()

        await state.add_event("coordinator", "completed", "Investigation complete — PR raised")
        await self._print_summary()

    async def _print_summary(self):
        """Print the full investigation summary at end of run."""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        await generate_summary(self.state, elapsed_s=elapsed)
