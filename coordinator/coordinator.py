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
  DeliveryAgent creates GitHub PR

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
from agents.delivery_agent import DeliveryAgent
from config import vcfg, CONFIDENCE_THRESHOLD, CHALLENGER_VETO_THRESHOLD
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

        # ── Phase 1: ThreatIntel + Static run in parallel ─────────────────────
        # StaticAgent (Semgrep) is independent — only needs repo_path.
        # ThreatIntel builds the graph + CVEs concurrently.
        # return_exceptions=True so one crash doesn't silently discard the other's result.
        print("\n[Phase 1] Threat Intelligence + Static Analysis (parallel)\n")
        threat_agent = self._make_agent(
            ThreatIntelAgent,
            "THREAT_AGENT_ID", "THREAT_AGENT_KEY",
            days=self.days,
        )
        static_agent = self._make_agent(StaticAgent, "STATIC_AGENT_ID", "STATIC_AGENT_KEY")

        phase1_results = await asyncio.gather(
            threat_agent.run(),
            static_agent.run(),
            return_exceptions=True,
        )
        threat_exc, static_exc = phase1_results

        # ── Partial failure semantics ──────────────────────────────────────────
        # ThreatIntel failure = hard abort (no graph → nothing to reason about).
        # Static failure = soft degraded mode (log it, continue without Semgrep findings).
        if isinstance(threat_exc, Exception):
            await state.add_event(
                "coordinator", "aborted",
                detail=f"ThreatIntel failed: {threat_exc}",
            )
            await state.log_decision(
                "coordinator", "PHASE1_ABORT",
                reason=f"ThreatIntel exception: {str(threat_exc)[:200]}",
            )
            print(f"\n[Vireon] ThreatIntel failed — cannot proceed: {threat_exc}")
            await self._print_summary()
            return

        if isinstance(static_exc, Exception):
            await state.add_event(
                "coordinator", "degraded",
                detail=f"StaticAgent failed: {static_exc} — continuing without Semgrep findings",
            )
            await state.log_decision(
                "coordinator", "STATIC_SKIPPED",
                reason=f"StaticAgent exception: {str(static_exc)[:200]}",
            )
            print(f"\n[Vireon] ⚠ StaticAgent failed ({static_exc}) — proceeding in degraded mode (CVE-only analysis)")

        if not state.graph:
            await state.add_event("coordinator", "aborted", "No knowledge graph — cannot proceed")
            print("\n[Vireon] No graph built — is the repo path correct and does it have dependencies?")
            await self._print_summary()
            return

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

        # ── Challenger veto check (enterprise mode) ────────────────────────────
        # Disabled by default (CHALLENGER_VETO_THRESHOLD=1.0).
        # When enabled: if Challenger found strong counter evidence above the threshold,
        # escalate rather than proceeding — forces re-analysis before patching.
        # To enable: set CHALLENGER_VETO_THRESHOLD=0.8 in .env
        challenger_result = await state.get_result("challenger")
        if (
            challenger_result is not None
            and challenger_result.verdict == "counter_evidence_found"
            and challenger_result.confidence >= CHALLENGER_VETO_THRESHOLD
        ):
            await state.add_event(
                "coordinator", "challenger_veto",
                detail=(
                    f"Challenger confidence {challenger_result.confidence:.2f} "
                    f">= veto threshold {CHALLENGER_VETO_THRESHOLD} — escalating"
                ),
                confidence=challenger_result.confidence,
            )
            await state.log_decision(
                "coordinator", "CHALLENGER_VETO_TRIGGERED",
                reason=(
                    f"Strong counter evidence (conf={challenger_result.confidence:.2f}) — "
                    f"set CHALLENGER_VETO_THRESHOLD higher to suppress"
                ),
            )
            print(
                f"\n[Vireon] ⚔ Challenger veto triggered "
                f"(conf={challenger_result.confidence:.2f} >= {CHALLENGER_VETO_THRESHOLD}). "
                f"Investigation escalated — manual review required."
            )
            await self._print_summary()
            return

        if fused < CONFIDENCE_THRESHOLD:
            await state.add_event("coordinator", "aborted", f"Fused confidence too low ({fused:.2f} < {CONFIDENCE_THRESHOLD}) — investigation inconclusive")
            print(f"\n[Vireon] Fused confidence {fused:.2f} below threshold {CONFIDENCE_THRESHOLD} — not proceeding to patch.")
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

        print("\n[Phase 5b] Delivery (GitHub PR)\n")
        delivery_agent = self._make_agent(DeliveryAgent, "PR_AGENT_ID", "PR_AGENT_KEY")
        await delivery_agent.run()

        await state.add_event("coordinator", "completed", "Investigation complete — PR raised")
        await self._print_summary()

    async def _print_summary(self):
        """Print the full investigation summary at end of run."""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        await generate_summary(self.state, elapsed_s=elapsed)
