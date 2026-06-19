"""
coordinator/coordinator.py — Vireon War Room Coordinator

Orchestrates the full investigation:

Phase 1 — Parallel Evidence Gathering:
  ThreatIntelAgent + StaticAgent run concurrently

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
"""

import asyncio
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

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

_con = Console()


_PHASE_COLORS = ["", "cyan", "magenta", "yellow", "green", "blue"]


def _phase(n: int, title: str, note: str = ""):
    color = _PHASE_COLORS[n] if n < len(_PHASE_COLORS) else "cyan"
    suffix = f"  [dim]{note}[/dim]" if note else ""
    _con.print()
    _con.print()
    _con.rule(
        f"[bold {color}] ❯ Phase {n}[/bold {color}]  [bold white]{title}[/bold white]{suffix}",
        style=color,
    )
    _con.print()


def _agent_row(label: str, result, attempt: int = 0):
    """Print one clean line per agent result."""
    verdict = result.verdict
    conf = int(result.confidence * 100)
    secs = (result.duration_ms or 0) / 1000

    if verdict in ("confirmed", "approved", "no_counter_evidence"):
        icon, color = "✓", "green"
    elif verdict in ("rejected",):
        icon, color = "✗", "red"
    else:
        icon, color = "~", "yellow"

    att = f"  [dim]attempt {attempt}[/dim]" if attempt else ""
    _con.print(
        f"  [{color}]{icon}[/{color}]  [bold]{label:<28}[/bold]"
        f"  [{color}]{conf}%[/{color}] conf"
        f"  [dim]{secs:.0f}s[/dim]{att}"
    )


class Coordinator:
    """
    Vireon War Room Coordinator.

    Usage:
        coordinator = Coordinator(repo_path="/path/to/repo", days=7)
        await coordinator.run()
    """

    def __init__(self, repo_path: str, days: int = 7, db=None):
        self.repo_path = repo_path
        self.days = days
        self.state = SharedState(repo_path=repo_path, db=db)
        self._db = db
        self.start_time = None

    def _make_agent(self, cls, id_key: str, key_key: str, **kwargs):
        agent_id = getattr(vcfg, id_key, "")
        api_key = getattr(vcfg, key_key, "")
        return cls(self.state, agent_id, api_key, **kwargs)

    async def run(self):
        self.start_time = datetime.now()
        state = self.state

        if self._db:
            await self._db.insert_investigation(state.inv_id, self.repo_path, self.days)

        # ── Header ────────────────────────────────────────────────────────────────
        display_repo = getattr(state, "original_repo_path", None) or self.repo_path
        _con.print()
        _con.print(Panel(
            f"[bold white]⚡ VIREON[/bold white]  [dim]·[/dim]  [cyan]{state.inv_id}[/cyan]\n"
            f"[dim]{display_repo}[/dim]  [dim]·[/dim]  [dim]{self.days}-day CVE window[/dim]"
            f"  [dim]·  {self.start_time.strftime('%H:%M:%S')}[/dim]",
            border_style="bright_magenta",
            padding=(0, 2),
        ))

        await state.add_event("coordinator", "started", f"[{state.inv_id}] repo={display_repo}")

        # ── Phase 1: ThreatIntel + Static (parallel) ──────────────────────────────
        _phase(1, "Threat Intelligence + Static Analysis", "parallel")
        _con.print("  [dim]Running in parallel — threat intel may take 1–2 min...[/dim]\n")

        threat_agent = self._make_agent(
            ThreatIntelAgent, "THREAT_AGENT_ID", "THREAT_AGENT_KEY", days=self.days,
        )
        static_agent = self._make_agent(StaticAgent, "STATIC_AGENT_ID", "STATIC_AGENT_KEY")

        phase1_results = await asyncio.gather(
            threat_agent.run(),
            static_agent.run(),
            return_exceptions=True,
        )
        threat_exc, static_exc = phase1_results

        # Show results
        static_result = await state.get_result("static")
        threat_result = await state.get_result("threat")

        if static_result:
            _agent_row("Semgrep Static", static_result)
        if isinstance(static_exc, Exception):
            _con.print(f"  [yellow]~[/yellow]  [bold]{'Static Analysis':<28}[/bold]  [dim]failed — degraded mode[/dim]")
            await state.add_event("coordinator", "degraded",
                detail=f"StaticAgent failed: {static_exc} — continuing without Semgrep findings")
            await state.log_decision("coordinator", "STATIC_SKIPPED",
                reason=f"StaticAgent exception: {str(static_exc)[:200]}")

        if isinstance(threat_exc, Exception):
            _con.print(f"\n  [red]✗  ThreatIntel failed — cannot proceed:[/red] {threat_exc}")
            await state.add_event("coordinator", "aborted",
                detail=f"ThreatIntel failed: {threat_exc}")
            await state.log_decision("coordinator", "PHASE1_ABORT",
                reason=f"ThreatIntel exception: {str(threat_exc)[:200]}")
            await self._print_summary()
            return

        if threat_result:
            _agent_row("NVD Threat Intel", threat_result)

        # Evidence summary line
        cves_n = threat_result.metadata.get("cves_fetched", 0) if threat_result else 0
        findings_n = static_result.metadata.get("findings_count", 0) if static_result else 0
        _con.print()
        _con.print(f"  [bold cyan]{cves_n}[/bold cyan] [dim]CVEs fetched[/dim]   [bold cyan]{findings_n}[/bold cyan] [dim]Semgrep findings[/dim]")

        await state.add_event("coordinator", "evidence_gathered",
            detail=f"threat+static complete | findings={len(state.findings)} CVEs={len(state.cves)}")

        if not state.graph:
            _con.print("\n  [red]No knowledge graph built — is this a Python project with requirements.txt?[/red]")
            await state.add_event("coordinator", "aborted", "No knowledge graph — cannot proceed")
            await self._print_summary()
            return

        if not state.findings:
            _con.print("\n  [green]✓  No Semgrep findings — repo looks clean for this CVE window.[/green]")
            await state.add_event("coordinator", "completed", "No findings — repo appears clean")
            await self._print_summary()
            return

        # ── Phase 2: Exploitability ───────────────────────────────────────────────
        _phase(2, "Exploitability Review")

        exploit_agent = self._make_agent(
            ExploitabilityAgent, "EXPLOITABILITY_AGENT_ID", "EXPLOITABILITY_AGENT_KEY"
        )
        await exploit_agent.run()

        exploit_result = await state.get_result("exploitability")
        if exploit_result:
            _agent_row("Exploitability", exploit_result)
            confirmed_n = exploit_result.metadata.get("confirmed_count", 0)
            total_n = exploit_result.metadata.get("total_findings", len(state.findings))
            _con.print(f"  [bold magenta]{confirmed_n}[/bold magenta] [dim]of[/dim] [bold magenta]{total_n}[/bold magenta] [dim]findings confirmed exploitable[/dim]")

        if not state.confirmed:
            _con.print("\n  [yellow]No exploitable findings confirmed — stopping.[/yellow]")
            await state.add_event("coordinator", "completed", "No exploitable findings confirmed")
            await self._print_summary()
            return

        # ── Phase 3: Challenger ───────────────────────────────────────────────────
        _phase(3, "Challenger Debate")

        challenger = self._make_agent(
            ChallengerAgent, "CHALLENGER_AGENT_ID", "CHALLENGER_AGENT_KEY"
        )
        await challenger.run()

        challenger_result = await state.get_result("challenger")
        if challenger_result:
            _agent_row("Challenger", challenger_result)

        fused = await state.fused_confidence()
        await state.add_event("coordinator", "confidence_fusion",
            detail=f"fused_confidence={fused:.2f}", confidence=fused)

        fused_color = "green" if fused >= 0.7 else ("yellow" if fused >= 0.4 else "red")
        _con.print(f"  [dim]Fused confidence: [/dim][{fused_color}][bold]{int(fused*100)}%[/bold][/{fused_color}]")

        # Challenger veto
        if (
            challenger_result is not None
            and challenger_result.verdict == "counter_evidence_found"
            and challenger_result.confidence >= CHALLENGER_VETO_THRESHOLD
        ):
            _con.print(
                f"\n  [yellow]⚔  Challenger veto triggered "
                f"(conf={challenger_result.confidence:.0%} ≥ {CHALLENGER_VETO_THRESHOLD:.0%}) "
                f"— escalating for manual review[/yellow]"
            )
            await state.add_event("coordinator", "challenger_veto",
                detail=(f"Challenger confidence {challenger_result.confidence:.2f} "
                        f">= veto threshold {CHALLENGER_VETO_THRESHOLD}"),
                confidence=challenger_result.confidence)
            await state.log_decision("coordinator", "CHALLENGER_VETO_TRIGGERED",
                reason=f"Strong counter evidence (conf={challenger_result.confidence:.2f})")
            await self._print_summary()
            return

        if fused < CONFIDENCE_THRESHOLD:
            _con.print(
                f"\n  [yellow]Fused confidence {int(fused*100)}% below threshold "
                f"{int(CONFIDENCE_THRESHOLD*100)}% — not proceeding to patch.[/yellow]"
            )
            await state.add_event("coordinator", "aborted",
                detail=f"Fused confidence too low ({fused:.2f} < {CONFIDENCE_THRESHOLD}) — investigation inconclusive")
            await self._print_summary()
            return

        # ── Phase 4: Remediation Loop ─────────────────────────────────────────────
        _phase(4, "Remediation + Compliance")

        remediation_approved = False

        while state.remediation_attempts < state.max_remediation_attempts:
            attempt = state.remediation_attempts + 1
            _con.print(f"  [dim]Attempt {attempt} of {state.max_remediation_attempts}...[/dim]")

            remediation_agent = self._make_agent(
                RemediationAgent, "REMEDIATION_AGENT_ID", "REMEDIATION_AGENT_KEY"
            )
            await remediation_agent.run()

            compliance_agent = self._make_agent(
                ComplianceAgent, "COMPLIANCE_AGENT_ID", "COMPLIANCE_AGENT_KEY"
            )
            await compliance_agent.run()

            compliance_result = await state.get_result("compliance")
            if compliance_result:
                _agent_row("Compliance", compliance_result, attempt=attempt)

            if state.compliance_approved:
                remediation_approved = True
                await state.add_event("coordinator", "compliance_approved", detail=f"attempt={attempt}")
                break
            else:
                await state.add_event("coordinator", "compliance_rejected",
                    detail=f"attempt={attempt} — retrying")
                state.patch_result = {}

        if not remediation_approved:
            _con.print(f"\n  [red]Remediation failed after {state.max_remediation_attempts} attempts.[/red]")
            await state.add_event("coordinator", "remediation_failed", "Max attempts reached")
            await self._print_summary()
            return

        # ── Phase 5: Verification + PR ────────────────────────────────────────────
        _phase(5, "Verification + Delivery")

        verification_agent = self._make_agent(
            VerificationAgent, "VERIFICATION_AGENT_ID", "VERIFICATION_AGENT_KEY"
        )
        await verification_agent.run()

        verify_result = await state.get_result("verification")
        if verify_result:
            _agent_row("Verification", verify_result)

        if verify_result and verify_result.verdict == "rejected":
            _con.print("\n  [red]Verification failed — patch not submitted.[/red]")
            await state.add_event("coordinator", "verification_failed")
            await self._print_summary()
            return

        delivery_agent = self._make_agent(DeliveryAgent, "PR_AGENT_ID", "PR_AGENT_KEY")
        await delivery_agent.run()

        pr_result = await state.get_result("pr")
        if pr_result:
            _agent_row("GitHub PR", pr_result)
            pr_url = pr_result.metadata.get("pr_url", "")
            if pr_url:
                _con.print(f"  [dim]  → {pr_url}[/dim]")

        await state.add_event("coordinator", "completed", "Investigation complete — PR raised")
        await self._print_summary()

    async def _print_summary(self, status: str = "completed"):
        """Print the full investigation summary at end of run."""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        await generate_summary(self.state, elapsed_s=elapsed)
        if self._db:
            fused = await self.state.fused_confidence()
            await self._db.update_investigation_status(
                self.state.inv_id, status, fused_confidence=fused
            )
