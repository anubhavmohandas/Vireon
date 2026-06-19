"""
coordinator/summary.py — Investigation Summary (Rich)

Produces the final report card at the end of a Vireon investigation.
All data comes from SharedState — no extra computation needed.
"""

from __future__ import annotations
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.text import Text

from memory.shared_state import SharedState

_con = Console()


async def generate_summary(state: SharedState, elapsed_s: float) -> str:
    results   = await state.get_results()
    decisions = await state.get_decision_log()
    conf_evo  = await state.get_confidence_evolution()
    fused     = await state.fused_confidence()

    elapsed_str = (
        f"{int(elapsed_s // 60)}m {int(elapsed_s % 60)}s"
        if elapsed_s >= 60
        else f"{elapsed_s:.1f}s"
    )

    _con.print()
    _con.print()
    _con.rule("[bold white] ⚡ VIREON — INVESTIGATION REPORT [/bold white]", style="bright_magenta")
    _con.print()

    # ── Meta ──────────────────────────────────────────────────────────────────────
    display_repo = getattr(state, "original_repo_path", None) or state.repo_path
    _con.print(f"  [dim]Investigation[/dim]   [bold cyan]{state.inv_id}[/bold cyan]")
    _con.print(f"  [dim]Repo         [/dim]   [white]{display_repo}[/white]")
    _con.print(f"  [dim]Duration     [/dim]   [bold white]{elapsed_str}[/bold white]")
    _con.print(f"  [dim]Completed    [/dim]   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    _con.print()

    # ── Findings ──────────────────────────────────────────────────────────────────
    _con.rule("[bold cyan] Findings [/bold cyan]", style="cyan")
    _con.print()

    threat_r  = results.get("threat")
    static_r  = results.get("static")
    exploit_r = results.get("exploitability")

    ft = Table(show_header=False, box=None, padding=(0, 3, 0, 2))
    ft.add_column("label", style="dim", width=18)
    ft.add_column("value", style="bold cyan")
    if threat_r:
        ft.add_row("CVEs fetched",  str(threat_r.metadata.get("cves_fetched",  "—")))
        ft.add_row("CVEs relevant", str(threat_r.metadata.get("cves_relevant", "—")))
        ft.add_row("Reachable",     str(threat_r.metadata.get("reachable_cves","—")))
    if static_r:
        ft.add_row("Semgrep hits",  str(static_r.metadata.get("findings_count","—")))
    if exploit_r:
        ft.add_row("LLM confirmed", str(exploit_r.metadata.get("confirmed_count","—")))
    _con.print(ft)
    _con.print()

    # ── Evidence Pipeline ─────────────────────────────────────────────────────────
    _con.rule("[bold magenta] Evidence Pipeline [/bold magenta]", style="magenta")
    _con.print()

    agent_labels = {
        "threat":         "NVD Threat Intel",
        "static":         "Semgrep Static",
        "exploitability": "Exploitability",
        "challenger":     "Challenger",
        "remediation":    "Remediation",
        "compliance":     "Compliance",
        "verification":   "Verification",
        "pr":             "GitHub PR",
    }

    pt = Table(show_header=True, box=None, padding=(0, 3, 0, 2), show_edge=False)
    pt.add_column("Agent",   style="bold", width=22)
    pt.add_column("Verdict", width=24)
    pt.add_column("Conf",    width=7,  justify="right")
    pt.add_column("Time",    width=7,  justify="right", style="dim")
    pt.add_column("Notes",   style="dim")

    for agent, label in agent_labels.items():
        r = results.get(agent)
        if r is None:
            continue

        verdict  = r.verdict
        conf_str = f"{int(r.confidence * 100)}%"
        secs_str = f"{(r.duration_ms or 0) / 1000:.0f}s"

        if verdict in ("confirmed", "approved", "no_counter_evidence"):
            vt = Text(f"✓  {verdict}", style="green")
        elif verdict == "rejected":
            vt = Text(f"✗  {verdict}", style="red")
        elif verdict == "counter_evidence_found":
            vt = Text(f"~  {verdict}", style="yellow")
        else:
            vt = Text(f"~  {verdict}", style="yellow")

        notes = ""
        if agent == "challenger":
            d   = r.metadata.get("dismissed", 0)
            red = r.metadata.get("reduced",   0)
            parts = []
            if d:   parts.append(f"{d} dismissed")
            if red: parts.append(f"{red} reduced")
            notes = ", ".join(parts)
        elif agent == "compliance":
            rem_r = results.get("remediation")
            att   = rem_r.metadata.get("attempt", 1) if rem_r else 1
            notes = f"approved attempt {att}"
        elif agent == "pr":
            pr_url = r.metadata.get("pr_url", "")
            if pr_url:
                notes = pr_url
            elif r.metadata.get("skipped"):
                notes = "push failed — draft at output/pr_draft.md"

        pt.add_row(label, vt, conf_str, secs_str, notes)

    _con.print(pt)
    _con.print()

    # ── Confidence Evolution ──────────────────────────────────────────────────────
    if conf_evo:
        _con.rule("[bold yellow] Confidence Evolution [/bold yellow]", style="yellow")
        _con.print()
        # Only per-agent snapshots (skip after_X intermediates)
        key_points = [e for e in conf_evo if not e["label"].startswith("after_")]
        parts = ["[dim]0%[/dim]"]
        for e in key_points:
            pct   = int(e["confidence"] * 100)
            color = "green" if pct >= 70 else ("yellow" if pct >= 40 else "red")
            parts.append(f"[{color}]{pct}%[/{color}] [dim]{e['label']}[/dim]")
        _con.print("  " + "  [dim]→[/dim]  ".join(parts))
        _con.print()

    # ── Decision Log ─────────────────────────────────────────────────────────────
    _con.rule("[bold white] Decision Log [/bold white]", style="white")
    _con.print()

    dt = Table(show_header=False, box=None, padding=(0, 2, 0, 2), show_edge=False)
    dt.add_column("time",   style="dim",  width=10)
    dt.add_column("agent",              width=16)
    dt.add_column("action",             width=32)
    dt.add_column("reason", style="dim")

    for d in decisions:
        ts     = d.get("timestamp", "")[:19].replace("T", " ")[11:]
        agent  = d.get("agent",  "").upper()
        action = d.get("action", "")
        reason = d.get("reason", "")[:70]

        if any(k in action for k in ("CONFIRMED", "APPROVED")):
            at = Text(action, style="green")
        elif any(k in action for k in ("REJECTED", "ABORT", "FAILED")):
            at = Text(action, style="red")
        elif any(k in action for k in ("COUNTER", "VETO", "SKIPPED")):
            at = Text(action, style="yellow")
        else:
            at = Text(action, style="dim")

        dt.add_row(f"[{ts}]", agent, at, reason)

    _con.print(dt)
    _con.print()

    # ── Outcome ───────────────────────────────────────────────────────────────────
    _con.rule("[bold green] Outcome [/bold green]", style="green")
    _con.print()

    fused_color = "green" if fused >= 0.7 else ("yellow" if fused >= 0.4 else "red")
    _con.print(
        f"  Fused Confidence   [{fused_color}][bold]{int(fused * 100)}%[/bold][/{fused_color}]"
    )

    compliance_r = results.get("compliance")
    if compliance_r:
        overall = compliance_r.metadata.get("overall", "?")
        rem_r   = results.get("remediation")
        att     = rem_r.metadata.get("attempt", 1) if rem_r else 1
        color   = "green" if overall == "APPROVED" else "red"
        _con.print(f"  Patch              [{color}]{overall}[/{color}]  [dim]attempt {att}[/dim]")

    pr_r = results.get("pr")
    if pr_r:
        pr_url = pr_r.metadata.get("pr_url", "")
        pr_num = pr_r.metadata.get("pr_number", "")
        if pr_url:
            _con.print(f"  PR                 [cyan]#{pr_num}[/cyan]  {pr_url}")
        else:
            _con.print("  PR                 [dim]skipped — draft saved to output/pr_draft.md[/dim]")

    _con.print()
    _con.rule(style="bright_magenta")
    _con.print()

    return ""  # kept for API compatibility
