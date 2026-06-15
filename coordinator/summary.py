"""
coordinator/summary.py — Investigation Summary Generator

Produces the final INV-XXXXX summary card shown at end of demo.
Reads everything from SharedState — no extra computation needed.

Output (terminal + Band room):

  ╔══════════════════════════════════════════════╗
  ║  VIREON INVESTIGATION REPORT                 ║
  ╚══════════════════════════════════════════════╝

  Investigation  INV-2026-04821
  Repo           /path/to/repo
  Duration       47.3s

  ── Findings ─────────────────────────────────────
  CVEs found       12
  Relevant         3
  Confirmed        2

  ── Evidence Sources ─────────────────────────────
  ✓ NVD Threat Intel        (confidence 0.81)
  ✓ Semgrep Static          (confidence 0.74)
  ✓ LLM Exploitability      (confidence 0.89)
  ✗ Challenger Objection    (confidence 0.42 — resolved)
  ✓ Compliance Approved     (attempt 2)
  ✓ Verification Passed     (confidence 0.95)

  ── Confidence Evolution ─────────────────────────
  0%  →  threat:81%  →  static:74%  →  exploit:89%
      →  challenger:42%  →  fused:86%  →  verify:95%

  ── Decision Log ─────────────────────────────────
  [09:00]  THREAT        VERDICT_CONFIRMED
  [09:01]  STATIC        VERDICT_CONFIRMED
  [09:02]  EXPLOITABILITY  VERDICT_CONFIRMED
  [09:03]  CHALLENGER    VERDICT_CONFIRMED   (1 dismissed)
  [09:04]  REMEDIATION   VERDICT_CONFIRMED
  [09:05]  COMPLIANCE    PATCH_REJECTED      Authentication check removed
  [09:06]  REMEDIATION   VERDICT_CONFIRMED   (retry)
  [09:07]  COMPLIANCE    VERDICT_CONFIRMED
  [09:08]  VERIFICATION  VERDICT_CONFIRMED
  [09:09]  PR            VERDICT_CONFIRMED   PR #42

  ── Outcome ──────────────────────────────────────
  Fused Confidence   86%
  Patch              APPROVED (attempt 2)
  PR                 https://github.com/...
  ═══════════════════════════════════════════════
"""

from __future__ import annotations
from datetime import datetime
from vireon.memory.shared_state import SharedState


BOLD  = "\033[1m"
CYAN  = "\033[96m"
GREEN = "\033[92m"
RED   = "\033[91m"
DIM   = "\033[2m"
RESET = "\033[0m"


async def generate_summary(state: SharedState, elapsed_s: float) -> str:
    """
    Build and return the full investigation summary string.
    Also prints it to terminal with ANSI colors.
    """
    results       = await state.get_results()
    timeline      = await state.get_timeline()
    decisions     = await state.get_decision_log()
    conf_evo      = await state.get_confidence_evolution()
    fused         = await state.fused_confidence()

    lines = []

    def _line(text=""):
        lines.append(text)

    # ── Header ────────────────────────────────────────────────────────────────
    _line("═" * 56)
    _line("  VIREON — INVESTIGATION REPORT")
    _line("═" * 56)
    _line()
    _line(f"  Investigation   {state.inv_id}")
    _line(f"  Repo            {state.repo_path}")
    _line(f"  Duration        {elapsed_s:.1f}s")
    _line(f"  Completed       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    _line()

    # ── Findings ──────────────────────────────────────────────────────────────
    _line("── Findings ─────────────────────────────────────")
    threat_r = results.get("threat")
    if threat_r:
        _line(f"  CVEs fetched    {threat_r.metadata.get('cves_fetched', '?')}")
        _line(f"  CVEs relevant   {threat_r.metadata.get('cves_relevant', '?')}")
        _line(f"  Reachable       {threat_r.metadata.get('reachable_cves', '?')}")
    static_r = results.get("static")
    if static_r:
        _line(f"  Semgrep hits    {static_r.metadata.get('findings_count', '?')}")
    exploit_r = results.get("exploitability")
    if exploit_r:
        _line(f"  LLM confirmed   {exploit_r.metadata.get('confirmed_count', '?')}")
    _line()

    # ── Evidence Sources ──────────────────────────────────────────────────────
    _line("── Evidence Sources ─────────────────────────────")
    agent_labels = {
        "threat":          "NVD Threat Intel",
        "static":          "Semgrep Static",
        "exploitability":  "LLM Exploitability",
        "challenger":      "Challenger Review",
        "remediation":     "Remediation",
        "compliance":      "Compliance",
        "verification":    "Verification",
        "pr":              "GitHub PR",
    }
    for agent, label in agent_labels.items():
        r = results.get(agent)
        if r is None:
            continue
        tick = "✓" if r.verdict == "confirmed" else ("✗" if r.verdict == "rejected" else "~")
        extra = ""
        if agent == "challenger" and r.verdict == "confirmed":
            dismissed = r.metadata.get("dismissed", 0)
            extra = f"  ({dismissed} dismissed — findings upheld)" if dismissed else "  (no mitigations found)"
        if agent == "compliance":
            attempt = results.get("remediation", None)
            att_num = attempt.metadata.get("attempt", 1) if attempt else 1
            extra = f"  (approved on attempt {att_num})"
        _line(f"  {tick} {label:28s} conf={r.confidence:.2f}{extra}")
    _line()

    # ── Confidence Evolution ──────────────────────────────────────────────────
    _line("── Confidence Evolution ─────────────────────────")
    if conf_evo:
        evo_parts = ["0%"] + [f"{e['label']}:{int(e['confidence']*100)}%" for e in conf_evo]
        # Wrap at 50 chars
        evo_str = "  →  ".join(evo_parts)
        # Chunk into lines
        chunk_size = 50
        for i in range(0, len(evo_str), chunk_size):
            _line(f"  {evo_str[i:i+chunk_size]}")
    _line()

    # ── Decision Log ─────────────────────────────────────────────────────────
    _line("── Decision Log ─────────────────────────────────")
    for d in decisions:
        ts = d.get("timestamp", "")[:19].replace("T", " ")[11:]  # HH:MM:SS
        agent = d.get("agent", "").upper()[:14]
        action = d.get("action", "")[:28]
        reason = d.get("reason", "")[:40]
        reason_str = f"  {reason}" if reason else ""
        _line(f"  [{ts}]  {agent:14s}  {action:28s}{reason_str}")
    _line()

    # ── Outcome ───────────────────────────────────────────────────────────────
    _line("── Outcome ──────────────────────────────────────")
    _line(f"  Fused Confidence   {int(fused * 100)}%")

    compliance_r = results.get("compliance")
    if compliance_r:
        overall = compliance_r.metadata.get("overall", "?")
        attempt = results.get("remediation")
        att_num = attempt.metadata.get("attempt", 1) if attempt else 1
        _line(f"  Patch              {overall} (attempt {att_num})")

    pr_r = results.get("pr")
    if pr_r:
        pr_url = pr_r.metadata.get("pr_url", "")
        pr_num = pr_r.metadata.get("pr_number", "")
        if pr_url:
            _line(f"  PR                 #{pr_num}  {pr_url}")
        elif pr_r.metadata.get("skipped"):
            _line("  PR                 skipped (no GitHub token)")

    _line("═" * 56)

    summary = "\n".join(lines)

    # Print with color
    colored = summary.replace("✓", f"{GREEN}✓{RESET}").replace("✗", f"{RED}✗{RESET}")
    print(f"\n{BOLD}{CYAN}" + "═" * 56 + RESET)
    for l in lines[1:]:
        print(l)

    return summary
