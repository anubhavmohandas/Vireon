"""
cli.py — Vireon Interactive Terminal

Usage:
    python cli.py

Paste a GitHub URL or a local path at the prompt.
GitHub URLs are auto-cloned to a temp directory and cleaned up after the run.

Supported input formats:
    https://github.com/user/repo
    github.com/user/repo
    git@github.com:user/repo.git
    /local/path/to/repo
    ./relative/path
"""

import asyncio
import os
import re
import shutil
import subprocess
import sys
import tempfile

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule

console = Console()


# ── Banner ─────────────────────────────────────────────────────────────────────

def print_banner():
    console.print()
    console.print(Panel.fit(
        "[bold white]⚡ VIREON[/bold white]\n"
        "[dim]Autonomous Multi-Agent Security Investigation[/dim]\n"
        "[dim]8 agents · confidence fusion · auto-patch[/dim]",
        border_style="bright_magenta",
        padding=(1, 4),
    ))
    console.print()


# ── URL detection + clone ──────────────────────────────────────────────────────

def is_github_url(s: str) -> bool:
    patterns = [
        r"^https?://github\.com/",
        r"^github\.com/",
        r"^git@github\.com:",
    ]
    return any(re.match(p, s.strip()) for p in patterns)


def normalize_url(s: str) -> str:
    s = s.strip()
    if s.startswith("github.com/"):
        s = "https://" + s
    return s


def clone_repo(url: str) -> str:
    """Clone a GitHub repo to a temp directory. Returns the local path."""
    url = normalize_url(url)

    # Strip .git suffix for display, ensure it's there for clone
    display_url = url.rstrip("/")
    clone_url = url if url.endswith(".git") else url

    tmpdir = tempfile.mkdtemp(prefix="vireon-")
    console.print(f"\n[dim]Cloning[/dim] [cyan]{display_url}[/cyan] [dim]→ {tmpdir}[/dim]")

    # "--" terminates option parsing so a hostile URL (e.g. one starting with
    # "--upload-pack=") can't be smuggled in as a git flag. Bounded by a timeout.
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--", clone_url, tmpdir],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmpdir, ignore_errors=True)
        console.print("[red]Clone failed:[/red] timed out after 120s")
        return ""

    if result.returncode != 0:
        shutil.rmtree(tmpdir, ignore_errors=True)
        console.print(f"[red]Clone failed:[/red] {result.stderr.strip()}")
        return ""

    console.print(f"[green]✓ Cloned successfully[/green]\n")
    return tmpdir


def resolve_path(s: str) -> str:
    """Resolve local path. Returns absolute path or empty string if not found."""
    path = os.path.abspath(os.path.expanduser(s.strip()))
    if os.path.isdir(path):
        return path
    console.print(f"[red]Path not found:[/red] {path}")
    return ""


# ── Mode selection ─────────────────────────────────────────────────────────────

def ask_mode() -> str:
    """Ask user to pick real or demo mode."""
    console.print("\n[bold]Run mode:[/bold]")
    console.print("  [cyan]1[/cyan] — Real mode  (live NVD fetch + Semgrep + LLM agents)")
    console.print("  [cyan]2[/cyan] — Demo mode  (pre-seeded CVEs, guaranteed full pipeline)\n")
    choice = Prompt.ask("Choose", choices=["1", "2"], default="1")
    return "demo" if choice == "2" else "real"


# ── Run pipeline ───────────────────────────────────────────────────────────────

async def run_real(repo_path: str, days: int, original_url: str = ""):
    from coordinator.coordinator import Coordinator
    coordinator = Coordinator(repo_path=repo_path, days=days, original_url=original_url)
    await coordinator.run()


async def run_demo(repo_path: str, days: int, original_url: str = ""):
    from demo_run import DemoCoordinator
    coordinator = DemoCoordinator(repo_path=repo_path, days=days)
    await coordinator.run()


# ── Main loop ──────────────────────────────────────────────────────────────────

def main():
    print_banner()

    while True:
        console.print(Rule(style="dim"))
        console.print()

        # ── Get repo input ─────────────────────────────────────────────────────
        repo_input = Prompt.ask(
            "[bold]Repository[/bold] [dim](GitHub URL or local path, or 'q' to quit)[/dim]"
        ).strip()

        if repo_input.lower() in ("q", "quit", "exit"):
            console.print("\n[dim]Bye.[/dim]\n")
            break

        if not repo_input:
            continue

        # ── Resolve to local path ──────────────────────────────────────────────
        cloned_tmpdir = None

        if is_github_url(repo_input):
            repo_path = clone_repo(repo_input)
            if not repo_path:
                continue
            cloned_tmpdir = repo_path
        else:
            repo_path = resolve_path(repo_input)
            if not repo_path:
                continue

        # ── Days ───────────────────────────────────────────────────────────────
        days_str = Prompt.ask(
            "[bold]CVE lookback[/bold] [dim](days)[/dim]",
            default="7",
        )
        try:
            days = int(days_str)
        except ValueError:
            days = 7

        # ── Mode ───────────────────────────────────────────────────────────────
        mode = ask_mode()

        # ── Run ────────────────────────────────────────────────────────────────
        # Pass original URL so reports show github.com/... not /var/folders/...
        original_url = repo_input if is_github_url(repo_input) else repo_path

        try:
            if mode == "demo":
                asyncio.run(run_demo(repo_path, days, original_url=original_url))
            else:
                asyncio.run(run_real(repo_path, days, original_url=original_url))

        except KeyboardInterrupt:
            console.print("\n[yellow]Investigation interrupted.[/yellow]")
        except Exception as e:
            console.print(f"\n[red]Error:[/red] {e}")
        finally:
            # Clean up cloned temp dir
            if cloned_tmpdir:
                shutil.rmtree(cloned_tmpdir, ignore_errors=True)
                console.print(f"\n[dim]Cleaned up temp clone: {cloned_tmpdir}[/dim]")

        # ── Ask to run again ───────────────────────────────────────────────────
        console.print()
        again = Confirm.ask("Run another investigation?", default=True)
        if not again:
            console.print("\n[dim]Bye.[/dim]\n")
            break


if __name__ == "__main__":
    main()
