"""
scanner/semgrep.py — Semgrep wrapper for Vireon

Runs Semgrep security rules on a repo.
Standalone — no SAGE dependency.

Falls back gracefully if semgrep is not installed.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path


# Semgrep rulesets to run — ordered by signal quality
RULESETS = [
    "p/python",           # Python security rules
    "p/javascript",       # JS/Node security rules
    "p/owasp-top-ten",    # OWASP Top 10
    "p/secrets",          # Hardcoded secrets/keys
    "p/sql-injection",    # SQLi
    "p/command-injection",# Command injection
    "p/xss",              # Cross-site scripting
]


def run_semgrep(repo_path: str, cves: list[dict] | None = None) -> list[dict]:
    """
    Run Semgrep on repo_path and return findings.

    Args:
        repo_path: Path to the repo to scan
        cves:      Optional CVE list — used to focus rules on affected packages

    Returns:
        List of finding dicts with file, line, rule, message, severity
    """
    if not _semgrep_available():
        print("[semgrep] semgrep not installed — skipping static analysis")
        print("[semgrep] Install: pip install semgrep")
        return []

    # Pick rulesets based on detected ecosystem
    rulesets = _pick_rulesets(repo_path)

    findings = []
    for ruleset in rulesets:
        batch = _run_ruleset(repo_path, ruleset)
        findings.extend(batch)

    # Deduplicate by (file, line, rule)
    seen = set()
    deduped = []
    for f in findings:
        key = (f.get("path"), f.get("start", {}).get("line"), f.get("check_id"))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    print(f"[semgrep] {len(deduped)} findings across {len({f.get('path') for f in deduped})} files")
    return deduped


def _run_ruleset(repo_path: str, ruleset: str) -> list[dict]:
    """Run a single Semgrep ruleset and return raw findings."""
    try:
        result = subprocess.run(
            [
                _semgrep_bin(),
                "--config", ruleset,
                "--json",
                "--no-git-ignore",
                "--quiet",
                repo_path,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.stdout:
            data = json.loads(result.stdout)
            return data.get("results", [])
    except subprocess.TimeoutExpired:
        print(f"[semgrep] Timeout on ruleset {ruleset}")
    except json.JSONDecodeError:
        pass
    except Exception as e:
        print(f"[semgrep] Error running {ruleset}: {e}")
    return []


def _pick_rulesets(repo_path: str) -> list[str]:
    """Pick relevant rulesets based on what's in the repo."""
    path = Path(repo_path)
    rulesets = ["p/owasp-top-ten", "p/secrets"]  # always run these

    # Python
    py_files = list(path.rglob("*.py"))
    if py_files or (path / "requirements.txt").exists():
        rulesets.extend(["p/python", "p/sql-injection", "p/command-injection"])

    # JavaScript/Node
    js_files = list(path.rglob("*.js")) + list(path.rglob("*.ts"))
    if js_files or (path / "package.json").exists():
        rulesets.extend(["p/javascript", "p/xss"])

    return list(dict.fromkeys(rulesets))  # deduplicate, preserve order


def _semgrep_bin() -> str:
    """Find the semgrep binary — checks venv, shutil.which, fallback."""
    import shutil
    # Check same venv as this Python process
    import sys
    venv_bin = os.path.join(os.path.dirname(sys.executable), "semgrep")
    if os.path.isfile(venv_bin):
        return venv_bin
    found = shutil.which("semgrep")
    if found:
        return found
    return "semgrep"  # fallback, will fail gracefully


def _semgrep_available() -> bool:
    """Check if semgrep is installed."""
    try:
        result = subprocess.run(
            [_semgrep_bin(), "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def normalize_findings(raw: list[dict]) -> list[dict]:
    """Normalize Semgrep output into Vireon's finding format."""
    normalized = []
    for f in raw:
        normalized.append({
            "check_id": f.get("check_id", ""),
            "path":     f.get("path", ""),
            "start":    f.get("start", {}),
            "end":      f.get("end", {}),
            "extra": {
                "message":  f.get("extra", {}).get("message", ""),
                "severity": f.get("extra", {}).get("severity", "WARNING"),
                "lines":    f.get("extra", {}).get("lines", ""),
                "cwe":      f.get("extra", {}).get("metadata", {}).get("cwe", []),
            },
        })
    return normalized
