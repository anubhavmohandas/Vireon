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
        if os.getenv("VIREON_VERBOSE") == "1":
            print("[semgrep] semgrep not installed — skipping static analysis")
        if os.getenv("VIREON_VERBOSE") == "1":
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

    if os.getenv("VIREON_VERBOSE") == "1":
        print(f"[semgrep] {len(deduped)} findings across {len({f.get('path') for f in deduped})} files")
    return deduped


def _run_ruleset(repo_path: str, ruleset: str) -> list[dict]:
    """Run a single Semgrep ruleset and return raw findings."""
    try:
        result = subprocess.run(
            _semgrep_cmd() + [
                "--config", ruleset,
                "--json",
                "--quiet",
                "--timeout", "30",
                "--max-memory", "1000",
                "--exclude", "venv",
                "--exclude", "myvenv",
                "--exclude", ".venv",
                "--exclude", "env",
                "--exclude", "node_modules",
                "--exclude", "data",
                "--exclude", "*.egg-info",
                "--exclude", "dist",
                "--exclude", "build",
                repo_path,
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.stdout:
            data = json.loads(result.stdout)
            return data.get("results", [])
    except subprocess.TimeoutExpired:
        if os.getenv("VIREON_VERBOSE") == "1":
            print(f"[semgrep] Timeout on ruleset {ruleset}")
    except json.JSONDecodeError:
        pass
    except Exception as e:
        if os.getenv("VIREON_VERBOSE") == "1":
            print(f"[semgrep] Error running {ruleset}: {e}")
    return []


def _pick_rulesets(repo_path: str) -> list[str]:
    """Pick relevant rulesets based on what's in the repo."""
    path = Path(repo_path)
    rulesets = []

    # Python — use p/python which is fast and comprehensive
    py_files = list(path.rglob("*.py"))
    if py_files or (path / "requirements.txt").exists():
        rulesets.append("p/python")

    # JavaScript/Node
    js_files = list(path.rglob("*.js")) + list(path.rglob("*.ts"))
    if js_files or (path / "package.json").exists():
        rulesets.append("p/javascript")

    # Always check secrets — fast rule, high value
    rulesets.append("p/secrets")

    # Only add heavy rulesets if repo is small enough (< 100 files)
    total_files = len(py_files) + len(js_files)
    if total_files < 100:
        rulesets.append("p/owasp-top-ten")

    return list(dict.fromkeys(rulesets))  # deduplicate, preserve order


def _semgrep_cmd() -> list[str]:
    """
    Return the command prefix to invoke semgrep.

    Prefers `python -m semgrep` (same venv, always works if the package is
    installed) over a bare binary path.  Falls back to the binary for envs
    where semgrep is installed system-wide rather than as a Python package.
    """
    import sys
    import shutil

    # Best: same interpreter, guaranteed correct venv
    try:
        result = subprocess.run(
            [sys.executable, "-m", "semgrep", "--version"],
            capture_output=True, timeout=10,
        )
        if result.returncode == 0:
            return [sys.executable, "-m", "semgrep"]
    except Exception:
        pass

    # Fallback: binary in venv bin dir
    venv_bin = os.path.join(os.path.dirname(sys.executable), "semgrep")
    if os.path.isfile(venv_bin):
        return [venv_bin]

    # Last resort: PATH
    found = shutil.which("semgrep")
    return [found] if found else ["semgrep"]


def _semgrep_bin() -> str:
    """Legacy helper — returns first element of _semgrep_cmd()."""
    return _semgrep_cmd()[0]


def _semgrep_available() -> bool:
    """Check if semgrep is installed and runnable."""
    try:
        result = subprocess.run(
            _semgrep_cmd() + ["--version"],
            capture_output=True, timeout=15,
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
