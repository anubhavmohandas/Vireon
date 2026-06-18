"""
scanner/verifier.py — Patch verification

Standalone replacement for sage.tests.runner + sage.verifier.semgrep.
Two verification steps:
  1. run_tests()    — run pytest/unittest against patched code
  2. run_verifier() — re-run Semgrep to confirm vuln pattern is gone
"""

import json
import os
import subprocess
import tempfile
import shutil
from pathlib import Path

_OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")


# ── Test runner ─────────────────────────────────────────────────────────────

def run_tests(patch_result: dict, confirmed: list[dict], repo_path: str) -> dict:
    """
    Apply patches to a temp copy of the repo and run existing tests.

    Args:
        patch_result: Output from engine.patcher.run_patcher()
        confirmed:    Confirmed findings from llm_analyzer
        repo_path:    Path to original repo

    Returns:
        {passed, failed, errors, test_output, skipped}
    """
    patches = patch_result.get("patches", []) if isinstance(patch_result, dict) else []

    if not patches:
        return {"passed": 0, "failed": 0, "errors": 0, "test_output": "No patches to apply", "skipped": True}

    # Create temp copy of repo
    tmp_dir = tempfile.mkdtemp(prefix="vireon_verify_")
    try:
        # Copy repo to temp dir
        shutil.copytree(repo_path, tmp_dir, dirs_exist_ok=True)

        # Apply patches
        apply_errors = _apply_patches(patches, tmp_dir)

        # Detect test runner
        runner = _detect_test_runner(tmp_dir)
        if not runner:
            return {
                "passed": 0,
                "failed": 0,
                "errors": len(apply_errors),
                "test_output": f"No test runner found. Patch errors: {apply_errors}",
                "skipped": True,
            }

        # Run tests
        result = subprocess.run(
            runner,
            cwd=tmp_dir,
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = result.stdout + result.stderr

        # Parse results
        passed, failed, errors = _parse_test_output(output, runner)

        return {
            "passed": passed,
            "failed": failed,
            "errors": errors + len(apply_errors),
            "test_output": output[:3000],
            "skipped": False,
            "return_code": result.returncode,
        }

    except subprocess.TimeoutExpired:
        return {"passed": 0, "failed": 0, "errors": 1, "test_output": "Tests timed out (120s)", "skipped": False}
    except Exception as e:
        return {"passed": 0, "failed": 0, "errors": 1, "test_output": str(e), "skipped": True}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def save_test_results(results: dict, out_dir: str = _OUT_DIR) -> str:
    """Save test results to output/test_results.json."""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "test_results.json")
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    return path


# ── Semgrep verifier ─────────────────────────────────────────────────────────

def run_verifier(patch_result: dict, confirmed: list[dict], repo_path: str) -> dict:
    """
    Apply patches to a temp copy of the repo and re-run Semgrep on the patched files.
    Confirms the vulnerability pattern is gone after patching.

    Rule IDs are sourced from ``confirmed`` (which always carries check_id from
    llm_analyzer) rather than ``patches``, because patches do not reliably
    propagate check_id.  Each confirmed finding is matched against remaining
    Semgrep hits by (check_id, normalized_path) so clearing is per-finding, not
    per-patch.

    Returns:
        {vulnerabilities_cleared, vulnerabilities_remaining, details}
    """
    patches = patch_result.get("patches", []) if isinstance(patch_result, dict) else []

    if not patches:
        return {
            "vulnerabilities_cleared": 0,
            "vulnerabilities_remaining": 0,
            "details": [],
            "skipped": True,
        }

    # Build the authoritative set of (check_id, path) pairs from confirmed findings.
    # These are what we need to verify are gone — NOT the patch list.
    exploitable_confirmed = [c for c in (confirmed or []) if c.get("vulnerable") and c.get("check_id")]
    confirmed_pairs: set[tuple[str, str]] = {
        (c["check_id"], os.path.normpath(c.get("path", "")))
        for c in exploitable_confirmed
    }

    # Also collect a flat set of rule IDs as fallback
    rule_ids: set[str] = {pair[0] for pair in confirmed_pairs}

    # Check semgrep availability
    if not _semgrep_available():
        print("[verifier] semgrep not installed — skipping re-verification")
        # Cannot claim anything cleared without actually scanning
        return {
            "vulnerabilities_cleared": 0,
            "vulnerabilities_remaining": len(confirmed_pairs) or len(patches),
            "details": [],
            "skipped": True,
            "reason": "semgrep not installed",
        }

    tmp_dir = tempfile.mkdtemp(prefix="vireon_semgrep_verify_")
    try:
        shutil.copytree(repo_path, tmp_dir, dirs_exist_ok=True)
        _apply_patches(patches, tmp_dir)

        # Re-run Semgrep on only the patched files for speed; fall back to full dir.
        patched_files_abs = []
        for patch in patches:
            rel = patch.get("patched_file", "")
            if rel:
                abs_path = rel if os.path.isabs(rel) else os.path.join(tmp_dir, rel)
                if os.path.exists(abs_path):
                    patched_files_abs.append(abs_path)
        scan_targets = patched_files_abs if patched_files_abs else [tmp_dir]

        from engine.semgrep import _semgrep_bin
        result = subprocess.run(
            [_semgrep_bin(), "--config", "p/owasp-top-ten", "--json", "--quiet"] + scan_targets,
            capture_output=True, text=True, timeout=120,
        )

        remaining_findings = []
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                remaining_findings = data.get("results", [])
            except json.JSONDecodeError:
                pass

        # Normalise paths in re-scan results to be relative to tmp_dir so they
        # match the relative paths in confirmed findings.
        def _rel_to_tmp(p: str) -> str:
            try:
                return os.path.normpath(os.path.relpath(p, tmp_dir))
            except ValueError:
                return os.path.normpath(p)

        # Build set of (check_id, rel_path) still firing after patch
        still_firing: set[tuple[str, str]] = {
            (f.get("check_id", ""), _rel_to_tmp(f.get("path", "")))
            for f in remaining_findings
            if f.get("check_id", "") in rule_ids
        }

        if confirmed_pairs:
            # Per-finding verdict: only count a finding as cleared if its exact
            # (check_id, path) pair is no longer in still_firing.
            still_vulnerable_pairs = confirmed_pairs & still_firing
            cleared_pairs = confirmed_pairs - still_firing
            cleared = len(cleared_pairs)
            remaining_count = len(still_vulnerable_pairs)
            details = [
                {"check_id": cid, "path": p, "status": "still_vulnerable"}
                for cid, p in still_vulnerable_pairs
            ]
        else:
            # No confirmed exploitable findings to track — fall back to rule-ID
            # count across all remaining findings (less precise but not falsely optimistic).
            still_vulnerable = [
                f for f in remaining_findings
                if f.get("check_id", "") in rule_ids
            ] if rule_ids else remaining_findings
            cleared = max(0, len(patches) - len(still_vulnerable))
            remaining_count = len(still_vulnerable)
            details = [
                {
                    "check_id": f.get("check_id"),
                    "path": f.get("path"),
                    "line": f.get("start", {}).get("line"),
                    "status": "still_vulnerable",
                }
                for f in still_vulnerable
            ]

        return {
            "vulnerabilities_cleared": cleared,
            "vulnerabilities_remaining": remaining_count,
            "details": details,
            "skipped": False,
        }

    except subprocess.TimeoutExpired:
        return {
            "vulnerabilities_cleared": 0,
            "vulnerabilities_remaining": len(patches),
            "details": [],
            "skipped": False,
            "reason": "semgrep timed out",
        }
    except Exception as e:
        return {
            "vulnerabilities_cleared": 0,
            "vulnerabilities_remaining": 0,
            "details": [],
            "skipped": True,
            "reason": str(e),
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def save_verifier_results(results: dict, out_dir: str = _OUT_DIR) -> str:
    """Save verifier results to output/verifier_results.json."""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "verifier_results.json")
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    return path


# ── Helpers ──────────────────────────────────────────────────────────────────

def _apply_patches(patches: list[dict], tmp_dir: str) -> list[str]:
    """Write patched code into temp dir. Returns list of error messages."""
    errors = []
    for patch in patches:
        patched_file = patch.get("patched_file", "")
        patched_code = patch.get("patched_code", "")
        if not patched_file or not patched_code:
            continue

        # Resolve path inside temp dir
        basename = os.path.basename(patched_file)
        # Try to find the file in tmp_dir
        target = _find_file_in_dir(tmp_dir, basename)
        if not target:
            target = os.path.join(tmp_dir, patched_file.lstrip("/"))

        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "w", encoding="utf-8") as f:
                f.write(patched_code)
        except Exception as e:
            errors.append(f"Failed to apply patch to {patched_file}: {e}")

    return errors


def _find_file_in_dir(base_dir: str, filename: str) -> str | None:
    """Find a file by basename in a directory tree."""
    for root, _, files in os.walk(base_dir):
        if filename in files:
            return os.path.join(root, filename)
    return None


def _detect_test_runner(repo_path: str) -> list[str] | None:
    """Detect available test runner in the repo."""
    path = Path(repo_path)
    # pytest
    if (path / "pytest.ini").exists() or (path / "setup.cfg").exists():
        return ["python", "-m", "pytest", "-v", "--tb=short", "-q"]
    # any test files
    test_files = list(path.rglob("test_*.py")) + list(path.rglob("*_test.py"))
    if test_files:
        return ["python", "-m", "pytest", "-v", "--tb=short", "-q"]
    # unittest discovery
    src_files = list(path.rglob("*.py"))
    if src_files:
        return ["python", "-m", "unittest", "discover", "-v"]
    return None


def _parse_test_output(output: str, runner: list[str]) -> tuple[int, int, int]:
    """Parse test runner output into (passed, failed, errors)."""
    import re
    passed = failed = errors = 0

    # pytest pattern: "5 passed, 2 failed, 1 error"
    m = re.search(r"(\d+) passed", output)
    if m:
        passed = int(m.group(1))
    m = re.search(r"(\d+) failed", output)
    if m:
        failed = int(m.group(1))
    m = re.search(r"(\d+) error", output)
    if m:
        errors = int(m.group(1))

    # unittest pattern: "Ran 5 tests"
    if passed == 0 and failed == 0:
        m = re.search(r"Ran (\d+) test", output)
        if m:
            total = int(m.group(1))
            if "OK" in output:
                passed = total
            elif "FAILED" in output:
                m2 = re.search(r"failures=(\d+)", output)
                failed = int(m2.group(1)) if m2 else 1
                passed = total - failed

    return passed, failed, errors


def _semgrep_available() -> bool:
    try:
        from engine.semgrep import _semgrep_bin
        result = subprocess.run([_semgrep_bin(), "--version"], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False
