"""
scanner/github_pr.py — GitHub PR creation

Standalone replacement for sage.github.pr.
Creates a PR with the verified security patch.

Requires: GITHUB_TOKEN and GITHUB_REPO env vars.
If not set, saves patch to output/pr_draft.md instead and returns skipped=True.
"""

import json
import os
import re
import datetime
from pathlib import Path

_OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")


def run_github_pr(
    patch_result: dict,
    confirmed: list[dict],
    all_cves: list[dict],
    test_results: dict,
    verify_results: dict,
    repo_path: str,
    github_repo: str = "",
) -> dict:
    """
    Create a GitHub PR with the security patch.

    `github_repo` — "owner/repo" derived from the scanned URL at scan time.
    Falls back to GITHUB_REPO env var if not supplied (CLI / local path scans).
    If neither is set, saves a PR draft to output/pr_draft.md instead.

    Returns:
        {url, number, skipped, pr_body, branch_name}
    """
    token = os.getenv("GITHUB_TOKEN", "")
    # Prefer the runtime-derived repo (from the scanned URL) over the env var
    # so PRs always target the repo that was actually scanned.
    repo = github_repo or os.getenv("GITHUB_REPO", "")  # format: "owner/repo"
    if github_repo and github_repo != os.getenv("GITHUB_REPO", ""):
        print(f"[github_pr] Using scanned repo target: {repo}")

    pr_body = _build_pr_body(patch_result, confirmed, all_cves, test_results, verify_results, repo_path)

    if not token or not repo:
        print("[github_pr] GITHUB_TOKEN/GITHUB_REPO not set — saving PR draft to output/")
        draft_path = _save_pr_draft(pr_body)
        return {
            "url": "",
            "number": 0,
            "skipped": True,
            "reason": "GITHUB_TOKEN or GITHUB_REPO not configured",
            "pr_body": pr_body,
            "draft_path": draft_path,
            "branch_name": "",
        }

    # Real GitHub PR creation
    try:
        import requests

        branch_name, default_branch, push_reason = _create_branch_and_push(patch_result, repo, token, repo_path)
        if not branch_name:
            draft_path = _save_pr_draft(pr_body)
            return {
                "url": "", "number": 0, "skipped": True,
                "reason": push_reason or "no patches to apply",
                "pr_body": pr_body,
                "draft_path": draft_path,
            }

        # Generate PR title
        cve_ids = [c.get("cve_id", "") for c in all_cves if c.get("cve_id")]
        title = f"[Vireon Security] Fix {', '.join(cve_ids[:3])}" if cve_ids else "[Vireon Security] Automated security patch"

        # Create PR via GitHub API
        response = requests.post(
            f"https://api.github.com/repos/{repo}/pulls",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={
                "title": title,
                "body": pr_body,
                "head": branch_name,
                "base": default_branch,
            },
            timeout=30,
        )

        if response.status_code in (200, 201):
            pr = response.json()
            print(f"[github_pr] PR created: {pr.get('html_url')}")
            return {
                "url": pr.get("html_url", ""),
                "number": pr.get("number", 0),
                "skipped": False,
                "pr_body": pr_body,
                "branch_name": branch_name,
            }
        else:
            print(f"[github_pr] GitHub API error: {response.status_code} {response.text[:200]}")
            draft_path = _save_pr_draft(pr_body)
            return {
                "url": "", "number": 0, "skipped": True,
                "reason": f"GitHub API {response.status_code}",
                "pr_body": pr_body,
                "draft_path": draft_path,
            }

    except ImportError:
        print("[github_pr] requests not installed")
        return {"url": "", "number": 0, "skipped": True, "reason": "requests not installed", "pr_body": pr_body}
    except Exception as e:
        print(f"[github_pr] Error: {e}")
        draft_path = _save_pr_draft(pr_body)
        return {"url": "", "number": 0, "skipped": True, "reason": str(e), "pr_body": pr_body, "draft_path": draft_path}


def save_pr_result(pr_result: dict, out_dir: str = _OUT_DIR) -> str:
    """Save PR result to output/pr_result.json."""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "pr_result.json")
    # pr_body can be large — trim for JSON
    result_to_save = {k: v for k, v in pr_result.items() if k != "pr_body"}
    with open(path, "w") as f:
        json.dump(result_to_save, f, indent=2)
    return path


def _build_pr_body(
    patch_result: dict,
    confirmed: list[dict],
    all_cves: list[dict],
    test_results: dict,
    verify_results: dict,
    repo_path: str,
) -> str:
    """Build the PR description markdown."""
    patches = patch_result.get("patches", []) if isinstance(patch_result, dict) else []
    dep_bumps = patch_result.get("dep_bumps", []) if isinstance(patch_result, dict) else []

    # CVE summary table
    cve_table = "| CVE | Package | Severity | Fixed In |\n|-----|---------|----------|----------|\n"
    for cve in all_cves[:20]:
        cve_table += f"| {cve.get('cve_id','?')} | {cve.get('package','?')} | {cve.get('severity','?')} | {cve.get('fixed_version','latest') or 'latest'} |\n"

    # Confirmed findings summary
    exploitable = [c for c in confirmed if c.get("vulnerable")]
    findings_text = ""
    for f in exploitable[:10]:
        avg_conf = f.get("confidence", 0.0)
        findings_text += f"- **{f.get('check_id','?')}** in `{f.get('path','?')}` line {f.get('line','?')} (confidence: {avg_conf:.0%})\n"
        findings_text += f"  - {f.get('reason','')[:150]}\n"

    # Test results
    tests_passed = test_results.get("passed", 0) if isinstance(test_results, dict) else 0
    tests_failed = test_results.get("failed", 0) if isinstance(test_results, dict) else 0
    tests_skipped = test_results.get("skipped", True) if isinstance(test_results, dict) else True
    test_status = "⏭️ Skipped (no tests found)" if tests_skipped else (
        f"✅ {tests_passed} passed, ❌ {tests_failed} failed"
    )

    # Verification results
    cleared = verify_results.get("vulnerabilities_cleared", 0) if isinstance(verify_results, dict) else 0
    remaining = verify_results.get("vulnerabilities_remaining", 0) if isinstance(verify_results, dict) else 0
    verify_skipped = verify_results.get("skipped", True) if isinstance(verify_results, dict) else True
    verify_status = "⏭️ Skipped" if verify_skipped else (
        f"✅ {cleared} cleared, ⚠️ {remaining} remaining"
    )

    # Patch summary
    patches_text = ""
    for p in patches[:5]:
        patches_text += f"- `{p.get('patched_file','?')}` — {p.get('explanation','')[:150]}\n"
    for b in dep_bumps[:10]:
        patches_text += f"- **{b.get('package','?')}**: `{b.get('current','?')}` → `{b.get('safe_version','latest')}` ({b.get('cve_id','?')})\n"

    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    return f"""## 🛡️ Vireon Automated Security Fix

> Generated by [Vireon](https://github.com/vireon) autonomous security investigation platform
> Timestamp: {timestamp}

---

### CVEs Addressed

{cve_table}

### Confirmed Exploitable Findings

{findings_text or "_No confirmed exploitable findings — patches are dependency upgrades only._"}

### Changes Made

{patches_text or "_No changes generated._"}

### Verification Results

| Check | Result |
|-------|--------|
| Test Suite | {test_status} |
| Semgrep Re-scan | {verify_status} |

### Investigation Details

- **Code patches**: {len(patches)}
- **Dependency bumps**: {len(dep_bumps)}
- **Exploitable findings confirmed**: {len(exploitable)}
- **Repository**: `{Path(repo_path).name}`

---

> ⚠️ This PR was generated automatically. A human security reviewer should verify the patches before merging.
> Review the diff carefully and run the full test suite in your CI before merging.
"""


def _get_default_branch(repo_path: str) -> str:
    """
    Read the actual default branch from the remote tracking ref.
    Falls back to 'main' if the ref is absent (e.g. shallow clone with no remote).
    """
    import subprocess

    try:
        result = subprocess.run(
            ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
            cwd=repo_path, capture_output=True, text=True,
        )
        if result.returncode == 0:
            # e.g. "refs/remotes/origin/main\n" → "main"
            ref = result.stdout.strip()
            return ref.split("/")[-1] if ref else "main"
    except Exception:
        pass

    # Fallback: try to read HEAD branch name from remote via ls-remote
    try:
        result = subprocess.run(
            ["git", "remote", "show", "origin"],
            cwd=repo_path, capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if "HEAD branch:" in line:
                return line.split("HEAD branch:")[-1].strip()
    except Exception:
        pass

    print("[github_pr] Could not determine default branch — falling back to 'main'")
    return "main"


def _resolve_latest_versions(dep_bumps: list[dict]) -> dict[str, str]:
    """
    For each unique package in dep_bumps that has no concrete version,
    fetch the current latest version from PyPI and return {pkg: version}.
    """
    import urllib.request
    import json as _json

    packages = {
        (b.get("package") or "").strip().lower()
        for b in dep_bumps
        if (b.get("package") or "").strip()
    }

    import ssl as _ssl
    # macOS Python doesn't ship with linked system certs — use unverified context
    # for public PyPI metadata (no sensitive data transmitted).
    _ctx = _ssl._create_unverified_context()

    resolved: dict[str, str] = {}
    for pkg in packages:
        if not pkg:
            continue
        try:
            url = f"https://pypi.org/pypi/{pkg}/json"
            with urllib.request.urlopen(url, timeout=8, context=_ctx) as resp:
                data = _json.loads(resp.read())
            version = data.get("info", {}).get("version", "")
            if version:
                resolved[pkg] = version
                print(f"[github_pr] Resolved {pkg} latest → {version}")
        except Exception as e:
            print(f"[github_pr] Could not resolve latest version for {pkg}: {e}")

    return resolved


def _apply_dep_bumps(dep_bumps: list[dict], repo_path: str) -> list[str]:
    """
    Write dependency version bumps into requirements.txt / pyproject.toml.
    Returns list of repo-relative file paths that were modified (for git staging).
    """
    if not dep_bumps:
        return []

    # Deduplicate: latest safe version per package
    pkg_version: dict[str, str] = {}
    for bump in dep_bumps:
        pkg = (bump.get("package") or "").strip().lower()
        to_ver = (bump.get("safe_version") or bump.get("to") or "").strip()
        if pkg and to_ver and to_ver not in ("latest", "?", ""):
            # Keep highest version seen (simple string comparison is ok for semver)
            if pkg not in pkg_version or to_ver > pkg_version[pkg]:
                pkg_version[pkg] = to_ver

    if not pkg_version:
        # No concrete versions — try to resolve 'latest' via PyPI
        pkg_version = _resolve_latest_versions(dep_bumps)
        if not pkg_version:
            print("[github_pr] dep bumps present but could not resolve versions — skipping requirements update")
            return []

    modified: list[str] = []

    # ── requirements.txt ──────────────────────────────────────────────────────
    req_file = os.path.join(repo_path, "requirements.txt")
    if os.path.isfile(req_file):
        with open(req_file) as f:
            req_lines = f.readlines()
        new_lines = []
        changed = False
        for line in req_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                new_lines.append(line)
                continue
            # Extract package name (before any version specifier)
            pkg_name = stripped.split("==")[0].split(">=")[0].split("<=")[0].split("~=")[0].strip().lower()
            if pkg_name in pkg_version:
                new_line = f"{pkg_name}>={pkg_version[pkg_name]}\n"
                if new_line != line:
                    print(f"[github_pr] Bump {pkg_name} → >={pkg_version[pkg_name]}")
                    changed = True
                new_lines.append(new_line)
            else:
                new_lines.append(line)
        if changed:
            with open(req_file, "w") as f:
                f.writelines(new_lines)
            modified.append("requirements.txt")

    # ── pyproject.toml (basic) ────────────────────────────────────────────────
    pyproject_file = os.path.join(repo_path, "pyproject.toml")
    if os.path.isfile(pyproject_file):
        with open(pyproject_file) as f:
            content = f.read()
        changed = False
        import re
        for pkg, ver in pkg_version.items():
            # Match: "packagename>=x.y" or "packagename==x.y" in toml strings
            pattern = rf'("{pkg}|{pkg.replace("-","_")})(>=|==|~=|<=)[^"\']*'
            replacement = rf'\g<1>>={ver}'
            new_content, n = re.subn(pattern, replacement, content, flags=re.IGNORECASE)
            if n:
                content = new_content
                changed = True
        if changed:
            with open(pyproject_file, "w") as f:
                f.write(content)
            modified.append("pyproject.toml")

    return modified


def _create_branch_and_push(patch_result: dict, repo: str, token: str, repo_path: str) -> tuple[str | None, str, str]:
    """
    Create a git branch, apply patches, and push.
    Returns (branch_name, default_branch, reason) — branch_name is None on failure.
    """
    import subprocess

    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    branch_name = f"vireon/security-fix-{timestamp}"

    patches = patch_result.get("patches", []) if isinstance(patch_result, dict) else []
    default_branch = _get_default_branch(repo_path)

    # Collect the set of files we will actually write so we stage only those.
    patched_files: list[str] = []

    try:
        # Ensure git user identity is set in this (possibly temp) clone
        subprocess.run(["git", "config", "user.email", "vireon-bot@vireon.ai"], cwd=repo_path, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Vireon Security Bot"], cwd=repo_path, capture_output=True)

        # Create branch
        subprocess.run(["git", "checkout", "-b", branch_name], cwd=repo_path, check=True, capture_output=True)

        # Apply patches and record which absolute paths were written
        for patch in patches:
            file_path = patch.get("patched_file", "")
            patched_code = patch.get("patched_code", "")
            if not file_path or not patched_code:
                continue
            full_path = file_path if os.path.isabs(file_path) else os.path.join(repo_path, file_path)
            try:
                with open(full_path, "w") as f:
                    f.write(patched_code)
                rel_path = os.path.relpath(full_path, repo_path)
                patched_files.append(rel_path)
            except Exception as e:
                print(f"[github_pr] Failed to write patch for {file_path}: {e}")

        # Apply dep bumps to requirements files even when no code patches exist
        dep_bumps = patch_result.get("dep_bumps", []) if isinstance(patch_result, dict) else []
        dep_files = _apply_dep_bumps(dep_bumps, repo_path)
        patched_files.extend(dep_files)

        if not patched_files:
            print("[github_pr] No files patched and no dep bumps — nothing to commit")
            subprocess.run(["git", "checkout", default_branch], cwd=repo_path, capture_output=True)
            return None, default_branch, "no code patches or dep bumps to apply"

        # Stage ONLY the patched/bumped files — never `git add -A`
        subprocess.run(["git", "add", "--"] + patched_files, cwd=repo_path, check=True, capture_output=True)

        subprocess.run(
            ["git", "commit", "-m", f"[Vireon] Automated security patch ({timestamp})"],
            cwd=repo_path, check=True, capture_output=True,
        )

        # Push using token auth.
        # -c credential.helper= disables macOS osxkeychain (and any other
        # credential helper) so the embedded token in the URL is used directly
        # rather than being overridden by cached credentials.
        remote_url = f"https://x-access-token:{token}@github.com/{repo}.git"
        result = subprocess.run(
            ["git", "-c", "credential.helper=", "push", remote_url, branch_name],
            cwd=repo_path, capture_output=True,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode() if result.stderr else ""
            print(f"[github_pr] Push failed: {stderr[:200]}")
            return None, default_branch, f"git push failed: {stderr[:100]}"

        return branch_name, default_branch, ""

    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        print(f"[github_pr] Git error: {stderr}")
        try:
            subprocess.run(["git", "checkout", default_branch], cwd=repo_path, capture_output=True)
        except Exception:
            pass
        return None, default_branch, f"git error: {stderr[:100]}"


def _save_pr_draft(pr_body: str, out_dir: str = _OUT_DIR) -> str:
    """Save PR body as markdown for manual use."""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "pr_draft.md")
    with open(path, "w") as f:
        f.write(pr_body)
    print(f"[github_pr] PR draft saved to {path}")
    return path
