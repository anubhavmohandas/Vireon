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
) -> dict:
    """
    Create a GitHub PR with the security patch.

    If GITHUB_TOKEN / GITHUB_REPO not set, falls back to saving a PR draft markdown.

    Returns:
        {url, number, skipped, pr_body, branch_name}
    """
    token = os.getenv("GITHUB_TOKEN", "")
    repo = os.getenv("GITHUB_REPO", "")  # format: "owner/repo"

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

        branch_name = _create_branch_and_push(patch_result, repo, token, repo_path)
        if not branch_name:
            return {
                "url": "", "number": 0, "skipped": True,
                "reason": "Failed to create branch",
                "pr_body": pr_body,
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
                "base": "main",
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


def _create_branch_and_push(patch_result: dict, repo: str, token: str, repo_path: str) -> str | None:
    """
    Create a git branch, apply patches, and push.
    Returns branch name or None on failure.
    """
    import subprocess

    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    branch_name = f"vireon/security-fix-{timestamp}"

    patches = patch_result.get("patches", []) if isinstance(patch_result, dict) else []

    try:
        # Create branch
        subprocess.run(["git", "checkout", "-b", branch_name], cwd=repo_path, check=True, capture_output=True)

        # Apply patches
        for patch in patches:
            file_path = patch.get("patched_file", "")
            patched_code = patch.get("patched_code", "")
            if not file_path or not patched_code:
                continue
            full_path = file_path if os.path.isabs(file_path) else os.path.join(repo_path, file_path)
            try:
                with open(full_path, "w") as f:
                    f.write(patched_code)
            except Exception as e:
                print(f"[github_pr] Failed to write patch for {file_path}: {e}")

        # Stage and commit
        subprocess.run(["git", "add", "-A"], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", f"[Vireon] Automated security patch ({timestamp})"],
            cwd=repo_path, check=True, capture_output=True,
        )

        # Push
        remote_url = f"https://x-access-token:{token}@github.com/{repo}.git"
        subprocess.run(
            ["git", "push", remote_url, branch_name],
            cwd=repo_path, check=True, capture_output=True,
        )

        return branch_name

    except subprocess.CalledProcessError as e:
        print(f"[github_pr] Git error: {e.stderr}")
        # Try to restore branch
        try:
            subprocess.run(["git", "checkout", "main"], cwd=repo_path, capture_output=True)
        except Exception:
            pass
        return None


def _save_pr_draft(pr_body: str, out_dir: str = _OUT_DIR) -> str:
    """Save PR body as markdown for manual use."""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "pr_draft.md")
    with open(path, "w") as f:
        f.write(pr_body)
    print(f"[github_pr] PR draft saved to {path}")
    return path
