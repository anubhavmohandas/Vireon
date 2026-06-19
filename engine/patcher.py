"""
scanner/patcher.py — LLM-based patch generator

Standalone replacement for sage.patcher.llm.
Generates two kinds of fixes:
  1. code_patches — LLM-written code fixes for confirmed findings
  2. dep_bumps   — version upgrades for CVE-affected dependencies

Uses Vireon's make_llm_client().
"""

import json
import os
import re
import difflib
from pathlib import Path

_OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")


def run_patcher(
    confirmed: list[dict],
    repo_path: str,
    all_cves: list[dict] | None = None,
) -> dict:
    """
    Generate patches for confirmed vulnerabilities.

    Args:
        confirmed:  Output from engine.llm_analyzer.analyze_findings()
        repo_path:  Path to the repo to patch
        all_cves:   All CVEs from graph (for dep bump generation)

    Returns:
        {
            "patches":   [code patch dicts],
            "dep_bumps": [dependency version bump dicts],
        }
    """
    from config import make_llm_client, default_model

    client = make_llm_client()
    model  = default_model()
    patches = []
    dep_bumps = []

    # ── 1. Code patches for confirmed exploitable findings ──────────────────
    exploitable = [c for c in confirmed if c.get("vulnerable")]
    patched_files: set[str] = set()

    for finding in exploitable[:10]:  # cap at 10 patches
        file_path = finding.get("path", "")
        if not file_path or file_path in patched_files:
            continue

        source = _read_file(file_path, repo_path)
        if not source:
            continue

        patch = _generate_code_patch(client, model, finding, source, file_path, repo_path)
        if patch:
            patches.append(patch)
            patched_files.add(file_path)

    # ── 2. Dependency bumps for CVE-affected packages ───────────────────────
    if all_cves:
        dep_bumps = _generate_dep_bumps(client, model, all_cves, repo_path)

    if os.getenv("VIREON_VERBOSE") == "1":
        print(f"[patcher] Generated {len(patches)} code patches, {len(dep_bumps)} dep bumps")
    return {"patches": patches, "dep_bumps": dep_bumps}


def save_patch_result(patch_result: dict, out_dir: str = _OUT_DIR) -> str:
    """Save patch result to output/patch_result.json."""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "patch_result.json")
    with open(path, "w") as f:
        json.dump(patch_result, f, indent=2)
    return path


def _generate_code_patch(
    client,
    model: str,
    finding: dict,
    source: str,
    file_path: str,
    repo_path: str,
) -> dict | None:
    """Ask LLM to fix a single vulnerable finding."""
    check_id = finding.get("check_id", "")
    line = finding.get("line", 0)
    reason = finding.get("reason", "")
    attack_vector = finding.get("attack_vector", "")
    cwe = finding.get("cwe", "")

    # Build source context: full file if small, targeted window if large.
    # Sending truncated source then asking for "complete file" produces corrupted patches.
    lines = source.splitlines(keepends=True)
    FULL_FILE_CHAR_LIMIT = 8000
    win_start = 0
    win_end = len(lines)
    if len(source) <= FULL_FILE_CHAR_LIMIT:
        source_block = source
        patch_instruction = "(complete fixed file content here — no markdown, no backticks, just the raw code)"
    else:
        # Window: ±60 lines around the vulnerable line
        ctx = 60
        win_start = max(0, line - ctx - 1)
        win_end = min(len(lines), line + ctx)
        source_block = "".join(lines[win_start:win_end])
        patch_instruction = (
            f"(patched version of ONLY the shown window — lines {win_start+1}–{win_end}. "
            f"No markdown, no backticks, just raw code. Do NOT include lines outside the window.)"
        )

    prompt = f"""You are a security engineer. Fix the vulnerability in this code.

FILE: {file_path}
RULE: {check_id}
LINE: {line}
CWE: {cwe}
ISSUE: {reason}
ATTACK VECTOR: {attack_vector}

SOURCE CODE:
```python
{source_block}
```

Generate a MINIMAL fix that:
1. Addresses the root cause (not just adds a check)
2. Preserves existing functionality
3. Does not introduce new vulnerabilities

Respond in this EXACT format with these exact delimiters (no other text):
<<<EXPLANATION>>>
One sentence explaining what you changed.
<<<PATCHED_CODE>>>
{patch_instruction}
<<<END>>>"""

    try:
        response = client.chat.completions.create(
            model=model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.choices[0].message.content.strip()

        # Parse delimited format
        explanation = ""
        patched_code = ""
        if "<<<EXPLANATION>>>" in raw and "<<<PATCHED_CODE>>>" in raw and "<<<END>>>" in raw:
            explanation = raw.split("<<<EXPLANATION>>>")[1].split("<<<PATCHED_CODE>>>")[0].strip()
            patched_code = raw.split("<<<PATCHED_CODE>>>")[1].split("<<<END>>>")[0].strip()
        else:
            # Fallback: try JSON
            try:
                snippet = raw
                if "```json" in snippet:
                    snippet = snippet.split("```json")[1].split("```")[0].strip()
                elif "```" in snippet:
                    snippet = snippet.split("```")[1].split("```")[0].strip()
                result = json.loads(snippet)
                patched_code = result.get("patched_code", "")
                explanation = result.get("explanation", "")
            except Exception:
                if os.getenv("VIREON_VERBOSE") == "1":
                    print(f"[patcher] Could not parse response for {file_path}")
                return None

        if not patched_code:
            return None

        # For windowed edits: reassemble the full file so patched_code is always
        # the complete file content (not just the window).
        if win_start > 0 or win_end < len(lines):
            pre = "".join(lines[:win_start])
            post = "".join(lines[win_end:])
            full_patched = pre + patched_code + post
            original_for_diff = source_block.splitlines(keepends=True)
            patched_for_diff = patched_code.splitlines(keepends=True)
        else:
            full_patched = patched_code
            original_for_diff = source.splitlines(keepends=True)
            patched_for_diff = patched_code.splitlines(keepends=True)

        diff = "".join(
            difflib.unified_diff(
                original_for_diff,
                patched_for_diff,
                fromfile=f"a/{file_path}",
                tofile=f"b/{file_path}",
                lineterm="",
            )
        )

        return {
            "cve_id": finding.get("cve_id", ""),
            "check_id": check_id,
            "patched_file": file_path,
            "diff": diff,
            "patched_code": full_patched,
            "explanation": explanation[:500],
            "lines_changed": [],
        }

    except Exception as e:
        if os.getenv("VIREON_VERBOSE") == "1":
            print(f"[patcher] Error patching {file_path}: {e}")
        return None


def _generate_dep_bumps(client, model: str, all_cves: list[dict], repo_path: str) -> list[dict]:
    """Generate dependency version bumps for CVE-affected packages."""
    if not all_cves:
        return []

    # Find requirements files
    req_files = _find_requirements_files(repo_path)
    if not req_files:
        return _simple_dep_bumps(all_cves)

    # Read requirements
    req_content = ""
    req_file_used = req_files[0]
    try:
        with open(req_file_used) as f:
            req_content = f.read()
    except Exception:
        return _simple_dep_bumps(all_cves)

    cve_summary = "\n".join(
        f"- {c['cve_id']}: {c['package']} (severity: {c.get('severity','?')}, fixed: {c.get('fixed_version','?') or 'upgrade to latest'})"
        for c in all_cves[:20]
    )

    # Filter requirements to only lines relevant to the CVE packages — avoids
    # truncating large requirements files and losing unrelated packages.
    vuln_pkgs = {c["package"].lower().replace("-", "_") for c in all_cves[:20] if c.get("package")}
    req_lines = req_content.splitlines()
    relevant_lines = [
        ln for ln in req_lines
        if any(pkg in ln.lower().replace("-", "_") for pkg in vuln_pkgs)
    ]
    # If nothing matched (unusual normalisation), fall back to first 2000 chars
    req_excerpt = "\n".join(relevant_lines) if relevant_lines else req_content[:2000]

    prompt = f"""You are a security engineer. Given these CVEs affecting dependencies, generate version bumps.

CURRENT requirements.txt (relevant packages shown):
```
{req_excerpt}
```

CVEs to fix:
{cve_summary}

For each CVE, provide the safe version to upgrade to. If fixed_version is given, use it.
If not, say "latest".

Respond with JSON array:
[
  {{
    "package": "<package name>",
    "cve_id": "<CVE-XXXX-XXXXX>",
    "current": "<current version from requirements>",
    "safe_version": "<version that fixes the CVE>",
    "severity": "<CRITICAL|HIGH|MEDIUM|LOW>"
  }}
]"""

    try:
        response = client.chat.completions.create(
            model=model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.choices[0].message.content.strip()
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0].strip()

        return json.loads(raw)

    except Exception as e:
        if os.getenv("VIREON_VERBOSE") == "1":
            if os.getenv("VIREON_VERBOSE") == "1":
                print(f"[patcher] Dep bump LLM error: {e}")
        return _simple_dep_bumps(all_cves)


def _simple_dep_bumps(all_cves: list[dict]) -> list[dict]:
    """Fallback: generate dep bumps from CVE data without LLM."""
    return [
        {
            "package": c.get("package", ""),
            "cve_id": c.get("cve_id", ""),
            "current": c.get("installed_version", "?"),
            "safe_version": c.get("fixed_version") or "latest",
            "severity": c.get("severity", "UNKNOWN"),
        }
        for c in all_cves
        if c.get("package")
    ]


def _find_requirements_files(repo_path: str) -> list[str]:
    """Find Python requirements files in repo."""
    candidates = [
        "requirements.txt", "requirements-dev.txt", "requirements/base.txt",
        "pyproject.toml", "Pipfile",
    ]
    found = []
    for name in candidates:
        full = os.path.join(repo_path, name)
        if os.path.exists(full):
            found.append(full)
    return found


def _read_file(file_path: str, repo_path: str) -> str:
    """Read a source file, trying relative and absolute paths."""
    full_path = file_path
    if not os.path.isabs(file_path) and repo_path:
        full_path = os.path.join(repo_path, file_path)
    try:
        with open(full_path, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""
