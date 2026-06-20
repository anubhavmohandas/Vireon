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
    # Deterministic — NOT an LLM call. Version resolution is a lookup, not a
    # reasoning task: OSV already tells us the exact fixed version, and PyPI
    # gives us the latest when it doesn't. The previous one-shot LLM call
    # truncated its JSON whenever there were many CVEs, silently degrading every
    # bump to "latest".
    if all_cves:
        dep_bumps = _generate_dep_bumps(all_cves, repo_path)

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


def _generate_dep_bumps(all_cves: list[dict], repo_path: str) -> list[dict]:
    """
    Generate dependency version bumps for CVE-affected packages — DETERMINISTIC.

    Resolution order per package (highest confidence first):
      1. OSV ``fixed_version`` — the exact version that patches the CVE.
      2. Latest version from PyPI (verified TLS) — when OSV gave no fix range.
      3. The literal string "latest" — only if PyPI is unreachable.

    One row per package (not per CVE): a package with N CVEs collapses to a
    single bump to the highest safe version, with all CVE IDs recorded. This is
    why the old LLM call truncated — it was asked to emit one object per CVE.
    """
    if not all_cves:
        return []

    # Map installed versions from requirements (authoritative for "current").
    installed = _read_installed_versions(repo_path)

    # Collapse CVEs to one entry per package.
    by_pkg: dict[str, dict] = {}
    for c in all_cves:
        pkg = (c.get("package") or "").strip()
        if not pkg:
            continue
        key = pkg.lower().replace("-", "_")
        entry = by_pkg.setdefault(key, {
            "package": pkg,
            "cve_ids": [],
            "current": "",
            "fixed_candidates": [],
            "severity": "UNKNOWN",
        })
        cve_id = c.get("cve_id", "")
        if cve_id and cve_id not in entry["cve_ids"]:
            entry["cve_ids"].append(cve_id)
        fv = (c.get("fixed_version") or "").strip()
        if fv:
            entry["fixed_candidates"].append(fv)
        # current version: prefer requirements file, then CVE metadata
        cur = installed.get(key) or (c.get("installed_version") or "").strip()
        if cur and not entry["current"]:
            entry["current"] = cur
        entry["severity"] = _max_severity(entry["severity"], c.get("severity", "UNKNOWN"))

    bumps: list[dict] = []
    for key, entry in by_pkg.items():
        # Highest fixed version across this package's CVEs is the safe target.
        safe_version = _max_version(entry["fixed_candidates"]) if entry["fixed_candidates"] else ""
        source = "osv_fixed_version"
        if not safe_version:
            latest = pypi_latest_version(entry["package"])
            if latest:
                safe_version = latest
                source = "pypi_latest"
            else:
                safe_version = "latest"
                source = "unresolved"

        bumps.append({
            "package":      entry["package"],
            "cve_id":       entry["cve_ids"][0] if entry["cve_ids"] else "",
            "cve_ids":      entry["cve_ids"],
            "current":      entry["current"] or "?",
            "safe_version": safe_version,
            "severity":     entry["severity"],
            "source":       source,
        })

    if os.getenv("VIREON_VERBOSE") == "1":
        unresolved = sum(1 for b in bumps if b["source"] == "unresolved")
        print(f"[patcher] {len(bumps)} dep bumps ({unresolved} unresolved → 'latest')")
    return bumps


def _simple_dep_bumps(all_cves: list[dict]) -> list[dict]:
    """Pure-data dep bumps (no network) — kept for callers that want offline behaviour."""
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


def _read_installed_versions(repo_path: str) -> dict[str, str]:
    """Best-effort {normalized_pkg: version} from the repo's requirements.txt."""
    out: dict[str, str] = {}
    req = os.path.join(repo_path or "", "requirements.txt")
    if not os.path.isfile(req):
        return out
    try:
        with open(req, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.split("#")[0].strip()
                if not line or line.startswith("-"):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s;]+)", line)
                if m:
                    out[m.group(1).lower().replace("-", "_")] = m.group(2)
    except Exception:
        pass
    return out


# Module-level cache so we never hit PyPI twice for the same package in a run.
_PYPI_CACHE: dict[str, str] = {}


def pypi_latest_version(pkg: str) -> str:
    """
    Return the latest released version of ``pkg`` from PyPI, or "" on any failure.

    Uses verified TLS (the requests default). A SECURITY tool must not disable
    certificate verification to fetch its own advisories. Never raises.
    """
    name = (pkg or "").strip().lower()
    if not name:
        return ""
    if name in _PYPI_CACHE:
        return _PYPI_CACHE[name]
    try:
        import requests
        resp = requests.get(f"https://pypi.org/pypi/{name}/json", timeout=8)
        if resp.status_code != 200:
            return ""
        version = (resp.json().get("info", {}) or {}).get("version", "") or ""
        _PYPI_CACHE[name] = version
        return version
    except Exception as e:
        if os.getenv("VIREON_VERBOSE") == "1":
            print(f"[patcher] PyPI lookup failed for {name}: {e}")
        return ""


def _parse_version(v: str) -> tuple:
    """Loose semver tuple for comparison; non-numeric parts sort last."""
    parts = re.split(r"[.\-+]", (v or "").strip())
    key = []
    for p in parts:
        if p.isdigit():
            key.append((0, int(p)))
        elif p:
            key.append((1, p))
    return tuple(key)


def _max_version(versions: list[str]) -> str:
    """Return the highest version string from a list (loose semver)."""
    candidates = [v for v in versions if v]
    if not candidates:
        return ""
    try:
        return max(candidates, key=_parse_version)
    except Exception:
        return candidates[0]


_SEV_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _max_severity(a: str, b: str) -> str:
    """Return the higher of two severity labels."""
    a = (a or "UNKNOWN").upper()
    b = (b or "UNKNOWN").upper()
    return a if _SEV_ORDER.get(a, 0) >= _SEV_ORDER.get(b, 0) else b


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
