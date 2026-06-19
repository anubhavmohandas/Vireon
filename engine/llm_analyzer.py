"""
scanner/llm_analyzer.py — LLM-based exploitability analyzer

Standalone replacement for sage.analyzer.llm.
Uses Vireon's make_llm_client() so it works with AIML_API_KEY or ANTHROPIC_API_KEY.

analyze_findings():
  Takes Semgrep findings + graph, returns list of confirmed exploitable vulns
  with confidence, reason, and attack vector.
"""

import json
import os
from typing import Optional

_OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")


def analyze_findings(
    findings: list[dict],
    graph=None,
    repo_path: str = "",
    reach_results: list[dict] | None = None,
) -> list[dict]:
    """
    Use LLM to confirm which Semgrep findings are genuinely exploitable.

    Args:
        findings:      Normalized Semgrep findings from engine.semgrep
        graph:         networkx DiGraph (optional — used for reachability context)
        repo_path:     Path to the repo (for context)
        reach_results: Reachability analysis results (optional)

    Returns:
        List of confirmed finding dicts with keys:
          cve_id, check_id, path, line, vulnerable (bool),
          confidence (0-1), reason, attack_vector
    """
    from config import make_llm_client, default_model

    if not findings:
        return []

    client = make_llm_client()
    model  = default_model()
    confirmed = []

    # Group findings by file to reduce LLM calls
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        path = f.get("path", "unknown")
        by_file.setdefault(path, []).append(f)

    # Build reachability index for context
    # reach_results can be a list[dict] or dict{cve_id: dict} — handle both
    reach_index: dict[str, dict] = {}
    if reach_results:
        if isinstance(reach_results, dict):
            reach_index = reach_results  # already keyed by cve_id
        else:
            for r in reach_results:
                if isinstance(r, dict):
                    cve_id = r.get("cve_id", "")
                    if cve_id:
                        reach_index[cve_id] = r

    for file_path, file_findings in list(by_file.items())[:20]:  # cap at 20 files
        # Build context from findings
        findings_text = _format_findings_for_llm(file_findings)

        # Read the actual source file for context (first 200 lines)
        source_snippet = _read_source_snippet(file_path, repo_path)

        prompt = f"""You are a security expert analyzing potential vulnerabilities found by Semgrep.

FILE: {file_path}
REPOSITORY: {repo_path or "unknown"}

SEMGREP FINDINGS:
{findings_text}

SOURCE CODE (excerpt):
```
{source_snippet}
```

For EACH finding, determine:
1. Is this GENUINELY exploitable by a real attacker? (not just a theoretical issue)
2. What is the confidence level (0.0-1.0)?
3. What is the attack vector? (e.g. "Attacker sends crafted HTTP request to /login with SQL payload")
4. What is the CWE? (e.g. CWE-89 for SQL injection)

Respond with a JSON array. Each element:
{{
  "check_id": "<rule id from the finding>",
  "line": <line number>,
  "vulnerable": true/false,
  "confidence": 0.0-1.0,
  "reason": "<brief explanation — why exploitable or why not>",
  "attack_vector": "<how an attacker would exploit this>",
  "cwe": "<CWE number if applicable>"
}}

Be conservative: only mark as vulnerable=true if a real attacker could exploit it without unrealistic preconditions."""

        try:
            response = client.chat.completions.create(
                model=model,
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.choices[0].message.content.strip()
            # Extract JSON from markdown code block if needed
            if "```json" in raw:
                raw = raw.split("```json")[1].split("```")[0].strip()
            elif "```" in raw:
                raw = raw.split("```")[1].split("```")[0].strip()

            results = json.loads(raw)
            if not isinstance(results, list):
                results = [results]

            for r in results:
                # Match back to original finding
                check_id = r.get("check_id", "")
                matched = next(
                    (f for f in file_findings if f.get("check_id", "") == check_id),
                    file_findings[0] if file_findings else {},
                )
                confirmed.append({
                    "cve_id": matched.get("cve_id", ""),
                    "check_id": check_id,
                    "path": file_path,
                    "line": r.get("line", matched.get("start", {}).get("line", 0)),
                    "vulnerable": r.get("vulnerable", False),
                    "confidence": float(r.get("confidence", 0.5)),
                    "reason": r.get("reason", "")[:300],
                    "attack_vector": r.get("attack_vector", "")[:300],
                    "cwe": r.get("cwe", ""),
                    "severity": matched.get("extra", {}).get("severity", "WARNING"),
                })

        except json.JSONDecodeError as e:
            if os.getenv("VIREON_VERBOSE") == "1":
                print(f"[llm_analyzer] JSON parse error for {file_path}: {e}")
            # Fallback: mark finding as needing manual review
            for f in file_findings:
                confirmed.append({
                    "cve_id": "",
                    "check_id": f.get("check_id", ""),
                    "path": file_path,
                    "line": f.get("start", {}).get("line", 0),
                    "vulnerable": False,
                    "confidence": 0.3,
                    "reason": "LLM analysis failed — manual review needed",
                    "attack_vector": "",
                    "cwe": "",
                    "severity": f.get("extra", {}).get("severity", "WARNING"),
                })
        except Exception as e:
            if os.getenv("VIREON_VERBOSE") == "1":
                print(f"[llm_analyzer] Error analyzing {file_path}: {e}")
            continue

    vuln_count = sum(1 for c in confirmed if c.get("vulnerable"))
    if os.getenv("VIREON_VERBOSE") == "1":
        print(f"[llm_analyzer] {vuln_count}/{len(confirmed)} findings confirmed exploitable")
    return confirmed


def save_confirmed(confirmed: list[dict], out_dir: str = _OUT_DIR) -> str:
    """Save confirmed findings to output/confirmed.json."""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "confirmed.json")
    with open(path, "w") as f:
        json.dump(confirmed, f, indent=2)
    return path


def _format_findings_for_llm(findings: list[dict]) -> str:
    lines = []
    for i, f in enumerate(findings[:10]):  # cap at 10 per file
        lines.append(
            f"{i+1}. Rule: {f.get('check_id', '?')} | "
            f"Line: {f.get('start', {}).get('line', '?')} | "
            f"Severity: {f.get('extra', {}).get('severity', '?')}\n"
            f"   Message: {f.get('extra', {}).get('message', '')[:150]}"
        )
    return "\n".join(lines)


def _read_source_snippet(file_path: str, repo_path: str, max_lines: int = 100) -> str:
    """Read first max_lines of a source file for LLM context."""
    # If file_path is relative, join with repo_path
    full_path = file_path
    if not os.path.isabs(file_path) and repo_path:
        full_path = os.path.join(repo_path, file_path)

    try:
        with open(full_path, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[:max_lines]
        return "".join(lines)
    except Exception:
        return "(source not available)"
