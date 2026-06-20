"""
engine/attack_path.py — Real source→sink attack-path analysis

Replaces the old "fake BFS" reachability (repo → package → CVE) with an actual
attack path through the CODE:

    external entry point  →  tainted input source  →  vulnerable call (sink)  →  impact

It works on the AST of the scanned repo, so the path is the real sequence an
attacker would traverse — an HTTP route, the request field they control, the
function chain that carries it, and the exact line where it detonates.

Design constraints (this runs mid-pipeline on a demo):
  * NEVER raises. Every public entry is wrapped; on any failure it returns a
    degraded path (sink only) rather than crashing the investigation.
  * Pure stdlib (`ast`) — no tree-sitter, no extra dependency.
  * Bounded — caps files scanned and path depth so a huge repo can't stall.
"""

from __future__ import annotations

import ast
import os

# Directories we never walk when building the cross-file caller index.
_SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env", "myvenv",
    ".mypy_cache", "dist", "build", ".pytest_cache", "data",
}

# Cap the caller index so a massive repo can't blow up the demo.
_MAX_INDEX_FILES = 400

# Web entry-point decorators → these mean "an external HTTP request reaches here".
_ROUTE_ATTRS = {"route", "get", "post", "put", "delete", "patch", "websocket", "head", "options"}

# Attribute chains on `request` that carry attacker-controlled input.
_REQUEST_TAINT_ATTRS = {
    "args", "form", "values", "json", "data", "files",
    "cookies", "headers", "get_json", "query_params", "path_params", "body",
}


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def build_attack_paths(
    confirmed: list[dict],
    repo_path: str,
    graph=None,
) -> list[dict]:
    """
    Build one attack-path dict per exploitable finding.

    Args:
        confirmed: output of llm_analyzer.analyze_findings (uses vulnerable=True subset)
        repo_path: repo root (findings carry repo-relative paths)
        graph:     optional dependency graph (unused today; kept for signature stability)

    Returns:
        list[dict] — see _empty_path() for the schema. Never raises.
    """
    try:
        exploitable = [c for c in (confirmed or []) if isinstance(c, dict) and c.get("vulnerable")]
        if not exploitable:
            return []

        caller_index = _build_caller_index(repo_path)
        paths = []
        for finding in exploitable:
            try:
                paths.append(_analyze_finding(finding, repo_path, caller_index))
            except Exception:
                paths.append(_empty_path(finding))
        return paths
    except Exception:
        return []


def attach_attack_paths(confirmed: list[dict], repo_path: str, graph=None) -> list[dict]:
    """
    Convenience: build paths and attach each onto its finding under
    ``finding["attack_path"]``. Mutates and returns ``confirmed``.
    """
    try:
        paths = build_attack_paths(confirmed, repo_path, graph=graph)
        by_key = {(p.get("check_id", ""), p.get("file", ""), p.get("line", 0)): p for p in paths}
        for c in confirmed or []:
            if not isinstance(c, dict) or not c.get("vulnerable"):
                continue
            key = (c.get("check_id", ""), _rel(c.get("path", ""), repo_path), c.get("line", 0))
            p = by_key.get(key)
            if p is None:
                # fall back to check_id-only match
                p = next((pp for pp in paths if pp.get("check_id") == c.get("check_id")), None)
            if p:
                c["attack_path"] = p
    except Exception:
        pass
    return confirmed


# ──────────────────────────────────────────────────────────────────────────────
# Per-finding analysis
# ──────────────────────────────────────────────────────────────────────────────

def _analyze_finding(finding: dict, repo_path: str, caller_index: dict) -> dict:
    rel_path = _rel(finding.get("path", ""), repo_path)
    abs_path = _abs(finding.get("path", ""), repo_path)
    sink_line = int(finding.get("line", 0) or 0)
    check_id = finding.get("check_id", "")
    cwe = _cwe_str(finding.get("cwe", ""))
    message = finding.get("reason", "") or finding.get("attack_vector", "")

    source_lines = _read_lines(abs_path)
    sink_code = source_lines[sink_line - 1].strip() if 0 < sink_line <= len(source_lines) else ""

    path = _empty_path(finding)
    path["file"] = rel_path
    path["line"] = sink_line
    path["sink"] = {
        "file": rel_path,
        "line": sink_line,
        "code": sink_code,
        "check_id": check_id,
        "cwe": cwe,
    }
    path["impact"] = _impact_for(check_id, cwe, message)

    tree = _safe_parse(abs_path)
    if tree is None:
        # Can't analyze code — degraded path: sink + impact only.
        path["steps"] = [_step("Vulnerable sink", rel_path, sink_line, sink_code)]
        path["summary"] = _summary(None, None, rel_path, sink_line, path["impact"])
        return path

    enclosing = _enclosing_function(tree, sink_line)
    fn_name = enclosing.name if enclosing else ""
    path["sink_function"] = fn_name

    # 1) Taint source inside the enclosing function (request.*, params, input()).
    source = _find_taint_source(enclosing, source_lines, rel_path) if enclosing else None
    if source:
        path["source"] = source

    # 2) Entry point: is the enclosing function itself a web route?
    entry, steps = _resolve_entry(
        enclosing, rel_path, source_lines, caller_index, repo_path,
    )
    path["entry_point"] = entry
    path["reachable"] = entry.get("kind") in ("http_route", "cli")

    # 3) Assemble the ordered steps: entry → source → sink.
    chain = list(steps)
    if source:
        chain.append(_step(
            f"Tainted input: {source['description']}",
            source["file"], source["line"], source.get("code", ""),
        ))
    chain.append(_step(
        f"Vulnerable sink ({check_id or 'finding'})",
        rel_path, sink_line, sink_code,
    ))
    path["steps"] = chain

    path["summary"] = _summary(entry, source, rel_path, sink_line, path["impact"])
    path["narrative"] = _narrative(path)
    return path


def _resolve_entry(enclosing, rel_path, source_lines, caller_index, repo_path):
    """
    Return (entry_point_dict, prefix_steps).

    Tries, in order: route decorator on the enclosing fn → a route-decorated
    caller elsewhere in the repo → a public function taking parameters →
    unknown.
    """
    if enclosing is None:
        return {"kind": "unknown", "function": "", "file": rel_path}, []

    # (a) The vulnerable function is itself an HTTP handler.
    route = _route_from_decorators(enclosing)
    if route:
        entry = {
            "kind": "http_route",
            "method": route["method"],
            "route": route["route"],
            "function": enclosing.name,
            "file": rel_path,
            "line": enclosing.lineno,
        }
        step = _step(
            f"HTTP {route['method']} {route['route']}",
            rel_path, enclosing.lineno,
            f"@{route['raw']}  def {enclosing.name}(...)",
        )
        return entry, [step]

    # (b) A function elsewhere that calls this one IS an HTTP handler.
    callers = caller_index.get(enclosing.name, [])
    for caller in callers[:8]:
        if caller.get("route"):
            r = caller["route"]
            entry = {
                "kind": "http_route",
                "method": r["method"],
                "route": r["route"],
                "function": caller["function"],
                "file": caller["file"],
                "line": caller["line"],
                "via": enclosing.name,
            }
            steps = [
                _step(f"HTTP {r['method']} {r['route']}", caller["file"], caller["line"],
                      f"def {caller['function']}(...)"),
                _step(f"calls {enclosing.name}(...)", caller["file"], caller["call_line"],
                      caller.get("call_code", "")),
            ]
            return entry, steps

    # (c) Public function that accepts parameters → caller-supplied input.
    params = [a.arg for a in getattr(enclosing.args, "args", []) if a.arg not in ("self", "cls")]
    if params:
        entry = {
            "kind": "function",
            "function": enclosing.name,
            "file": rel_path,
            "line": enclosing.lineno,
            "params": params,
        }
        step = _step(
            f"Call {enclosing.name}({', '.join(params)})",
            rel_path, enclosing.lineno,
            f"def {enclosing.name}({', '.join(params)})",
        )
        return entry, [step]

    # (d) Unknown entry.
    return {"kind": "unknown", "function": enclosing.name, "file": rel_path, "line": enclosing.lineno}, []


# ──────────────────────────────────────────────────────────────────────────────
# AST helpers
# ──────────────────────────────────────────────────────────────────────────────

def _safe_parse(abs_path: str):
    try:
        with open(abs_path, encoding="utf-8", errors="ignore") as f:
            return ast.parse(f.read())
    except Exception:
        return None


def _enclosing_function(tree, line: int):
    """Smallest FunctionDef/AsyncFunctionDef whose span contains `line`."""
    best = None
    best_span = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", None) or start
            if start <= line <= end:
                span = end - start
                if best_span is None or span < best_span:
                    best, best_span = node, span
    return best


def _route_from_decorators(fn) -> dict | None:
    """Extract {method, route, raw} from Flask/FastAPI route decorators, else None."""
    for dec in getattr(fn, "decorator_list", []):
        if not isinstance(dec, ast.Call):
            continue
        func = dec.func
        attr = func.attr if isinstance(func, ast.Attribute) else None
        if attr not in _ROUTE_ATTRS:
            continue

        # URL is the first positional string arg.
        route = "/"
        if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
            route = dec.args[0].value

        # Method: explicit methods=[...] (Flask) or the decorator verb (FastAPI/Flask shortcuts).
        method = attr.upper() if attr != "route" else "GET"
        for kw in dec.keywords or []:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                vals = [e.value for e in kw.value.elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                if vals:
                    method = "/".join(v.upper() for v in vals)

        base = func.value.id if isinstance(func.value, ast.Name) else "app"
        raw = f"{base}.{attr}(\"{route}\")"
        return {"method": method, "route": route, "raw": raw}
    return None


def _find_taint_source(fn, source_lines, rel_path) -> dict | None:
    """
    Find where attacker-controlled input enters the function:
    request.args/form/json/..., input(), sys.argv, or a parameter.
    Returns {description, file, line, code} or None.
    """
    if fn is None:
        return None

    for node in ast.walk(fn):
        # request.args.get(...) / request.form[...] / request.get_json()
        if isinstance(node, ast.Attribute) and node.attr in _REQUEST_TAINT_ATTRS:
            if _chain_root_is_request(node):
                ln = getattr(node, "lineno", fn.lineno)
                return {
                    "description": f"request.{node.attr}",
                    "file": rel_path,
                    "line": ln,
                    "code": _line(source_lines, ln),
                }
        # input(...)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "input":
            ln = getattr(node, "lineno", fn.lineno)
            return {"description": "input()", "file": rel_path, "line": ln, "code": _line(source_lines, ln)}
        # sys.argv
        if isinstance(node, ast.Attribute) and node.attr == "argv":
            ln = getattr(node, "lineno", fn.lineno)
            return {"description": "sys.argv", "file": rel_path, "line": ln, "code": _line(source_lines, ln)}

    # Fallback: a function parameter is the externally-supplied value.
    params = [a.arg for a in getattr(fn.args, "args", []) if a.arg not in ("self", "cls")]
    if params:
        return {
            "description": f"parameter '{params[0]}'",
            "file": rel_path,
            "line": fn.lineno,
            "code": _line(source_lines, fn.lineno),
        }
    return None


def _chain_root_is_request(node) -> bool:
    """True if the attribute chain bottoms out at a Name called 'request'."""
    cur = node
    depth = 0
    while isinstance(cur, ast.Attribute) and depth < 6:
        cur = cur.value
        depth += 1
    if isinstance(cur, ast.Call):
        cur = cur.func
        while isinstance(cur, ast.Attribute) and depth < 8:
            cur = cur.value
            depth += 1
    return isinstance(cur, ast.Name) and cur.id == "request"


# ──────────────────────────────────────────────────────────────────────────────
# Cross-file caller index (light call graph)
# ──────────────────────────────────────────────────────────────────────────────

def _build_caller_index(repo_path: str) -> dict:
    """
    Map callee_name → [ {function, file, line, call_line, call_code, route} ]
    for every call site in the repo. `route` is set when the calling function is
    itself an HTTP handler — that's what lets us chain route → helper → sink.
    Bounded by _MAX_INDEX_FILES. Never raises.
    """
    index: dict[str, list] = {}
    try:
        count = 0
        for root, dirs, files in os.walk(repo_path or "."):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                if count >= _MAX_INDEX_FILES:
                    return index
                count += 1
                fpath = os.path.join(root, fname)
                rel = _rel(fpath, repo_path)
                tree = _safe_parse(fpath)
                if tree is None:
                    continue
                _index_file(tree, rel, index)
    except Exception:
        pass
    return index


def _index_file(tree, rel: str, index: dict):
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route = _route_from_decorators(fn)
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                callee = _called_name(node.func)
                if not callee:
                    continue
                index.setdefault(callee, []).append({
                    "function": fn.name,
                    "file": rel,
                    "line": fn.lineno,
                    "call_line": getattr(node, "lineno", fn.lineno),
                    "call_code": "",
                    "route": route,
                })


def _called_name(func) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


# ──────────────────────────────────────────────────────────────────────────────
# Impact mapping
# ──────────────────────────────────────────────────────────────────────────────

# (keyword substrings, impact statement). First match wins.
_IMPACT_RULES = [
    (("eval", "exec", "code-injection", "code_injection", "cwe-94", "cwe-95"),
     "Remote code execution — attacker runs arbitrary Python on the host"),
    (("command", "subprocess", "shell", "os-system", "cwe-78"),
     "Command injection — arbitrary OS commands on the host"),
    (("ssti", "template", "render", "jinja", "cwe-1336"),
     "Server-side template injection → remote code execution"),
    (("deserial", "yaml", "pickle", "marshal", "cwe-502"),
     "Insecure deserialization → remote code execution"),
    (("sql", "sqli", "cwe-89"),
     "SQL injection — read, modify or exfiltrate the entire database"),
    (("path-travers", "path_travers", "traversal", "cwe-22"),
     "Path traversal — read or overwrite arbitrary files on disk"),
    (("ssrf", "cwe-918"),
     "SSRF — pivot from the server into internal networks/metadata"),
    (("redirect", "cwe-601"),
     "Open redirect — phishing and OAuth token theft"),
    (("xss", "cross-site", "cwe-79"),
     "Cross-site scripting — session hijacking / credential theft"),
    (("ssl", "verify", "tls", "certificate", "cwe-295"),
     "TLS verification disabled — man-in-the-middle of all traffic"),
    (("secret", "hardcoded", "credential", "cwe-798"),
     "Hardcoded credential — direct unauthorized access"),
    (("xxe", "cwe-611"),
     "XXE — file disclosure and SSRF via XML entities"),
]


def _impact_for(check_id: str, cwe: str, message: str) -> str:
    blob = " ".join([str(check_id), str(cwe), str(message)]).lower()
    for keywords, impact in _IMPACT_RULES:
        if any(k in blob for k in keywords):
            return impact
    return "Exploitable vulnerability — integrity/confidentiality impact"


# ──────────────────────────────────────────────────────────────────────────────
# Formatting helpers
# ──────────────────────────────────────────────────────────────────────────────

def _summary(entry, source, rel_path, sink_line, impact) -> str:
    """One-line attacker's-eye view of the chain."""
    parts = []
    if entry and entry.get("kind") == "http_route":
        parts.append(f"Attacker → {entry.get('method','GET')} {entry.get('route','/')}")
        if entry.get("via"):
            parts.append(f"{entry['function']}() → {entry['via']}()")
        else:
            parts.append(f"{entry.get('function','handler')}()")
    elif entry and entry.get("kind") == "cli":
        parts.append(f"Attacker → CLI {entry.get('function','main')}()")
    elif entry and entry.get("kind") == "function":
        parts.append(f"Caller → {entry.get('function','fn')}({', '.join(entry.get('params', []))})")
    else:
        parts.append("Untrusted input")
    if source:
        parts.append(source["description"])
    parts.append(f"{os.path.basename(rel_path)}:{sink_line}")
    parts.append(impact)
    return "  →  ".join(parts)


def _narrative(path: dict) -> list[str]:
    """Numbered human-readable steps for the PR body / CLI."""
    out = []
    for i, s in enumerate(path.get("steps", []), 1):
        loc = f" ({s['file']}:{s['line']})" if s.get("line") else ""
        out.append(f"{i}. {s['label']}{loc}")
    return out


def _step(label, file, line, code) -> dict:
    return {"label": label, "file": file, "line": int(line or 0), "code": (code or "").strip()[:200]}


def _empty_path(finding: dict) -> dict:
    return {
        "cve_id": finding.get("cve_id", ""),
        "check_id": finding.get("check_id", ""),
        "file": _rel(finding.get("path", ""), ""),
        "line": int(finding.get("line", 0) or 0),
        "reachable": False,
        "entry_point": {"kind": "unknown"},
        "source": None,
        "sink_function": "",
        "sink": {
            "file": finding.get("path", ""),
            "line": int(finding.get("line", 0) or 0),
            "code": "",
            "check_id": finding.get("check_id", ""),
            "cwe": _cwe_str(finding.get("cwe", "")),
        },
        "steps": [],
        "impact": _impact_for(finding.get("check_id", ""), finding.get("cwe", ""), finding.get("reason", "")),
        "summary": "",
        "narrative": [],
    }


# ──────────────────────────────────────────────────────────────────────────────
# Path / string utilities
# ──────────────────────────────────────────────────────────────────────────────

def _abs(path: str, repo_path: str) -> str:
    if not path:
        return ""
    if os.path.isabs(path):
        return path
    return os.path.join(repo_path or "", path)


def _rel(path: str, repo_path: str) -> str:
    if not path:
        return ""
    if repo_path and os.path.isabs(path):
        try:
            return os.path.relpath(path, repo_path)
        except Exception:
            return path
    return path


def _read_lines(abs_path: str) -> list[str]:
    try:
        with open(abs_path, encoding="utf-8", errors="ignore") as f:
            return f.read().splitlines()
    except Exception:
        return []


def _line(lines: list[str], n: int) -> str:
    return lines[n - 1].strip()[:200] if 0 < n <= len(lines) else ""


def _cwe_str(cwe) -> str:
    if isinstance(cwe, (list, tuple)):
        return ", ".join(str(c) for c in cwe)
    return str(cwe or "")
