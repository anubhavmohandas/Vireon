"""
scanner/graph.py — Lightweight dependency graph builder

Builds a NetworkX graph from detected stack + CVEs.
Standalone replacement for SAGE's synapse module.
No tree-sitter required — pure import scanning.
"""

import os
import re
from pathlib import Path

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False


def build_graph(repo_path: str, stack: dict[str, str], cves: list[dict]):
    """
    Build a dependency graph:
      repo → package → CVE

    Also scans Python files for import statements to add
    file → package edges (basic call graph).

    Returns: nx.DiGraph or None if networkx not available
    """
    if not HAS_NETWORKX:
        if os.getenv("VIREON_VERBOSE") == "1":
            print("[graph] networkx not installed — skipping graph build")
        return None

    import networkx as nx
    G = nx.DiGraph()

    repo_name = Path(repo_path).name
    G.add_node("repo", type="repo", name=repo_name, path=repo_path)

    # Add library nodes
    for pkg, version in stack.items():
        G.add_node(pkg, type="library", name=pkg, version=version)
        G.add_edge("repo", pkg, relation="depends_on")

    # Add CVE nodes
    for cve in cves:
        m = cve.get("sage_match", {})
        cve_id = m.get("cve_id", "")
        pkg = m.get("package", "")
        if cve_id and pkg and pkg in G.nodes:
            G.add_node(cve_id, type="cve", **m)
            G.add_edge(pkg, cve_id, relation="has_cve")

    # Basic file scanning — find which files import which packages
    py_files = _scan_python_files(repo_path)
    for file_path, imports in py_files.items():
        rel_path = os.path.relpath(file_path, repo_path)
        G.add_node(rel_path, type="file", path=file_path)
        G.add_edge("repo", rel_path, relation="contains")
        for imp in imports:
            if imp in G.nodes:
                G.add_edge(rel_path, imp, relation="imports")

    if os.getenv("VIREON_VERBOSE") == "1":
        print(f"[graph] Built graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G


def cves_from_graph(G) -> list[dict]:
    """
    Extract one dict per unique CVE node from the dependency graph.

    Carries the FULL fix metadata (fixed_version, installed_version, severity,
    cvss_score, attack_vector, description) so downstream dep-bump generation can
    pin an exact safe version instead of falling back to "latest".

    Returns [] for a missing/empty graph — never raises.
    """
    if G is None:
        return []

    out: list[dict] = []
    seen: set[str] = set()
    try:
        nodes = list(G.nodes(data=True))
    except Exception:
        return []

    for node, data in nodes:
        if not isinstance(data, dict) or data.get("type") != "cve":
            continue
        cve_id = data.get("cve_id", node)
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        out.append({
            "cve_id":            cve_id,
            "package":           data.get("package", ""),
            "installed_version": data.get("installed_version", ""),
            "fixed_version":     data.get("fixed_version", ""),
            "affected_range":    data.get("affected_range", ""),
            "severity":          data.get("severity", "UNKNOWN"),
            "cvss_score":        data.get("cvss_score", 0.0),
            "attack_vector":     data.get("attack_vector", "UNKNOWN"),
            "description":       data.get("description", ""),
        })
    return out


def _scan_python_files(repo_path: str) -> dict[str, list[str]]:
    """Scan Python files and extract import statements."""
    result = {}
    import_pattern = re.compile(
        r"^\s*(?:import|from)\s+([a-zA-Z_][a-zA-Z0-9_]*)"
    )

    for root, dirs, files in os.walk(repo_path):
        # Skip common non-source dirs
        dirs[:] = [d for d in dirs if d not in {
            ".git", "__pycache__", "node_modules", ".venv", "venv",
            "env", "myvenv", ".mypy_cache", "dist", "build", "*.egg-info"
        }]

        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            imports = []
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        m = import_pattern.match(line)
                        if m:
                            imports.append(m.group(1).lower().replace("-", "_"))
            except Exception:
                pass
            if imports:
                result[fpath] = list(set(imports))

    return result
