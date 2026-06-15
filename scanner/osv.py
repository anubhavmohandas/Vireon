"""
scanner/osv.py — OSV.dev vulnerability lookup

Primary CVE source for Vireon. Queries by package name directly —
no CPE name-matching guesswork like NVD requires.
Free, no API key, works for PyPI, npm, Go, Rust, Maven, etc.

API: https://google.github.io/osv.dev/post-v1-query/
"""

import re
import requests

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

_ECOSYSTEM_MAP = {
    # Python packages → PyPI
    "requests": "PyPI", "flask": "PyPI", "django": "PyPI",
    "fastapi": "PyPI", "sqlalchemy": "PyPI", "pyyaml": "PyPI",
    "pillow": "PyPI", "cryptography": "PyPI", "werkzeug": "PyPI",
    "jinja2": "PyPI", "urllib3": "PyPI", "setuptools": "PyPI",
    "pip": "PyPI", "numpy": "PyPI", "pandas": "PyPI",
    "aiohttp": "PyPI", "httpx": "PyPI", "paramiko": "PyPI",
    "twisted": "PyPI", "tornado": "PyPI", "gunicorn": "PyPI",
    "celery": "PyPI", "redis": "PyPI", "pymongo": "PyPI",
    "anthropic": "PyPI", "openai": "PyPI", "langchain": "PyPI",
    "transformers": "PyPI", "torch": "PyPI", "tensorflow": "PyPI",
}

_JS_PACKAGES = {
    "express", "react", "vue", "angular", "next", "axios", "lodash",
    "moment", "jquery", "webpack", "babel", "jest", "typescript",
    "socket.io", "multer", "passport", "jsonwebtoken", "bcrypt",
    "mongoose", "sequelize", "pg", "mysql2", "tar", "semver",
    "minimist", "ansi-regex", "cross-spawn", "got", "node-fetch",
    "sharp", "uuid", "debug", "dotenv", "cors", "helmet",
}


def fetch_osv_for_stack(stack: dict[str, str]) -> list[dict]:
    """
    Query OSV for every package in the stack.
    Returns list of normalized CVE dicts with sage_match attached.
    """
    if not stack:
        return []

    # Determine ecosystem per package
    queries = []
    pkg_list = []

    for pkg, version in stack.items():
        pkg_lower = pkg.lower().replace("_", "-")
        ecosystem = _detect_ecosystem(pkg_lower)
        if not ecosystem:
            continue

        query: dict = {"package": {"name": pkg_lower, "ecosystem": ecosystem}}
        if version and version != "any":
            bare = _bare_version(version)
            if bare:
                query["version"] = bare

        queries.append(query)
        pkg_list.append((pkg, version, ecosystem))

    if not queries:
        return []

    # OSV batch endpoint — one call for all packages
    try:
        resp = requests.post(
            OSV_BATCH_URL,
            json={"queries": queries},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[osv] Query failed: {e}")
        return []

    results_list = data.get("results", [])
    normalized = []
    seen_ids = set()

    for i, result in enumerate(results_list):
        vulns = result.get("vulns", [])
        if not vulns or i >= len(pkg_list):
            continue

        pkg_name, pkg_version, ecosystem = pkg_list[i]

        for vuln in vulns:
            entry = _normalize(vuln, pkg_name, pkg_version)
            if not entry:
                continue
            vid = entry["sage_match"]["cve_id"]
            if vid not in seen_ids:
                seen_ids.add(vid)
                normalized.append(entry)

    print(f"[osv] {len(normalized)} vulnerabilities found across {len(stack)} packages")
    return normalized


def _detect_ecosystem(pkg: str) -> str | None:
    """Guess the ecosystem for a package name."""
    if pkg in _ECOSYSTEM_MAP:
        return _ECOSYSTEM_MAP[pkg]
    if pkg in _JS_PACKAGES:
        return "npm"
    # Default Python packages to PyPI
    return "PyPI"


def _bare_version(version: str) -> str:
    """Strip specifier operators to get a bare version string."""
    v = version.lstrip("=><!~").split(",")[0].strip()
    # Remove any remaining operators
    v = re.sub(r"^[=><!~]+", "", v).strip() if v else ""
    return v


def _normalize(vuln: dict, pkg_name: str, pkg_version: str) -> dict | None:
    """Normalize an OSV vuln record into Vireon's CVE format."""
    vuln_id = vuln.get("id", "UNKNOWN")

    # Prefer CVE alias
    cve_id = vuln_id
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            cve_id = alias
            break

    summary = (vuln.get("summary") or vuln.get("details") or "")[:300]

    # Severity from database_specific (GitHub/OSV often puts it here)
    severity = "UNKNOWN"
    cvss_score = 0.0
    db = vuln.get("database_specific", {})
    if "severity" in db:
        severity = db["severity"].upper()
    if "cvss_score" in db:
        try:
            cvss_score = float(db["cvss_score"])
            severity = _score_to_severity(cvss_score)
        except (TypeError, ValueError):
            pass

    # Also check severity array
    for sev in vuln.get("severity", []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
            try:
                score_str = sev.get("score", "")
                # CVSS vector — extract AV component for attack_vector
                pass
            except Exception:
                pass

    # Extract fixed version
    fixed_version = ""
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower().replace("-", "_") == pkg_name.lower().replace("-", "_"):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        fixed_version = event["fixed"]
                        break

    return {
        "osv_id": vuln_id,
        "sage_match": {
            "cve_id":            cve_id,
            "package":           pkg_name,
            "installed_version": pkg_version,
            "fixed_version":     fixed_version,
            "severity":          severity,
            "cvss_score":        cvss_score,
            "description":       summary,
            "attack_vector":     "NETWORK",
            "source":            "OSV",
        },
    }


def _score_to_severity(score: float) -> str:
    if score >= 9.0:  return "CRITICAL"
    if score >= 7.0:  return "HIGH"
    if score >= 4.0:  return "MEDIUM"
    if score > 0:     return "LOW"
    return "UNKNOWN"


