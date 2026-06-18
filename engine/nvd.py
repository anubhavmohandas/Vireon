"""
scanner/nvd.py — NVD supplemental CVE lookup

Secondary source — supplements OSV with NVD data.
Queries NVD's keyword search per package rather than fetching all CVEs.
Much more targeted than SAGE's date-range fetch approach.

NVD API: https://nvd.nist.gov/developers/vulnerabilities
"""

import os
import time
import requests

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SLEEP = 0.7  # with API key; without key use 6.5
MAX_PER_PKG = 20  # max CVEs to fetch per package


def fetch_nvd_for_stack(stack: dict[str, str], days: int = 90) -> list[dict]:
    """
    Query NVD keyword search for each package in the stack.
    Returns normalized CVE dicts with sage_match attached.
    """
    api_key = os.getenv("NVD_API_KEY", "")
    if not api_key:
        print("[nvd] No NVD_API_KEY — skipping NVD (OSV will cover PyPI packages)")
        return []

    headers = {"Accept": "application/json", "apiKey": api_key}
    results = []
    seen_ids = set()

    for pkg, version in list(stack.items())[:30]:  # Cap at 30 packages to avoid rate limits
        pkg_clean = pkg.replace("_", "-")
        try:
            resp = requests.get(
                NVD_BASE,
                params={"keywordSearch": pkg_clean, "resultsPerPage": MAX_PER_PKG},
                headers=headers,
                timeout=15,
            )
            time.sleep(SLEEP)

            if resp.status_code != 200:
                continue

            data = resp.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id or cve_id in seen_ids:
                    continue

                entry = _normalize(cve, pkg, version)
                if entry:
                    seen_ids.add(cve_id)
                    results.append(entry)

        except Exception as e:
            print(f"[nvd] Error fetching {pkg}: {e}")
            continue

    print(f"[nvd] {len(results)} additional CVEs from NVD keyword search")
    return results


def _normalize(cve: dict, pkg_name: str, pkg_version: str) -> dict | None:
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # Description
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")[:300]
            break

    # Severity + attack vector
    severity = "UNKNOWN"
    cvss_score = 0.0
    attack_vector = "UNKNOWN"
    metrics = cve.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            try:
                data = metrics[key][0]["cvssData"]
                severity = data.get("baseSeverity", "UNKNOWN")
                cvss_score = float(data.get("baseScore", 0))
                # CVSSv3.x uses "attackVector"; CVSSv2 uses "accessVector"
                av_raw = data.get("attackVector") or data.get("accessVector", "")
                if av_raw:
                    # Normalise CVSSv2 ADJACENT_NETWORK → ADJACENT
                    attack_vector = av_raw.replace("_NETWORK", "").upper()
                break
            except (KeyError, IndexError, TypeError):
                pass

    return {
        "sage_match": {
            "cve_id":            cve_id,
            "package":           pkg_name,
            "installed_version": pkg_version,
            "severity":          severity,
            "cvss_score":        cvss_score,
            "description":       desc,
            "attack_vector":     attack_vector,
            "source":            "NVD",
        },
    }
