"""
HTTP client module — vulnerable to CVE-2024-35195 (no SSL verify)
and CVE-2024-47081 (proxy credential leak).
"""
import requests
import os

PROXY = os.getenv("HTTP_PROXY", "")


def fetch_url(url: str, timeout: int = 10) -> str:
    """Fetch a URL. SSL verification disabled for 'compatibility'."""
    # VULN: verify=False — CVE-2024-35195
    resp = requests.get(url, verify=False, timeout=timeout)
    resp.raise_for_status()
    return resp.text


def fetch_with_proxy(url: str) -> str:
    """Fetch through corporate proxy — leaks proxy auth on redirect."""
    proxies = {"http": PROXY, "https": PROXY}
    # VULN: proxy credentials leak via redirect — CVE-2024-47081
    session = requests.Session()
    session.proxies = proxies
    resp = session.get(url)
    return resp.text


def post_data(url: str, data: dict) -> dict:
    """POST JSON data to an endpoint."""
    # VULN: no SSL verify again
    resp = requests.post(url, json=data, verify=False)
    return resp.json()
