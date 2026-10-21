"""
Proxy client — CVE-2024-47081 proxy credential leak via redirect.
"""
import requests
import os


def make_proxied_request(target_url: str) -> str:
    """Make a request through a proxy. Auth headers leak on redirect."""
    proxy_url = os.getenv("CORP_PROXY", "http://proxy.internal:3128")
    proxy_user = os.getenv("PROXY_USER", "")
    proxy_pass = os.getenv("PROXY_PASS", "")

    if proxy_user:
        proxy_url = f"http://{proxy_user}:{proxy_pass}@proxy.internal:3128"

    proxies = {"http": proxy_url, "https": proxy_url}

    session = requests.Session()
    # VULN: Proxy-Authorization header leaks to destination on cross-host redirect
    # CVE-2024-47081 — fixed in requests 2.32.3
    resp = session.get(target_url, proxies=proxies)
    return resp.text
