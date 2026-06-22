"""
eval_fixtures/safe.py — NEGATIVE CONTROLS for the exploitability harness.

Every function here is written CORRECTLY. The right answer for each is
"not vulnerable". If the analyzer flags one as exploitable, that's a FALSE
POSITIVE — the model crying wolf, which is as useless as missing a real bug.

These exist because a harness made only of real bugs can be passed by a model
that just answers "vulnerable" to everything. Negative controls are what make
the test measure judgment instead of pessimism.
"""

from urllib.parse import urlparse

import requests
import subprocess
import yaml
from sqlalchemy import create_engine, text

_engine = create_engine("sqlite:///demo.db")
_ALLOWED_HOSTS = {"example.com", "app.example.com"}


def safe_search(name: str):
    """SAFE: bound parameter — the value never becomes SQL."""
    with _engine.connect() as conn:
        result = conn.execute(
            text("SELECT * FROM users WHERE name = :name"), {"name": name}
        )
        return result.fetchall()


def safe_load_config(config_str: str) -> dict:
    """SAFE: safe_load cannot construct arbitrary Python objects."""
    return yaml.safe_load(config_str)


def safe_run(host: str) -> str:
    """SAFE: argument vector, no shell — nothing to inject into."""
    completed = subprocess.run(
        ["ping", "-c", "1", host], capture_output=True, text=True
    )
    return completed.stdout


def safe_redirect(target: str) -> str:
    """SAFE: only redirect when the parsed host is on the allowlist."""
    host = urlparse(target).hostname or ""
    if host in _ALLOWED_HOSTS:
        return target
    return "/"


def safe_fetch(url: str) -> str:
    """SAFE: TLS verification is on (the default) — no MITM."""
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    return resp.text
