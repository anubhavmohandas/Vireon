"""
eval_fixtures/subtle.py — SUBTLE POSITIVES for the exploitability harness.

Each function IS exploitable, but the bug hides behind a guard that LOOKS
protective. The right answer is "vulnerable". These are the hard cases — the
ones that separate pattern-matching from real reasoning.

They are NOT gated in the harness (reasonable models can disagree on the
edges); the harness just reports whether the model saw past the decoy.
"""

import shlex
import subprocess

import yaml


def subtle_redirect(target: str) -> str:
    """
    VULN: startswith() is not a host check. 'https://trusted.com.evil.com'
    and 'https://trusted.com@evil.com' both pass — open redirect / SSRF.
    """
    if target.startswith("https://trusted.com"):
        return target
    return "/"


def subtle_yaml(config_str: str) -> dict:
    """
    VULN: people add Loader= thinking it's the safe knob, but yaml.Loader IS
    the full loader — arbitrary object construction / code execution.
    """
    return yaml.load(config_str, Loader=yaml.Loader)


def subtle_command(host: str, count: str) -> str:
    """
    VULN: host is shell-quoted (looks handled), but count is concatenated raw
    into a shell string — inject via count, e.g. '1; rm -rf /'.
    """
    cmd = f"ping {shlex.quote(host)} -c {count}"
    completed = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return completed.stdout
