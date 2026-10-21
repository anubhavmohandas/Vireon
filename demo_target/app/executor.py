"""
Code execution module — vulnerable to RCE (eval on user input).
Simulates CVE-2024-6345 attack surface.
"""
import subprocess
import yaml


def run_expression(user_input: str) -> object:
    """Evaluate a user-provided expression."""
    # VULN: eval on user-controlled input — RCE
    result = eval(user_input)
    return result


def load_config(config_str: str) -> dict:
    """Load YAML configuration from string."""
    # VULN: yaml.load without Loader — CVE-2022-30917 (arbitrary code exec)
    return yaml.load(config_str)


def run_command(cmd: str) -> str:
    """Run a shell command."""
    # VULN: shell=True with user input — command injection
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
