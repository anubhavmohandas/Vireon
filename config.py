"""
config.py — Vireon configuration

Loads env vars for:
  - Band SDK (agent IDs + API keys per agent)
  - AI/ML API (used instead of direct Anthropic — hackathon credits)
  - SAGE passthrough (NVD_API_KEY, GITHUB_TOKEN)

AI/ML API is OpenAI-compatible and proxies Claude + 200+ other models.
Get your key at: aimlapi.com → claim via lablab.ai coupon (BANDHACK26)

Band agent IDs: create each agent at app.band.ai → Agents → New Agent (Remote Agent)
Copy the UUID and API key from each agent's settings page.
"""

import os
import anthropic
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


def make_llm_client() -> anthropic.Anthropic:
    """
    Returns an Anthropic client pointed at AI/ML API if AIML_API_KEY is set,
    otherwise falls back to direct Anthropic (for local dev with own key).

    AI/ML API is OpenAI-compatible but also exposes an Anthropic-compatible
    endpoint at https://api.aimlapi.com — we use the anthropic SDK with a
    custom base_url.
    """
    aiml_key = os.getenv("AIML_API_KEY", "")
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")

    if aiml_key:
        return anthropic.Anthropic(
            api_key=aiml_key,
            base_url="https://api.aimlapi.com/v1",
        )
    elif anthropic_key:
        return anthropic.Anthropic(api_key=anthropic_key)
    else:
        raise EnvironmentError(
            "\n[Vireon] No LLM API key found.\n"
            "Set AIML_API_KEY (hackathon credits) or ANTHROPIC_API_KEY in .env\n"
        )


@dataclass
class VireonConfig:
    # ── LLM keys (use AIML_API_KEY for hackathon credits, ANTHROPIC_API_KEY for direct) ──
    AIML_API_KEY: str = ""         # AI/ML API key (hackathon: $10 credits)
    ANTHROPIC_API_KEY: str = ""    # direct Anthropic (local dev fallback)

    # ── SAGE passthrough ──────────────────────────────────────────────────────
    NVD_API_KEY: str = ""
    GITHUB_TOKEN: str = ""
    GITHUB_REPO: str = ""

    # ── Band connection ───────────────────────────────────────────────────────
    BAND_REST_URL: str = "https://app.band.ai/"
    BAND_WS_URL: str = "wss://app.band.ai/api/v1/socket/websocket"

    # ── Band agent IDs + keys (one per agent) ────────────────────────────────
    # Get these from app.band.ai → Agents → <agent> → Settings
    THREAT_AGENT_ID: str = ""
    THREAT_AGENT_KEY: str = ""

    GRAPH_AGENT_ID: str = ""
    GRAPH_AGENT_KEY: str = ""

    STATIC_AGENT_ID: str = ""
    STATIC_AGENT_KEY: str = ""

    EXPLOITABILITY_AGENT_ID: str = ""
    EXPLOITABILITY_AGENT_KEY: str = ""

    CHALLENGER_AGENT_ID: str = ""
    CHALLENGER_AGENT_KEY: str = ""

    REMEDIATION_AGENT_ID: str = ""
    REMEDIATION_AGENT_KEY: str = ""

    VERIFICATION_AGENT_ID: str = ""
    VERIFICATION_AGENT_KEY: str = ""

    PR_AGENT_ID: str = ""
    PR_AGENT_KEY: str = ""


def load_config() -> VireonConfig:
    aiml_key = os.getenv("AIML_API_KEY", "")
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")

    if not aiml_key and not anthropic_key:
        raise EnvironmentError(
            "\n[Vireon] No LLM key found.\n"
            "Set AIML_API_KEY (hackathon credits from aimlapi.com)\n"
            "or ANTHROPIC_API_KEY (direct Anthropic) in .env\n"
        )

    # Set ANTHROPIC_API_KEY in env so SAGE's own config.py picks it up
    # SAGE calls os.getenv("ANTHROPIC_API_KEY") directly
    if aiml_key and not anthropic_key:
        os.environ["ANTHROPIC_API_KEY"] = aiml_key
        # Also set the base URL so SAGE's anthropic client hits AI/ML API
        os.environ.setdefault("ANTHROPIC_BASE_URL", "https://api.aimlapi.com/v1")

    return VireonConfig(
        AIML_API_KEY=aiml_key,
        ANTHROPIC_API_KEY=os.getenv("ANTHROPIC_API_KEY", ""),
        NVD_API_KEY=os.getenv("NVD_API_KEY", ""),
        GITHUB_TOKEN=os.getenv("GITHUB_TOKEN", ""),
        GITHUB_REPO=os.getenv("GITHUB_REPO", ""),

        BAND_REST_URL=os.getenv("BAND_REST_URL", "https://app.band.ai/"),
        BAND_WS_URL=os.getenv("BAND_WS_URL", "wss://app.band.ai/api/v1/socket/websocket"),

        THREAT_AGENT_ID=os.getenv("THREAT_AGENT_ID", ""),
        THREAT_AGENT_KEY=os.getenv("THREAT_AGENT_KEY", ""),

        GRAPH_AGENT_ID=os.getenv("GRAPH_AGENT_ID", ""),
        GRAPH_AGENT_KEY=os.getenv("GRAPH_AGENT_KEY", ""),

        STATIC_AGENT_ID=os.getenv("STATIC_AGENT_ID", ""),
        STATIC_AGENT_KEY=os.getenv("STATIC_AGENT_KEY", ""),

        EXPLOITABILITY_AGENT_ID=os.getenv("EXPLOITABILITY_AGENT_ID", ""),
        EXPLOITABILITY_AGENT_KEY=os.getenv("EXPLOITABILITY_AGENT_KEY", ""),

        CHALLENGER_AGENT_ID=os.getenv("CHALLENGER_AGENT_ID", ""),
        CHALLENGER_AGENT_KEY=os.getenv("CHALLENGER_AGENT_KEY", ""),

        REMEDIATION_AGENT_ID=os.getenv("REMEDIATION_AGENT_ID", ""),
        REMEDIATION_AGENT_KEY=os.getenv("REMEDIATION_AGENT_KEY", ""),

        VERIFICATION_AGENT_ID=os.getenv("VERIFICATION_AGENT_ID", ""),
        VERIFICATION_AGENT_KEY=os.getenv("VERIFICATION_AGENT_KEY", ""),

        PR_AGENT_ID=os.getenv("PR_AGENT_ID", ""),
        PR_AGENT_KEY=os.getenv("PR_AGENT_KEY", ""),
    )


vcfg = load_config()
