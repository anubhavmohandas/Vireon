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
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


# ── Pipeline tuning knobs ─────────────────────────────────────────────────────
# Change these to tune without touching agent code.

# Weight of the Challenger agent in fused_confidence().
# Negative because higher challenger confidence = more doubt cast on findings.
CHALLENGER_WEIGHT: float = float(os.getenv("CHALLENGER_WEIGHT", "-0.15"))

# Pipeline aborts (no patch generated) if fused confidence falls below this.
CONFIDENCE_THRESHOLD: float = float(os.getenv("CONFIDENCE_THRESHOLD", "0.3"))

# Max times RemediationAgent retries before coordinator gives up.
MAX_REMEDIATION_ATTEMPTS: int = int(os.getenv("MAX_REMEDIATION_ATTEMPTS", "3"))

# Challenger veto threshold (enterprise mode).
# If Challenger confidence exceeds this AND verdict is "counter_evidence_found",
# coordinator can escalate rather than just weighting the score down.
# Set to 1.0 to disable (default — advisory-only mode for hackathon).
# Set to e.g. 0.8 to enable: strong counter evidence triggers re-analysis.
CHALLENGER_VETO_THRESHOLD: float = float(os.getenv("CHALLENGER_VETO_THRESHOLD", "1.0"))


# ── Default model per provider ────────────────────────────────────────────────
_FEATHERLESS_MODEL = "Qwen/Qwen2.5-72B-Instruct"
_AIML_MODEL        = "claude-sonnet-4-5"
_ANTHROPIC_MODEL   = "claude-sonnet-4-5"


def make_llm_client():
    """
    Returns an OpenAI-compatible client.

    Provider priority:
      1. FEATHERLESS_API_KEY → api.featherless.ai (open-weight models, no cost)
      2. AIML_API_KEY        → api.aimlapi.com    (hackathon credits)
      3. ANTHROPIC_API_KEY   → direct Anthropic via openai-compat shim

    All providers speak OpenAI /v1/chat/completions — use llm_call() not the
    client directly so model selection is handled automatically.
    """
    from openai import OpenAI

    featherless_key = os.getenv("FEATHERLESS_API_KEY", "")
    aiml_key        = os.getenv("AIML_API_KEY", "")
    anthropic_key   = os.getenv("ANTHROPIC_API_KEY", "")

    if featherless_key:
        return OpenAI(
            api_key=featherless_key,
            base_url="https://api.featherless.ai/v1",
        )
    elif aiml_key:
        return OpenAI(
            api_key=aiml_key,
            base_url="https://api.aimlapi.com/v1",
        )
    elif anthropic_key:
        # Anthropic's OpenAI-compatible endpoint
        return OpenAI(
            api_key=anthropic_key,
            base_url="https://api.anthropic.com/v1",
        )
    else:
        raise EnvironmentError(
            "\n[Vireon] No LLM API key found.\n"
            "Set FEATHERLESS_API_KEY, AIML_API_KEY, or ANTHROPIC_API_KEY in .env\n"
        )


def default_model() -> str:
    """Return the right model string for whichever provider is active."""
    if os.getenv("FEATHERLESS_API_KEY"):
        return _FEATHERLESS_MODEL
    elif os.getenv("AIML_API_KEY"):
        return _AIML_MODEL
    else:
        return _ANTHROPIC_MODEL


def llm_call(prompt: str, system: str = "", max_tokens: int = 2048) -> str:
    """
    Single-turn LLM call. Returns the response text.
    Handles provider differences internally — callers get plain text back.
    """
    client = make_llm_client()
    model  = default_model()

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    response = client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        messages=messages,
    )
    return response.choices[0].message.content.strip()


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
    BAND_ROOM_ID: str = ""   # ID of the shared investigation chat room in Band

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
    featherless_key = os.getenv("FEATHERLESS_API_KEY", "")
    aiml_key        = os.getenv("AIML_API_KEY", "")
    anthropic_key   = os.getenv("ANTHROPIC_API_KEY", "")

    if not featherless_key and not aiml_key and not anthropic_key:
        print("[Vireon] WARNING: No LLM key found — LLM-dependent agents will be skipped.")
        print("  Set FEATHERLESS_API_KEY, AIML_API_KEY, or ANTHROPIC_API_KEY in .env to enable full pipeline.")

    if aiml_key and not anthropic_key:
        os.environ["ANTHROPIC_API_KEY"] = aiml_key
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
