"""
agents/pr_agent.py — DEPRECATED

Renamed to delivery_agent.py / DeliveryAgent.
This file is kept only so git history is readable.
Delete it after the hackathon.
"""

# Re-export so any stale import doesn't hard-crash
from agents.delivery_agent import DeliveryAgent as PRAgent  # noqa: F401

__all__ = ["PRAgent"]
