"""
main.py — Vireon entry point

Usage:
    python main.py --repo /path/to/repo
    python main.py --repo /path/to/repo --days 7

Vireon runs a full autonomous security investigation:
  1. Threat Intelligence (CVE fetch + knowledge graph)
  2. Static Analysis (Semgrep on blast radius)
  3. Exploitability Review (LLM confirmation)
  4. Challenger Debate (red team review)
  5. Remediation + Compliance Loop (patch generation + approval)
  6. Verification (tests + final Semgrep)
  7. GitHub PR (if all passes)

All agents connect to Band and post live updates to the war room.
"""

import argparse
import asyncio
import sys
import os

# Ensure both Vireon and SAGE are importable
_ROOT = os.path.dirname(os.path.abspath(__file__))
_SAGE = os.path.join(_ROOT, "..", "SAGE")
for p in [_ROOT, _SAGE]:
    if p not in sys.path:
        sys.path.insert(0, p)

from vireon.coordinator.coordinator import Coordinator


def main():
    parser = argparse.ArgumentParser(
        description="Vireon — Autonomous Multi-Agent Security Investigation Platform"
    )
    parser.add_argument(
        "--repo", type=str, required=True,
        help="Path to the repository to investigate"
    )
    parser.add_argument(
        "--days", type=int, default=7,
        help="CVE lookback window in days (default: 7)"
    )
    args = parser.parse_args()

    if not os.path.isdir(args.repo):
        print(f"[Vireon] Directory not found: {args.repo}")
        sys.exit(1)

    coordinator = Coordinator(repo_path=args.repo, days=args.days)

    try:
        asyncio.run(coordinator.run())
    except KeyboardInterrupt:
        print("\n[Vireon] Interrupted — investigation stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
