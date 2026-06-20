"""
engine/json_utils.py — tolerant JSON extraction for LLM output

LLMs wrap JSON in prose, fence it in ```json blocks, and — when the response hits
the token cap — truncate mid-array. Every agent that parses LLM output hit this
in slightly different, ad-hoc ways. This centralizes it.

extract_json_array() recovers a list[dict] even from a response whose final
object was cut off, by trimming back to the last complete object and closing the
array. Returns [] rather than raising — callers decide what an empty result means.
"""

from __future__ import annotations

import json
import re


def _strip_fences(raw: str) -> str:
    s = raw.strip()
    if "```json" in s:
        s = s.split("```json", 1)[1]
        s = s.split("```", 1)[0]
    elif "```" in s:
        parts = s.split("```")
        if len(parts) >= 3:
            s = parts[1]
    return s.strip()


def extract_json_array(raw: str) -> list:
    """
    Parse a JSON array of objects from messy LLM text. Tolerates code fences,
    leading/trailing prose, and a truncated final element.

    Always returns a list (possibly empty). Never raises.
    """
    if not raw or not isinstance(raw, str):
        return []

    candidate = _strip_fences(raw)

    # Fast path: clean parse.
    for text in (candidate, raw):
        try:
            val = json.loads(text)
            if isinstance(val, list):
                return val
            if isinstance(val, dict):
                return [val]
        except Exception:
            pass

    # Locate the array span.
    start = candidate.find("[")
    if start == -1:
        # Maybe a single object — try object recovery.
        obj = _extract_json_object(candidate)
        return [obj] if obj is not None else []

    fragment = candidate[start:]

    # Try shrinking from the end to the last balanced position.
    end = fragment.rfind("]")
    if end != -1:
        try:
            val = json.loads(fragment[: end + 1])
            if isinstance(val, list):
                return val
        except Exception:
            pass

    # Truncated array: keep whole objects only, then close the bracket.
    repaired = _repair_truncated_array(fragment)
    if repaired is not None:
        return repaired

    return []


def extract_json_object(raw: str) -> dict | None:
    """Parse a single JSON object from messy LLM text, or None."""
    if not raw or not isinstance(raw, str):
        return None
    return _extract_json_object(_strip_fences(raw))


def _extract_json_object(text: str) -> dict | None:
    try:
        val = json.loads(text)
        return val if isinstance(val, dict) else None
    except Exception:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            val = json.loads(text[start : end + 1])
            return val if isinstance(val, dict) else None
        except Exception:
            return None
    return None


def _repair_truncated_array(fragment: str) -> list | None:
    """
    Given text that starts with '[' but whose final object was truncated,
    walk brace depth and cut at the end of the last complete top-level object.
    """
    depth = 0
    in_str = False
    escape = False
    last_complete = -1  # index just past the last balanced top-level '}'

    for i, ch in enumerate(fragment):
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                last_complete = i

    if last_complete == -1:
        return None

    repaired = fragment[: last_complete + 1] + "]"
    try:
        val = json.loads(repaired)
        return val if isinstance(val, list) else None
    except Exception:
        return None
