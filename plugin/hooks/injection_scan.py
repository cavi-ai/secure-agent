#!/usr/bin/env python3
"""PostToolUse hook: scans tool results for prompt injection patterns (ECG Layer 2 port)."""

from __future__ import annotations

import json
import re
import sys

INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all|any|the)\s+(previous|above)\s+(instructions|directives|prompts)", re.IGNORECASE),
    re.compile(r"disregard\s+(all|any|the)\s+(previous|above)", re.IGNORECASE),
    re.compile(r"system\s+prompt\s+(override|bypass)", re.IGNORECASE),
    re.compile(r"new\s+(instruction|directive|rule)s?:", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(in|a)\s+(developer|dan|unrestricted|jailbreak)", re.IGNORECASE),
    re.compile(r"\[(system|assistant|user)\]\s*:", re.IGNORECASE),
]

def scan_text(obj: any) -> list[str]:
    hits = []
    if isinstance(obj, str):
        for pattern in INJECTION_PATTERNS:
            if pattern.search(obj):
                hits.append(pattern.pattern)
    elif isinstance(obj, dict):
        for val in obj.values():
            hits.extend(scan_text(val))
    elif isinstance(obj, list):
        for item in obj:
            hits.extend(scan_text(item))
    return hits

func_mode = False

def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return
        payload = json.loads(raw)
    except Exception:
        return

    result = payload.get("tool_result") or payload.get("content") or payload
    hits = scan_text(result)

    if hits:
        msg = f"[secure-agent] Warning: Prompt injection pattern detected in tool result"
        out = {
            "systemMessage": msg,
            "user_message": msg,
        }
        print(json.dumps(out))
    else:
        print("{}")

if __name__ == "__main__":
    main()
