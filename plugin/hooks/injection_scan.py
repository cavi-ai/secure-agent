#!/usr/bin/env python3
"""PostToolUse hook: scans tool results for prompt injection patterns (ECG Layer 2 port).

Detection is warn-only by design, but the detector itself should not be
trivially evadable: text is NFKC-normalized and stripped of zero-width/format
characters before matching, so `ign​ore` (zero-width space) and Cyrillic
homoglyphs (`disregаrd`) still hit the ASCII patterns.
"""

from __future__ import annotations

import json
import re
import sys
import unicodedata

INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|former)\s+(?:instructions?|directives?|prompts?|context|rules?)", re.IGNORECASE),
    re.compile(r"ignore\s+(?:previous|prior|above|former)\s+(?:instructions?|directives?|prompts?|context|rules?)", re.IGNORECASE),
    re.compile(r"disregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|former)", re.IGNORECASE),
    re.compile(r"forget\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|former)", re.IGNORECASE),
    re.compile(r"do\s+not\s+follow\s+(?:any\s+|the\s+)?(?:previous|prior|above)", re.IGNORECASE),
    re.compile(r"system\s+prompt\s+(?:override|bypass|injection)", re.IGNORECASE),
    re.compile(r"new\s+(?:instruction|directive|rule|prompt|goal|task)s?:", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:in|a|an)?\s*(?:developer|dan|unrestricted|jailbreak|god\s+mode)", re.IGNORECASE),
    re.compile(r"\[(?:system|assistant|user|im_start)\]\s*:", re.IGNORECASE),
    re.compile(r"<\s*\|?\s*(?:im_start|im_end|system|user|assistant)\s*\|?\s*>", re.IGNORECASE),
]

# Recursion bound: tool results can be deeply nested JSON; an unbounded
# recursive walk crashes the hook with RecursionError (and a crashed hook's
# fail behavior is harness-defined). 64 levels is far past real payloads.
MAX_DEPTH = 64
MAX_STRING_CHARS = 1_000_000


# Classic Cyrillic/Greek homoglyphs of Latin letters (а е о р с х ...). NFKC
# does not fold these — they are a standard detector-evasion trick.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "к": "k", "м": "m", "т": "t",
    "в": "b", "н": "h", "ԁ": "d", "ɡ": "g", "ο": "o", "α": "a", "ρ": "p",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "В": "B",
    "Н": "H", "К": "K", "М": "M", "Т": "T",
})


def _normalize(s: str) -> str:
    # NFKC folds full-width/compatibility chars to ASCII; then drop
    # zero-width/format chars (category Cf) that visually split keywords;
    # then fold homoglyphs so `disregаrd` matches `disregard`.
    s = unicodedata.normalize("NFKC", s)
    s = "".join(c for c in s if unicodedata.category(c) != "Cf")
    return s.translate(_HOMOGLYPHS)


def scan_text(obj: any, _depth: int = 0) -> list[str]:
    hits = []
    if _depth > MAX_DEPTH:
        return hits
    if isinstance(obj, str):
        text = _normalize(obj[:MAX_STRING_CHARS])
        for pattern in INJECTION_PATTERNS:
            if pattern.search(text):
                hits.append(pattern.pattern)
    elif isinstance(obj, dict):
        for val in obj.values():
            hits.extend(scan_text(val, _depth + 1))
    elif isinstance(obj, list):
        for item in obj:
            hits.extend(scan_text(item, _depth + 1))
    return hits

def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return
        payload = json.loads(raw)
        result = payload.get("tool_result") or payload.get("content") or payload
        hits = scan_text(result)
    except Exception:
        # A scanner crash must never break the harness's tool loop — emit the
        # clean no-hit payload rather than exiting nonzero with no JSON.
        print("{}")
        return

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
