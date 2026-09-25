#!/bin/bash
# check_no_personal_paths.sh — fail if a tracked file contains a personal
# machine path: /Users/<name> or /Volumes/<name> outside the neutral
# placeholder names test fixtures use.
# Regression guard: this repo is public; a real home directory or external
# volume name leaking into a comment, test fixture, or doc example is
# personal data, not code (2026-09-25 scrub).
set -euo pipefail

python3 - << 'PYEOF'
import re
import subprocess
import sys

EXCLUDE = {"LICENSE", "plugin/.claude-plugin/plugin.json"}
USERS_OK = {"dev", "me", "test", "user", "example", "runner", "alice", "bob", "shared", "Shared", "a", "b", "other", "tester", "u", "x"}
VOLUMES_OK = {"Data", "External", "Backup", "Work", "work", "workspace", "x", "M", "USB"}

NAME_RE = re.compile(r"/Users/([A-Za-z0-9_.-]+)|/Volumes/([A-Za-z0-9_.-]+)")

files = subprocess.run(
    ["git", "ls-files"], capture_output=True, text=True, check=True
).stdout.splitlines()

hits = []
for path in files:
    if path in EXCLUDE:
        continue
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        continue
    if b"\0" in data:
        continue
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        continue
    for lineno, line in enumerate(text.splitlines(), 1):
        for m in NAME_RE.finditer(line):
            name = m.group(1) if m.group(1) is not None else m.group(2)
            allowed = USERS_OK if m.group(1) is not None else VOLUMES_OK
            if name not in allowed:
                hits.append(f"{path}:{lineno}:{line}")
                break

if hits:
    print("personal machine paths found (fix, or add the placeholder to the allowed list):", file=sys.stderr)
    for h in hits:
        print(f"  {h}", file=sys.stderr)
    sys.exit(1)

print(f"no personal paths: {len(files)} tracked files clean")
PYEOF
