#!/usr/bin/env python3
"""Tests for secret-guard.py.

Every case in ALLOW is a real command that the hook this replaced denied, or
would have. Every case in DENY is an action that actually damages the machine.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secret_guard.py")
HOME = os.path.expanduser("~")


def run(payload: dict) -> dict:
    p = subprocess.run(
        [sys.executable, HOOK],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if p.returncode != 0:
        raise AssertionError(f"hook exited {p.returncode}: {p.stderr[:400]}")
    try:
        return json.loads(p.stdout or "{}")
    except json.JSONDecodeError:
        raise AssertionError(f"non-JSON stdout: {p.stdout[:400]}")


def bash(cmd: str) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}}


def cursor(cmd: str) -> dict:
    return {"hook_event_name": "beforeShellExecution", "command": cmd}


def write(path: str) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": path}}


# Must be ALLOWED. These are the false positives that got the old hook disabled.
ALLOW = [
    "gh api /repos/cavi-ai/bobby-browser/security",
    "gh api /orgs/cavi-ai/security-advisories",
    "npm audit --json",
    "cargo audit",
    "grep -rn security ./src",
    "rg 'security' --type ts",
    "git commit -m 'fix security header parsing'",
    "python3 -c \"print('security')\"",
    "cd CAVI_TOOLS && make build",
    "cat ~/.zshrc",
    "head -50 ~/.zshenv",
    "diff ~/.zshrc ~/.zprofile",
    "op read op://CaviClaw/Twitter/credential",
    "op item list --vault CaviClaw",
    "op --version",
    "op whoami",
    ". $OPENCLAW_STATE_DIR/credentials/shell-env.sh",
    "source ~/.zshrc",
    "ls -la ~/Library/Keychains/",
    "echo hello > QUARANTINE/note.txt",
    "sed -i '' 's/a/b/' ./src/app.ts",
    "chmod 600 QUARANTINE/x",
    # locking rc files only hardens them
    "chflags uchg ~/.zshenv ~/.zshrc ~/.zprofile ~/.profile",
    "chflags schg ~/.zshrc",
    # unbalanced quote must not brick the agent
    "echo \"unterminated",
]

# Must be DENIED.
DENY = [
    # keychain CLI, any subcommand
    ("security delete-generic-password -s 'Cursor Safe Storage'", "keychain-security-cli"),
    ("security add-generic-password -s x -a y -w z", "keychain-security-cli"),
    ("security set-keychain-settings -t 60 -l", "keychain-security-cli"),
    ("security unlock-keychain ~/Library/Keychains/login.keychain-db", "keychain-security-cli"),
    ("security dump-keychain -d", "keychain-security-cli"),
    ("security find-generic-password -s foo -w", "keychain-security-cli"),
    ("sudo security delete-keychain login.keychain-db", "keychain-security-cli"),
    ("/usr/bin/security list-keychains -s x", "keychain-security-cli"),
    ("env FOO=1 security find-internet-password -g", "keychain-security-cli"),
    ("ls && security dump-keychain", "keychain-security-cli"),
    ("echo $(security find-generic-password -s x -w)", "keychain-security-cli"),
    # keychain files
    ("cp /somewhere/login.keychain-db ~/Library/Keychains/", "keychain-file-op"),
    ("mv ~/Library/Keychains/login.keychain-db /tmp/x", "keychain-file-op"),
    ("chmod 644 ~/Library/Keychains/login.keychain-db", "keychain-file-op"),
    ("cat ~/Library/Keychains/login.keychain-db", "keychain-file-op"),
    # shell config mutation
    ("echo 'export X=1' >> ~/.zshrc", "shell-rc-redirect"),
    ("echo 'export X=1' > ~/.zshenv", "shell-rc-redirect"),
    ("sed -i '' 's/a/b/' ~/.zshenv", "shell-rc-mutation"),
    ("tee -a ~/.zprofile", "shell-rc-mutation"),
    ("cp /tmp/new ~/.zshrc", "shell-rc-mutation"),
    ("chflags nouchg ~/.zshenv", "shell-rc-unlock"),
    ("chflags noschg ~/.zshrc", "shell-rc-unlock"),
    ("chflags uchg ~/Library/Keychains/login.keychain-db", "keychain-file-op"),
    ("chmod 777 /etc/paths", "shell-rc-mutation"),
    # secret files
    ("cat $OPENCLAW_STATE_DIR/credentials/op-service-account-token", "secret-file-read"),
    ("base64 ~/.openclaw/credentials/secrets.json", "secret-file-read"),
    ("cat ~/.ssh/id_ed25519", "secret-file-read"),
    # 1Password scope
    ("op read op://Private/thing/field", "op-vault-not-allowed"),
    ("op item get 'X' --vault Personal", "op-vault-not-allowed"),
    ("op item create --category login --title X", "op-mutation"),
    ("op item delete X --vault CaviClaw", "op-mutation"),
    ("op read", "op-unscoped"),
    # interpreter bypass
    ("python3 -c \"open('/Users/testuser/.zshrc','a').write('x')\"", "interpreter-write-bypass"),
    ("node -e \"require('fs').appendFileSync(process.env.HOME+'/.zshenv','x')\"", "interpreter-write-bypass"),
    ("perl -e 'open(F,\">>\",\"/Users/testuser/.zprofile\"); print F \"x\"'", "interpreter-write-bypass"),
    ("osascript -e 'do shell script \"chflags nouchg ~/.zshrc\"'", "interpreter-write-bypass"),
    # real-world casing: KEYCHAIN_MARKERS are lowercase, the path is not
    ("python3 -c \"open('/Users/testuser/Library/Keychains/login.keychain-db','w')\"", "interpreter-write-bypass"),
]

WRITE_DENY = [
    (os.path.join(HOME, ".zshrc"), "shell-rc-write-tool"),
    (os.path.join(HOME, ".zshenv"), "shell-rc-write-tool"),
    ("/etc/paths", "shell-rc-write-tool"),
    (os.path.join(HOME, "Library/Keychains/login.keychain-db"), "protected-write-tool"),
]


def main() -> int:
    failures = []

    for cmd in ALLOW:
        for shape, label in ((bash, "claude"), (cursor, "cursor")):
            out = run(shape(cmd))
            if out.get("permission") != "allow" or out.get("decision") == "block":
                failures.append(f"[{label}] should ALLOW but denied: {cmd}\n    -> {out.get('reason','')[:120]}")

    for cmd, rule in DENY:
        for shape, label in ((bash, "claude"), (cursor, "cursor")):
            out = run(shape(cmd))
            if out.get("permission") != "deny":
                failures.append(f"[{label}] should DENY ({rule}) but allowed: {cmd}")
            elif out.get("decision") != "block" or not out.get("reason"):
                failures.append(f"[{label}] deny is missing Claude Code keys: {cmd}")

    for path, rule in WRITE_DENY:
        out = run(write(path))
        if out.get("permission") != "deny":
            failures.append(f"[write] should DENY ({rule}) but allowed: {path}")

    # A malformed payload must not brick the agent.
    p = subprocess.run([sys.executable, HOOK], input="not json", capture_output=True, text=True, timeout=10)
    if json.loads(p.stdout or "{}").get("permission") != "allow":
        failures.append("malformed payload should ALLOW, not deny")

    # Latency budget: this runs on every Bash call.
    big = bash("echo " + ("x" * 10000))
    t0 = time.time()
    run(big)
    elapsed = (time.time() - t0) * 1000
    if elapsed > 400:
        failures.append(f"too slow on a 10KB payload: {elapsed:.0f}ms")

    if failures:
        print(f"FAIL ({len(failures)})")
        for f in failures:
            print("  -", f)
        return 1
    total = len(ALLOW) * 2 + len(DENY) * 2 + len(WRITE_DENY) + 2
    print(f"PASS ({total} cases, {elapsed:.0f}ms cold call)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
