#!/usr/bin/env python3
"""Tests for secret-guard.py.

Every case in ALLOW is a real command that the hook this replaced denied, or
would have. Every case in DENY is an action that actually damages the machine.
"""

from __future__ import annotations

import contextlib
import glob as _glob
import json
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secret_guard.py")
HOME = os.path.expanduser("~")


def run(payload: dict, env: dict | None = None) -> dict:
    base = dict(os.environ)
    # Strip runtime-detection vars the invoking shell may already carry (this
    # suite can itself run inside a Claude Code session), so each test's env
    # overlay is the sole source of truth for the hook's runtime() detection.
    base.pop("CLAUDE_CODE_ENTRYPOINT", None)
    base.pop("CURSOR_TRACE_ID", None)
    p = subprocess.run(
        [sys.executable, HOOK],
        input=json.dumps(payload),
        capture_output=True, text=True, timeout=10,
        env={**base, **(env or {})},
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


def read(path: str) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": path}}


def with_modes(**modes) -> dict:
    d = os.path.join(tempfile.mkdtemp(), "guard-modes.json")
    open(d, "w").write(json.dumps(modes))
    return {"SECURE_AGENT_GUARD_MODES": d}


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
    "cd /Volumes/MIRZA/workspace/CAVI/security-tools && make build",
    "cat ~/.zshrc",
    "head -50 ~/.zshenv",
    "diff ~/.zshrc ~/.zprofile",
    "source ~/.zshrc",
    "ls -la ~/Library/Keychains/",
    "echo hello > /Volumes/MIRZA/.quarantine/note.txt",
    "sed -i '' 's/a/b/' ./src/app.ts",
    "chmod 600 /Volumes/MIRZA/.quarantine/x",
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
    ("cat ~/.ssh/id_ed25519", "secret-file-read"),
    ("cat ~/.aws/credentials", "secret-file-read"),
    ("cat ~/.azure/accessTokens.json", "secret-file-read"),
    # interpreter bypass
    (f"python3 -c \"open('{HOME}/.zshrc','a').write('x')\"", "interpreter-write-bypass"),
    ("node -e \"require('fs').appendFileSync(process.env.HOME+'/.zshenv','x')\"", "interpreter-write-bypass"),
    (f"perl -e 'open(F,\">>\",\"{HOME}/.zprofile\"); print F \"x\"'", "interpreter-write-bypass"),
    ("osascript -e 'do shell script \"chflags nouchg ~/.zshrc\"'", "interpreter-write-bypass"),
    # real-world casing: KEYCHAIN_MARKERS are lowercase, the path is not
    (f"python3 -c \"open('{HOME}/Library/Keychains/login.keychain-db','w')\"", "interpreter-write-bypass"),
    # guard control-plane: an agent must not be able to disable its own guard
    ("echo '{}' > ~/.config/secure-agent/guard-modes.json", "guard-control-redirect"),
    ("rm ~/.config/secure-agent/guard-modes.json", "guard-control-mutation"),
    ("curl --unix-socket ~/.config/secure-agent/daemon.sock -X POST http://unix/guard/resolve -d '{}'",
     "guard-control-network"),
    ("nc -U ~/.config/secure-agent/daemon.sock", "guard-control-network"),
    ("wget --unix-socket=~/.config/secure-agent/daemon.sock http://unix/guard/resolve", "guard-control-network"),
]

WRITE_DENY = [
    (os.path.join(HOME, ".zshrc"), "shell-rc-write-tool"),
    (os.path.join(HOME, ".zshenv"), "shell-rc-write-tool"),
    ("/etc/paths", "shell-rc-write-tool"),
    (os.path.join(HOME, "Library/Keychains/login.keychain-db"), "protected-write-tool"),
    (os.path.join(HOME, ".config/secure-agent/guard-modes.json"), "guard-control-write-tool"),
]


# --- config-driven guard modes (Directory Guard) -----------------------------

def test_read_monitor_default_allows():
    # keychain ships monitor; a read is allowed (and logged), not blocked
    out = run(read(os.path.expanduser("~/Library/Keychains/login.keychain-db")))
    assert out.get("permission") == "allow", out


def test_read_deny_override_blocks():
    out = run(read(os.path.expanduser("~/Library/Keychains/login.keychain-db")),
              env=with_modes(keychain="deny"))
    assert out.get("permission") == "deny", out


def test_read_unknown_allows():
    out = run(read("/tmp/project/main.go"))
    assert out.get("permission") == "allow", out


EXTRA_TESTS = [
    test_read_monitor_default_allows,
    test_read_deny_override_blocks,
    test_read_unknown_allows,
]


# --- config-driven guard modes apply to Bash reads too, not just file tools -

def test_bash_read_denied_by_guard_mode_override():
    out = run(bash("cat /tmp/x/.env"), env=with_modes(**{"env-files": "deny"}))
    assert out.get("permission") == "deny", out


def test_bash_read_prompt_mode_on_bash_denies_without_asking():
    # Bounded rule: Bash never gets the interactive prompt the file-tool path
    # uses (it can touch too many paths at once, and a printed secret is
    # unrecoverable) — a prompt-mode rule resolves straight to deny, never
    # the ask-mode hookSpecificOutput emit_ask() produces.
    out = run(bash("cat /tmp/x/.env"), env=with_modes(**{"env-files": "prompt"}))
    assert out.get("permission") == "deny", out
    assert out.get("hookSpecificOutput", {}).get("permissionDecision") != "ask", out


EXTRA_TESTS += [
    test_bash_read_denied_by_guard_mode_override,
    test_bash_read_prompt_mode_on_bash_denies_without_asking,
]


# --- deny() emits the current PreToolUse shape, not the deprecated one ------

def test_deny_uses_current_pretooluse_shape():
    out = run(write(os.path.expanduser("~/.zshrc")))
    assert out.get("permission") == "deny", out
    hso = out.get("hookSpecificOutput", {})
    assert hso.get("hookEventName") == "PreToolUse", out
    assert hso.get("permissionDecision") == "deny", out
    assert hso.get("permissionDecisionReason"), out
    # Cursor keys stay for the other runtime.
    assert out.get("user_message"), out
    assert out.get("agent_message"), out
    # The deprecated top-level keys must be gone.
    assert "decision" not in out, out
    assert "reason" not in out, out


EXTRA_TESTS += [
    test_deny_uses_current_pretooluse_shape,
]


# --- prompt mode: daemon call, fail-safe deadline, ask fallback -------------

@contextlib.contextmanager
def guard_stub(decision):
    d = tempfile.mkdtemp()
    sock = os.path.join(d, "daemon.sock")
    body = json.dumps(decision).encode()
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.recv(65536)
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body))
    srv = socketserver.UnixStreamServer(sock, H)
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    try:
        yield sock
    finally:
        srv.shutdown(); srv.server_close()


def _prompt_env(sock=None):
    e = with_modes(**{"cloud-creds": "prompt"})
    if sock:
        e["SECURE_AGENT_SOCK"] = sock
    return e


def test_prompt_daemon_down_claude_asks():
    out = run(read(os.path.expanduser("~/.aws/credentials")),
              env={**_prompt_env("/tmp/nonexistent-guard.sock"), "CLAUDE_CODE_ENTRYPOINT": "cli"})
    assert out.get("hookSpecificOutput", {}).get("permissionDecision") == "ask", out


def test_prompt_daemon_down_cursor_denies():
    out = run(read(os.path.expanduser("~/.aws/credentials")),
              env={**_prompt_env("/tmp/nonexistent-guard.sock"), "CURSOR_TRACE_ID": "abc"})
    assert out.get("permission") == "deny", out


def test_prompt_daemon_allows():
    with guard_stub({"verdict": "allow", "scope": "always"}) as sock:
        out = run(read(os.path.expanduser("~/.aws/credentials")), env=_prompt_env(sock))
    assert out.get("permission") == "allow", out


def test_prompt_daemon_malformed_response_denies():
    # A daemon that returns valid JSON that is NOT an object (a bare string here,
    # not {"verdict": ...}) must never be treated as an allow. The guard fails
    # closed on anything it cannot positively parse as an allow decision.
    with guard_stub("allow") as sock:
        out = run(read(os.path.expanduser("~/.aws/credentials")), env=_prompt_env(sock))
    assert out.get("permission") == "deny", out


EXTRA_TESTS += [
    test_prompt_daemon_down_claude_asks,
    test_prompt_daemon_down_cursor_denies,
    test_prompt_daemon_allows,
    test_prompt_daemon_malformed_response_denies,
]


# --- de-personalization gate --------------------------------------------------

def test_no_personal_strings_in_shipped_hooks():
    # "cavi-ai" is the public org and is allowed; personal vault/owner/incident are not.
    # Tokens are built from split literals so this assertion's own source line
    # does not itself trip the scan it performs on every *.py file here.
    banned = ("cavi" + "claw", "fran" + "co", "open" + "claw", "2026-08" + "-12")
    for f in _glob.glob(os.path.join(os.path.dirname(__file__), "*.py")):
        src = open(f, encoding="utf-8").read().lower()
        for token in banned:
            assert token not in src, f"{os.path.basename(f)} leaks personal token: {token}"


EXTRA_TESTS += [
    test_no_personal_strings_in_shipped_hooks,
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
            hso = out.get("hookSpecificOutput", {})
            if out.get("permission") != "deny":
                failures.append(f"[{label}] should DENY ({rule}) but allowed: {cmd}")
            elif hso.get("permissionDecision") != "deny" or not hso.get("permissionDecisionReason"):
                failures.append(f"[{label}] deny is missing current Claude Code keys: {cmd}")

    for path, rule in WRITE_DENY:
        out = run(write(path))
        if out.get("permission") != "deny":
            failures.append(f"[write] should DENY ({rule}) but allowed: {path}")

    for fn in EXTRA_TESTS:
        try:
            fn()
        except AssertionError as e:
            failures.append(f"{fn.__name__}: {e}")

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
    total = len(ALLOW) * 2 + len(DENY) * 2 + len(WRITE_DENY) + len(EXTRA_TESTS) + 2
    print(f"PASS ({total} cases, {elapsed:.0f}ms cold call)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
