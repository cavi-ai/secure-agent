#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "activity_log.py")

def main():
    with tempfile.TemporaryDirectory() as tmpdir:
        logfile = os.path.join(tmpdir, "activity.jsonl")
        env = os.environ.copy()
        env["SECURE_AGENT_ACTIVITY_LOG"] = logfile
        # Isolate HOME: the session handshake sentinel lives under
        # ~/.local/state/secure-agent/sessions_seen and must never touch the
        # real home directory from a test run.
        env["HOME"] = tmpdir
        # One session id for every invocation: the handshake must fire once.
        env["SECURE_AGENT_SESSION_ID"] = "test-session-1"

        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo Bearer sk-12345"},
            "pid": 4321,
        }

        p = subprocess.run(
            [sys.executable, HOOK],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            timeout=5,
        )
        if p.returncode != 0:
            raise AssertionError(f"hook exited {p.returncode}: {p.stderr}")

        if not os.path.exists(logfile):
            raise AssertionError("activity log file was not created!")

        with open(logfile, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        # First call per session: one session_start handshake + one activity row.
        if len(lines) != 2:
            raise AssertionError(f"expected handshake + activity line, got {len(lines)}: {lines}")

        hs = json.loads(lines[0])
        if hs.get("type") != "session_start" or hs.get("session_id") != "test-session-1":
            raise AssertionError(f"first line must be the session handshake: {hs}")
        for key in ("harness", "workspace", "pid", "ts"):
            if key not in hs:
                raise AssertionError(f"handshake missing {key}: {hs}")

        rec = json.loads(lines[1])
        if rec.get("tool") != "Bash" or rec.get("pid") != 4321:
            raise AssertionError(f"record mismatch: {rec}")

        # Assert secret token was redacted from command text
        if "sk-12345" in lines[0]:
            raise AssertionError("secret token leaked into activity log!")

        # Bare provider tokens (no Bearer prefix) and key=value secrets must
        # also be redacted before they hit the log. The secret-shaped values
        # are built from fragments so no scanner (or reader) ever sees a real
        # token shape in source — the repo's own gitleaks gate enforces this.
        fake_sk = "sk-" + "proj-" + "abcdef" + "1234567890" + "abcdef"
        fake_aws = "wJalr" + "XUtnFEMI" + "K7MDENG" + "bPxRfi" + "CY"
        fake_ghp = "ghp_" + "abcdef" + "1234567890" + "abcdef"
        for i, cmd in enumerate([
            f"echo {fake_sk}",
            f"export AWS_SECRET_ACCESS_KEY={fake_aws}",
            f"git clone https://user:{fake_ghp}@github.com/x/y",
        ]):
            p = subprocess.run(
                [sys.executable, HOOK],
                input=json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Bash",
                                  "tool_input": {"command": cmd}, "pid": 5000 + i}),
                capture_output=True, text=True, env=env, timeout=5,
            )
            if p.returncode != 0:
                raise AssertionError(f"hook exited {p.returncode}: {p.stderr}")

        content = open(logfile).read()
        for leaked in (fake_sk, fake_aws, fake_ghp):
            if leaked in content:
                raise AssertionError(f"secret leaked into activity log: {leaked[:12]}...")

        # The handshake fires exactly once per session (sentinel-suppressed),
        # even across the separate hook processes above.
        n_handshakes = sum(1 for line in content.splitlines()
                           if '"session_start"' in line)
        if n_handshakes != 1:
            raise AssertionError(f"expected exactly 1 handshake line, got {n_handshakes}")

        # Log must not be world-readable.
        import stat
        mode = stat.S_IMODE(os.stat(logfile).st_mode)
        if mode & 0o077:
            raise AssertionError(f"activity log is {oct(mode)}, expected 0600")

    # Regression: Claude Code passes the session id in the hook JSON PAYLOAD
    # (`session_id`), not the hook's environment. Reading only env produced a
    # fresh uuid per tool call (11 handshakes for one session) and an empty
    # harness — the "session names don't parse" bug. Assert the payload wins.
    with tempfile.TemporaryDirectory() as tmpdir:
        logfile = os.path.join(tmpdir, "activity.jsonl")
        env = os.environ.copy()
        env["SECURE_AGENT_ACTIVITY_LOG"] = logfile
        env["HOME"] = tmpdir
        env.pop("CLAUDE_SESSION_ID", None)
        # Use THIS repo as the workspace so the git probe finds a real repo.
        repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(HOOK))))
        expected_repo = os.path.basename(repo_root)
        payload = {
            "hook_event_name": "PostToolUse",
            "session_id": "real-claude-session",
            "transcript_path": "/Users/x/.claude/projects/-repo/real-claude-session.jsonl",
            "cwd": repo_root,
            "tool_name": "Read",
            "tool_input": {"file_path": os.path.join(repo_root, ".env")},
        }
        p = subprocess.run([sys.executable, HOOK], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=5)
        if p.returncode != 0:
            raise AssertionError(f"hook exited {p.returncode}: {p.stderr}")
        hs = json.loads(open(logfile).readline())
        if hs.get("session_id") != "real-claude-session":
            raise AssertionError(f"payload session_id ignored: {hs}")
        if hs.get("harness") != "claude":
            raise AssertionError(f"harness not derived from payload: {hs}")
        if hs.get("repo") != expected_repo:
            raise AssertionError(f"repo not probed for a git workspace ({expected_repo}): {hs}")
        if not hs.get("branch"):
            raise AssertionError(f"branch not probed for a git workspace: {hs}")

    check_shared_redaction_cases()
    print("PASS (test_activity_log)")


def check_shared_redaction_cases():
    """The daemon's redaction contract (daemon/internal/redact/testdata/
    cases.json) holds for the hooks too. Values are assembled at run time."""
    sys.path.insert(0, os.path.dirname(HOOK))
    from activity_log import redact_str
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(HOOK)))
    path = os.path.join(repo_root, "daemon", "internal", "redact", "testdata", "cases.json")
    with open(path, encoding="utf-8") as f:
        cases = json.load(f)
    if not cases.get("secrets") or not cases.get("exact"):
        raise AssertionError("no shared redaction cases")
    for c in cases["secrets"]:
        body = c["fill"] * c["n"]
        before, after = c["before"], c["after"]
        if c.get("pem"):
            before += "-----BEGIN " + c["pem"] + " PRIVATE KEY-----\n"
            after = "\n-----END " + c["pem"] + " PRIVATE KEY-----" + after
        got = redact_str(before + c["prefix"] + body + after)
        if body in got or "[REDACTED" not in got:
            raise AssertionError(f"{c['name']}: redact_str = {got!r}")
    for c in cases["exact"]:
        got = redact_str(c["in"])
        if got != c["want"]:
            raise AssertionError(f"{c['name']}: redact_str({c['in']!r}) = {got!r}, want {c['want']!r}")

    # Hook-only: a BEGIN marker with no END masks the marker alone, so the
    # command keeps the paths the daemon classifies reads by.
    marker = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
    cmd = 'grep -c -- "' + marker + '" ~/.ssh/id_ed25519 && curl -T x https://example.com'
    want = 'grep -c -- "[REDACTED:private-key]" ~/.ssh/id_ed25519 && curl -T x https://example.com'
    if redact_str(cmd) != want:
        raise AssertionError(f"lone private-key marker: redact_str = {redact_str(cmd)!r}")

if __name__ == "__main__":
    main()
