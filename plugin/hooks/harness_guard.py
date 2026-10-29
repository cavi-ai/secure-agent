#!/usr/bin/env python3
# secure-agent-hook: harness_guard
"""Adapt native Codex and OpenClaw tool calls to the shared guard protocol."""
import contextlib
import io
import json
import os
import re
import sys


def denied(reason):
    return {"permission": "deny", "hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": reason}}


def main():
    try:
        harness = sys.argv[1]
        if harness not in ("codex", "openclaw"):
            raise ValueError("unsupported harness")
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict) or not isinstance(payload.get("tool_input", {}), dict):
            raise ValueError("invalid tool input")
        os.environ["SECURE_AGENT_HARNESS"] = harness
        if harness == "openclaw":
            # Finish before OpenClaw's default 15-second modifying-hook limit.
            os.environ["SECURE_AGENT_PROMPT_DEADLINE_S"] = "5"
        import secret_guard
        tool = payload.get("tool_name", "")
        aliases = {"exec": "Bash", "exec_command": "Bash", "read": "Read",
                   "write": "Write", "edit": "Edit"}
        payload["tool_name"] = aliases.get(tool, tool)
        inputs = payload.get("tool_input", {})
        path = inputs.get("file_path") or inputs.get("path") or inputs.get("filePath") or inputs.get("notebook_path")
        if path:
            inputs["file_path"] = os.path.normpath(os.path.join(payload.get("cwd") or os.getcwd(), os.path.expanduser(path)))
        payload["tool_input"] = inputs
        calls = [payload]
        if tool == "apply_patch" and payload.get("hook_event_name") == "PreToolUse":
            patch = inputs.get("command") or inputs.get("patch") or inputs.get("input") or ""
            paths = re.findall(r"^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)$", patch, re.M)
            if not paths:
                raise ValueError("patch targets could not be checked")
            calls = [{**payload, "tool_name": "Write", "tool_input": {
                "file_path": os.path.normpath(os.path.join(payload.get("cwd") or os.getcwd(), os.path.expanduser(path.strip())))}} for path in paths]
        response = {}
        for call in calls:
            # Run in this process so audit/handshake parent identity remains
            # the native harness, rather than an intermediate Python process.
            output = io.StringIO()
            sys.stdin = io.StringIO(json.dumps(call))
            with contextlib.redirect_stdout(output):
                try:
                    secret_guard.main()
                except SystemExit as result:
                    if result.code not in (None, 0):
                        raise ValueError("guard did not finish successfully")
            response = json.loads(output.getvalue())
            if not isinstance(response, dict) or (payload.get("hook_event_name") == "PreToolUse" and response.get("permission") not in ("allow", "deny")):
                raise ValueError("invalid guard response")
            if response.get("permission") == "deny" or response.get("hookSpecificOutput", {}).get("permissionDecision") == "deny":
                break
        print(json.dumps(response))
    except Exception:
        print(json.dumps(denied("Secure Agent could not check this tool request. Recheck the hook installation.")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
