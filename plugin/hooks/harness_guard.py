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
    harness = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        if harness not in ("codex", "openclaw", "antigravity", "hermes", "opencode"):
            raise ValueError("unsupported harness")
        payload = json.load(sys.stdin)
        if harness == "antigravity":
            call = payload["toolCall"]
            args = call["args"]
            workspaces = payload.get("workspacePaths", [])
            payload = {"hook_event_name": sys.argv[2], "tool_name": call["name"], "tool_input": args,
                       "session_id": payload.get("conversationId"), "transcript_path": payload.get("transcriptPath"),
                       "cwd": args.get("Cwd") or (workspaces[0] if len(workspaces) == 1 else None)}
            args["command"] = args.get("CommandLine", "")
            path = args.get("Path") if call["name"] in ("read_file", "write_file") else None
            path = path or args.get("AbsolutePath") or args.get("TargetFile") or args.get("SearchPath") or args.get("SearchDirectory") or args.get("DirectoryPath")
            if path:
                args["file_path"] = path
        if not isinstance(payload, dict) or not isinstance(payload.get("tool_input", {}), dict):
            raise ValueError("invalid tool input")
        os.environ["SECURE_AGENT_HARNESS"] = harness
        if harness in ("openclaw", "hermes", "opencode"):
            # Finish before OpenClaw's default 15-second modifying-hook limit.
            os.environ["SECURE_AGENT_PROMPT_DEADLINE_S"] = "5"
            # The plugins wait 10 seconds for this process.
            os.environ["SECURE_AGENT_HOOK_BUDGET_S"] = "8"
        import secret_guard
        tool = payload.get("tool_name", "")
        aliases = {"exec": "Bash", "exec_command": "Bash", "read": "Read",
                   "write": "Write", "edit": "Edit", "bash": "Bash", "terminal": "Bash",
                   "read_file": "Read", "write_file": "Write", "patch": "Edit", "search_files": "Grep",
                   "grep": "Grep", "glob": "Glob", "run_command": "Bash", "view_file": "Read",
                   "write_to_file": "Write", "replace_file_content": "Edit", "multi_replace_file_content": "MultiEdit",
                   "grep_search": "Grep", "find_by_name": "Glob", "list_dir": "Glob"}
        payload["tool_name"] = aliases.get(tool, tool)
        inputs = payload.get("tool_input", {})
        path = inputs.get("file_path") or inputs.get("path") or inputs.get("filePath") or inputs.get("notebook_path")
        if path:
            inputs["file_path"] = os.path.normpath(os.path.join(payload.get("cwd") or os.getcwd(), os.path.expanduser(path)))
        payload["tool_input"] = inputs
        calls = [payload]
        patch_call = tool == "apply_patch" or (tool == "patch" and inputs.get("mode") == "patch")
        if patch_call and payload.get("hook_event_name") == "PreToolUse":
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
        if harness == "antigravity":
            response = ({"decision": response["permission"], "reason": response.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")}
                        if payload["hook_event_name"] == "PreToolUse" else {})
        print(json.dumps(response))
    except Exception:
        reason = "Secure Agent could not check this tool request. Recheck the hook installation."
        print(json.dumps({"decision": "deny", "reason": reason} if harness == "antigravity" else denied(reason)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
