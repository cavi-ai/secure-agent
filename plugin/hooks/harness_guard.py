#!/usr/bin/env python3
# secure-agent-hook: harness_guard
"""Adapt native Codex, OpenClaw, Antigravity, Hermes, and OpenCode tool calls to the shared guard protocol."""
import contextlib
import io
import json
import os
import re
import sys

# A symlinked or PYTHONSAFEPATH hook loads sibling modules from the real directory.
_HOOK_DIR = os.path.dirname(os.path.realpath(__file__))
if _HOOK_DIR not in sys.path:
    sys.path.insert(0, _HOOK_DIR)

SUPPORTED_HARNESSES = ("codex", "openclaw", "antigravity", "hermes", "opencode")


def denied(reason):
    return {"permission": "deny", "hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": reason}}


def _is_post_event(event):
    return event in ("PostToolUse", "postToolUse")


def _disengaged_response(harness, event):
    if _is_post_event(event):
        return {}
    return {"decision": "allow"} if harness == "antigravity" else {"permission": "allow"}


def _app_running_safe():
    try:
        from activity_log import app_running
        return bool(app_running())
    except Exception:
        return True


def _pick_workspace(workspaces, path):
    if not isinstance(workspaces, list) or not workspaces:
        return None
    if isinstance(path, str) and path:
        norm_path = os.path.normpath(os.path.expanduser(path))
        for ws in workspaces:
            if isinstance(ws, str) and ws:
                norm_ws = os.path.normpath(ws)
                if norm_path == norm_ws or norm_path.startswith(norm_ws + os.sep):
                    return ws
    if len(workspaces) == 1 and isinstance(workspaces[0], str):
        return workspaces[0]
    return workspaces[0] if isinstance(workspaces[0], str) else None


def main():
    harness = sys.argv[1] if len(sys.argv) > 1 else ""
    event_hint = sys.argv[2] if harness == "antigravity" and len(sys.argv) > 2 else ""
    try:
        if harness not in SUPPORTED_HARNESSES:
            raise ValueError("unsupported harness")
        from activity_log import app_running
        if not app_running():
            print(json.dumps(_disengaged_response(harness, event_hint)))
            return 0
        payload = json.load(sys.stdin)
        if isinstance(payload, dict) and payload.get("context_error"):
            raise ValueError("harness context unavailable")
        if harness == "antigravity":
            call = payload["toolCall"]
            raw_args = call.get("args")
            if raw_args is None:
                args = {}
            elif isinstance(raw_args, dict):
                args = dict(raw_args)
            else:
                raise ValueError("invalid tool args")
            workspaces = payload.get("workspacePaths", [])
            tool_name = call["name"]
            if "CommandLine" in args:
                args["command"] = args.get("CommandLine") or ""
            path = args.get("Path") if tool_name in ("read_file", "write_file", "edit_file") else None
            path = path or args.get("AbsolutePath") or args.get("TargetFile") or args.get("SearchPath") or args.get("SearchDirectory") or args.get("DirectoryPath")
            if isinstance(path, str) and path:
                args["file_path"] = path
            adapted = {"hook_event_name": sys.argv[2], "tool_name": tool_name, "tool_input": args,
                       "session_id": payload.get("conversationId"), "transcript_path": payload.get("transcriptPath"),
                       "cwd": args.get("Cwd") or _pick_workspace(workspaces, path)}
            for resp_key in ("toolResponse", "toolResult", "tool_response", "result", "output"):
                if resp_key in payload and payload[resp_key] is not None:
                    adapted["tool_response"] = payload[resp_key]
                    break
            payload = adapted
        if not isinstance(payload, dict):
            raise ValueError("invalid tool input")
        event_hint = str(payload.get("hook_event_name") or event_hint)
        raw_input = payload.get("tool_input")
        if raw_input is not None and not isinstance(raw_input, dict):
            raise ValueError("invalid tool input")
        inputs = dict(raw_input) if isinstance(raw_input, dict) else {}
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
                   "read_file": "Read", "write_file": "Write", "edit_file": "Edit", "patch": "Edit",
                   "search_files": "Grep", "grep": "Grep", "glob": "Glob", "run_command": "Bash",
                   "view_file": "Read", "view_file_outline": "Read", "view_code_item": "Read",
                   "write_to_file": "Write", "replace_file_content": "Edit", "multi_replace_file_content": "MultiEdit",
                   "grep_search": "Grep", "find_by_name": "Glob", "list_dir": "Glob",
                   "read_url_content": "WebFetch", "search_web": "WebSearch"}
        payload["tool_name"] = aliases.get(tool, tool)
        path = inputs.get("file_path") or inputs.get("path") or inputs.get("filePath") or inputs.get("notebook_path")
        if isinstance(path, str) and path:
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
        if harness in SUPPORTED_HARNESSES:
            if _is_post_event(event_hint) or not _app_running_safe():
                print(json.dumps(_disengaged_response(harness, event_hint)))
                return 0
        reason = "Secure Agent could not check this tool request. Recheck the hook installation."
        print(json.dumps({"decision": "deny", "reason": reason} if harness == "antigravity" else denied(reason)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
