# secure-agent-managed-plugin: hermes
"""Native Hermes tool interception through the shared Secure Agent guard."""
import json
import os
from pathlib import Path
import subprocess
import sys


def _check(event, tool_name, args, result=None, **kwargs):
    payload = {"hook_event_name": event, "tool_name": tool_name, "tool_input": args,
               "tool_response": result, "session_id": kwargs.get("session_id"), "cwd": kwargs.get("cwd") or os.getcwd()}
    process = subprocess.run([sys.executable, str(Path(__file__).with_name("harness_guard.py")), "hermes"],
                             input=json.dumps(payload), text=True, capture_output=True, timeout=10)
    if process.returncode:
        raise ValueError("guard exited unsuccessfully")
    return json.loads(process.stdout)


def register(ctx):
    def before(tool_name, args, **kwargs):
        try:
            response = _check("PreToolUse", tool_name, args, **kwargs)
            if response.get("permission") == "allow":
                return None
            reason = response.get("hookSpecificOutput", {}).get("permissionDecisionReason")
        except Exception:
            reason = None
        return {"action": "block", "message": reason or "Secure Agent could not check this tool request. Recheck the hook installation."}

    def after(tool_name, args, result=None, **kwargs):
        try:
            _check("PostToolUse", tool_name, args, result, **kwargs)
        except Exception:
            import logging
            logging.getLogger(__name__).warning("Secure Agent could not record the completed tool call.")

    ctx.register_hook("pre_tool_call", before)
    ctx.register_hook("post_tool_call", after)
