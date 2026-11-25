#!/usr/bin/env python3
"""Score the agent-facing surfaces offline: the replies the guard hooks give a
coding agent when a guard rule stops its action, and the tool definitions the
local agent exposes.

    python3 packaging/test/agent_scenarios.py [--hooks FILE] [--tools FILE] [--bar N]

Hook scenarios run plugin/hooks entry points with harness JSON in a temporary
HOME. Tool scenarios run TestAgentToolScenarios in daemon/internal/sysagent.
Exits non-zero when the total is below the bar, a guard rule id or local agent
tool has no scenario, or a scenario does not trigger its rule.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HOOKS_DIR = ROOT / "plugin" / "hooks"
SCENARIO_DIR = Path(__file__).resolve().parent / "agent-scenarios"
TOOL_TEST = "^TestAgentToolScenarios$"

# Lowest total points (hook replies plus local agent tools) a run accepts.
SCORE_BAR = 41


@contextlib.contextmanager
def app_lease(home: Path):
    """Hold the desktop app lease in the temporary HOME so the hooks run active."""
    path = home / ".config" / "secure-agent" / "menubar.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            fcntl.flock(lease, fcntl.LOCK_UN)


def expand(value, places: dict):
    """Replace {home} and {project} placeholders in scenario strings."""
    if isinstance(value, str):
        for key, real in places.items():
            value = value.replace("{" + key + "}", real)
        return value
    if isinstance(value, list):
        return [expand(v, places) for v in value]
    if isinstance(value, dict):
        return {k: expand(v, places) for k, v in value.items()}
    return value


def hook_reply(harness: str, reply: dict) -> tuple:
    """Read the decision and reason from the selected harness's reply fields."""
    if harness == "cursor":
        return reply.get("permission"), reply.get("agent_message")
    if harness == "antigravity":
        return reply.get("decision"), reply.get("reason")
    native = reply.get("hookSpecificOutput")
    if not isinstance(native, dict):
        native = {}
    if harness in ("claude", "codex"):
        return native.get("permissionDecision"), native.get("permissionDecisionReason")
    if harness in ("openclaw", "hermes", "opencode"):
        return reply.get("permission"), native.get("permissionDecisionReason")
    return None, None


def run_hook(scenario: dict, envelope: dict) -> tuple[dict, str, str]:
    """Run one hook entry point in a temporary HOME. Returns the printed reply,
    the rule of the last audit record and stderr."""
    with tempfile.TemporaryDirectory(prefix="agent-scenario-") as tmp:
        home = Path(tmp)
        project = home / "project"
        project.mkdir()
        config = home / ".config" / "secure-agent"
        config.mkdir(parents=True)
        (config / "guard-modes.json").write_text(json.dumps(scenario.get("modes", {})))
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("SECURE_AGENT_", "CLAUDE_", "CURSOR_", "CODEX_"))}
        env.update(HOME=str(home), PYTHONDONTWRITEBYTECODE="1",
                   SECURE_AGENT_ACTIVITY_LOG=str(home / "activity.jsonl"),
                   SECURE_AGENT_SOCK=str(config / "daemon.sock"))
        payload = expand({**envelope, **scenario["payload"]}, {"home": str(home), "project": str(project)})
        entry = scenario["entry"]
        with app_lease(home):
            proc = subprocess.run([sys.executable, str(HOOKS_DIR / entry[0]), *entry[1:]],
                                  input=json.dumps(payload), capture_output=True, text=True,
                                  timeout=30, cwd=project, env=env)
        try:
            reply = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            reply = {"unparsed": proc.stdout[:400]}
        audit_log = home / ".agents" / "logs" / "secret-guard.jsonl"
        audited = ""
        if audit_log.exists():
            lines = audit_log.read_text().strip().splitlines()
            audited = json.loads(lines[-1]).get("rule", "") if lines else ""
        return reply if isinstance(reply, dict) else {}, audited, proc.stderr


def score_hooks(path: Path, rule_ids: list) -> tuple[list, list]:
    """Score each hook scenario: names the rule, states the cause, gives a next step."""
    doc = json.loads(path.read_text())
    cues = [c.lower() for c in doc["next_step_cues"]]
    results, failures, covered = [], [], set()
    for scenario in doc["scenarios"]:
        name, rule = scenario["name"], scenario["rule"]
        if rule not in rule_ids:
            failures.append(f"scenario {name} names unknown rule {rule}")
            continue
        entry, *args = scenario["entry"]
        harness = args[0] if entry == "harness_guard.py" and args else scenario.get("harness", "claude")
        reply, audited, stderr = run_hook(scenario, doc["envelope"])
        decision, text = hook_reply(harness, reply)
        if decision != "deny" or audited != "guard-deny:" + rule:
            failures.append(f"scenario {name} did not trigger {rule}: decision={decision!r} "
                            f"audit={audited!r} stderr={stderr.strip()[:200]!r}")
            continue
        covered.add(rule)
        if not isinstance(text, str) or not text.strip():
            failures.append(f"scenario {name} has a missing native reason for {harness}")
            continue
        low = text.lower()
        lost = []
        if rule.lower() not in low:
            lost.append("rule")
        if not any(c.lower() in low for c in scenario["cause"]):
            lost.append("cause")
        if not any(c in low for c in cues):
            lost.append("next step")
        results.append({"name": name, "rule": rule, "points": 3 - len(lost), "max": 3,
                        "lost": lost, "reply": text})
    for rule in rule_ids:
        if rule not in covered:
            failures.append(f"rule {rule} has no scenario that triggers it")
    return results, failures


def score_tools(path: Path) -> tuple[list, list]:
    """Run the Go tool scenarios and read the scores they write."""
    with tempfile.TemporaryDirectory(prefix="agent-tool-scores-") as tmp:
        out = Path(tmp, "scores.json")
        env = {**os.environ, "SECURE_AGENT_TOOL_SCENARIOS": str(path.resolve()),
               "SECURE_AGENT_TOOL_SCORES": str(out)}
        cmd = ["go", "test", "./daemon/internal/sysagent", "-run", TOOL_TEST, "-count=1", "-v"]
        proc = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=900)
        if proc.returncode != 0 or not out.exists():
            detail = [line for line in proc.stdout.splitlines() if "agent_scenarios_test.go" in line or "FAIL" in line]
            return [], [f"{' '.join(cmd)} exited {proc.returncode}: " + " | ".join(detail or [proc.stderr.strip()[-400:]])]
        return [{**s, "lost": s.get("lost") or []} for s in json.loads(out.read_text()) or []], []


def report_scores(hooks: list, tools: list, failures: list, bar: int) -> int:
    """Print the score report and return the gate's exit code."""
    total = maximum = 0
    for title, results in (("hook replies", hooks), ("local agent tools", tools)):
        points, possible = sum(r["points"] for r in results), sum(r["max"] for r in results)
        total, maximum = total + points, maximum + possible
        print(f"{title}: {points}/{possible}")
        for r in results:
            label = f"{r['name']} [{r['rule']}]" if "rule" in r else r["name"]
            print(f"  {r['points']}/{r['max']} {label}" + (f" lost: {', '.join(r['lost'])}" if r["lost"] else ""))
            if r["lost"] and "reply" in r:
                print(f"      reply: {r['reply']}")
    print(f"total: {total}/{maximum} (bar {bar})")

    if total < bar:
        failures = [*failures, f"total {total} is below the bar {bar}"]
    for failure in failures:
        print(f"FAIL: {failure}")
    print("FAIL" if failures else "PASS")
    return 1 if failures else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Score hook replies and local agent tool schemas.")
    parser.add_argument("--hooks", type=Path, default=SCENARIO_DIR / "hooks.json")
    parser.add_argument("--tools", type=Path, default=SCENARIO_DIR / "tools.json")
    parser.add_argument("--bar", type=int, default=SCORE_BAR)
    args = parser.parse_args(argv)

    rule_ids = [r["id"] for r in json.loads((HOOKS_DIR / "guard-rules.json").read_text())["rules"]]
    hooks, hook_failures = score_hooks(args.hooks, rule_ids)
    tools, tool_failures = score_tools(args.tools)
    return report_scores(hooks, tools, hook_failures + tool_failures, args.bar)


if __name__ == "__main__":
    raise SystemExit(main())
