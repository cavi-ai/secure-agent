#!/usr/bin/env python3
"""The agent scenario runner exits non-zero below its bar and when a guard
rule id or local agent tool has no scenario."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import agent_scenarios

DATA = agent_scenarios.SCENARIO_DIR


class AgentScenarioGateTests(unittest.TestCase):
    def write(self, name: str, doc: dict) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name, name)
        path.write_text(json.dumps(doc))
        return path

    def hooks_where(self, keep) -> Path:
        doc = json.loads((DATA / "hooks.json").read_text())
        doc["scenarios"] = [s for s in doc["scenarios"] if keep(s)]
        return self.write("hooks.json", doc)

    def test_codex_requires_native_decision_and_reason(self):
        hooks = self.hooks_where(lambda s: s["name"] == "harness-config-codex-read-denied")
        reason = "harness-config: .cursor/hooks.json is protected; ask the user"
        for field, error in (("permissionDecision", "decision=None"),
                             ("permissionDecisionReason", "missing native reason")):
            reply = {
                "permission": "deny",
                "agent_message": reason,
                "hookSpecificOutput": {
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                },
            }
            del reply["hookSpecificOutput"][field]
            with self.subTest(field=field), patch.object(
                agent_scenarios, "run_hook", return_value=(reply, "guard-deny:harness-config", "")
            ):
                _, failures = agent_scenarios.score_hooks(hooks, ["harness-config"])
                self.assertTrue(any(error in failure for failure in failures), failures)

    def test_shell_fixtures_work_under_spaced_temp_parent(self):
        rules = ["env-files", "shell-rc"]
        hooks = self.hooks_where(lambda s: s["rule"] in rules and s["payload"]["tool_name"] == "Bash")
        with tempfile.TemporaryDirectory(prefix="scenario test ") as parent, patch.object(tempfile, "tempdir", parent):
            results, failures = agent_scenarios.score_hooks(hooks, rules)
        self.assertEqual(failures, [])
        self.assertEqual({result["rule"] for result in results}, set(rules))

    def test_total_score_must_meet_bar(self):
        hooks = [{"name": "denied read", "rule": "keychain", "points": 2, "max": 3, "lost": ["cause"]}]
        tools = [{"name": "inspect_snapshot", "points": 3, "max": 3, "lost": []}]
        for bar, exit_code, status in ((6, 1, "FAIL: total 5 is below the bar 6"), (5, 0, "PASS")):
            with self.subTest(bar=bar), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(agent_scenarios.report_scores(hooks, tools, [], bar), exit_code)
                self.assertIn(f"total: 5/6 (bar {bar})", output.getvalue())
                self.assertIn(status, output.getvalue().splitlines())

    def test_rule_without_scenario_fails(self):
        hooks = self.hooks_where(lambda s: s["name"] == "ssh-keys-read-denied")
        results, failures = agent_scenarios.score_hooks(hooks, ["ssh-keys", "keychain"])
        self.assertEqual([result["rule"] for result in results], ["ssh-keys"])
        self.assertEqual(failures, ["rule keychain has no scenario that triggers it"])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(agent_scenarios.report_scores(results, [], failures, bar=0), 1)

    def test_tool_without_scenario_fails(self):
        doc = json.loads((DATA / "tools.json").read_text())
        doc["tools"] = [t for t in doc["tools"] if t["name"] != "inspect_skill"]
        _, failures = agent_scenarios.score_tools(self.write("tools.json", doc))
        self.assertTrue(any("tool inspect_skill has no scenario" in failure for failure in failures), failures)


if __name__ == "__main__":
    unittest.main()
