#!/usr/bin/env python3
"""The agent scenario runner exits non-zero below its bar and when a guard
rule id or local agent tool has no scenario."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNNER = HERE / "agent_scenarios.py"
DATA = HERE / "agent-scenarios"


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(RUNNER), *args], capture_output=True, text=True, timeout=900)


class AgentScenarioGateTests(unittest.TestCase):
    def write(self, name: str, doc: dict) -> str:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name, name)
        path.write_text(json.dumps(doc))
        return str(path)

    def hooks_where(self, keep) -> str:
        doc = json.loads((DATA / "hooks.json").read_text())
        doc["scenarios"] = [s for s in doc["scenarios"] if keep(s)]
        return self.write("hooks.json", doc)

    def test_score_below_bar_fails(self):
        # One scenario per rule covers every rule with fewer points than the recorded set.
        seen = set()

        def first_per_rule(scenario):
            fresh = scenario["rule"] not in seen
            seen.add(scenario["rule"])
            return fresh

        hooks = self.hooks_where(first_per_rule)
        below = run("--hooks", hooks)
        self.assertEqual(below.returncode, 1, below.stdout)
        self.assertIn("is below the bar", below.stdout)
        passing = run("--hooks", hooks, "--bar", "0")
        self.assertEqual(passing.returncode, 0, passing.stdout)

    def test_rule_without_scenario_fails(self):
        result = run("--hooks", self.hooks_where(lambda s: s["rule"] != "keychain"), "--bar", "0")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("FAIL: rule keychain has no scenario that triggers it", result.stdout)

    def test_tool_without_scenario_fails(self):
        doc = json.loads((DATA / "tools.json").read_text())
        doc["tools"] = [t for t in doc["tools"] if t["name"] != "inspect_skill"]
        result = run("--tools", self.write("tools.json", doc), "--bar", "0")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("tool inspect_skill has no scenario", result.stdout)


if __name__ == "__main__":
    unittest.main()
