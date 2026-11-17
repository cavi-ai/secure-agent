import json
import unittest
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[1]


class ClaudePluginPackageTest(unittest.TestCase):
    def test_default_hooks_use_packaged_guard(self):
        manifest = json.loads((PLUGIN / ".claude-plugin/plugin.json").read_text())
        self.assertNotIn("hooks", manifest)  # hooks/hooks.json loads by convention
        self.assertTrue((PLUGIN / "README.md").is_file())
        config = json.loads((PLUGIN / "hooks/hooks.json").read_text())
        self.assertEqual(set(config), {"hooks"})
        events = config["hooks"]
        self.assertEqual(set(events), {"PreToolUse", "PostToolUse"})
        self.assertEqual([entry["matcher"] for entry in events["PreToolUse"]], [
            "Bash", "Read|Grep|Glob|Write|Edit|MultiEdit|NotebookEdit",
        ])
        self.assertEqual([entry["matcher"] for entry in events["PostToolUse"]], [".*"])
        for entries in events.values():
            for entry in entries:
                self.assertEqual(entry["hooks"], [{
                    "type": "command",
                    "command": 'python3 "${CLAUDE_PLUGIN_ROOT}/hooks/secret_guard.py"',
                }])
        for name in ("secret_guard.py", "activity_log.py", "injection_scan.py", "guard-rules.json"):
            self.assertTrue((PLUGIN / "hooks" / name).is_file(), name)


if __name__ == "__main__":
    unittest.main()
