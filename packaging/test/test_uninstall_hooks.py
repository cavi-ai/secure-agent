"""uninstall.sh removes only the hook files Secure Agent installed.

The test runs uninstall.sh's remove_hook function on its own, never the
script: the rest of it unloads launch agents and may ask for sudo.
"""

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UNINSTALL = ROOT / "packaging" / "uninstall.sh"
HOOKS = ("secret_guard", "injection_scan", "activity_log")


def remove_hook(path: Path, name: str) -> str:
    function = re.search(r"^remove_hook\(\) \{\n.*?^\}\n", UNINSTALL.read_text(), re.S | re.M).group(0)
    result = subprocess.run(["bash", "-c", function + 'remove_hook "$1" "$2"\n', "bash", str(path), name],
                            capture_output=True, text=True, check=True)
    return result.stdout


class RemoveHookTest(unittest.TestCase):
    def test_every_bundled_hook_carries_its_marker(self):
        for name in HOOKS:
            lines = (ROOT / "plugin" / "hooks" / f"{name}.py").read_text().splitlines()
            self.assertIn(f"# secure-agent-hook: {name}", lines[:3], name)

    def test_removes_installed_copies_and_symlinks_and_keeps_other_files(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            installed = d / "secret_guard.py"
            installed.write_text((ROOT / "plugin" / "hooks" / "secret_guard.py").read_text())
            linked = d / "injection_scan.py"
            linked.symlink_to(ROOT / "plugin" / "hooks" / "injection_scan.py")
            own = d / "activity_log.py"
            own.write_text("#!/bin/sh\n# my own hook; it calls secure-agent status\n")
            remove_hook(installed, "secret_guard")
            remove_hook(linked, "injection_scan")
            out = remove_hook(own, "activity_log")
            self.assertFalse(installed.exists())
            self.assertFalse(linked.is_symlink())
            self.assertTrue(own.exists())
            self.assertIn("kept (not ours)", out)


UNREGISTER = ROOT / "packaging" / "lib" / "unregister_hooks.py"


def unregister(home: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["python3", str(UNREGISTER), str(home)], capture_output=True, text=True)


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


class UnregisterHooksTest(unittest.TestCase):
    def test_removes_only_secure_agent_entries(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            guard = f"python3 '{home}/.claude/hooks/secret_guard.py'"
            mine = {"type": "command", "command": "~/bin/my-hook"}
            write_json(home / ".claude/settings.json", {"model": "x", "hooks": {
                "PreToolUse": [{"hooks": [{"type": "command", "command": guard, "timeout": 60}]},
                               {"matcher": "Bash", "hooks": [mine, {"type": "command", "command": guard}]}],
                "PostToolUse": [{"hooks": [{"type": "command", "command": guard}]}]}})
            write_json(home / ".cursor/hooks.json", {"version": 1, "hooks": {
                "preToolUse": [{"command": f"python3 '{home}/.cursor/hooks/secret_guard.py'"}, {"command": "other"}]}})
            write_json(home / ".codex/hooks.json", {"hooks": {
                "PreToolUse": [{"hooks": [{"type": "command", "command": f"python3 '{home}/.codex/hooks/harness_guard.py' codex"}]}]}})
            ag = f"python3 '{home}/.config/secure-agent/hooks/antigravity/harness_guard.py' antigravity"
            write_json(home / ".gemini/config/hooks.json", {"other": {"PreToolUse": []}, "secure-agent": {
                "enabled": True, "PreToolUse": [{"matcher": "*", "hooks": [{"command": ag + " PreToolUse"}]}],
                "PostToolUse": [{"matcher": "*", "hooks": [{"command": ag + " PostToolUse"}]}]}})
            plugin = f"{home}/.config/opencode/plugins/secure-agent"
            write_json(home / ".config/opencode/opencode.json", {"plugins": [plugin, "other-plugin"]})

            result = unregister(home)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            claude = json.loads((home / ".claude/settings.json").read_text())
            self.assertEqual(claude["model"], "x")
            self.assertEqual(claude["hooks"]["PreToolUse"], [{"matcher": "Bash", "hooks": [mine]}])
            self.assertEqual(claude["hooks"]["PostToolUse"], [])
            self.assertTrue((home / ".claude/settings.json.bak-secure-agent-uninstall").exists())
            cursor = json.loads((home / ".cursor/hooks.json").read_text())
            self.assertEqual(cursor["hooks"]["preToolUse"], [{"command": "other"}])
            self.assertEqual(json.loads((home / ".codex/hooks.json").read_text())["hooks"]["PreToolUse"], [])
            self.assertEqual(json.loads((home / ".gemini/config/hooks.json").read_text()), {"other": {"PreToolUse": []}})
            self.assertEqual(json.loads((home / ".config/opencode/opencode.json").read_text())["plugins"], ["other-plugin"])

    def test_unparsable_config_is_left_and_reported(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            path = home / ".config/opencode/opencode.jsonc"
            path.parent.mkdir(parents=True)
            path.write_text('{\n  // comment\n  "plugins": []\n}\n')
            result = unregister(home)
            self.assertEqual(result.returncode, 1)
            self.assertIn("left unchanged", result.stdout)
            self.assertIn("// comment", path.read_text())

    def test_untouched_config_is_not_rewritten(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            write_json(home / ".claude/settings.json", {"hooks": {"PreToolUse": [{"hooks": [{"command": "x"}]}]}})
            before = (home / ".claude/settings.json").read_text()
            self.assertEqual(unregister(home).returncode, 0)
            self.assertEqual((home / ".claude/settings.json").read_text(), before)
            self.assertFalse((home / ".claude/settings.json.bak-secure-agent-uninstall").exists())


if __name__ == "__main__":
    unittest.main()
