import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HOOKS = ROOT / "plugin/hooks"
SCRIPT = ROOT / "plugin/package_marketplace.py"
RUNTIME = (
    "secret_guard.py", "harness_guard.py", "activity_log.py",
    "injection_scan.py", "guard-rules.json",
)
ADAPTERS = {
    "openclaw": ("openclaw.plugin.json", "package.json", "index.mjs"),
    "hermes": ("plugin.yaml", "__init__.py"),
    "opencode": ("package.json", "index.js"),
}


class MarketplacePackagesTest(unittest.TestCase):
    def test_packages_and_existing_output(self):
        with tempfile.TemporaryDirectory() as temp:
            for host in ("claude", "codex", "cursor", "antigravity", *ADAPTERS):
                with self.subTest(host=host):
                    out = Path(temp) / host
                    command = [sys.executable, str(SCRIPT), "--host", host, "--output", str(out)]
                    run = subprocess.run(command, capture_output=True, text=True)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    if host in ("claude", "codex", "cursor"):
                        runtime = out / "hooks"
                    elif host == "antigravity":
                        runtime = out / "scripts"
                    else:
                        runtime = out
                    for name in RUNTIME:
                        self.assertEqual((runtime / name).read_bytes(), (HOOKS / name).read_bytes())
                    self.assertEqual((out / "LICENSE").read_bytes(), (ROOT / "LICENSE").read_bytes())
                    self.assertTrue((out / "README.md").is_file())
                    self.assertFalse(any(
                        p.name.startswith("test_") or p.name == "__pycache__" for p in out.rglob("*")
                    ))
                    if host in ADAPTERS:
                        for name in ADAPTERS[host]:
                            self.assertEqual((out / name).read_bytes(), (HOOKS / host / name).read_bytes())
                        if host == "openclaw":
                            manifest = json.loads((out / "openclaw.plugin.json").read_text())
                            self.assertIs(manifest.get("activation", {}).get("onStartup"), True)
                    elif host == "claude":
                        source = ROOT / "plugin/.claude-plugin/plugin.json"
                        manifest = (out / ".claude-plugin/plugin.json").read_bytes()
                        self.assertEqual(manifest, source.read_bytes())
                        # Claude loads hooks/hooks.json by convention.
                        self.assertNotIn("hooks", json.loads(manifest))
                        hooks = (out / "hooks/hooks.json").read_bytes()
                        self.assertEqual(hooks, (HOOKS / "hooks.json").read_bytes())
                        event_hooks = [{
                            "matcher": "*",
                            "hooks": [{
                                "type": "command",
                                "command": 'python3 "${CLAUDE_PLUGIN_ROOT}/hooks/secret_guard.py"',
                            }],
                        }]
                        self.assertEqual(json.loads(hooks), {
                            "hooks": {event: event_hooks for event in ("PreToolUse", "PostToolUse")},
                        })
                    elif host in ("codex", "cursor"):
                        manifest = json.loads((out / f".{host}-plugin/plugin.json").read_text())
                        self.assertEqual(manifest["name"], "secure-agent")
                        config = json.loads((out / "hooks/hooks.json").read_text())
                        if host == "codex":
                            self.assertEqual(set(config["hooks"]), {"PreToolUse", "PostToolUse"})
                            for groups in config["hooks"].values():
                                hook_command = groups[0]["hooks"][0]["command"]
                                self.assertEqual(
                                    hook_command, 'python3 "${PLUGIN_ROOT}/hooks/harness_guard.py" codex'
                                )
                        else:
                            self.assertEqual(config["version"], 1)
                            self.assertEqual(set(config["hooks"]), {"preToolUse", "postToolUse"})
                            for entries in config["hooks"].values():
                                self.assertEqual(entries, [{
                                    "command": 'python3 "${CURSOR_PLUGIN_ROOT}/hooks/secret_guard.py"',
                                }])
                    else:
                        config = json.loads((out / "hooks.json").read_text())["secure-agent"]
                        self.assertTrue(config["enabled"])
                        for event in ("PreToolUse", "PostToolUse"):
                            self.assertEqual(config[event], [{
                                "matcher": ".*", "hooks": [{
                                    "type": "command", "timeout": 60,
                                    "command": f"python3 ./scripts/harness_guard.py antigravity {event}",
                                }],
                            }])
                        logo = ROOT / "daemon/internal/api/web_dist/brand-icon.png"
                        self.assertEqual((out / "assets/logo.png").read_bytes(), logo.read_bytes())
                    marker = out / "sentinel"
                    marker.write_text("keep")
                    again = subprocess.run(command, capture_output=True)
                    self.assertNotEqual(again.returncode, 0)
                    self.assertEqual(marker.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
