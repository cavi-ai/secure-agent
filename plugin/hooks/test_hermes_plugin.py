"""Native Hermes callbacks execute the real shared guard."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch


class HermesPluginTests(unittest.TestCase):
    def test_callbacks_block_preserve_identity_and_handle_missing_guard(self):
        source = Path(__file__).parent
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("harness_guard.py", "secret_guard.py", "activity_log.py", "injection_scan.py", "guard-rules.json"):
                shutil.copy2(source / name, root / name)
            shutil.copy2(source / "hermes/__init__.py", root / "__init__.py")
            (root / "modes.json").write_text(json.dumps({"ssh-keys": "deny"}))
            spec = importlib.util.spec_from_file_location("secure_agent_hermes_fixture", root / "__init__.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            callbacks = {}
            class Context:
                def register_hook(self, name, callback):
                    callbacks[name] = callback
            module.register(Context())
            with patch.dict(os.environ, {"HOME": directory, "SECURE_AGENT_ACTIVITY_LOG": str(root / "activity.jsonl"),
                                         "SECURE_AGENT_GUARD_MODES": str(root / "modes.json")}):
                before = callbacks["pre_tool_call"]
                identity = {"session_id": "hermes-native-session", "cwd": directory}
                self.assertEqual(before("read_file", {"path": directory + "/.ssh/id_rsa"}, **identity)["action"], "block")
                self.assertIsNone(before("terminal", {"command": "echo hello"}, **identity))
                callbacks["post_tool_call"]("terminal", {"command": "echo hello"}, "hello", **identity)
                rows = [json.loads(line) for line in (root / "activity.jsonl").read_text().splitlines()]
                self.assertTrue(any(row.get("session_id") == identity["session_id"] for row in rows))
                self.assertTrue(all(row.get("pid") == os.getpid() for row in rows if row.get("pid")))
                (root / "harness_guard.py").unlink()
                self.assertEqual(before("terminal", {"command": "echo hello"}, **identity)["action"], "block")


if __name__ == "__main__":
    unittest.main()
