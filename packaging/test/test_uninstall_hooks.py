"""uninstall.sh removes only the hook files Secure Agent installed.

The test runs uninstall.sh's remove_hook function on its own, never the
script: the rest of it unloads launch agents and may ask for sudo.
"""

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


if __name__ == "__main__":
    unittest.main()
