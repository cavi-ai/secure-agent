#!/usr/bin/env python3
"""Build a host-specific Secure Agent plugin in a new directory."""
import argparse
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugin"
HOOKS = PLUGIN / "hooks"
HOSTS = ("claude", "codex", "cursor", "antigravity", "openclaw", "hermes", "opencode")
RUNTIME = (
    "secret_guard.py", "harness_guard.py", "activity_log.py",
    "injection_scan.py", "guard-rules.json",
)
ADAPTERS = {
    "openclaw": ("openclaw.plugin.json", "package.json", "index.mjs"),
    "hermes": ("plugin.yaml", "__init__.py"),
    "opencode": ("package.json", "index.js"),
}


def build(host, output):
    if host not in HOSTS:
        raise ValueError(f"unsupported host: {host}")
    output = Path(output)
    # A pre-existing path, including a dangling link, is never replaced.
    output.mkdir()
    try:
        def copy(source, destination):
            dest = output / destination
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest)

        def write(path, value):
            dest = output / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

        copy(ROOT / "LICENSE", "LICENSE")
        version = json.loads((PLUGIN / ".claude-plugin/plugin.json").read_text())["version"]
        readme = (
            f"# Secure Agent for {host}\n\n"
            "Install and configure Secure Agent and Python 3.12 or later first. "
            "Disable the previous hook integration before enabling this package. "
            "Keep Secure Agent's manual setup hooks disabled while this package is enabled. "
            "Use one Secure Agent hook installation per host. Restart the host after setup.\n\n"
            "[Installation instructions](https://github.com/cavi-ai/secure-agent/blob/main/"
            "plugin/README.md#local-plugin-packages)\n"
        )
        if host == "codex":
            readme += "\nCodex requires the user to trust the plugin hooks before they run.\n"
        (output / "README.md").write_text(readme, encoding="utf-8")
        if host in ("claude", "codex", "cursor"):
            runtime_dir = Path("hooks")
        elif host == "antigravity":
            runtime_dir = Path("scripts")
        else:
            runtime_dir = Path()
        for name in RUNTIME:
            copy(HOOKS / name, runtime_dir / name)
        if host in ADAPTERS:
            for name in ADAPTERS[host]:
                copy(HOOKS / host / name, name)
        elif host == "claude":
            copy(PLUGIN / ".claude-plugin/plugin.json", ".claude-plugin/plugin.json")
            copy(HOOKS / "hooks.json", "hooks/hooks.json")
        elif host == "codex":
            write(".codex-plugin/plugin.json", {
                "name": "secure-agent", "version": version,
                "description": "Check tool requests with Secure Agent and record tool activity.",
            })
            cmd = 'python3 "${PLUGIN_ROOT}/hooks/harness_guard.py" codex'
            write("hooks/hooks.json", {
                "hooks": {
                    event: [{"hooks": [{"type": "command", "command": cmd}]}]
                    for event in ("PreToolUse", "PostToolUse")
                },
            })
        elif host == "cursor":
            write(".cursor-plugin/plugin.json", {
                "name": "secure-agent", "version": version,
                "description": "Check tool requests with Secure Agent and record tool activity.",
            })
            cmd = 'python3 "${CURSOR_PLUGIN_ROOT}/hooks/secret_guard.py"'
            write("hooks/hooks.json", {
                "version": 1,
                "hooks": {event: [{"command": cmd}] for event in ("preToolUse", "postToolUse")},
            })
        elif host == "antigravity":
            write(".antigravity-plugin/plugin.json", {
                "$schema": "https://antigravity.google/schemas/v1/plugin.json",
                "name": "secure-agent", "displayName": "Secure Agent", "version": version,
                "description": "Check tool requests with Secure Agent and record tool activity.",
                "license": "MIT", "author": {"name": "CAVI", "url": "https://cavi-ai.xyz"},
                "logo": "assets/logo.png",
                "suggestedPrompts": ["Explain how Secure Agent protects tool requests."],
            })
            copy(ROOT / "daemon/internal/api/web_dist/brand-icon.png", "assets/logo.png")
            events = {
                event: [{
                    "matcher": ".*",
                    "hooks": [{
                        "type": "command",
                        "command": f"python3 ./scripts/harness_guard.py antigravity {event}",
                        "timeout": 60,
                    }],
                }]
                for event in ("PreToolUse", "PostToolUse")
            }
            write("hooks.json", {"secure-agent": {"enabled": True, **events}})
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", choices=HOSTS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        build(args.host, args.output)
    except OSError as exc:
        parser.exit(1, f"package creation failed: {exc}\n")


if __name__ == "__main__":
    main()
