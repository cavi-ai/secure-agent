#!/usr/bin/env python3
"""Usage: unregister_hooks.py <home>

Removes Secure Agent hook entries from harness configs; exits 1 when a config
does not parse."""

import json
import os
import sys

SCRIPTS = ("secret_guard.py", "harness_guard.py")


def hook_dirs(home):
    return [
        f"{home}/.claude/hooks",
        f"{home}/.cursor/hooks",
        f"{home}/.codex/hooks",
        f"{home}/.config/secure-agent/hooks/antigravity",
        f"{home}/.gemini/secure-agent/hooks",
    ]


def ours(command, dirs):
    return isinstance(command, str) and any(f"{d}/{s}" in command for d in dirs for s in SCRIPTS)


def strip_groups(events, dirs):
    """Claude, Codex and Antigravity: {event: [{"hooks": [{"command"}]}]}."""
    changed = False
    for event, groups in list(events.items()):
        if not isinstance(groups, list):
            continue
        kept = []
        for group in groups:
            entries = group.get("hooks") if isinstance(group, dict) else None
            if not isinstance(entries, list):
                kept.append(group)
                continue
            left = [h for h in entries if not (isinstance(h, dict) and ours(h.get("command"), dirs))]
            if len(left) != len(entries):
                changed = True
                if not left:
                    continue
                group = {**group, "hooks": left}
            kept.append(group)
        events[event] = kept
    return changed


def strip_flat(events, dirs):
    """Cursor: {event: [{"command"}]}."""
    changed = False
    for event, entries in list(events.items()):
        if not isinstance(entries, list):
            continue
        left = [h for h in entries if not (isinstance(h, dict) and ours(h.get("command"), dirs))]
        changed |= len(left) != len(entries)
        events[event] = left
    return changed


def edit(path, change):
    """False when the file does not parse."""
    try:
        with open(path, encoding="utf-8") as fh:
            original = fh.read()
    except FileNotFoundError:
        return True
    try:
        root = json.loads(original)
    except ValueError:
        return False
    if not isinstance(root, dict) or not change(root):
        return isinstance(root, dict)
    backup = path + ".bak-secure-agent-uninstall"
    if not os.path.exists(backup):
        with open(backup, "w", encoding="utf-8") as fh:
            fh.write(original)
    real = os.path.realpath(path)
    mode = os.stat(real).st_mode & 0o777
    tmp = f"{real}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(root, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, real)
    return True


def main(home):
    dirs = hook_dirs(home)

    def hooks_key(strip):
        def change(root):
            hooks = root.get("hooks")
            return isinstance(hooks, dict) and strip(hooks, dirs)
        return change

    def antigravity(root):
        hook = root.get("secure-agent")
        if not isinstance(hook, dict) or not strip_groups(hook, dirs):
            return False
        if all(not hook.get(e) for e in ("PreToolUse", "PostToolUse")) and set(hook) <= {"enabled", "PreToolUse", "PostToolUse"}:
            del root["secure-agent"]
        return True

    plugin = f"{home}/.config/opencode/plugins/secure-agent"

    def opencode(root):
        plugins = root.get("plugins")
        if not isinstance(plugins, list):
            return False
        left = [p for p in plugins if (p if isinstance(p, str) else (p or {}).get("package")) != plugin]
        root["plugins"] = left
        return len(left) != len(plugins)

    configs = [
        (f"{home}/.claude/settings.json", hooks_key(strip_groups)),
        (f"{home}/.codex/hooks.json", hooks_key(strip_groups)),
        (f"{home}/.cursor/hooks.json", hooks_key(strip_flat)),
        (f"{home}/.gemini/config/hooks.json", antigravity),
        (f"{home}/.config/opencode/opencode.json", opencode),
        (f"{home}/.config/opencode/opencode.jsonc", opencode),
    ]
    failed = False
    for path, change in configs:
        if not edit(path, change):
            print(f"  left unchanged (not plain JSON): {path}; remove its Secure Agent hook entries by hand")
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
