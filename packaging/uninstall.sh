#!/usr/bin/env bash
set -euo pipefail

BIN_DEST="${HOME}/.local/bin/secure-agentd"
MENUBAR_DEST="${HOME}/.local/bin/secure-agent-menubar"
PLIST_DEST="${HOME}/Library/LaunchAgents/com.cavi-ai.secure-agentd.plist"
MENUBAR_PLIST_DEST="${HOME}/Library/LaunchAgents/com.cavi-ai.secure-agent-menubar.plist"

echo "Unloading LaunchAgents..."
launchctl unload "${PLIST_DEST}" 2>/dev/null || true
launchctl unload "${MENUBAR_PLIST_DEST}" 2>/dev/null || true

echo "Removing LaunchAgent plists..."
rm -f "${PLIST_DEST}" "${MENUBAR_PLIST_DEST}"

echo "Removing installed binaries..."
rm -f "${BIN_DEST}" "${MENUBAR_DEST}" "${HOME}/.local/bin/secure-agent"

# Endpoint Security collector installed by earlier versions outside the app
# bundle (the in-bundle collector is unregistered by the app's Uninstall).
ESD_LABEL="com.cavi-ai.secure-agent-esd"
LEGACY_ESD=(
  "/Library/LaunchDaemons/${ESD_LABEL}.plist"
  "/Library/PrivilegedHelperTools/${ESD_LABEL}"
  "/Library/Application Support/secure-agent/esd.binhash"
)
for path in "${LEGACY_ESD[@]}"; do
  if [ -e "$path" ]; then
    echo "Removing the old file-telemetry collector (admin password)..."
    sudo launchctl bootout system "${LEGACY_ESD[0]}" 2>/dev/null || true
    sudo rm -f "${LEGACY_ESD[@]}"
    break
  fi
done

echo "Removing hook registrations..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Entries first: a registered hook whose script is gone blocks the harness.
registrations_ok=1
python3 "${SCRIPT_DIR}/lib/unregister_hooks.py" "${HOME}" || registrations_ok=0

echo "Unlinking plugin hooks..."
# Only remove symlinks (what the development installer creates) or copies
# carrying the hook's own marker line (what the app installs) — a user's own
# file with the same name must not be deleted.
remove_hook() {
  local path="$1" marker="# secure-agent-hook: $2"
  if [ -L "$path" ]; then
    rm -f "$path"
  elif [ -f "$path" ] && grep -qxF "$marker" "$path" 2>/dev/null; then
    rm -f "$path"
  elif [ -e "$path" ]; then
    echo "  kept (not ours): $path"
  fi
}
# guard-rules.json goes with the secret_guard.py beside it.
remove_hook_dir() {
  local dir="$1" hook
  [ -d "$dir" ] || return 0
  if [ "$registrations_ok" -eq 0 ] && { [ -e "$dir/secret_guard.py" ] || [ -e "$dir/harness_guard.py" ]; }; then
    echo "  kept (a config still may register it): $dir"
    return 0
  fi
  local had_guard=0
  if [ -L "$dir/secret_guard.py" ] || grep -qxF "# secure-agent-hook: secret_guard" "$dir/secret_guard.py" 2>/dev/null; then
    had_guard=1
  fi
  for hook in secret_guard injection_scan activity_log harness_guard; do
    remove_hook "${dir}/${hook}.py" "$hook"
  done
  if [ "$had_guard" -eq 1 ] && { [ -L "$dir/guard-rules.json" ] || [ -f "$dir/guard-rules.json" ]; }; then
    rm -f "$dir/guard-rules.json"
  fi
}
for target in "${HOME}/.claude/hooks" "${HOME}/.cursor/hooks" "${HOME}/.codex/hooks" \
  "${HOME}/.config/opencode/hooks" "${HOME}/.config/secure-agent/hooks/antigravity"; do
  remove_hook_dir "$target"
done
# Plugin directories, when their own marker shows they are ours.
remove_plugin_dir() {
  local dir="$1" marker_file="$2" marker="$3"
  [ -d "$dir" ] || return 0
  if head -n 2 "$dir/$marker_file" 2>/dev/null | grep -qF "$marker"; then
    rm -rf "$dir"
  else
    echo "  kept (not ours): $dir"
  fi
}
remove_plugin_dir "${HOME}/.config/opencode/plugins/secure-agent" index.js "secure-agent-managed-plugin: opencode-v2"
remove_plugin_dir "${HOME}/.hermes/plugins/secure-agent" plugin.yaml "secure-agent-managed-plugin: hermes"
if grep -qs "secure-agent" "${HOME}/.hermes/config.yaml"; then
  echo "  Hermes: remove secure-agent from plugins in ~/.hermes/config.yaml"
fi
# OpenClaw keeps its plugin entry in its own config, so its files stay.
if [ -d "${HOME}/.openclaw/extensions/secure-agent" ]; then
  if ! { command -v openclaw >/dev/null 2>&1 && openclaw plugins disable secure-agent >/dev/null 2>&1; }; then
    echo "  OpenClaw: run 'openclaw plugins disable secure-agent'"
  fi
fi

echo ""
echo "Removed binaries, LaunchAgents, and hooks."
echo "State left behind (delete manually if unwanted):"
for leftover in \
  "${HOME}/.config/secure-agent" \
  "${HOME}/.local/state/secure-agent" \
  "${HOME}/.agents/logs" \
  "${HOME}/Library/Logs/secure-agent"; do
  [ -e "$leftover" ] && echo "  $leftover"
done
