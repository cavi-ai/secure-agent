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
for target in "${HOME}/.claude/hooks" "${HOME}/.cursor/hooks" "${HOME}/.config/opencode/hooks"; do
  for hook in secret_guard injection_scan activity_log; do
    remove_hook "${target}/${hook}.py" "$hook"
  done
done

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
