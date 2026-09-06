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

echo "Unlinking plugin hooks..."
# Only remove symlinks (what the installer creates) or files carrying our
# marker comment — a user's own replacement file must not be deleted.
remove_hook() {
  local path="$1"
  if [ -L "$path" ]; then
    rm -f "$path"
  elif [ -f "$path" ] && grep -q "secure-agent" "$path" 2>/dev/null; then
    rm -f "$path"
  elif [ -e "$path" ]; then
    echo "  kept (not ours): $path"
  fi
}
for target in "${HOME}/.claude/hooks" "${HOME}/.cursor/hooks" "${HOME}/.config/opencode/hooks"; do
  for hook in secret_guard.py injection_scan.py activity_log.py; do
    remove_hook "${target}/${hook}"
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
