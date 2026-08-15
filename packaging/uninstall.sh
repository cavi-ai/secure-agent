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
rm -f "${HOME}/.claude/hooks/secret_guard.py"
rm -f "${HOME}/.claude/hooks/injection_scan.py"
rm -f "${HOME}/.claude/hooks/activity_log.py"
rm -f "${HOME}/.cursor/hooks/secret_guard.py"
rm -f "${HOME}/.cursor/hooks/injection_scan.py"
rm -f "${HOME}/.cursor/hooks/activity_log.py"

echo "============================================================"
echo "secure-agent has been completely uninstalled."
echo "============================================================"
