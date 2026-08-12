#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DEST="${HOME}/.local/bin/secure-agentd"
PLIST_DEST="${HOME}/Library/LaunchAgents/com.cavi-ai.secure-agentd.plist"

mkdir -p "${HOME}/.local/bin" "${HOME}/Library/LaunchAgents"

echo "Building secure-agentd daemon..."
cd "${SCRIPT_DIR}"
go build -o "${BIN_DEST}" ./daemon/cmd/secure-agentd

echo "Installing LaunchAgent plist..."
sed "s|/usr/local/bin/secure-agentd|${BIN_DEST}|g" packaging/com.cavi-ai.secure-agentd.plist > "${PLIST_DEST}"

echo "Installing plugin hooks..."
bash plugin/install.sh

echo "Loading LaunchAgent..."
launchctl unload "${PLIST_DEST}" 2>/dev/null || true
launchctl load "${PLIST_DEST}"

echo "============================================================"
echo "secure-agentd installed successfully!"
echo "Binary: ${BIN_DEST}"
echo "Plist:  ${PLIST_DEST}"
echo ""
echo "NOTE: For Endpoint Security (eslogger) file monitoring,"
echo "grant Full Disk Access to ${BIN_DEST} in System Settings ->"
echo "Privacy & Security -> Full Disk Access."
echo "============================================================"
