#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DEST="${HOME}/.local/bin/secure-agentd"
MENUBAR_DEST="${HOME}/.local/bin/secure-agent-menubar"
CLI_DEST="${HOME}/.local/bin/secure-agent"
PLIST_DEST="${HOME}/Library/LaunchAgents/com.cavi-ai.secure-agentd.plist"
MENUBAR_PLIST_DEST="${HOME}/Library/LaunchAgents/com.cavi-ai.secure-agent-menubar.plist"

mkdir -p "${HOME}/.local/bin" "${HOME}/Library/LaunchAgents"

echo "Building secure-agentd daemon & CLI tool..."
cd "${SCRIPT_DIR}"
go build -o "${BIN_DEST}" ./daemon/cmd/secure-agentd
go build -o "${CLI_DEST}" ./cmd/secure-agent

echo "Building secure-agent-menubar..."
cd "${SCRIPT_DIR}/menubar"
swift build -c release
cp .build/release/secure-agent-menubar "${MENUBAR_DEST}"

echo "Installing LaunchAgent plists..."
cd "${SCRIPT_DIR}"
sed "s|/usr/local/bin/secure-agentd|${BIN_DEST}|g" packaging/com.cavi-ai.secure-agentd.plist > "${PLIST_DEST}"
sed "s|/usr/local/bin/secure-agent-menubar|${MENUBAR_DEST}|g" packaging/com.cavi-ai.secure-agent-menubar.plist > "${MENUBAR_PLIST_DEST}"

echo "Installing plugin hooks..."
bash plugin/install.sh

echo "Loading LaunchAgents..."
launchctl unload "${PLIST_DEST}" 2>/dev/null || true
launchctl load "${PLIST_DEST}"
launchctl unload "${MENUBAR_PLIST_DEST}" 2>/dev/null || true
launchctl load "${MENUBAR_PLIST_DEST}"

echo "============================================================"
echo "secure-agent installed successfully!"
echo "Daemon Binary:  ${BIN_DEST}"
echo "Menubar Binary: ${MENUBAR_DEST}"
echo "Daemon Plist:   ${PLIST_DEST}"
echo "Menubar Plist:  ${MENUBAR_PLIST_DEST}"
echo ""
echo "NOTE: For Endpoint Security (eslogger) file monitoring,"
echo "grant Full Disk Access to ${BIN_DEST} in System Settings ->"
echo "Privacy & Security -> Full Disk Access."
echo "============================================================"
