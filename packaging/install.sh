#!/usr/bin/env bash
# Local/dev install. Builds "Secure Agent.app" and launches it.
#
# The app is fully self-contained: it runs the secure-agentd daemon as a CHILD
# process (see menubar DaemonSupervisor), so the daemon lives and dies with the
# visible menu bar app. There is NO LaunchAgent, nothing is placed in
# ~/.local/bin, and nothing keeps running after you quit from the menu bar.
#
# For distribution, build the single DMG instead:  make dmg
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="Secure Agent"
APP_DIR="${REPO_ROOT}/dist/${APP_NAME}.app"

"${REPO_ROOT}/packaging/make_app.sh"

echo "============================================================"
echo "Built ${APP_DIR}"
echo ""
echo "Launching it now. Use the menu bar icon to open Setup and"
echo "install the harness hooks, and to Quit (which stops the"
echo "background monitor completely)."
echo ""
echo "To install for real, build and open the DMG:  make dmg"
echo "============================================================"

open "${APP_DIR}"
