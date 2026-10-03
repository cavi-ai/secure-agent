#!/usr/bin/env bash
# Local/dev install. Builds "Secure Agent.app", installs it as
# /Applications/Secure Agent.app and launches that copy.
#
# One build, one location: macOS Background Task Management binds the
# file-telemetry helper to the copy that registered it, so the build output in
# dist/ is never registered with LaunchServices or opened. The previous
# /Applications copy goes to the Trash.
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
BUILD_DIR="${REPO_ROOT}/dist/${APP_NAME}.app"
INSTALL_DIR="/Applications/${APP_NAME}.app"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

source "${REPO_ROOT}/packaging/lib/sign_identity.sh"
source "${REPO_ROOT}/packaging/lib/telemetry_status.sh"
source "${REPO_ROOT}/packaging/lib/replaced_bundle.sh"

# Resolve once and export, so make_app.sh signs with the exact identity this
# script reports below.
CODESIGN_IDENTITY="$(resolve_sign_identity)"
export CODESIGN_IDENTITY

"${REPO_ROOT}/packaging/make_app.sh"

# The menu bar app and its daemon child, from any copy. The file-telemetry
# helper (Contents/MacOS/secure-agent-esd) is launchd's and keeps running.
app_running() {
  pgrep -f "/${APP_NAME}\.app/Contents/(MacOS/SecureAgent|Helpers/secure-agentd)( |$)" >/dev/null 2>&1
}

# `open` does NOT replace a running instance, and the bundle is about to be
# replaced: quit the app and wait for its daemon child to exit.
if app_running; then
  echo "Quitting the running Secure Agent..."
  osascript -e 'tell application "Secure Agent" to quit' >/dev/null 2>&1 || true
  for _ in $(seq 1 40); do
    app_running || break
    sleep 0.5
  done
  if app_running; then
    echo "install: Secure Agent did not quit; quit it from the menu bar and run make install again." >&2
    exit 1
  fi
fi

# The replaced copy goes to the Trash without an .app suffix, and is
# unregistered after the move: LaunchServices follows a moved bundle.
if [[ -e "${INSTALL_DIR}" ]]; then
  "${LSREGISTER}" -u "${INSTALL_DIR}" >/dev/null 2>&1 || true
  TRASHED="$(replaced_bundle_path "${HOME}/.Trash" "${APP_NAME}" "$(date +%Y%m%d-%H%M%S)-$$")"
  mv "${INSTALL_DIR}" "${TRASHED}"
  "${LSREGISTER}" -u "${TRASHED}" >/dev/null 2>&1 || true
  echo "Moved the previous copy to the Trash: ${TRASHED}"
fi

ditto "${BUILD_DIR}" "${INSTALL_DIR}"
codesign --verify --deep --strict "${INSTALL_DIR}"

# Only the /Applications copy is known to LaunchServices.
"${LSREGISTER}" -u "${BUILD_DIR}" >/dev/null 2>&1 || true
"${LSREGISTER}" -f "${INSTALL_DIR}"

echo "============================================================"
echo "Built ${BUILD_DIR}"
echo "Installed ${INSTALL_DIR}"
echo ""
echo "Launching ${INSTALL_DIR}. Use the menu bar icon to open"
echo "Setup and install the harness hooks, and to Quit (which stops"
echo "the background monitor completely). The build in dist/ is"
echo "never opened: only the /Applications copy manages file telemetry."
echo ""
echo "This is the real install. To build a DMG for distribution:  make dmg"
echo "============================================================"

open "${INSTALL_DIR}"

# Report whether file telemetry is actually running post-install. Best
# effort only — never fails the install.
report_file_telemetry() {
  local ad_hoc=0 config default_socket socket state=""
  [[ "${CODESIGN_IDENTITY}" == "-" ]] && ad_hoc=1

  if [[ "${CODESIGN_IDENTITY}" == "-" ]]; then
    echo "Signing mode: ad-hoc"
  else
    echo "Signing mode: ${CODESIGN_IDENTITY}"
  fi

  config="${HOME}/.config/secure-agent/config.yaml"
  default_socket="${HOME}/.config/secure-agent/daemon.sock"
  socket="$(resolve_socket_path "${config}" "${default_socket}")"

  if command -v python3 >/dev/null 2>&1; then
    state="$(wait_for_status "${socket}" 90 || true)"
  fi

  telemetry_status_line "${state}" "${ad_hoc}"
}
report_file_telemetry || true
