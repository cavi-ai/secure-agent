#!/usr/bin/env bash
# Builds universal binaries and assembles "Secure Agent.app".
#
# Environment:
#   CODESIGN_IDENTITY  Signing identity (default "-" = ad-hoc).
#                      Use "Developer ID Application: <Name> (<TeamID>)" for distribution.
#   VERSION            Marketing version (default: git describe or 0.1.0).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

APP_NAME="Secure Agent"
APP_DIR="${REPO_ROOT}/dist/${APP_NAME}.app"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 0.1.0)}"
BUILD_NUMBER="${BUILD_NUMBER:-$(git rev-parse --short HEAD 2>/dev/null || echo 1)}"
CODESIGN_IDENTITY="${CODESIGN_IDENTITY:--}"
BUNDLE_ID="com.cavi-ai.secure-agent"

echo "==> Building universal Go binaries (version ${VERSION})..."
mkdir -p bin
VERSION_LDFLAGS="-s -w -X github.com/cavi-ai/secure-agent/daemon/internal/api.Version=${VERSION}"
for arch in arm64 amd64; do
  CGO_ENABLED=0 GOOS=darwin GOARCH=${arch} go build -trimpath -ldflags "${VERSION_LDFLAGS}" \
    -o "bin/secure-agentd-${arch}" ./daemon/cmd/secure-agentd
  CGO_ENABLED=0 GOOS=darwin GOARCH=${arch} go build -trimpath -ldflags "${VERSION_LDFLAGS}" \
    -o "bin/secure-agent-${arch}" ./cmd/secure-agent
done
lipo -create -output bin/secure-agentd bin/secure-agentd-arm64 bin/secure-agentd-amd64
lipo -create -output bin/secure-agent  bin/secure-agent-arm64  bin/secure-agent-amd64
rm -f bin/secure-agentd-arm64 bin/secure-agentd-amd64 bin/secure-agent-arm64 bin/secure-agent-amd64

echo "==> Building universal menubar app..."
(cd menubar && swift build -c release --arch arm64 --arch x86_64)
MENUBAR_BIN="${REPO_ROOT}/menubar/.build/apple/Products/Release/secure-agent-menubar"
if [[ ! -x "${MENUBAR_BIN}" ]]; then
  MENUBAR_BIN="${REPO_ROOT}/menubar/.build/release/secure-agent-menubar"
fi
[[ -x "${MENUBAR_BIN}" ]] || { echo "error: menubar binary not found" >&2; exit 1; }

echo "==> Assembling ${APP_NAME}.app..."
rm -rf "${APP_DIR}"
mkdir -p "${APP_DIR}/Contents/MacOS" "${APP_DIR}/Contents/Helpers" "${APP_DIR}/Contents/Resources/hooks"

cp "${MENUBAR_BIN}" "${APP_DIR}/Contents/MacOS/SecureAgent"
cp bin/secure-agentd bin/secure-agent "${APP_DIR}/Contents/Helpers/"

for hook in plugin/hooks/*.py; do
  case "$(basename "${hook}")" in test_*) continue;; esac
  cp "${hook}" "${APP_DIR}/Contents/Resources/hooks/"
done
cp plugin/hooks/hooks.json "${APP_DIR}/Contents/Resources/hooks/" 2>/dev/null || true

if [[ -f "${REPO_ROOT}/packaging/AppIcon.icns" ]]; then
  cp "${REPO_ROOT}/packaging/AppIcon.icns" "${APP_DIR}/Contents/Resources/AppIcon.icns"
fi

cat > "${APP_DIR}/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Secure Agent</string>
    <key>CFBundleDisplayName</key><string>Secure Agent</string>
    <key>CFBundleIdentifier</key><string>${BUNDLE_ID}</string>
    <key>CFBundleExecutable</key><string>SecureAgent</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleVersion</key><string>${BUILD_NUMBER}</string>
    <key>CFBundleShortVersionString</key><string>${VERSION}</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>LSUIElement</key><true/>
    <key>NSUserNotificationAlertUsageDescription</key><string>Secure Agent sends alerts when AI agents trigger security flags.</string>
</dict>
</plist>
EOF

echo "==> Signing (${CODESIGN_IDENTITY})..."
codesign --force --options runtime --sign "${CODESIGN_IDENTITY}" \
  "${APP_DIR}/Contents/Helpers/secure-agentd" \
  "${APP_DIR}/Contents/Helpers/secure-agent"
codesign --force --options runtime --sign "${CODESIGN_IDENTITY}" "${APP_DIR}"

echo "==> Done: ${APP_DIR}"
codesign -dv "${APP_DIR}" 2>&1 | grep -E "Identifier|Signature|TeamIdentifier" || true
