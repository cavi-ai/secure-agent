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
# git-describe output lands in Info.plist XML — strip XML metacharacters so a
# crafted tag name can't break or inject the plist.
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 0.1.0)}"
VERSION="$(printf '%s' "$VERSION" | tr -d '<>&"'"'"'')"
BUILD_NUMBER="${BUILD_NUMBER:-$(git rev-parse --short HEAD 2>/dev/null || echo 1)}"
BUILD_NUMBER="$(printf '%s' "$BUILD_NUMBER" | tr -cd 'a-zA-Z0-9.-')"
CODESIGN_IDENTITY="${CODESIGN_IDENTITY:--}"
BUNDLE_ID="com.cavi-ai.secure-agent"
ESD_LABEL="com.cavi-ai.secure-agent-esd"

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
# Locate the product via SwiftPM itself: hardcoded .build/apple/... paths go
# silently stale when the scratch dir differs (custom SWIFTPM build dir,
# Xcode/SwiftPM layout changes) — the build then "succeeds" while shipping a
# days-old binary. --show-bin-path always tells the truth.
MENUBAR_BIN="$(cd menubar && swift build -c release --arch arm64 --arch x86_64 --show-bin-path)/secure-agent-menubar"
[[ -x "${MENUBAR_BIN}" ]] || { echo "error: menubar binary not found at ${MENUBAR_BIN}" >&2; exit 1; }
# Freshness assertion: the product must be newer than every Swift source.
# A stale product here means the build lied — fail loudly instead of
# assembling an app with yesterday's menubar.
NEWEST_SRC="$(find menubar/Sources menubar/Package.swift -name '*.swift' -newer "${MENUBAR_BIN}" | head -1)"
[[ -z "${NEWEST_SRC}" ]] || { echo "error: menubar binary is STALE (older than ${NEWEST_SRC}) — clean menubar/.build and retry" >&2; exit 1; }

echo "==> Assembling ${APP_NAME}.app..."
rm -rf "${APP_DIR}"
mkdir -p "${APP_DIR}/Contents/MacOS" "${APP_DIR}/Contents/Helpers" "${APP_DIR}/Contents/Resources/hooks" \
  "${APP_DIR}/Contents/Library/LaunchDaemons"

cp "${MENUBAR_BIN}" "${APP_DIR}/Contents/MacOS/SecureAgent"
cp bin/secure-agentd bin/secure-agent "${APP_DIR}/Contents/Helpers/"
# The Endpoint Security collector: the same daemon binary under the name that
# selects collector mode, registered with SMAppService.daemon from the plist
# below so macOS attributes it (and its privacy grant) to the app.
cp bin/secure-agentd "${APP_DIR}/Contents/MacOS/secure-agent-esd"

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

cat > "${APP_DIR}/Contents/Library/LaunchDaemons/${ESD_LABEL}.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>${ESD_LABEL}</string>
    <key>BundleProgram</key><string>Contents/MacOS/secure-agent-esd</string>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><dict>
        <key>SuccessfulExit</key><false/>
        <key>Crashed</key><true/>
    </dict>
    <key>ThrottleInterval</key><integer>60</integer>
    <key>StandardErrorPath</key><string>/var/log/secure-agent-esd.log</string>
</dict>
</plist>
EOF

echo "==> Signing (${CODESIGN_IDENTITY})..."
codesign --force --options runtime --sign "${CODESIGN_IDENTITY}" \
  "${APP_DIR}/Contents/Helpers/secure-agentd" \
  "${APP_DIR}/Contents/Helpers/secure-agent" \
  "${APP_DIR}/Contents/MacOS/secure-agent-esd"
codesign --force --options runtime --sign "${CODESIGN_IDENTITY}" "${APP_DIR}"

echo "==> Done: ${APP_DIR}"
codesign -dv "${APP_DIR}" 2>&1 | grep -E "Identifier|Signature|TeamIdentifier" || true
