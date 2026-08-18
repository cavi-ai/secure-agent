#!/usr/bin/env bash
# Builds "Secure Agent.app" (via make_app.sh), optionally notarizes it, and
# packages a distributable DMG.
#
# Signing/notarization environment:
#   CODESIGN_IDENTITY  Signing identity for make_app.sh (default "-" = ad-hoc).
#   NOTARY_PROFILE     Keychain profile name for `xcrun notarytool` (created via
#                      `xcrun notarytool store-credentials`). If unset, notarization
#                      is skipped and the DMG will only run after right-click > Open
#                      unless the app was ad-hoc signed for local use.
#   VERSION            Marketing version (default: git describe or 0.1.0).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

APP_NAME="Secure Agent"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 0.1.0)}"
APP_DIR="${REPO_ROOT}/dist/${APP_NAME}.app"
STAGING="${REPO_ROOT}/dist/dmg-staging"
DMG_PATH="${REPO_ROOT}/dist/SecureAgent-${VERSION}.dmg"

"${REPO_ROOT}/packaging/make_app.sh"

if [[ -n "${NOTARY_PROFILE:-}" ]]; then
  echo "==> Notarizing app..."
  ZIP_PATH="${REPO_ROOT}/dist/SecureAgent-notarize.zip"
  ditto -c -k --keepParent "${APP_DIR}" "${ZIP_PATH}"
  xcrun notarytool submit "${ZIP_PATH}" --keychain-profile "${NOTARY_PROFILE}" --wait
  xcrun stapler staple "${APP_DIR}"
  rm -f "${ZIP_PATH}"
else
  echo "==> NOTARY_PROFILE not set — skipping notarization (ad-hoc/dev build)."
fi

echo "==> Creating DMG..."
rm -rf "${STAGING}" "${DMG_PATH}"
mkdir -p "${STAGING}"
cp -R "${APP_DIR}" "${STAGING}/"
ln -s /Applications "${STAGING}/Applications"

hdiutil create \
  -volname "${APP_NAME}" \
  -srcfolder "${STAGING}" \
  -ov -format UDZO \
  "${DMG_PATH}"

if [[ -n "${NOTARY_PROFILE:-}" && "${CODESIGN_IDENTITY:--}" != "-" ]]; then
  codesign --force --sign "${CODESIGN_IDENTITY}" "${DMG_PATH}" || true
  xcrun notarytool submit "${DMG_PATH}" --keychain-profile "${NOTARY_PROFILE}" --wait || true
  xcrun stapler staple "${DMG_PATH}" || true
fi

rm -rf "${STAGING}"
echo "==> Done: ${DMG_PATH}"
