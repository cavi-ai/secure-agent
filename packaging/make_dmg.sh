#!/usr/bin/env bash
# Builds "Secure Agent.app" (via make_app.sh), optionally notarizes it, and
# packages a distributable DMG.
#
# Signing/notarization environment:
#   CODESIGN_IDENTITY  Signing identity for make_app.sh (default "-" = ad-hoc).
#   DEVELOPER_TEAM     Team ID: re-sign the app with the team's Developer ID
#                      through an Xcode export and notarize it with the signed-in
#                      Xcode account (devid_export.sh). The DMG is then signed
#                      and notarized only with CODESIGN_IDENTITY and
#                      NOTARY_PROFILE.
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
DMG_PATH="${REPO_ROOT}/dist/SecureAgent-${VERSION}.dmg"

if [[ "${RELEASE_BUILD:-0}" == 1 ]]; then
  source "${REPO_ROOT}/packaging/lib/release.sh"
  require_release_settings
fi

"${REPO_ROOT}/packaging/make_app.sh"

BUILD_DIR="$(mktemp -d "${REPO_ROOT}/dist/.dmg-build.XXXXXX")"
trap 'rm -rf "${BUILD_DIR}"' EXIT
STAGING="${BUILD_DIR}/staging"
CANDIDATE_DMG="${BUILD_DIR}/$(basename "${DMG_PATH}")"

if [[ -n "${DEVELOPER_TEAM:-}" ]]; then
  "${REPO_ROOT}/packaging/devid_export.sh" "${APP_DIR}" "${DEVELOPER_TEAM}" "${BUILD_DIR}/devid"
  APP_DIR="${BUILD_DIR}/devid/notarized/${APP_NAME}.app"
elif [[ -n "${NOTARY_PROFILE:-}" ]]; then
  echo "==> Notarizing app..."
  ZIP_PATH="${REPO_ROOT}/dist/SecureAgent-notarize.zip"
  ditto -c -k --keepParent "${APP_DIR}" "${ZIP_PATH}"
  xcrun notarytool submit "${ZIP_PATH}" --keychain-profile "${NOTARY_PROFILE}" --wait
  xcrun stapler staple "${APP_DIR}"
  rm -f "${ZIP_PATH}"
elif [[ "${CODESIGN_IDENTITY:--}" == *"Developer ID Application"* ]]; then
  echo "==> NOTE: Developer ID cert present but NOTARY_PROFILE unset — DMG will be"
  echo "    Gatekeeper-blocked for other users. Set NOTARY_PROFILE to your keychain"
  echo "    profile (xcrun notarytool store-credentials --profile <name>) for a"
  echo "    distributable release."
fi

echo "==> Creating DMG..."
mkdir -p "${STAGING}"
cp -R "${APP_DIR}" "${STAGING}/"
ln -s /Applications "${STAGING}/Applications"

hdiutil create \
  -volname "${APP_NAME}" \
  -srcfolder "${STAGING}" \
  -ov -format UDZO \
  "${CANDIDATE_DMG}"

if [[ -n "${NOTARY_PROFILE:-}" && "${CODESIGN_IDENTITY:--}" != "-" ]]; then
  # When a notary profile is configured, the user asked for a distributable
  # DMG — silently shipping an unnotarized one (old `|| true`) is a lie.
  # Fail loudly; for ad-hoc dev builds, just leave NOTARY_PROFILE unset.
  codesign --force --sign "${CODESIGN_IDENTITY}" "${CANDIDATE_DMG}"
  xcrun notarytool submit "${CANDIDATE_DMG}" --keychain-profile "${NOTARY_PROFILE}" --wait
  xcrun stapler staple "${CANDIDATE_DMG}"
fi

if [[ "${RELEASE_BUILD:-0}" == 1 ]]; then
  codesign --verify --deep --strict "${APP_DIR}"
  xcrun stapler validate "${APP_DIR}"
  spctl --assess --type execute "${APP_DIR}"
  if [[ -n "${NOTARY_PROFILE:-}" ]]; then
    codesign --verify --strict "${CANDIDATE_DMG}"
    xcrun stapler validate "${CANDIDATE_DMG}"
    spctl --assess --type open --context context:primary-signature "${CANDIDATE_DMG}"
  fi
fi

rm -rf "${STAGING}"

# SHA-256 checksums: the in-app updater's stable channel verifies the DMG
# against this file before mounting. Replace rebuilt artifacts while retaining
# every other asset in the release.
echo "==> Writing checksums..."
CHECKSUMS="${REPO_ROOT}/dist/checksums.txt"
CANDIDATE_CHECKSUMS="${BUILD_DIR}/checksums.txt"
if [[ -f "${CHECKSUMS}" ]]; then
  cp "${CHECKSUMS}" "${CANDIDATE_CHECKSUMS}"
fi
source "${REPO_ROOT}/packaging/lib/checksum.sh"
write_artifact_checksum "${CANDIDATE_DMG}" "${CANDIDATE_CHECKSUMS}" "dist/$(basename "${DMG_PATH}")"
# Preserve the previous image until both output files have been replaced.
if [[ -f "${DMG_PATH}" ]]; then
  ln "${DMG_PATH}" "${BUILD_DIR}/previous.dmg"
fi
mv -f "${CANDIDATE_DMG}" "${DMG_PATH}"
if ! mv -f "${CANDIDATE_CHECKSUMS}" "${CHECKSUMS}"; then
  if [[ -f "${BUILD_DIR}/previous.dmg" ]]; then
    mv -f "${BUILD_DIR}/previous.dmg" "${DMG_PATH}"
  else
    rm -f "${DMG_PATH}"
  fi
  echo "error: could not publish the DMG checksum" >&2
  exit 1
fi
echo "    $(tail -1 "${CHECKSUMS}")"

echo "==> Done: ${DMG_PATH}"
