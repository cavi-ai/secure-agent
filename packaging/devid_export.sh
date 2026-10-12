#!/usr/bin/env bash
# Signs a built app bundle with the team's Developer ID Application certificate
# through an Xcode export, notarizes it with the signed-in Xcode account, and
# validates the stapled ticket. The certificate may be managed by Xcode: no
# local signing identity or notarytool profile is needed.
#
# Usage: devid_export.sh <app> <team-id> <work-dir>
#   <work-dir> must not exist; the notarized app is written to
#   <work-dir>/notarized/<app name>.
#   NOTARY_ATTEMPTS (default 40) and NOTARY_INTERVAL (seconds, default 30)
#   bound the wait for notarization.
set -euo pipefail

USAGE="usage: devid_export.sh <app> <team-id> <work-dir>"
APP="${1:?${USAGE}}"
TEAM="${2:?${USAGE}}"
WORK="${3:?${USAGE}}"
ATTEMPTS="${NOTARY_ATTEMPTS:-40}"
INTERVAL="${NOTARY_INTERVAL:-30}"

if [[ ! -d "${APP}" ]]; then
  echo "devid_export: no app at ${APP}" >&2
  exit 2
fi
if [[ -e "${WORK}" ]]; then
  echo "devid_export: ${WORK} already exists" >&2
  exit 2
fi

NAME="$(basename "${APP}")"
INFO="${APP}/Contents/Info.plist"
info() { plutil -extract "$1" raw -o - "${INFO}"; }
EXECUTABLE="$(info CFBundleExecutable)"
AUTHORITY="$(codesign -dvv "${APP}" 2>&1 | sed -n 's/^Authority=//p' | head -1)"

ARCHIVE="${WORK}/app.xcarchive"
PLIST="${ARCHIVE}/Info.plist"
mkdir -p "${ARCHIVE}/Products/Applications"
ditto "${APP}" "${ARCHIVE}/Products/Applications/${NAME}"

plutil -create xml1 "${PLIST}"
plutil -insert ApplicationProperties -dictionary "${PLIST}"
plutil -insert ApplicationProperties.ApplicationPath -string "Applications/${NAME}" "${PLIST}"
plutil -insert ApplicationProperties.Architectures -array "${PLIST}"
i=0
for arch in $(lipo -archs "${APP}/Contents/MacOS/${EXECUTABLE}"); do
  plutil -insert "ApplicationProperties.Architectures.${i}" -string "${arch}" "${PLIST}"
  i=$((i + 1))
done
for key in CFBundleIdentifier CFBundleShortVersionString CFBundleVersion; do
  plutil -insert "ApplicationProperties.${key}" -string "$(info "${key}")" "${PLIST}"
done
if [[ -n "${AUTHORITY}" ]]; then
  plutil -insert ApplicationProperties.SigningIdentity -string "${AUTHORITY}" "${PLIST}"
fi
plutil -insert ApplicationProperties.Team -string "${TEAM}" "${PLIST}"
plutil -insert ArchiveVersion -integer 2 "${PLIST}"
plutil -insert CreationDate -date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${PLIST}"
plutil -insert Name -string "${NAME%.app}" "${PLIST}"
plutil -insert SchemeName -string "${NAME%.app}" "${PLIST}"

OPTIONS="${WORK}/ExportOptions.plist"
plutil -create xml1 "${OPTIONS}"
plutil -insert method -string developer-id "${OPTIONS}"
plutil -insert signingStyle -string automatic "${OPTIONS}"
plutil -insert teamID -string "${TEAM}" "${OPTIONS}"
plutil -insert destination -string upload "${OPTIONS}"

echo "==> Signing with Developer ID (${TEAM}) and uploading for notarization..."
xcodebuild -exportArchive -archivePath "${ARCHIVE}" -exportOptionsPlist "${OPTIONS}" \
  -exportPath "${WORK}/upload" -allowProvisioningUpdates

NOTARIZED="${WORK}/notarized/${NAME}"
for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
  if xcodebuild -exportNotarizedApp -archivePath "${ARCHIVE}" \
    -exportPath "${WORK}/notarized" > "${WORK}/notarize.log" 2>&1; then
    xcrun stapler validate "${NOTARIZED}"
    codesign --verify --deep --strict "${NOTARIZED}"
    echo "==> Notarized: ${NOTARIZED}"
    exit 0
  fi
  if ((attempt < ATTEMPTS)); then
    sleep "${INTERVAL}"
  fi
done
echo "devid_export: not notarized after ${ATTEMPTS} attempts" >&2
tail -5 "${WORK}/notarize.log" >&2
exit 1
