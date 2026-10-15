#!/usr/bin/env bash
# Builds every macOS icon size from the console's canonical application artwork.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
SOURCE="${REPO_ROOT}/daemon/internal/api/web_dist/brand-icon.png"

ICONSET="${WORK}/AppIcon.iconset"
mkdir -p "${ICONSET}"
for spec in "16:icon_16x16.png" "32:icon_16x16@2x.png" "32:icon_32x32.png" "64:icon_32x32@2x.png" \
            "128:icon_128x128.png" "256:icon_128x128@2x.png" "256:icon_256x256.png" \
            "512:icon_256x256@2x.png" "512:icon_512x512.png" "1024:icon_512x512@2x.png"; do
  px="${spec%%:*}"; name="${spec##*:}"
  sips -z "${px}" "${px}" "${SOURCE}" --out "${ICONSET}/${name}" >/dev/null
done

iconutil -c icns "${ICONSET}" -o "${REPO_ROOT}/packaging/AppIcon.icns"
echo "==> Wrote ${REPO_ROOT}/packaging/AppIcon.icns"
