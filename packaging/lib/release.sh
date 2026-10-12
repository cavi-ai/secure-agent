#!/usr/bin/env bash
# Release builds must be distributable; local app/DMG builds remain separate.
require_release_settings() {
  if [[ "${CODESIGN_IDENTITY:-}" != "Developer ID Application: "* ]]; then
    echo "error: release builds require an explicit Developer ID Application signing identity" >&2
    return 1
  fi
  if [[ -z "${NOTARY_PROFILE:-}" ]]; then
    echo "error: release builds require NOTARY_PROFILE" >&2
    return 1
  fi
  if [[ ! "${VERSION:-}" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: release builds require VERSION=x.y.z or vX.Y.Z" >&2
    return 1
  fi
  if ! git diff --quiet || ! git diff --cached --quiet || \
     [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
    echo "error: release builds require a clean committed tree" >&2
    return 1
  fi
}
