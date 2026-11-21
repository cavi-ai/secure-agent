#!/usr/bin/env bash
# Release builds must be distributable; local app/DMG builds remain separate.
# DEVELOPER_TEAM replaces the identity and notary profile: the app is signed
# and notarized through an Xcode export (devid_export.sh).
require_release_settings() {
  if [[ -n "${DEVELOPER_TEAM:-}" ]]; then
    if [[ ! "${DEVELOPER_TEAM}" =~ ^[A-Z0-9]{10}$ ]]; then
      echo "error: DEVELOPER_TEAM must be a 10-character team ID" >&2
      return 1
    fi
  else
    if [[ "${CODESIGN_IDENTITY:-}" != "Developer ID Application: "* ]]; then
      echo "error: release builds require an explicit Developer ID Application signing identity or DEVELOPER_TEAM" >&2
      return 1
    fi
    if [[ -z "${NOTARY_PROFILE:-}" ]]; then
      echo "error: release builds require NOTARY_PROFILE" >&2
      return 1
    fi
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
  local tag="v${VERSION#v}" head tagged
  head="$(git rev-parse HEAD)" || return 1
  if ! tagged="$(git rev-parse -q --verify "refs/tags/${tag}^{commit}")" || [[ -z "${head}" || "${tagged}" != "${head}" ]]; then
    echo "error: release builds require tag ${tag} at HEAD" >&2
    return 1
  fi
  if ! command -v govulncheck >/dev/null 2>&1; then
    echo "error: release builds require govulncheck on PATH" >&2
    return 1
  fi
  # Scan with the selected compiler before producing distribution artifacts.
  govulncheck ./...
}

# Emit a revision only when this directory is the clean Git worktree root.
release_source_revision() {
  local root head untracked
  root="$(git rev-parse --show-toplevel 2>/dev/null)" || return 0
  [[ "$(cd "$root" && pwd -P)" == "$(pwd -P)" ]] || return 0
  head="$(git rev-parse --verify HEAD 2>/dev/null)" || return 0
  [[ "$head" =~ ^[0-9a-f]{40}$ ]] || return 0
  git diff --quiet && git diff --cached --quiet || return 0
  untracked="$(git ls-files --others --exclude-standard)" || return 0
  [[ -z "$untracked" ]] || return 0
  printf '%s\n' "$head"
}
