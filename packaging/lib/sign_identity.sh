#!/usr/bin/env bash
# Shared signing-identity resolution for make_app.sh and `make release`.
# Sourced, not executed.

# resolve_sign_identity
# Prints, on stdout, the codesign identity to use:
#   1. $CODESIGN_IDENTITY, if set (including "-" for ad-hoc) — always wins.
#   2. The first "Apple Development" identity from `security find-identity`.
#   3. The first "Developer ID Application" identity.
#   4. "-" (ad-hoc).
# Whenever the resolved identity is "-", also prints a warning on stderr:
# an ad-hoc build's file-telemetry grants (Full Disk Access, Login Items &
# Extensions) do not survive the next rebuild, because codesign gives every
# ad-hoc build a fresh designated requirement.
resolve_sign_identity() {
  local identity ids

  if [[ -n "${CODESIGN_IDENTITY:-}" ]]; then
    identity="${CODESIGN_IDENTITY}"
  else
    ids="$(security find-identity -v -p codesigning 2>/dev/null || true)"

    identity="$(printf '%s\n' "${ids}" | grep -oE '"[^"]*Apple Development[^"]*"' | head -1 | tr -d '"')"
    if [[ -z "${identity}" ]]; then
      identity="$(printf '%s\n' "${ids}" | grep -oE '"[^"]*Developer ID Application[^"]*"' | head -1 | tr -d '"')"
    fi
    [[ -n "${identity}" ]] || identity="-"
  fi

  printf '%s\n' "${identity}"
  if [[ "${identity}" == "-" ]]; then
    echo "warning: signing ad-hoc (-) — file-telemetry grants reset on every build" >&2
  fi
}
