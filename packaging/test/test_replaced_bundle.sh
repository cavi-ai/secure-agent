#!/usr/bin/env bash
# Unit tests for packaging/lib/replaced_bundle.sh — the Trash name install.sh
# gives the copy it replaces. No real install.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${REPO_ROOT}/packaging/lib/replaced_bundle.sh"

pass=0
fail=0

check() {
  local desc="$1" ok="$2"
  if [[ "${ok}" == "yes" ]]; then
    echo "ok - ${desc}"
    pass=$((pass + 1))
  else
    echo "not ok - ${desc}"
    fail=$((fail + 1))
  fi
}

name="$(replaced_bundle_path "/Users/u/.Trash" "Secure Agent" "20261002-120000-42")"
check "keeps the app name and stamp" \
  "$([[ "${name}" == "/Users/u/.Trash/Secure Agent 20261002-120000-42.app.replaced" ]] && echo yes || echo no)"
check "the name does not end in .app" "$([[ "${name}" != *.app ]] && echo yes || echo no)"
check "the name is not an .app bundle at any depth" \
  "$([[ "$(basename "${name}")" != *.app && "${name##*.}" != "app" ]] && echo yes || echo no)"
check "install.sh moves the replaced copy to this name" \
  "$(grep -q 'replaced_bundle_path' "${REPO_ROOT}/packaging/install.sh" && echo yes || echo no)"

echo "${pass} passed, ${fail} failed"
[[ "${fail}" -eq 0 ]]
