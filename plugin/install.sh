#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS_DIR="${SCRIPT_DIR}/hooks"

TARGET_DIRS=(
  "${HOME}/.claude/hooks"
  "${HOME}/.cursor/hooks"
)

skipped=0
for target in "${TARGET_DIRS[@]}"; do
  mkdir -p "${target}"
  for hook_file in "${HOOKS_DIR}"/*.py; do
    filename="$(basename "${hook_file}")"
    if [[ "${filename}" == test_* ]]; then
      continue
    fi
    dest="${target}/${filename}"
    marker="# secure-agent-hook: ${filename%.py}"
    # A file of the same name that is not ours is left alone.
    if [[ -e "${dest}" && ! -L "${dest}" ]] && ! grep -qxF "${marker}" "${dest}" 2>/dev/null; then
      echo "Skipped ${dest}: not a Secure Agent hook" >&2
      skipped=1
      continue
    fi
    ln -sfn "${hook_file}" "${dest}"
    echo "Symlinked ${filename} -> ${dest}"
  done
done

if [[ "${skipped}" -ne 0 ]]; then
  echo "secure-agent plugin hooks installed, except the files skipped above." >&2
  exit 1
fi
echo "secure-agent plugin hooks installed successfully."
