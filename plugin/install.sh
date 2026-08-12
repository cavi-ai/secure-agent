#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS_DIR="${SCRIPT_DIR}/hooks"

TARGET_DIRS=(
  "${HOME}/.claude/hooks"
  "${HOME}/.cursor/hooks"
)

for target in "${TARGET_DIRS[@]}"; do
  mkdir -p "${target}"
  for hook_file in "${HOOKS_DIR}"/*.py; do
    filename="$(basename "${hook_file}")"
    if [[ "${filename}" == test_* ]]; then
      continue
    fi
    ln -sf "${hook_file}" "${target}/${filename}"
    echo "Symlinked ${filename} -> ${target}/${filename}"
  done
done

echo "secure-agent plugin hooks installed successfully."
