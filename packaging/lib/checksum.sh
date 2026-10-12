#!/usr/bin/env bash
# Replace one artifact's checksum without losing the release's other assets.
write_artifact_checksum() (
  set -euo pipefail
  local artifact="$1" checksums="$2" relative="$3" filename temporary digest
  filename="$(basename "${artifact}")"
  temporary="$(mktemp "${checksums}.XXXXXX")"
  trap 'rm -f "${temporary}"' EXIT
  if [[ -f "${checksums}" ]]; then
    awk -v filename="${filename}" '{path=$NF; sub(/^.*\//, "", path); if (path != filename) print}' \
      "${checksums}" > "${temporary}"
  fi
  digest="$(shasum -a 256 "${artifact}" | awk '{print $1}')"
  printf '%s  %s\n' "${digest}" "${relative}" >> "${temporary}"
  mv -f "${temporary}" "${checksums}"
)
