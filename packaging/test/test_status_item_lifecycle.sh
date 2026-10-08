#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT
sdk="$(xcrun --sdk macosx27.0 --show-sdk-path)"
xcrun swiftc -parse-as-library -sdk "${sdk}" \
  -Xclang-linker -isysroot -Xclang-linker "${sdk}" \
  "${root}/menubar/Sources/SecureAgentMenubar/StatusItemController.swift" \
  "${root}/packaging/test/status_item_lifecycle.swift" \
  -o "${scratch}/status-item-lifecycle"
"${scratch}/status-item-lifecycle"
