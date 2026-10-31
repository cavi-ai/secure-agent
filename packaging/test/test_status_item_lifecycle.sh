#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT
source "${root}/packaging/lib/macos_sdk.sh"
sdk="$(macos_sdk_path)"
xcrun swiftc -parse-as-library -sdk "${sdk}" \
  -Xclang-linker -isysroot -Xclang-linker "${sdk}" \
  "${root}/menubar/Sources/SecureAgentMenubar/StatusItemController.swift" \
  "${root}/packaging/test/status_item_lifecycle.swift" \
  -o "${scratch}/status-item-lifecycle"
"${scratch}/status-item-lifecycle"
