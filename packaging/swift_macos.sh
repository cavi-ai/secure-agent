#!/usr/bin/env bash
# Keep compilation and Darwin linking on the same selected SDK.
set -euo pipefail

command="${1:?Usage: swift_macos.sh build|test [arguments]}"
shift
case "${command}" in
  build|test) ;;
  *) echo "error: expected build or test" >&2; exit 2 ;;
esac

sdk_path="$(xcrun --sdk macosx27.0 --show-sdk-path)"
# The Swift driver forwards --sysroot to Clang. Darwin SDK version detection
# requires -isysroot as well; otherwise the executable can record the minimum
# OS version as its SDK version. Let Clang read the actual SDK metadata.
exec xcrun swift "${command}" --sdk "${sdk_path}" \
  -Xswiftc -Xclang-linker -Xswiftc -isysroot \
  -Xswiftc -Xclang-linker -Xswiftc "${sdk_path}" "$@"
