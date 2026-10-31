# Prints the selected Xcode's macOS SDK path; fails unless it is a macOS 27 SDK.
macos_sdk_path() {
  local version
  version="$(xcrun --sdk macosx --show-sdk-version)" || return 1
  if [[ "${version%%.*}" != 27 ]]; then
    echo "error: the selected macOS SDK is ${version}; a macOS 27 SDK is required" >&2
    return 1
  fi
  xcrun --sdk macosx --show-sdk-path
}
