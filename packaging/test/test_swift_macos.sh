#!/usr/bin/env bash
# Unit tests for packaging/swift_macos.sh SDK selection. Stubs `xcrun` on
# PATH: the selected SDK version and path are the stub's, swift is not run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

mkdir -p "${REPO_ROOT}/.tmp"
WORK="$(mktemp -d "${REPO_ROOT}/.tmp/test_swift_macos.XXXXXX")"
trap 'mkdir -p "${REPO_ROOT}/.quarantine" 2>/dev/null; mv "${WORK}" "${REPO_ROOT}/.quarantine/" 2>/dev/null || true' EXIT
STUB_BIN="${WORK}/bin"
mkdir -p "${STUB_BIN}"

pass=0
fail=0

check() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "${actual}" == "${expected}" ]]; then
    echo "ok - ${desc}"
    pass=$((pass + 1))
  else
    echo "not ok - ${desc} (expected [${expected}] got [${actual}])"
    fail=$((fail + 1))
  fi
}

# write_stub <selected-sdk-version>: an Xcode whose only macOS SDK is that
# version; `xcrun swift` records its arguments instead of building.
write_stub() {
  cat > "${STUB_BIN}/xcrun" <<STUB
#!/usr/bin/env bash
case "\$*" in
  "--sdk macosx --show-sdk-version") echo "$1" ;;
  "--sdk macosx --show-sdk-path") echo "/sdks/MacOSX$1.sdk" ;;
  "--sdk macosx$1 --show-sdk-path") echo "/sdks/MacOSX$1.sdk" ;;
  --sdk*) echo "xcrun: error: SDK \"\${2}\" cannot be located" >&2; exit 1 ;;
  swift*) shift; echo "\$*" > "${WORK}/swift-args" ;;
  *) exit 1 ;;
esac
STUB
  chmod +x "${STUB_BIN}/xcrun"
}

# run_wrapper: exit status of swift_macos.sh build; swift's arguments, if
# it ran, land in ${WORK}/swift-args.
run_wrapper() {
  rm -f "${WORK}/swift-args"
  local status=0
  PATH="${STUB_BIN}:${PATH}" bash "${REPO_ROOT}/packaging/swift_macos.sh" build --product x \
    > /dev/null 2> "${WORK}/stderr.log" || status=$?
  echo "${status}"
}

write_stub 27.2
check "a macOS 27.2 SDK builds" "0" "$(run_wrapper)"
check "swift compiles and links against the selected SDK" \
  "build --sdk /sdks/MacOSX27.2.sdk -Xswiftc -Xclang-linker -Xswiftc -isysroot -Xswiftc -Xclang-linker -Xswiftc /sdks/MacOSX27.2.sdk --product x" \
  "$(cat "${WORK}/swift-args" 2>/dev/null)"

write_stub 26.4
check "a macOS 26 SDK fails" "1" "$(run_wrapper)"
check "swift does not run without a macOS 27 SDK" "no" "$([[ -e "${WORK}/swift-args" ]] && echo yes || echo no)"
check "the failure names the selected SDK" "error: the selected macOS SDK is 26.4; a macOS 27 SDK is required" \
  "$(cat "${WORK}/stderr.log")"

echo "${pass} passed, ${fail} failed"
[[ "${fail}" -eq 0 ]]
