#!/usr/bin/env bash
# Unit tests for packaging/devid_export.sh. Stubs xcodebuild, xcrun, codesign
# and lipo on PATH — never signs, uploads or notarizes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
EXPORT="${REPO_ROOT}/packaging/devid_export.sh"

mkdir -p "${REPO_ROOT}/.tmp"
WORK="$(mktemp -d "${REPO_ROOT}/.tmp/test_devid_export.XXXXXX")"
trap 'mkdir -p "${REPO_ROOT}/.quarantine" 2>/dev/null; mv "${WORK}" "${REPO_ROOT}/.quarantine/" 2>/dev/null || true' EXIT
STUB_BIN="${WORK}/bin"
CALLS="${WORK}/calls.log"
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

# xcodebuild: -exportNotarizedApp copies the archived app to -exportPath when
# STUB_NOTARY=ok and fails otherwise.
cat > "${STUB_BIN}/xcodebuild" <<'STUB'
#!/usr/bin/env bash
echo "xcodebuild $*" >> "${CALLS}"
archive="" out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -archivePath) archive="$2"; shift ;;
    -exportPath) out="$2"; shift ;;
    -exportNotarizedApp) mode=notarize ;;
  esac
  shift
done
if [[ "${mode:-}" == notarize ]]; then
  [[ "${STUB_NOTARY}" == ok ]] || exit 1
  mkdir -p "${out}" && cp -R "${archive}/Products/Applications/"*.app "${out}/"
fi
STUB
cat > "${STUB_BIN}/xcrun" <<'STUB'
#!/usr/bin/env bash
echo "xcrun $*" >> "${CALLS}"
STUB
cat > "${STUB_BIN}/codesign" <<'STUB'
#!/usr/bin/env bash
echo "codesign $*" >> "${CALLS}"
[[ "$1" == -dvv && -n "${STUB_AUTHORITY:-}" ]] && echo "Authority=${STUB_AUTHORITY}" >&2
exit 0
STUB
cat > "${STUB_BIN}/lipo" <<'STUB'
#!/usr/bin/env bash
echo "arm64 x86_64"
STUB
chmod +x "${STUB_BIN}"/*

APP="${WORK}/Secure Agent.app"
mkdir -p "${APP}/Contents/MacOS"
: > "${APP}/Contents/MacOS/SecureAgent"
plutil -create xml1 "${APP}/Contents/Info.plist"
plutil -insert CFBundleExecutable -string SecureAgent "${APP}/Contents/Info.plist"
plutil -insert CFBundleIdentifier -string com.example.agent "${APP}/Contents/Info.plist"
plutil -insert CFBundleShortVersionString -string v9.9.9 "${APP}/Contents/Info.plist"
plutil -insert CFBundleVersion -string abc1234 "${APP}/Contents/Info.plist"

# run_export <work-dir> [env...]: exit status of devid_export.sh.
run_export() {
  local out="$1"
  shift
  : > "${CALLS}"
  set +e
  env PATH="${STUB_BIN}:${PATH}" CALLS="${CALLS}" STUB_NOTARY=ok NOTARY_INTERVAL=0 "$@" \
    "${EXPORT}" "${APP}" TEAM123 "${out}" > "${WORK}/out.log" 2>&1
  local status=$?
  set -e
  echo "${status}"
}

# Some plutil versions print the extraction error on stdout; keep output only on success.
value() {
  local v
  if v="$(plutil -extract "$2" raw -o - "$1" 2>/dev/null)"; then printf '%s\n' "$v"; else echo "<missing>"; fi
}

# --- notarized on the first attempt ---
OUT="${WORK}/ok"
check "exits 0 once notarized" 0 "$(run_export "${OUT}" STUB_AUTHORITY='Apple Development: Jane Doe (TEAM123)')"
ARCH_PLIST="${OUT}/app.xcarchive/Info.plist"
check "archive app path" "Applications/Secure Agent.app" "$(value "${ARCH_PLIST}" ApplicationProperties.ApplicationPath)"
check "archive bundle id" com.example.agent "$(value "${ARCH_PLIST}" ApplicationProperties.CFBundleIdentifier)"
check "archive version" v9.9.9 "$(value "${ARCH_PLIST}" ApplicationProperties.CFBundleShortVersionString)"
check "archive build" abc1234 "$(value "${ARCH_PLIST}" ApplicationProperties.CFBundleVersion)"
check "archive first arch" arm64 "$(value "${ARCH_PLIST}" ApplicationProperties.Architectures.0)"
check "archive second arch" x86_64 "$(value "${ARCH_PLIST}" ApplicationProperties.Architectures.1)"
check "archive signing identity" "Apple Development: Jane Doe (TEAM123)" "$(value "${ARCH_PLIST}" ApplicationProperties.SigningIdentity)"
check "archive team" TEAM123 "$(value "${ARCH_PLIST}" ApplicationProperties.Team)"
check "archived app copied" yes "$([[ -f "${OUT}/app.xcarchive/Products/Applications/Secure Agent.app/Contents/Info.plist" ]] && echo yes || echo no)"
OPTS="${OUT}/ExportOptions.plist"
check "export method" developer-id "$(value "${OPTS}" method)"
check "export team" TEAM123 "$(value "${OPTS}" teamID)"
check "export uploads for notarization" upload "$(value "${OPTS}" destination)"
check "export, then fetch the notarized app" "-exportArchive -exportNotarizedApp" \
  "$(grep '^xcodebuild' "${CALLS}" | awk '{print $2}' | xargs)"
check "staple validated" "xcrun stapler validate ${OUT}/notarized/Secure Agent.app" "$(grep '^xcrun' "${CALLS}")"
check "notarized app verified" "codesign --verify --deep --strict ${OUT}/notarized/Secure Agent.app" \
  "$(grep '^codesign --verify' "${CALLS}")"

# --- an unsigned app archives without a signing identity ---
OUT="${WORK}/unsigned"
check "unsigned app exits 0" 0 "$(run_export "${OUT}")"
check "no signing identity key" "<missing>" "$(value "${OUT}/app.xcarchive/Info.plist" ApplicationProperties.SigningIdentity)"

# --- notarization never completes ---
OUT="${WORK}/pending"
check "exits 1 when never notarized" 1 "$(run_export "${OUT}" STUB_NOTARY=pending NOTARY_ATTEMPTS=2)"
check "asks for the notarized app each attempt" 2 "$(grep -c -- '-exportNotarizedApp' "${CALLS}")"
check "no staple check without a notarized app" 0 "$(grep -c '^xcrun' "${CALLS}" || true)"

# --- an existing work dir is refused before any export ---
OUT="${WORK}/existing"
mkdir -p "${OUT}"
check "exits 2 for an existing work dir" 2 "$(run_export "${OUT}")"
check "no xcodebuild call" 0 "$(grep -c '^xcodebuild' "${CALLS}" || true)"

echo "${pass} passed, ${fail} failed"
[[ "${fail}" -eq 0 ]]
