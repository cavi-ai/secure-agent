#!/usr/bin/env bash
# Import CI-only credentials into a disposable keychain, then build a release.
set -euo pipefail
set +x
umask 077

missing=0
for name in MACOS_CERTIFICATE_P12_BASE64 MACOS_CERTIFICATE_PASSWORD \
  MACOS_CODESIGN_IDENTITY MACOS_NOTARY_KEY_P8_BASE64 \
  MACOS_NOTARY_KEY_ID MACOS_NOTARY_ISSUER_ID; do
  if [[ -z "${!name:-}" ]]; then
    echo "error: missing Actions secret ${name}" >&2
    missing=1
  fi
done
[[ "$missing" == 0 ]] || exit 1
if [[ "$MACOS_CODESIGN_IDENTITY" != "Developer ID Application: "* ]]; then
  echo "error: MACOS_CODESIGN_IDENTITY must be a Developer ID Application identity" >&2
  exit 1
fi
[[ "${1:-}" != check ]] || exit 0
[[ "${1:-}" == build && $# == 3 ]] || { echo "usage: ci_release.sh check | build SOURCE TAG" >&2; exit 1; }
[[ "$3" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "error: invalid release tag" >&2; exit 1; }

original_default="$(security default-keychain -d user)"
original_default="${original_default#*\"}"
original_default="${original_default%\"*}"
original_keychains=()
while IFS= read -r item; do
  item="${item#*\"}"
  item="${item%\"*}"
  original_keychains+=("$item")
done < <(security list-keychains -d user)
credentials="$(mktemp -d "${RUNNER_TEMP:?}/secure-agent-signing.XXXXXX")"
keychain="$credentials/signing.keychain-db"
cleanup() {
  local status=$? failed=0
  trap - EXIT
  set +e
  security default-keychain -d user -s "$original_default" || failed=1
  security list-keychains -d user -s "${original_keychains[@]}" || failed=1
  security delete-keychain "$keychain" || failed=1
  rm -rf "$credentials" || failed=1
  [[ "$status" != 0 ]] || status=$failed
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf '%s' "$MACOS_CERTIFICATE_P12_BASE64" | base64 --decode > "$credentials/certificate.p12"
printf '%s' "$MACOS_NOTARY_KEY_P8_BASE64" | base64 --decode > "$credentials/AuthKey.p8"
password="$(openssl rand -hex 24)"
security create-keychain -p "$password" "$keychain"
security set-keychain-settings -lut 7200 "$keychain"
security unlock-keychain -p "$password" "$keychain"
security import "$credentials/certificate.p12" -P "$MACOS_CERTIFICATE_PASSWORD" \
  -t cert -f pkcs12 -k "$keychain" -T /usr/bin/codesign -T /usr/bin/security
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain"
security list-keychains -d user -s "$keychain" "${original_keychains[@]}"
security default-keychain -d user -s "$keychain"
export NOTARY_PROFILE=secure-agent-ci
xcrun notarytool store-credentials "$NOTARY_PROFILE" --key "$credentials/AuthKey.p8" \
  --key-id "$MACOS_NOTARY_KEY_ID" --issuer "$MACOS_NOTARY_ISSUER_ID" \
  --keychain "$keychain" --no-validate
export CODESIGN_IDENTITY="$MACOS_CODESIGN_IDENTITY"
unset DEVELOPER_TEAM
make -C "$2" release VERSION="$3"
