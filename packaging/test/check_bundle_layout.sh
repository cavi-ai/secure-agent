#!/bin/bash
# check_bundle_layout.sh — fail unless the built app bundle carries the
# Endpoint Security collector daemon that SMAppService.daemon registers:
# the LaunchDaemon plist lints, its Label is the collector label, it has no
# ProgramArguments, and its BundleProgram resolves to an executable inside
# the bundle. Before that, fail unless packaging/make_app.sh assigns BUNDLE_ID
# exactly once, to the app's one identity.
#
# Usage: check_bundle_layout.sh [path/to/Secure Agent.app]
# (default: dist/Secure Agent.app, as written by packaging/make_app.sh)
set -eu

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
app="${1:-${repo_root}/dist/Secure Agent.app}"
label="com.cavi-ai.secure-agent-esd"
app_id="com.cavi-ai.secure-agent"
plist="${app}/Contents/Library/LaunchDaemons/${label}.plist"

fail() {
    echo "bundle layout: $*" >&2
    exit 1
}

make_app="${repo_root}/packaging/make_app.sh"
bundle_ids="$(grep -E '^[[:space:]]*BUNDLE_ID=' "$make_app")" || fail "no BUNDLE_ID in ${make_app}"
[ "$bundle_ids" = "BUNDLE_ID=\"${app_id}\"" ] || fail "make_app.sh sets '${bundle_ids}', want BUNDLE_ID=\"${app_id}\""

[ -d "$app" ] || fail "no app bundle at ${app} (build it with packaging/make_app.sh)"
bundle_id="$(plutil -extract CFBundleIdentifier raw -o - "${app}/Contents/Info.plist")" || fail "missing CFBundleIdentifier"
[ "$bundle_id" = "$app_id" ] || fail "CFBundleIdentifier is '${bundle_id}', want '${app_id}'"
[ -f "$plist" ] || fail "missing ${plist}"
plutil -lint "$plist" >/dev/null || fail "plutil -lint rejects ${plist}"

got_label="$(plutil -extract Label raw -o - "$plist")" || fail "no Label in ${plist}"
[ "$got_label" = "$label" ] || fail "Label is '${got_label}', want '${label}'"

if plutil -extract ProgramArguments xml1 -o - "$plist" >/dev/null 2>&1; then
    fail "${plist} sets ProgramArguments; the daemon must run from BundleProgram"
fi

program="$(plutil -extract BundleProgram raw -o - "$plist")" || fail "no BundleProgram in ${plist}"
[ -f "${app}/${program}" ] && [ -x "${app}/${program}" ] ||
    fail "BundleProgram ${program} is not an executable file in ${app}"

check_signing_identity() {
    signed_id="$(codesign -d --verbose=2 "$1" 2>&1 | sed -n 's/^Identifier=//p')" || fail "cannot inspect signature for $1"
    [ "$signed_id" = "$2" ] || fail "signing identity '${signed_id}' for $1, want '$2'"
}
check_signing_identity "$app" "$app_id"
check_signing_identity "${app}/${program}" "$label"
check_signing_identity "${app}/Contents/Helpers/secure-agentd" "com.cavi-ai.secure-agent.daemon"
check_signing_identity "${app}/Contents/Helpers/secure-agent" "com.cavi-ai.secure-agent.cli"

echo "bundle layout: ${label} plist valid, BundleProgram ${program} executable"
