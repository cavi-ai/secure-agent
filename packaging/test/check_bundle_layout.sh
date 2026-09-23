#!/bin/bash
# check_bundle_layout.sh — fail unless the built app bundle carries the
# Endpoint Security collector daemon that SMAppService.daemon registers:
# the LaunchDaemon plist lints, its Label is the collector label, it has no
# ProgramArguments, and its BundleProgram resolves to an executable inside
# the bundle.
#
# Usage: check_bundle_layout.sh [path/to/Secure Agent.app]
# (default: dist/Secure Agent.app, as written by packaging/make_app.sh)
set -eu

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
app="${1:-${repo_root}/dist/Secure Agent.app}"
label="com.cavi-ai.secure-agent-esd"
plist="${app}/Contents/Library/LaunchDaemons/${label}.plist"

fail() {
    echo "bundle layout: $*" >&2
    exit 1
}

[ -d "$app" ] || fail "no app bundle at ${app} (build it with packaging/make_app.sh)"
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

echo "bundle layout: ${label} plist valid, BundleProgram ${program} executable"
