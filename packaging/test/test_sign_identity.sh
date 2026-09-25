#!/usr/bin/env bash
# Unit tests for packaging/lib/sign_identity.sh. Stubs `security` on PATH —
# never touches the real keychain.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${REPO_ROOT}/packaging/lib/sign_identity.sh"

WORK="$(mktemp -d "${REPO_ROOT}/.tmp/test_sign_identity.XXXXXX")"
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

# write_stub <identities-list-output>
write_stub() {
  cat > "${STUB_BIN}/security" <<STUB
#!/usr/bin/env bash
cat <<'IDS'
$1
IDS
STUB
  chmod +x "${STUB_BIN}/security"
}

# run_resolve [codesign_identity_value]
# Runs resolve_sign_identity in a clean subshell: PATH prepended with the
# stub, CODESIGN_IDENTITY unset unless an arg is given. stderr captured.
run_resolve() {
  local stderr_file="${WORK}/stderr.log"
  : > "${stderr_file}"
  if [[ $# -ge 1 ]]; then
    (export PATH="${STUB_BIN}:${PATH}"; export CODESIGN_IDENTITY="$1"; resolve_sign_identity) 2>"${stderr_file}"
  else
    (unset CODESIGN_IDENTITY; export PATH="${STUB_BIN}:${PATH}"; resolve_sign_identity) 2>"${stderr_file}"
  fi
}

# --- identities list with Apple Development -> it is chosen ---
write_stub '  1) AAAA111122223333444455556666777788889999 "Apple Development: Jane Doe (TEAMID)"
     1 valid identities found'
got="$(run_resolve)"
check "Apple Development identity chosen" 'Apple Development: Jane Doe (TEAMID)' "${got}"

# --- identities list with only Developer ID -> that one ---
write_stub '  1) BBBB111122223333444455556666777788889999 "Developer ID Application: Jane Doe (TEAMID)"
     1 valid identities found'
got="$(run_resolve)"
check "Developer ID Application identity chosen" 'Developer ID Application: Jane Doe (TEAMID)' "${got}"

# --- both present -> Apple Development wins ---
write_stub '  1) AAAA111122223333444455556666777788889999 "Apple Development: Jane Doe (TEAMID)"
  2) BBBB111122223333444455556666777788889999 "Developer ID Application: Jane Doe (TEAMID)"
     2 valid identities found'
got="$(run_resolve)"
check "Apple Development preferred over Developer ID" 'Apple Development: Jane Doe (TEAMID)' "${got}"

# --- none -> "-" plus a warning on stderr ---
write_stub '     0 valid identities found'
got="$(run_resolve)"
check "no identities falls back to ad-hoc" '-' "${got}"
if grep -qi "warning" "${WORK}/stderr.log"; then
  echo "ok - ad-hoc fallback warns on stderr"
  pass=$((pass + 1))
else
  echo "not ok - ad-hoc fallback warns on stderr (stderr was empty)"
  fail=$((fail + 1))
fi

# --- CODESIGN_IDENTITY=- wins even when Apple Development exists ---
write_stub '  1) AAAA111122223333444455556666777788889999 "Apple Development: Jane Doe (TEAMID)"
     1 valid identities found'
got="$(run_resolve -)"
check "explicit CODESIGN_IDENTITY=- overrides available identity" '-' "${got}"

# --- CODESIGN_IDENTITY=X passes through untouched ---
got="$(run_resolve "Developer ID Application: Someone Else (OTHERID)")"
check "explicit CODESIGN_IDENTITY passes through" 'Developer ID Application: Someone Else (OTHERID)' "${got}"

echo "${pass} passed, ${fail} failed"
[[ "${fail}" -eq 0 ]]
