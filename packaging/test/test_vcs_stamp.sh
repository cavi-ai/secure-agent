#!/usr/bin/env bash
# Unit tests for packaging/lib/vcs_stamp.sh. Stubs `go` on PATH; the HEAD
# comes from a throwaway git repository.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${REPO_ROOT}/packaging/lib/vcs_stamp.sh"

mkdir -p "${REPO_ROOT}/.tmp"
WORK="$(mktemp -d "${REPO_ROOT}/.tmp/test_vcs_stamp.XXXXXX")"
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

REPO="${WORK}/repo"
git init -q "${REPO}"
git -C "${REPO}" -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -q --allow-empty -m one
HEAD_SHA="$(git -C "${REPO}" rev-parse HEAD)"
OTHER_SHA="0123456789abcdef0123456789abcdef01234567"

# write_go_stub <revision or empty>: `go version -m` prints build info with
# that vcs.revision (none when empty); `go env GOVERSION` prints go1.26.6.
write_go_stub() {
  local rev_line=""
  [[ -n "$1" ]] && rev_line="	build	vcs.revision=$1"
  cat > "${STUB_BIN}/go" <<STUB
#!/usr/bin/env bash
if [[ "\$1" == "env" ]]; then echo go1.26.6; exit 0; fi
printf '%s: go1.26.6\n\tpath\tgithub.com/cavi-ai/secure-agent/daemon/cmd/secure-agentd\n' "\$3"
[[ -n "${rev_line}" ]] && printf '%s\n' "${rev_line}"
exit 0
STUB
  chmod +x "${STUB_BIN}/go"
}

# run_check <dir>: exit status of check_vcs_stamp with the stub first on PATH;
# stderr lands in ${WORK}/stderr.log.
run_check() {
  (export PATH="${STUB_BIN}:${PATH}"; check_vcs_stamp "${WORK}/bin/secure-agentd" "$1") 2>"${WORK}/stderr.log" && echo 0 || echo 1
}

write_go_stub "${HEAD_SHA}"
check "stamp equal to HEAD passes" 0 "$(run_check "${REPO}")"

write_go_stub "${OTHER_SHA}"
check "stamp of another commit fails" 1 "$(run_check "${REPO}")"
check "the error names the stamped commit" 1 "$(grep -c "stamped ${OTHER_SHA}" "${WORK}/stderr.log")"
check "the error names HEAD" 1 "$(grep -c "HEAD is ${HEAD_SHA}" "${WORK}/stderr.log")"
check "the error names the toolchain" 1 "$(grep -c 'go1.26.6 stamps the enclosing checkout' "${WORK}/stderr.log")"

write_go_stub ""
check "a binary without a stamp passes" 0 "$(run_check "${REPO}")"

write_go_stub "${OTHER_SHA}"
mkdir -p "${WORK}/notgit"
# The work dir sits inside this repository; stop git's upward search at it.
check "a tree outside git passes" 0 "$(GIT_CEILING_DIRECTORIES="${WORK}" run_check "${WORK}/notgit")"

echo "${pass} passed, ${fail} failed"
[[ "${fail}" -eq 0 ]]
