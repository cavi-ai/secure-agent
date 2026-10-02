#!/usr/bin/env bash
# check_vcs_stamp <binary> [repo_dir]
#
# Fails when a Go binary's build info names a commit other than repo_dir's
# HEAD. Go before 1.27 does not treat a git worktree's .git file as a
# repository root (go.dev/issue/58218): built in a worktree that sits inside
# another checkout, it stamps that checkout's commit instead. A binary with
# no stamp (-buildvcs=false) or a tree outside git passes.
check_vcs_stamp() {
  local bin="$1" dir="${2:-.}" head stamp
  head="$(git -C "${dir}" rev-parse HEAD 2>/dev/null)" || return 0
  stamp="$(go version -m "${bin}" 2>/dev/null | awk -F= '/vcs\.revision=/ {print $2; exit}')"
  if [[ -z "${stamp}" || "${stamp}" == "${head}" ]]; then
    return 0
  fi
  echo "ERROR: ${bin} is stamped ${stamp}, but HEAD is ${head}." >&2
  echo "       $(go env GOVERSION 2>/dev/null) stamps the enclosing checkout's commit when building in a git worktree; build with Go 1.27 or later, or from a clone." >&2
  return 1
}
