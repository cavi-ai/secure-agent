#!/usr/bin/env bash
# Unit tests for packaging/lib/telemetry_status.sh — the post-install
# file-telemetry status line install.sh prints. No real daemon or install.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${REPO_ROOT}/packaging/lib/telemetry_status.sh"

# A plain system mktemp, not the worktree's .tmp/: AF_UNIX socket paths are
# capped at ~104 bytes on macOS, and the fake status server below binds one
# inside this directory — the worktree's own path is already too long.
WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [[ -n "${SERVER_PID}" ]] && kill "${SERVER_PID}" >/dev/null 2>&1 || true
  rm -rf "${WORK}"
}
trap cleanup EXIT

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

# --- es_service_state: fixture JSON ---
check "es_service_state reads running" "running" "$(es_service_state '{"es_service":{"state":"running"}}')"
check "es_service_state reads not-loaded" "not-loaded" "$(es_service_state '{"es_service":{"state":"not-loaded"}}')"
check "es_service_state empty when field absent" "" "$(es_service_state '{"proxy_port":1}')"
check "es_service_state empty on invalid JSON" "" "$(es_service_state 'not json')"
check "es_service_state empty on empty input" "" "$(es_service_state '')"

# --- telemetry_status_line: composed text ---
check "running, non-ad-hoc" \
  "File telemetry: running" \
  "$(telemetry_status_line running 0)"
check "running, ad-hoc adds the rebuild caveat" \
  "File telemetry: running; ad-hoc builds lose this grant on every rebuild" \
  "$(telemetry_status_line running 1)"
check "not-loaded names the two grants to check" \
  "File telemetry: not-loaded — approve Secure Agent in System Settings → General → Login Items & Extensions, then allow it in Privacy & Security → Full Disk Access (once per signing identity)" \
  "$(telemetry_status_line not-loaded 0)"
check "unknown, without approval steps, when the daemon did not answer" \
  "File telemetry: unknown — the daemon did not answer in time; the menu bar shows the state once it is up; ad-hoc builds lose this grant on every rebuild" \
  "$(telemetry_status_line '' 1)"

# --- resolve_socket_path: fixture config.yaml ---
printf 'socket_path: "%s/daemon.sock"\n' "${WORK}" > "${WORK}/quoted.yaml"
printf "socket_path: '%s/daemon.sock'\n" "${WORK}" > "${WORK}/single.yaml"
printf 'socket_path: %s/daemon.sock\n' "${WORK}" > "${WORK}/bare.yaml"

check "resolve_socket_path reads a double-quoted value" \
  "${WORK}/daemon.sock" "$(resolve_socket_path "${WORK}/quoted.yaml" "/default/sock")"
check "resolve_socket_path reads a single-quoted value" \
  "${WORK}/daemon.sock" "$(resolve_socket_path "${WORK}/single.yaml" "/default/sock")"
check "resolve_socket_path reads a bare value" \
  "${WORK}/daemon.sock" "$(resolve_socket_path "${WORK}/bare.yaml" "/default/sock")"
check "resolve_socket_path falls back when config is missing" \
  "/default/sock" "$(resolve_socket_path "${WORK}/missing.yaml" "/default/sock")"

# --- read_status_json + es_service_state: fake HTTP-over-unix-socket server ---
cat > "${WORK}/fake_status_server.py" <<'PYSRV'
import http.server
import socketserver
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"es_service": {"state": "running"}}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class UnixHTTPServer(socketserver.UnixStreamServer):
    pass


UnixHTTPServer.allow_reuse_address = True
srv = UnixHTTPServer(sys.argv[1], Handler)
srv.serve_forever()
PYSRV

SOCK="${WORK}/daemon.sock"

# A stale socket file (the previous daemon's, nobody listening) is not an
# answer: wait_for_status times out and prints nothing.
python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1])
' "${SOCK}"
if STALE="$(wait_for_status "${SOCK}" 2)"; then
  echo "not ok - wait_for_status times out on a stale socket file"
  fail=$((fail + 1))
else
  check "wait_for_status prints nothing on a stale socket file" "" "${STALE}"
fi
rm -f "${SOCK}"

# The daemon comes up while install.sh waits: the state is read once it answers.
( sleep 2; exec python3 "${WORK}/fake_status_server.py" "${SOCK}" ) > "${WORK}/server.log" 2>&1 &
SERVER_PID=$!
if LATE="$(wait_for_status "${SOCK}" 15)"; then
  check "wait_for_status reads the state of a daemon that starts during the wait" "running" "${LATE}"
else
  echo "not ok - wait_for_status reads the state of a daemon that starts during the wait"
  fail=$((fail + 1))
fi

BODY="$(read_status_json "${SOCK}")"
check "read_status_json reaches the fake daemon" '{"es_service": {"state": "running"}}' "${BODY}"
check "es_service_state parses the real response" "running" "$(es_service_state "${BODY}")"

echo "${pass} passed, ${fail} failed"
[[ "${fail}" -eq 0 ]]
