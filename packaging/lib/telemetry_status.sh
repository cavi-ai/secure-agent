#!/usr/bin/env bash
# Shared by packaging/install.sh and its test: turns the daemon's /status
# response into the one line the installer prints about file telemetry.
# Sourced, not executed.

# es_service_state <json-text>
# Extracts es_service.state from a /status JSON payload, on stdout. Empty
# (and nothing else) when the payload is empty, invalid, or the field absent.
es_service_state() {
  python3 -c '
import json, sys
raw = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    data = json.loads(raw) if raw else {}
except ValueError:
    data = {}
svc = data.get("es_service") or {}
print(svc.get("state") or "")
' "${1:-}"
}

# telemetry_status_line <state> <ad_hoc:0|1>
# <state> is "" when /status could not be read at all (daemon never came up
# within the wait). Never used to fail the install — it only formats text.
telemetry_status_line() {
  local state="${1:-}" ad_hoc="${2:-0}" line
  if [[ "${state}" == "running" ]]; then
    line="File telemetry: running"
  else
    [[ -n "${state}" ]] || state="unreachable"
    line="File telemetry: ${state} — approve Secure Agent in System Settings → General → Login Items & Extensions, then allow it in Privacy & Security → Full Disk Access (once per signing identity)"
  fi
  if [[ "${ad_hoc}" == "1" ]]; then
    line="${line}; ad-hoc builds lose this grant on every rebuild"
  fi
  printf '%s\n' "${line}"
}

# resolve_socket_path <config_yaml_path> <default_path>
# Reads socket_path: from a secure-agent config.yaml when present and set,
# else <default_path>. Handles a quoted, single-quoted, or bare scalar value.
resolve_socket_path() {
  local config="$1" default_path="$2" value=""
  if [[ -f "${config}" ]]; then
    value="$(grep -E '^[[:space:]]*socket_path:' "${config}" 2>/dev/null | head -1 \
      | sed -E 's/^[[:space:]]*socket_path:[[:space:]]*//; s/[[:space:]]*(#.*)?$//; s/^"(.*)"$/\1/; s/^'"'"'(.*)'"'"'$/\1/')"
  fi
  if [[ -n "${value}" ]]; then
    printf '%s\n' "${value/#\~/${HOME}}"
  else
    printf '%s\n' "${default_path}"
  fi
}

# wait_for_socket <path> <timeout_seconds>
# Polls once a second until a unix-socket file exists at <path>.
wait_for_socket() {
  local path="$1" timeout="${2:-30}" waited=0
  while [[ ! -S "${path}" ]]; do
    if (( waited >= timeout )); then
      return 1
    fi
    sleep 1
    waited=$(( waited + 1 ))
  done
  return 0
}

# read_status_json <socket_path>
# Curls /status over the unix socket; prints the raw body, empty on failure.
read_status_json() {
  local socket="$1"
  curl -s --max-time 5 --unix-socket "${socket}" http://unix/status 2>/dev/null || true
}
