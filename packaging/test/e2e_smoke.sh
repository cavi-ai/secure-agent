#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

SOCKET_PATH="$tmp/daemon.sock"

rm -f "${HOME}/.local/state/secure-agent/activity.jsonl"
printf 'SECRET_KEY=dummy_val_123\n' > "$tmp/.env"

# Create a test overlay config with fast sampling interval for smoke test
cat > "$tmp/test_config.yaml" <<EOF
agents:
  - { name: cursor, match: ["fake-cursor", "cursor"] }
net_sample_interval_ms: 200
socket_path: "$SOCKET_PATH"
db_path: "$tmp/events.db"
jsonl_path: "$tmp/events.jsonl"
proxy_port: 0
EOF

# Build daemon
go build -o "$tmp/secure-agentd" "$SCRIPT_DIR/daemon/cmd/secure-agentd"

# Launch daemon
echo "Launching test instance of secure-agentd..."
"$tmp/secure-agentd" -config "$tmp/test_config.yaml" &
DAEMON_PID=$!
sleep 1

# Create fake-cursor Go test agent binary to guarantee process name matching in sysctl proc list
cat > "$tmp/fake_cursor_main.go" <<EOF
package main

import (
	"encoding/json"
	"net"
	"os"
	"time"
)

func main() {
	time.Sleep(500 * time.Millisecond)
	home, _ := os.UserHomeDir()
	actPath := home + "/.local/state/secure-agent/activity.jsonl"
	os.MkdirAll(home+"/.local/state/secure-agent", 0755)
	targetEnv := os.Args[1] + "/.env"
	rec := map[string]interface{}{
		"tool": "Read",
		"file_path": targetEnv,
		"pid": os.Getpid(),
	}
	data, _ := json.Marshal(rec)
	f, err := os.OpenFile(actPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		panic(err)
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		panic(err)
	}
	f.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		defer l.Close()
		done := make(chan struct{})
		go func() {
			conn, err := l.Accept()
			if err == nil {
				<-done
				conn.Close()
			}
		}()

		clientConn, err := net.Dial("tcp", l.Addr().String())
		if err == nil {
			time.Sleep(10 * time.Second)
			close(done)
			clientConn.Close()
		}
	}
}
EOF

go build -o "$tmp/fake-cursor" "$tmp/fake_cursor_main.go"

# Execute fake agent
"$tmp/fake-cursor" "$tmp" &
AGENT_PID=$!

echo "Waiting for flag & incident report via API..."
PASSED=false
INCIDENT_PASSED=false
INCIDENT_RESP=""
FLAGS_RESP=""

for _ in $(seq 1 30); do
  FLAGS_RESP=$(curl -s --unix-socket "$SOCKET_PATH" http://unix/flags 2>/dev/null || true)
  INCIDENT_RESP=$(curl -s --unix-socket "$SOCKET_PATH" http://unix/incidents 2>/dev/null || true)

  if echo "$FLAGS_RESP" | grep -E -q "sensitive-read-then-connect|keychain-access"; then
    PASSED=true
  fi
  if echo "$INCIDENT_RESP" | grep -E -q "rot-env|Environment File|sensitive-read-then-connect"; then
    INCIDENT_PASSED=true
  fi
  if [ "$PASSED" = true ] && [ "$INCIDENT_PASSED" = true ]; then
    break
  fi
  sleep 0.3
done

wait $AGENT_PID 2>/dev/null || true

if [ "$PASSED" = true ] && [ "$INCIDENT_PASSED" = true ]; then
  echo "E2E SMOKE TEST: PASS (Flag and Incident report verified via API)"
  if [ -n "$DAEMON_PID" ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
  fi
  exit 0
else
  echo "DEBUG DB EVENTS: $(sqlite3 "$tmp/events.db" "SELECT count(*), kind FROM events GROUP BY kind;" 2>/dev/null || true)"
  echo "DEBUG DB FLAGS: $(sqlite3 "$tmp/events.db" "SELECT * FROM flags;" 2>/dev/null || true)"
  echo "DEBUG DB INCIDENTS: $(sqlite3 "$tmp/events.db" "SELECT * FROM incidents;" 2>/dev/null || true)"
  echo "DEBUG INCIDENTS RESPONSE: $INCIDENT_RESP"
  echo "DEBUG FLAGS RESPONSE: $FLAGS_RESP"
  if [ -n "$DAEMON_PID" ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
  fi
  echo "E2E SMOKE TEST: FAIL (Flag passed: $PASSED, Incident passed: $INCIDENT_PASSED)"
  exit 1
fi
