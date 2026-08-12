#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOCKET_PATH="${HOME}/.config/secure-agent/daemon.sock"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

printf 'SECRET_KEY=dummy_val_123\n' > "$tmp/.env"

# Create a test overlay config with fast sampling interval for smoke test
cat > "$tmp/test_config.yaml" <<EOF
agents:
  - { name: cursor, match: ["fake-cursor", "cursor"] }
net_sample_interval_ms: 200
socket_path: "$SOCKET_PATH"
EOF

# Build daemon
go build -o "$tmp/secure-agentd" "$SCRIPT_DIR/daemon/cmd/secure-agentd"

# Launch daemon
echo "Launching test instance of secure-agentd..."
"$tmp/secure-agentd" -config "$tmp/test_config.yaml" >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 1

# Create fake-cursor Go test agent binary to guarantee process name matching in sysctl proc list
cat > "$tmp/fake_cursor_main.go" <<EOF
package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	home, _ := os.UserHomeDir()
	actPath := filepath.Join(home, ".local", "state", "secure-agent", "activity.jsonl")
	os.MkdirAll(filepath.Dir(actPath), 0755)

	targetEnv := os.Args[1] + "/.env"
	rec := map[string]interface{}{
		"tool": "Read",
		"file_path": targetEnv,
		"pid": os.Getpid(),
	}
	data, _ := json.Marshal(rec)
	f, _ := os.OpenFile(actPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if f != nil {
		f.Write(append(data, '\n'))
		f.Close()
	}

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
			time.Sleep(2 * time.Second)
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

echo "Waiting for flag via API..."
PASSED=false
for _ in $(seq 1 15); do
  if curl -s --unix-socket "$SOCKET_PATH" http://unix/flags 2>/dev/null \
       | grep -q "sensitive-read-then-connect\|keychain-access"; then
    PASSED=true
    break
  fi
  sleep 0.3
done

wait $AGENT_PID 2>/dev/null || true

if [ -n "$DAEMON_PID" ]; then
  kill "$DAEMON_PID" 2>/dev/null || true
fi

if [ "$PASSED" = true ]; then
  echo "E2E SMOKE TEST: PASS"
  exit 0
else
  echo "E2E SMOKE TEST: FAIL (no flag detected via API)"
  exit 1
fi
