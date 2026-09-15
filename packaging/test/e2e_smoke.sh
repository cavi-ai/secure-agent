#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"
COLLECTOR_PID=""
ADVISOR_STUB_PID=""
DAEMON_PID=""
AGENT_PID=""
DECISION1_PID=""
SSE_CURL_PID=""
# With `set -e`, any mid-script failure used to leave the collector, daemon,
# and fake agent running with their state dir deleted underneath them.
cleanup() {
  for pid in $DECISION1_PID $SSE_CURL_PID $AGENT_PID $DAEMON_PID $COLLECTOR_PID $ADVISOR_STUB_PID; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  rm -rf "$tmp"
}
trap cleanup EXIT

# Preserve the real Go toolchain locations before HOME moves, so `go build`
# below still finds its module cache/build cache and never needs network.
export GOPATH="$(go env GOPATH)"
export GOCACHE="$(go env GOCACHE)"
export GOMODCACHE="$(go env GOMODCACHE)"
export GOENV="$(go env GOENV)"
export GOPROXY="$(go env GOPROXY)"
export GOSUMDB="$(go env GOSUMDB)"

# The daemon and the fake agent below both derive state paths from HOME
# (activity.jsonl tail target, ~/.claude and ~/.cursor watch globs, the CA
# cert/key, the firewall salt) that aren't all covered by test_config.yaml's
# explicit overrides. Route all of it into the throwaway dir instead of
# ever touching the real home.
export HOME="$tmp"

SOCKET_PATH="$tmp/daemon.sock"

printf 'SECRET_KEY=dummy_val_123\n' > "$tmp/.env"

# Reference collector: verifies the fleet webhook contract (signed delivery,
# rollup) end to end. Random port; secret shared with the node config below.
# The node id is pinned by pre-seeding the node-id file the daemon reads, so
# the collector's secret map can name it exactly.
NODE_ID="e2e0de00de00de00de00de00de00de00"  # must be 32 hex chars (LoadNodeID validates)
mkdir -p "$tmp"
printf '%s\n' "$NODE_ID" > "$tmp/node-id"
COLL_PORT=$((19000 + RANDOM % 2000))
COLL_SECRET="e2e-webhook-secret"
printf '%s=%s\n' "$NODE_ID" "$COLL_SECRET" > "$tmp/collector-secrets.txt"
go build -o "$tmp/secure-agent-collector" "$SCRIPT_DIR/cmd/secure-agent-collector"
"$tmp/secure-agent-collector" -addr "127.0.0.1:$COLL_PORT" -store "$tmp/collstore" -config "$tmp/collector-secrets.txt" > "$tmp/collector.log" 2>&1 &
COLLECTOR_PID=$!

# Local-advisor stub: an OpenAI-compatible chat endpoint on loopback that
# always returns a benign triage verdict. The daemon's advisor must call it
# for the flag below and attach the verdict to /flags.
ADVISOR_PORT=$((21000 + RANDOM % 2000))
cat > "$tmp/advisor_stub.py" <<PYEOF
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        body = json.dumps({"choices": [{"message": {"role": "assistant",
            "content": '{"assessment":"benign","confidence":0.9,"rationale":"routine workflow","suggested_action":"none"}'}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.HTTPServer(("127.0.0.1", $ADVISOR_PORT), H).serve_forever()
PYEOF
python3 "$tmp/advisor_stub.py" > "$tmp/advisor_stub.log" 2>&1 &
ADVISOR_STUB_PID=$!

# Create a test overlay config with fast sampling interval for smoke test
cat > "$tmp/test_config.yaml" <<EOF
agents:
  - { name: cursor, match: ["fake-cursor", "cursor"] }
net_sample_interval_ms: 200
socket_path: "$SOCKET_PATH"
db_path: "$tmp/events.db"
jsonl_path: "$tmp/events.jsonl"
proxy_port: 0
directory_guard:
  prompt_deadline_ms: 8000
firewall:
  registry:
    salt_ref: "$tmp/fw-salt"
advisor:
  enabled: true
  endpoint: "http://127.0.0.1:$ADVISOR_PORT"
  model: "e2e-stub-4b"
  timeout_ms: 4000
fleet:
  hostname: "e2e-node"
  labels: { env: e2e }
  heartbeat_interval_sec: 2
  webhooks:
    - url: "http://127.0.0.1:$COLL_PORT/hooks/secure-agent"
      secret: "$COLL_SECRET"
      events: [flag, incident, guard]
EOF

# Build daemon
go build -o "$tmp/secure-agentd" "$SCRIPT_DIR/daemon/cmd/secure-agentd"

# Launch daemon
echo "Launching test instance of secure-agentd..."
"$tmp/secure-agentd" -config "$tmp/test_config.yaml" > "$tmp/daemon.log" 2>&1 &
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

# ---------------------------------------------------------------------------
# Local advisor: the flag above must have been triaged by the stub model
# server and the verdict attached to /flags (advisory annotation only).
# ---------------------------------------------------------------------------
ADVISOR_PASSED=false
for _ in $(seq 1 30); do
  ADVISOR_RESP=$(curl -s --unix-socket "$SOCKET_PATH" http://unix/flags 2>/dev/null || true)
  if echo "$ADVISOR_RESP" | grep -q '"advisor"' && echo "$ADVISOR_RESP" | grep -q '"assessment":"benign"'; then
    ADVISOR_PASSED=true
    break
  fi
  sleep 0.3
done
if [ "$ADVISOR_PASSED" = true ]; then
  echo "Advisor: flag carries the stub model's benign verdict."
else
  echo "Advisor: MISSING verdict on /flags."
fi

# ---------------------------------------------------------------------------
# Directory Guard: real HTTP round-trip through the unix socket.
#
# 1. POST /guard/decision in the background (it BLOCKS until resolved or the
#    broker deadline) and capture its body to a file.
# 2. Poll GET /guard/pending until the prompt shows up, and pull its id.
# 3. POST /guard/resolve allow/always for that id.
# 4. Wait for the backgrounded decision curl; assert verdict=allow.
# 5. POST a second /guard/decision for the same (agent,rule_id): it must
#    return the cached allow instantly (reason=cached), with pending now empty.
# ---------------------------------------------------------------------------
GUARD_PASSED=false
GUARD_AGENT="claude"
GUARD_RULE_ID="e2e-cloud-creds"
GUARD_PATH="$tmp/.aws/credentials"
DECISION1_OUT="$tmp/guard_decision1.json"
DECISION2_OUT="$tmp/guard_decision2.json"
PENDING_AFTER_OUT="$tmp/guard_pending_after.json"

guard_decision_payload() {
  printf '{"agent":"%s","tool":"Read","path":"%s","rule_id":"%s"}' \
    "$GUARD_AGENT" "$GUARD_PATH" "$GUARD_RULE_ID"
}

echo "Guard: posting first /guard/decision (backgrounded, blocks until resolved)..."

# SSE: subscribe to the event stream first — the guard decision must publish a
# guard-prompt event on the bus, and the stream must carry it (this is what
# the menubar's instant-prompt path consumes).
SSE_OUT="$tmp/sse_stream.txt"
# -N (unbuffered) so frames hit the file as they arrive — the later kill must
# not lose buffered output.
curl -sN --unix-socket "$SOCKET_PATH" --max-time 15 http://unix/events/stream > "$SSE_OUT" 2>/dev/null &
SSE_CURL_PID=$!

# The greeting line means the daemon has SUBSCRIBED this connection to the
# bus (it subscribes before writing it). Posting the guard decision before
# the greeting races subscription registration and can drop the guard events
# — that exact window was a CI flake.
for _ in $(seq 1 50); do
  if grep -q "secure-agent event stream" "$SSE_OUT" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

curl -s --unix-socket "$SOCKET_PATH" -X POST http://unix/guard/decision \
  -d "$(guard_decision_payload)" > "$DECISION1_OUT" 2>/dev/null &
DECISION1_PID=$!

echo "Guard: polling /guard/pending for the prompt..."
PENDING_ID=""
for _ in $(seq 1 50); do
  PENDING_RESP=$(curl -s --unix-socket "$SOCKET_PATH" http://unix/guard/pending 2>/dev/null || true)
  PENDING_ID=$(printf '%s' "$PENDING_RESP" | python3 -c '
import json, sys
try:
    items = json.load(sys.stdin)
except Exception:
    items = []
for it in items:
    if it.get("agent") == "'"$GUARD_AGENT"'" and it.get("rule_id") == "'"$GUARD_RULE_ID"'":
        print(it.get("id", ""))
        break
' 2>/dev/null || true)
  if [ -n "$PENDING_ID" ]; then
    break
  fi
  sleep 0.1
done

if [ -n "$PENDING_ID" ]; then
  echo "Guard: pending prompt id=$PENDING_ID, resolving allow/always..."
  curl -s --unix-socket "$SOCKET_PATH" -X POST http://unix/guard/resolve \
    -d "{\"id\":\"$PENDING_ID\",\"verdict\":\"allow\",\"scope\":\"always\"}" >/dev/null 2>&1 || true

  wait "$DECISION1_PID" 2>/dev/null || true
  DECISION1_BODY=$(cat "$DECISION1_OUT" 2>/dev/null || true)

  if printf '%s' "$DECISION1_BODY" | grep -q '"verdict":"allow"'; then
    echo "Guard: first decision resolved allow, checking second decision is served from cache..."
    START_MS=$(python3 -c 'import time; print(int(time.time() * 1000))')
    curl -s --unix-socket "$SOCKET_PATH" -X POST http://unix/guard/decision \
      -d "$(guard_decision_payload)" > "$DECISION2_OUT" 2>/dev/null || true
    END_MS=$(python3 -c 'import time; print(int(time.time() * 1000))')
    ELAPSED_MS=$((END_MS - START_MS))
    DECISION2_BODY=$(cat "$DECISION2_OUT" 2>/dev/null || true)
    curl -s --unix-socket "$SOCKET_PATH" http://unix/guard/pending > "$PENDING_AFTER_OUT" 2>/dev/null || true
    PENDING_AFTER_COUNT=$(python3 -c '
import json
try:
    with open("'"$PENDING_AFTER_OUT"'") as f:
        print(len(json.load(f)))
except Exception:
    print(-1)
' 2>/dev/null || echo -1)

    if printf '%s' "$DECISION2_BODY" | grep -q '"verdict":"allow"' \
      && printf '%s' "$DECISION2_BODY" | grep -q '"reason":"cached"' \
      && [ "$ELAPSED_MS" -lt 2000 ] \
      && [ "$PENDING_AFTER_COUNT" = "0" ]; then
      GUARD_PASSED=true
    fi
  fi
else
  echo "Guard: prompt never appeared in /guard/pending within the poll window."
  kill "$DECISION1_PID" 2>/dev/null || true
  wait "$DECISION1_PID" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# SSE stream: the guard round-trip above must have published guard-prompt (and
# guard-resolved) events on the bus, carried over /events/stream.
# ---------------------------------------------------------------------------
SSE_PASSED=false
kill "$SSE_CURL_PID" 2>/dev/null || true
wait "$SSE_CURL_PID" 2>/dev/null || true
SSE_BODY=$(cat "$SSE_OUT" 2>/dev/null || true)
if printf '%s' "$SSE_BODY" | grep -q "secure-agent event stream" \
  && printf '%s' "$SSE_BODY" | grep -q "event: guard-prompt" \
  && printf '%s' "$SSE_BODY" | grep -q "event: guard-resolved"; then
  echo "SSE: stream carried the guard lifecycle events."
  SSE_PASSED=true
else
  echo "SSE: MISSING guard events on /events/stream."
fi

# ---------------------------------------------------------------------------
# Console auth: the browser console's telemetry endpoints on the proxy port
# require the console token; the proxy token (which agents carry) must NOT
# work there.
# ---------------------------------------------------------------------------
CONSOLE_PASSED=false
PROXY_PORT=$(curl -s --unix-socket "$SOCKET_PATH" http://unix/status 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("proxy_port", 0))' 2>/dev/null || echo 0)
if [ "$PROXY_PORT" != "0" ] && [ -f "$tmp/console-token" ]; then
  CT=$(tr -d '[:space:]' < "$tmp/console-token")
  PT=$(tr -d '[:space:]' < "$tmp/proxy-token")
  CODE_NONE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$PROXY_PORT/status" || true)
  CODE_PT=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 -H "X-SecureAgent-Proxy-Token: $PT" "http://127.0.0.1:$PROXY_PORT/status" || true)
  CODE_CT=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 -H "X-SecureAgent-Console-Token: $CT" "http://127.0.0.1:$PROXY_PORT/status" || true)
  if [ "$CODE_NONE" = "403" ] && [ "$CODE_PT" = "403" ] && [ "$CODE_CT" = "200" ]; then
    echo "Console auth: 403 without token, 403 with proxy token, 200 with console token."
    CONSOLE_PASSED=true
  else
    echo "Console auth FAILED: none=$CODE_NONE proxy-token=$CODE_PT console-token=$CODE_CT (want 403/403/200)"
  fi
  # Whitelist-drift regression: the endpoints the console fetches must NOT
  # fall through to the proxy-token challenge (407). This exact drift
  # silently blanked half the console behind a healthy daemon.
  DRIFT_FAILED=""
  for p in /status /posture /flags /events /incidents /audit /fleet \
           /firewall/sources /stats/rollup /mute /allowlist/suggestions \
           /egress/uninspected /notify/rules; do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
      -H "X-SecureAgent-Console-Token: $CT" "http://127.0.0.1:$PROXY_PORT$p" || true)
    if [ "$CODE" != "200" ]; then
      DRIFT_FAILED="$DRIFT_FAILED $p=$CODE"
    fi
  done
  if [ -z "$DRIFT_FAILED" ]; then
    echo "Console whitelist: all console-fetched endpoints answer 200 with the console token."
  else
    echo "Console whitelist FAILED (want 200):$DRIFT_FAILED"
    CONSOLE_PASSED=false
  fi
else
  echo "Console auth: proxy not running or console token missing (port=$PROXY_PORT)."
fi

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Operator loop: the menubar's whole surface against the live daemon.
#   mute → retro-ack of existing flags → acknowledge → per-path allow →
#   re-triage → incident status transition. Every disposition must persist
#   and leave the active set.
# ---------------------------------------------------------------------------
OPERATOR_PASSED=false
FLAG_ID=$(curl -s --unix-socket "$SOCKET_PATH" "http://unix/flags?limit=1" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["id"] if d else "")' 2>/dev/null || echo "")
if [ -n "$FLAG_ID" ]; then
  # 1. Mute the flag's rule+host: must persist AND acknowledge existing flags.
  HOST=$(echo "$FLAGS_RESP" | python3 -c "
import json,sys,re
d=json.load(sys.stdin)
f=[x for x in d if x['id']=='$FLAG_ID'][0]
for line in f.get('evidence',[]):
    i=line.find('connected to ')
    if i>=0:
        h=line[i+13:].split(' ')[0].split(':')[0]
        print(h); break
" 2>/dev/null | head -1)
  RULE=$(echo "$FLAGS_RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
f=[x for x in d if x['id']=='$FLAG_ID'][0]
print(f['rule'])" 2>/dev/null)
  MUTE_RESP=$(curl -s --unix-socket "$SOCKET_PATH" -X POST http://unix/mute -H "Content-Type: application/json" -d "{\"rule\":\"$RULE\",\"host\":\"$HOST\"}" 2>/dev/null || true)
  ACK_STATE=$(curl -s --unix-socket "$SOCKET_PATH" "http://unix/flags?limit=20" | python3 -c "
import json,sys
d=json.load(sys.stdin)
f=[x for x in d if x['id']=='$FLAG_ID']
print(f[0].get('acknowledged', False) if f else 'MISSING')" 2>/dev/null || echo MISSING)
  # 2. Acknowledge directly (idempotent double-call).
  curl -s --unix-socket "$SOCKET_PATH" -X POST http://unix/flags/acknowledge -H "Content-Type: application/json" -d "{\"flag_id\":\"$FLAG_ID\"}" > /dev/null 2>&1 || true
  ACK2_STATE=$(curl -s --unix-socket "$SOCKET_PATH" "http://unix/flags?limit=20" | python3 -c "
import json,sys
d=json.load(sys.stdin)
f=[x for x in d if x['id']=='$FLAG_ID'][0]
print(f.get('acknowledged', False))" 2>/dev/null || echo "")
  # 3. Per-path allow on a temp path.
  ALLOW_RESP=$(curl -s --unix-socket "$SOCKET_PATH" -X POST http://unix/guard/path-allow -H "Content-Type: application/json" -d "{\"agent\":\"e2e-test\",\"rule_id\":\"ssh-keys\",\"path\":\"/tmp/e2e-allow-test\"}" 2>/dev/null || true)
  DEC_CHECK=$(curl -s --unix-socket "$SOCKET_PATH" -X POST http://unix/guard/decision -H "Content-Type: application/json" --max-time 3 -d "{\"agent\":\"e2e-test\",\"tool\":\"Read\",\"path\":\"/tmp/e2e-allow-test/child\",\"rule_id\":\"ssh-keys\"}" 2>/dev/null || true)
  # 4. Re-triage: idempotent (second call queued=false).
  RET1=$(curl -s --unix-socket "$SOCKET_PATH" -X POST http://unix/advisor/retriage -H "Content-Type: application/json" -d "{\"flag_id\":\"$FLAG_ID\"}" 2>/dev/null || true)
  RET2=$(curl -s --unix-socket "$SOCKET_PATH" -X POST http://unix/advisor/retriage -H "Content-Type: application/json" -d "{\"flag_id\":\"$FLAG_ID\"}" 2>/dev/null || true)
  # 5. Incident status transition.
  INC_ID=$(echo "$INCIDENT_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[0]['id'] if d else '')" 2>/dev/null)
  INC_ACK=""
  if [ -n "$INC_ID" ]; then
    curl -s --unix-socket "$SOCKET_PATH" -X POST http://unix/incidents/status -H "Content-Type: application/json" -d "{\"id\":\"$INC_ID\",\"status\":\"acknowledged\"}" > /dev/null 2>&1 || true
    INC_ACK=$(curl -s --unix-socket "$SOCKET_PATH" "http://unix/incidents?limit=5" 2>/dev/null || true)
  fi

  if echo "$ACK_STATE" | grep -q "True" && echo "$MUTE_RESP" | grep -q "ok"; then
    OPERATOR_PASSED=true
  fi
fi

if [ "$OPERATOR_PASSED" = true ]; then
  echo "Operator loop: mute persisted + retro-acknowledged the flag, acknowledge idempotent, per-path allow served cached decision."
else
  echo "Operator loop FAILED: flag_id=$FLAG_ID mute_resp=$MUTE_RESP ack_state=$ACK_STATE ack2=$ACK2_STATE allow=$ALLOW_RESP"
fi

# Enroll UX: one command provisions the node side (secret + config) and
# prints the collector line — no manual node-id hunting, no daemon restart
# (config watcher picks it up; here we only assert the CLI contract).
# ---------------------------------------------------------------------------
ENROLL_PASSED=false
go build -o "$tmp/secure-agent-cli" "$SCRIPT_DIR/cmd/secure-agent"
ENROLL_CFG="$tmp/enroll-config.yaml"
ENROLL_OUT=$(SECURE_AGENT_SOCK="$SOCKET_PATH" SECURE_AGENT_CONFIG="$ENROLL_CFG" "$tmp/secure-agent-cli" fleet enroll "http://127.0.0.1:$COLL_PORT" 2>&1)
if [ -s "$ENROLL_CFG" ] && echo "$ENROLL_OUT" | grep -q "$NODE_ID=" && grep -q "hooks/secure-agent" "$ENROLL_CFG"; then
  ENROLL_PASSED=true
  echo "Enroll: CLI provisioned fleet.webhooks and printed the collector line."
else
  echo "Enroll FAILED: $ENROLL_OUT"
fi

# Fleet webhook: the collector must have received and verified the flag the
# fake agent triggered above. Sequential check (no heredoc-in-if).
# ---------------------------------------------------------------------------
WEBHOOK_PASSED=false
if [ -n "$DAEMON_PID" ]; then kill "$DAEMON_PID" 2>/dev/null || true; fi
sleep 1  # give in-flight webhook retries a moment to land
COLL_STORE="$tmp/collstore/$NODE_ID.jsonl"
if [ -s "$COLL_STORE" ] && python3 -c '
import json, sys
with open(sys.argv[1]) as f:
    recs = [json.loads(l) for l in f if l.strip()]
envs = [r.get("envelope", {}) for r in recs]
flags = [e for e in envs if e.get("kind") == "flag"]
status = [e for e in envs if e.get("kind") == "status"]
if not flags:
    sys.exit(1)
# The heartbeat must have landed too, carrying the nodes own posture
# headline and identity — even though this sink subscribes to flag/incident/guard only.
p = status[-1].get("payload", {}) if status else {}
if not (p.get("hostname") == "e2e-node"
    and p.get("posture_state") in ("all-clear", "attention", "critical")
    and p.get("labels", {}).get("env") == "e2e"):
    sys.exit(1)
# Gap detection: every envelope is stamped with one boot id, and the seq
# stream is contiguous — no silent loss on a healthy loopback chain.
seqs = sorted(e.get("seq", 0) for e in envs)
boots = {e.get("boot", "") for e in envs}
ok = (seqs and seqs[0] >= 1 and seqs == list(range(seqs[0], seqs[-1] + 1))
      and boots and boots != {""} and len(boots) == 1)
sys.exit(0 if ok else 1)
' "$COLL_STORE"; then
  WEBHOOK_PASSED=true
  echo "Fleet webhook: collector verified flag + status envelopes; seq stream contiguous, one boot id."
else
  echo "DEBUG collector log: $(cat "$tmp/collector.log" 2>/dev/null || true)"
fi
kill "$COLLECTOR_PID" 2>/dev/null || true

if [ "$PASSED" = true ] && [ "$INCIDENT_PASSED" = true ] && [ "$GUARD_PASSED" = true ] && [ "$WEBHOOK_PASSED" = true ] && [ "$SSE_PASSED" = true ] && [ "$CONSOLE_PASSED" = true ] && [ "$ADVISOR_PASSED" = true ] && [ "$OPERATOR_PASSED" = true ] && [ "$ENROLL_PASSED" = true ]; then
  echo "E2E SMOKE TEST: PASS (Flag, Incident, Directory Guard, fleet webhook + seq, enroll, SSE, console auth, advisor verdict, and operator loop verified)"
  if [ -n "$DAEMON_PID" ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
  fi
  exit 0
else
  echo "DEBUG DB EVENTS: $(sqlite3 "$tmp/events.db" "SELECT count(*), kind FROM events GROUP BY kind;" 2>/dev/null || true)"
  echo "DEBUG DB FLAGS: $(sqlite3 "$tmp/events.db" "SELECT * FROM flags;" 2>/dev/null || true)"
  echo "DEBUG DB INCIDENTS: $(sqlite3 "$tmp/events.db" "SELECT * FROM incidents;" 2>/dev/null || true)"
  echo "DEBUG DB GUARD RULES: $(sqlite3 "$tmp/events.db" "SELECT * FROM guard_rules;" 2>/dev/null || true)"
  echo "DEBUG INCIDENTS RESPONSE: $INCIDENT_RESP"
  echo "DEBUG FLAGS RESPONSE: $FLAGS_RESP"
  echo "DEBUG GUARD PENDING ID: $PENDING_ID"
  echo "DEBUG GUARD DECISION1 RESPONSE: $(cat "$DECISION1_OUT" 2>/dev/null || true)"
  echo "DEBUG GUARD DECISION2 RESPONSE: $(cat "$DECISION2_OUT" 2>/dev/null || true)"
  echo "DEBUG GUARD PENDING AFTER: $(cat "$PENDING_AFTER_OUT" 2>/dev/null || true)"
  if [ -n "$DAEMON_PID" ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
  fi
  echo "E2E SMOKE TEST: FAIL (Flag passed: $PASSED, Incident passed: $INCIDENT_PASSED, Guard passed: $GUARD_PASSED, Webhook passed: $WEBHOOK_PASSED, Enroll passed: $ENROLL_PASSED, SSE passed: $SSE_PASSED, Console passed: $CONSOLE_PASSED, Advisor passed: $ADVISOR_PASSED, Operator passed: $OPERATOR_PASSED)"
  echo "DEBUG SSE STREAM: $SSE_BODY"
  exit 1
fi
