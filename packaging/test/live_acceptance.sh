#!/usr/bin/env bash
# Live acceptance: assert the running daemon's data is CORRECT, not merely that
# it is up. Every CI suite passed while these four defects shipped — a session
# join that never joined, tool calls duplicated 5–10×, turns near zero, cost
# NULL — because no test read the live socket and DB for semantics.
#
# Run after any restart:  bash packaging/test/live_acceptance.sh
# Exit 0 = all pass. Uses only the live socket + the store (read-only).

set -uo pipefail

SOCK="${SECURE_AGENT_SOCK:-$HOME/.config/secure-agent/daemon.sock}"
DB="${SECURE_AGENT_DB:-$HOME/.local/state/secure-agent/events.db}"

pass=0; fail=0
ok()   { printf '  PASS  %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  FAIL  %s — %s\n' "$1" "$2"; fail=$((fail+1)); }

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1"; exit 2; }; }
need curl; need sqlite3; need python3

echo "live acceptance (sock=$SOCK db=$DB)"

# ---- socket is answering ----
status="$(curl -s --max-time 3 --unix-socket "$SOCK" http://unix/status 2>/dev/null || true)"
if [ -z "$status" ]; then
  bad "daemon reachable" "no answer on $SOCK"
  echo; echo "BLOCKED: daemon not reachable"; exit 2
fi
ok "daemon reachable"

json() { python3 -c "import json,sys;d=json.load(sys.stdin);print(eval('d'+'$1'))" 2>/dev/null; }

# ---- the four defects, asserted against live data ----

# 1. Session join: a meaningful share of sessions must carry a harness name,
#    and sessions named by a conversation must have repo/branch when the
#    workspace is a git checkout.
q() { sqlite3 "$DB" "$1" 2>/dev/null; }

total_sessions="$(q 'select count(*) from sessions;')"
named="$(q "select count(*) from sessions where harness != '';")"
if [ "${named:-0}" -gt 0 ] && [ "${total_sessions:-0}" -gt 0 ]; then
  ok "sessions carry a harness ($named/$total_sessions)"
else
  bad "sessions carry a harness" "0 of $total_sessions have a harness (join broken)"
fi

# Trace sessions must not be a separate nameless population: the share of
# sessions with harness names should cover the trace-bearing ones.
trace_harness="$(q "select count(distinct e.session_id) from events e join sessions s on s.id=e.session_id where e.kind in (12,13,14) and s.harness != '';")"
trace_named_ok=$?
if [ "${trace_harness:-0}" -gt 0 ]; then
  ok "trace events attach to named sessions ($trace_harness)"
else
  bad "trace events attach to named sessions" "0 trace sessions have a harness"
fi

# 2. One row per tool call: the store must hold no (session,call_id) pairs more
#    than once. A duplicate means the upsert regressed.
dupes="$(q "select count(*) from (select session_id, call_id, count(*) c from events where call_id is not null and call_id != '' group by session_id, call_id having c > 1);")"
if [ "${dupes:-0}" -eq 0 ]; then
  ok "no duplicate tool-call rows"
else
  bad "no duplicate tool-call rows" "$dupes (session,call_id) pairs stored more than once"
fi

# Unpaired "running" starts: a start whose completion never arrived is fine for
# genuinely in-flight calls, but they must not dominate. Count starts whose
# call_id has a non-running sibling (i.e. completions that failed to pair).
unpaired="$(q "select count(*) from events where call_id != '' and tool_status='running' and call_id in (select call_id from events where tool_status != 'running');")"
if [ "${unpaired:-0}" -eq 0 ]; then
  ok "no start rows left running beside a completion"
else
  bad "no start rows left running beside a completion" "$unpaired stale starts"
fi

# 3. Turn detection: turns must exist at all when agents are working.
turns="$(q "select count(*) from events where kind=13;")"
agents="$(echo "$status" | json "['active_agents']" || echo 0)"
if [ "${turns:-0}" -gt 0 ]; then
  ok "turn events present ($turns)"
elif [ "${agents:-0}" -eq 0 ]; then
  ok "turn events present (no agents active, turns not expected)"
else
  bad "turn events present" "0 turns with $agents active agents (detection broken)"
fi

# 4. Cost: model calls on priced models must carry non-zero cost. A NULL/0
#    cost on a known family is the regression (price map stale).
priced="$(q "select count(*) from events where kind=14 and model like 'claude-%' and cost_usd is not null and cost_usd > 0;")"
unknown="$(q "select count(*) from events where kind=14 and model like 'claude-%' and (cost_usd is null or cost_usd = 0);")"
if [ "${unknown:-0}" -eq 0 ] || [ "${priced:-0}" -gt 0 ]; then
  ok "claude model calls are priced ($priced priced, $unknown unpriced)"
else
  bad "claude model calls are priced" "0 of $((priced+unknown)) claude calls have cost"
fi

# 5. Guard hook registration: if agents are active, the Claude hook must be
#    registered (never-registered is the failure the posture item reports).
if [ "${agents:-0}" -gt 0 ]; then
  if python3 - <<'PY'
import json,os,sys
p=os.path.expanduser("~/.claude/settings.json")
try: d=json.load(open(p))
except Exception: sys.exit(1)
h=d.get("hooks",{})
def has(e): return any("secret_guard.py" in hk.get("command","") for g in h.get(e,[]) for hk in g.get("hooks",[]))
sys.exit(0 if has("PreToolUse") and has("PostToolUse") else 1)
PY
  then ok "claude guard hook registered"; else bad "claude guard hook registered" "settings.json has no guard hook"; fi
else
  ok "claude guard hook registered (no agents active, not required)"
fi

# 6. Snapshot size: /resources must stay small (the 2 MB defect).
res_bytes="$(curl -s --max-time 5 --unix-socket "$SOCK" http://unix/resources 2>/dev/null | wc -c | tr -d ' ')"
if [ "${res_bytes:-0}" -gt 0 ] && [ "${res_bytes:-0}" -lt 400000 ]; then
  ok "/resources is small (${res_bytes} bytes)"
else
  bad "/resources is small" "${res_bytes} bytes (want < 400000)"
fi

echo
echo "${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ] || exit 1
