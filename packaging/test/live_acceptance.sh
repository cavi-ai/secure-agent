#!/usr/bin/env bash
# Live acceptance: assert the running daemon's data is CORRECT, not merely that
# it is up. v2 asserts RATIOS, not presence: the v1 gate printed 9/9 PASS on a
# machine with four known data defects (turns 1-of-20, sessions flooding,
# repo on 1-of-1667 rows, a crash-looping root service invisible to the
# monitor) because every assertion only checked that rows existed.
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

echo "live acceptance v2 (sock=$SOCK db=$DB)"

# ---- socket is answering ----
status="$(curl -s --max-time 3 --unix-socket "$SOCK" http://unix/status 2>/dev/null || true)"
if [ -z "$status" ]; then
  bad "daemon reachable" "no answer on $SOCK"
  echo; echo "BLOCKED: daemon not reachable"; exit 2
fi
ok "daemon reachable"

json() { python3 -c "import json,sys;d=json.load(sys.stdin);print(eval('d'+'$1'))" 2>/dev/null; }
q() { sqlite3 "$DB" "$1" 2>/dev/null; }

# Parsed ONCE, safely: v1 shelled eval() on the whole /status per field and
# the `agents` parse returned a string, so the hook assertion skipped on
# "no agents active" while active_agents was 25.
agents=0; infra=0; uptime_s=0
eval "$(echo "$status" | python3 -c "
import json,sys,re
d=json.load(sys.stdin)
print('agents=%d' % d.get('active_agents', 0))
print('infra=%d' % d.get('infra_count', 0))
u=d.get('uptime','0s')
m=re.match(r'(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?', u or '')
h=int(m.group(1) or 0); mi=int(m.group(2) or 0); s=int(m.group(3) or 0)
print('uptime_s=%d' % (h*3600+mi*60+s))
" 2>/dev/null || echo 'agents=0; infra=0; uptime_s=0')"

active_agents="$agents"  # compat name for the hook check below

# Grace: the boot window in which coverage signals legitimately have no data.
# All ratio assertions skip (count as pass-with-note) while uptime < 10 min.
grace=0
[ "$uptime_s" -ge 600 ] && grace=1

# ---- 1. Session identity: harness names + repo coverage ----
# Resolution reads .git at resolve time. Both asserted as ratios, not presence.
total_sessions="$(q 'select count(*) from sessions;')"
named="$(q "select count(*) from sessions where harness != '';")"
if [ "$grace" = 1 ]; then
  if [ "${total_sessions:-0}" -eq 0 ]; then
    ok "session identity (no sessions yet)"
  else
    share=$((100 * named / total_sessions))
    if [ "$share" -ge 80 ]; then
      ok "sessions carry a harness ($named/$total_sessions = ${share}%)"
    else
      bad "sessions carry a harness" "$named of $total_sessions = ${share}% (want >= 80%)"
    fi
    ws_sessions="$(q "select count(*) from sessions where harness != '' and workspace like '/Volumes/Work/workspace/%';")"
    with_repo="$(q "select count(*) from sessions where harness != '' and workspace like '/Volumes/Work/workspace/%' and repo != '';")"
    if [ "${ws_sessions:-0}" -eq 0 ]; then
      ok "session repo coverage (no workspace-backed sessions yet)"
    else
      repo_share=$((100 * with_repo / ws_sessions))
      if [ "$repo_share" -ge 50 ]; then
        ok "session repo coverage ($with_repo/$ws_sessions = ${repo_share}%)"
      else
        bad "session repo coverage" "$with_repo of $ws_sessions = ${repo_share}% (want >= 50%)"
      fi
    fi
  fi
else
  ok "session repo coverage (skipped inside 10-min boot grace)"
fi

# ---- 2. Tool-call pairing ----
dupes="$(q "select count(*) from (select session_id, call_id, count(*) c from events where call_id is not null and call_id != '' group by session_id, call_id having c > 1);")"
if [ "${dupes:-0}" -eq 0 ]; then
  ok "no duplicate tool-call rows"
else
  bad "no duplicate tool-call rows" "$dupes (session,call_id) pairs stored more than once"
fi

# No id-less tool rows from the LIVE build: agy/Cursor mint synthetic ids now.
# Scoped to the daemon's current uptime — legacy id-less rows predate the fix
# and cannot be re-paired retroactively (their real tool ids are unrecoverable).
# uptime_s is known-good here (parsed above, before the boot-grace branch).
idless="$(q "select count(*) from events where kind = 12 and datetime(ts) > datetime('now', '-' || $uptime_s || ' seconds') and (call_id is null or call_id = '');")"
if [ "${idless:-0}" -eq 0 ]; then
  ok "no id-less tool-call rows"
else
  bad "no id-less tool-call rows" "$idless rows with empty call_id (pairing impossible)"
fi

# ---- 3. Turn ratio vs human prompts ----
# v1 passed on "turns > 0". v2 compares turns against the floor count of
# human prompts in Claude transcripts touched in the last 16h. Files are
# passed as ARGV (xargs); fileinput opens each — the earlier stdin read
# never saw the files, so the assertion was dead.
turns="$(q "select count(*) from events where kind = 13;")"
turns_win="$(q "select count(*) from events where kind = 13 and ts > datetime('now', '-16 hours');")"
prompts=0
prompt_minutes=960
claude_dir="$HOME/.claude/projects"
if [ -d "$claude_dir" ]; then
  # Window matches the DB-side turn window (16h), not raw file age: old-build
  # transcripts outside the window would inflate the floor while their turns
  # were pruned, making the ratio asymmetric.
  prompts=$(find "$claude_dir" -name '*.jsonl' -mmin -960 -print0 2>/dev/null |
    xargs -0 -n 32 python3 -c '
import json,sys,fileinput
seen=0
for line in fileinput.input(files=sys.argv[1:]):
    line=line.strip()
    if not line.startswith("{"): continue
    try: rec=json.loads(line)
    except Exception: continue
    if rec.get("type")!="user" or rec.get("isMeta") or rec.get("isSidechain"): continue
    c=rec.get("message",{}).get("content")
    texts=[]
    if isinstance(c,str): texts=[c]
    elif isinstance(c,list): texts=[b.get("text","") for b in c if isinstance(b,dict) and b.get("type")=="text"]
    for t in texts:
        t=t.strip()
        if not t: continue
        if t.startswith(("<task-notification>","<system-reminder>","<command-name>","<local-command")): continue
        seen+=1; break
print(seen)
' 2>/dev/null | awk '{s+=$1} END {print s+0}')
fi
turns="$turns_win"
if [ "$grace" = 0 ] || [ "${prompts:-0}" -eq 0 ]; then
  ok "turn ratio (grace/no prompts — not asserted)"
elif [ "${turns:-0}" -ge $((prompts * 8 / 10)) ]; then
  ok "turn ratio ($turns turns vs $prompts prompts)"
else
  bad "turn ratio" "$turns turns vs $prompts human prompts (want >= 80%)"
fi

# ---- 4. Session flood control: created-per-hour vs agent roots ----
if [ "$grace" = 1 ] && [ "$agents" -gt 0 ]; then
  recent="$(q "select count(*) from sessions where started_at > datetime('now', '-1 hour');")"
  budget=$((agents * 2 + 10))
  if [ "${recent:-0}" -le "$budget" ]; then
    ok "session creation rate ($recent/h <= $budget)"
  else
    bad "session creation rate" "$recent sessions in the last hour > $budget (stub flood)"
  fi
else
  ok "session creation rate (skipped: grace or no agents)"
fi

# ---- 5. Cost: priced claude calls (ratio, not presence) ----
priced="$(q "select count(*) from events where kind=14 and model like 'claude-%' and cost_usd is not null and cost_usd > 0;")"
unknown="$(q "select count(*) from events where kind=14 and model like 'claude-%' and (cost_usd is null or cost_usd = 0);")"
claude_calls=$((priced + unknown))
if [ "${claude_calls:-0}" -eq 0 ]; then
  ok "claude model calls are priced (no claude calls yet)"
else
  price_share=$((100 * priced / claude_calls))
  if [ "$price_share" -ge 90 ]; then
    ok "claude model calls are priced ($priced/$claude_calls = ${price_share}%)"
  else
    bad "claude model calls are priced" "$priced of $claude_calls = ${price_share}% (want >= 90%)"
  fi
fi

# ---- 6. Guard hook registration: ratio, not skip ----
if [ "$active_agents" -gt 0 ]; then
  if python3 - <<'PY'
import json,os,sys
p=os.path.expanduser("~/.claude/settings.json")
try: d=json.load(open(p))
except Exception: sys.exit(1)
h=d.get("hooks",{})
def has(e): return any("secret_guard.py" in hk.get("command","") for g in h.get(e,[]) for hk in g.get("hooks",[]))
sys.exit(0 if has("PreToolUse") and has("PostToolUse") else 1)
PY
  then ok "claude guard hook registered"; else bad "claude guard hook registered" "settings.json has no guard hook with $active_agents agents active"; fi
else
  ok "claude guard hook registered (no agents active, not required)"
fi

# ---- 7. Snapshot size: /resources must stay small ----
res_bytes="$(curl -s --max-time 5 --unix-socket "$SOCK" http://unix/resources 2>/dev/null | wc -c | tr -d ' ')"
if [ "${res_bytes:-0}" -gt 0 ] && [ "${res_bytes:-0}" -lt 400000 ]; then
  ok "/resources is small (${res_bytes} bytes)"
else
  bad "/resources is small" "${res_bytes} bytes (want < 400000)"
fi

# ---- 8. Root ES service state: honest, not tailer-green ----
es_status="$(echo "$status" | json "['es_service']['state']" 2>/dev/null || echo absent)"
if [ "$es_status" = "absent" ]; then
  ok "ES service state (not spool-based, nothing to probe)"
elif echo "$es_status" | grep -qE "spawn|exit"; then
  bad "ES service state" "root service reports: $es_status"
else
  ok "ES service state ($es_status)"
fi

echo
echo "${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ] || exit 1