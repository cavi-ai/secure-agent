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
    # Repo coverage is judged on the LIVE build's sessions only: the startup
    # repair pass re-resolves older rows, but rows started before this boot
    # still reflect whatever their original resolver saw at ingest time.
    scope="datetime(started_at) > datetime('now', '-' || $uptime_s || ' seconds')"
    ws_sessions="$(q "select count(*) from sessions where $scope and harness != '' and workspace like '/Volumes/Work/workspace/%';")"
    with_repo="$(q "select count(*) from sessions where $scope and harness != '' and workspace like '/Volumes/Work/workspace/%' and repo != '';")"
    if [ "${ws_sessions:-0}" -eq 0 ]; then
      ok "session repo coverage (no workspace-backed sessions since boot)"
    else
      repo_share=$((100 * with_repo / ws_sessions))
      if [ "$repo_share" -ge 50 ]; then
        ok "session repo coverage ($with_repo/$ws_sessions = ${repo_share}% since boot)"
      else
        bad "session repo coverage" "$with_repo of $ws_sessions = ${repo_share}% since boot (want >= 50%)"
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
# human prompts in Claude transcripts touched in the same window. Both sides
# are scoped to the CURRENT daemon's uptime (capped at 16h): files already
# known to the tailer are seeded to EOF at boot, so their pre-boot prompts
# can never produce turns — a wider prompt window only measures the previous
# binary. Files are passed as ARGV (xargs); fileinput opens each — the
# earlier stdin read never saw the files, so the assertion was dead.
win_s="$uptime_s"
[ "$win_s" -gt 57600 ] && win_s=57600
prompt_minutes=$(( (win_s + 59) / 60 ))
boot_epoch=$(( $(date +%s) - uptime_s ))
turns="$(q "select count(*) from events where kind = 13 and datetime(ts) > datetime('now', '-' || $win_s || ' seconds');")"
prompts=0
claude_dir="$HOME/.claude/projects"
if [ -d "$claude_dir" ]; then
  # File mtime is only a pre-filter: a transcript touched after boot still
  # holds pre-boot prompt lines, and the daemon seeds files to EOF at boot —
  # those records can never produce turns. The floor counts only prompt
  # records timestamped at/after the daemon's boot.
  prompts=$(find "$claude_dir" -name '*.jsonl' -mmin -"$prompt_minutes" -print0 2>/dev/null |
    xargs -0 -n 32 env BOOT_EPOCH="$boot_epoch" python3 -c '
import json,sys,fileinput,datetime,os
boot=datetime.datetime.fromtimestamp(int(os.environ["BOOT_EPOCH"]), datetime.timezone.utc)
seen=0
for line in fileinput.input(files=sys.argv[1:]):
    line=line.strip()
    if not line.startswith("{"): continue
    try: rec=json.loads(line)
    except Exception: continue
    if rec.get("type")!="user" or rec.get("isMeta") or rec.get("isSidechain"): continue
    ts=rec.get("timestamp")
    if ts:
        try: rt=datetime.datetime.fromisoformat(ts.replace("Z","+00:00"))
        except Exception: rt=None
        if rt is not None and rt < boot: continue
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
if [ "$grace" = 0 ] || [ "${prompts:-0}" -eq 0 ]; then
  ok "turn ratio (grace/no prompts — not asserted)"
elif [ "${turns:-0}" -ge $((prompts * 8 / 10)) ]; then
  ok "turn ratio ($turns turns vs $prompts prompts)"
else
  bad "turn ratio" "$turns turns vs $prompts human prompts (want >= 80%)"
fi

# ---- 4. Session flood control: created-per-hour vs agent roots ----
if [ "$grace" = 1 ] && [ "$agents" -gt 0 ]; then
  recent="$(q "select count(*) from sessions where datetime(started_at) > datetime('now', '-1 hour');")"
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

# ---- 6. Guard hook ACTIVITY, not registration ----
# Registration in settings.json proves nothing: a registered hook can still
# stay silent for days. With agents active past the boot grace, the guard
# must have produced plugin actions.
hook_events="$(q "select count(*) from events where kind = 8 and datetime(ts) > datetime('now', '-1 hour');")"
if [ "$active_agents" -eq 0 ] || [ "$grace" = 0 ]; then
  ok "guard hook activity (no agents active / boot grace — not asserted)"
elif [ "${hook_events:-0}" -gt 0 ]; then
  ok "guard hook activity ($hook_events hook events in the last hour)"
else
  bad "guard hook activity" "0 hook events in the last hour with $active_agents agents active — hook registered but silent?"
fi

# ---- 7. Snapshot size: /resources must stay small ----
res_bytes="$(curl -s --max-time 5 --unix-socket "$SOCK" http://unix/resources 2>/dev/null | wc -c | tr -d ' ')"
if [ "${res_bytes:-0}" -gt 0 ] && [ "${res_bytes:-0}" -lt 400000 ]; then
  ok "/resources is small (${res_bytes} bytes)"
else
  bad "/resources is small" "${res_bytes} bytes (want < 400000)"
fi

# ---- 8. Root ES service state: honest, not tailer-green ----
# Parse with a heredoc: the old one-liner interpolated ['es_service'] into the
# python source, where the single quotes terminated its string literals — every
# probe read as "absent" even with es_service present.
es_status="$(python3 - "$status" <<'PY'
import json,sys
try:
    d=json.loads(sys.argv[1])
    print((d.get("es_service") or {}).get("state") or "absent")
except Exception:
    print("absent")
PY
)"
if [ "$es_status" = "absent" ]; then
  ok "ES service state (not spool-based, nothing to probe)"
elif [ "$es_status" = "not-loaded" ]; then
  bad "ES service state" "daemon is spool-based but the root service is not loaded"
elif echo "$es_status" | grep -qE "spawn|exit"; then
  bad "ES service state" "root service reports: $es_status"
else
  ok "ES service state ($es_status)"
fi

echo
echo "${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ] || exit 1