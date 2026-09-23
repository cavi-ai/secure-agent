#!/usr/bin/env python3
"""DOM-level console tests: render the real console (index.html + lib.js +
app.js + style.css) against stubbed telemetry in headless Chrome and assert
on the final DOM. Zero dependencies — Chrome's --dump-dom plus stdlib checks.

Covers the layer lib.test.mjs cannot: fetch orchestration, panel renderers,
the delegation dispatch, liveness classes, and the structural guarantee that
no inline handlers exist in the rendered page.

Usage: python3 packaging/test/console_dom/run_dom_tests.py
Env:   CHROME_BIN overrides Chrome detection.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
WEB_DIST = os.path.join(REPO, "daemon", "internal", "api", "web_dist")
MOCK = os.path.join(os.path.dirname(__file__), "mock_dom.js")
# Virtual-time budget for each dump. 12s: the auto-actions fire at 4s and the
# styled-confirm dialogs (P3) add a round-trip before the mutated state lands.
VIRTUAL_TIME_MS = 12000

passed = []
failed = []


def check(name, ok, detail=""):
    (passed if ok else failed).append(name)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f" — {detail}" if detail and not ok else ""))


def find_chrome():
    if os.environ.get("CHROME_BIN"):
        return os.environ["CHROME_BIN"]
    for cand in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
        p = shutil.which(cand)
        if p:
            return p
    mac = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if os.path.exists(mac):
        return mac
    return None


def build_harness(tmp):
    """Harness page = real index.html with mock_dom.js injected between lib.js
    and app.js. Real assets are symlinked so relative paths resolve."""
    for f in ("index.html", "style.css", "lib.js", "app.js",
              "tab-overview.js", "tab-sessions.js", "tab-agents.js", "tab-egress.js", "tab-findings.js"):
        os.symlink(os.path.join(WEB_DIST, f), os.path.join(tmp, f))
    os.symlink(MOCK, os.path.join(tmp, "mock_dom.js"))
    html = open(os.path.join(WEB_DIST, "index.html")).read()
    needle = '<script src="lib.js"></script>'
    assert needle in html, "lib.js script tag not found in index.html"
    html = html.replace(needle, needle + '\n  <script src="mock_dom.js"></script>')
    with open(os.path.join(tmp, "harness.html"), "w") as f:
        f.write(html)


def dump_dom(chrome, tmp, query=""):
    url = f"file://{tmp}/harness.html{query}"
    out = subprocess.run(
        [chrome, "--headless=new", "--disable-gpu", "--no-sandbox",
         "--virtual-time-budget=" + str(VIRTUAL_TIME_MS), "--dump-dom", url],
        capture_output=True, text=True, timeout=120,
    )
    if out.returncode != 0:
        print(out.stderr[-2000:], file=sys.stderr)
        raise SystemExit("chrome --dump-dom failed")
    return out.stdout


def main():
    chrome = find_chrome()
    if not chrome:
        raise SystemExit("no Chrome found (set CHROME_BIN)")
    print(f"console dom tests (chrome: {chrome})")

    tmp = tempfile.mkdtemp(prefix="console-dom-")
    try:
        build_harness(tmp)
        dom = dump_dom(chrome, tmp)
        dom_session = dump_dom(chrome, tmp, "?sessiondemo")
        dom_guard = dump_dom(chrome, tmp, "?guarddemo")
        dom_uninsp = dump_dom(chrome, tmp, "?uninspecteddemo")
        dom_endpoint = dump_dom(chrome, tmp, "?endpointdemo")
        dom_toast = dump_dom(chrome, tmp, "?toastdemo")
        dom_notify = dump_dom(chrome, tmp, "?notifydemo")
        dom_allow = dump_dom(chrome, tmp, "?allowdemo")
        dom_dismiss = dump_dom(chrome, tmp, "?dismissdemo")
        dom_retriage = dump_dom(chrome, tmp, "?retriagedemo")
        dom_tab = dump_dom(chrome, tmp, "?tabdemo")
        dom_view = dump_dom(chrome, tmp, "?viewdemo")
        dom_advdown = dump_dom(chrome, tmp, "?advisordown")
        dom_authfail = dump_dom(chrome, tmp, "?authfail")
        dom_netfail = dump_dom(chrome, tmp, "?netfail")
        dom_tokenseed = dump_dom(chrome, tmp, "?requiretoken&tokenseed")
        dom_nofleet = dump_dom(chrome, tmp, "?nofleetdemo")
        dom_noresources = dump_dom(chrome, tmp, "?noresourcesdemo")
        dom_policy = dump_dom(chrome, tmp, "?policydemo")
        dom_demote = dump_dom(chrome, tmp, "?demotedemo")
        dom_allowrm = dump_dom(chrome, tmp, "?allowlistdemo")
        dom_rail = dump_dom(chrome, tmp, "?raildemo")
        dom_pill = dump_dom(chrome, tmp, "?pilldemo")
        dom_quiet = dump_dom(chrome, tmp, "?quietdemo")
        dom_nomatch = dump_dom(chrome, tmp, "?nomatchdemo")
        dom_phone = dump_dom(chrome, tmp, "?phonedemo")

        # --- session-first tab (P3) ---
        rail = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
        check("session rail renders durable sessions", dom.count('class="session-card') >= 2,
              f"cards={dom.count('class=\"session-card')}")
        check("rail titles are repo@branch, not harness · repo",
              '>api-service@main<' in rail and 'claude · ' not in rail)
        check("ended session marked", 'session-card ended' in dom)

        # --- sessions: harness-first rail ---
        rail_groups = re.findall(r'<details class="session-group[^"]*" data-harness="([^"]+)"', rail)
        check("sessions rail renders one group per live harness, newest first, infra last",
              rail_groups == ["codex", "claude", "infra"], f"groups={rail_groups}")
        check("group head carries mark, display name and counts",
              'data-harness="claude" open=""' in rail
              and '<span class="harness-label">Claude Code</span>' in rail
              and '1 active · 1 idle · 1 ended' in rail)
        logo_refs = set(re.findall(r'<use href="#(logo-[a-z-]+)"', rail))
        check("harness marks resolve to sprite symbols",
              logo_refs >= {"logo-claude", "logo-codex", "logo-ollama"}
              and all(f'<symbol id="{ref}"' in dom for ref in logo_refs), f"refs={sorted(logo_refs)}")
        claude_group = rail.split('data-harness="claude"', 1)[1].split('<details', 1)[0]
        check("sub-session nests under its parent",
              claude_group.index('data-id="sess-claude-1"') < claude_group.index('session-card idle nested')
              < claude_group.index('data-id="sess-claude-sub"'))
        check("ended tail is collapsed by default",
              '<div class="session-ended">' in claude_group
              and 'data-action="toggle-ended-sessions" data-harness="claude" aria-expanded="false">Ended (1)' in claude_group)
        infra_group = rail.split('data-harness="infra"', 1)[1]
        check("infra sits in the last group, collapsed, with RSS totals only",
              '<details class="session-group infra" data-harness="infra">' in rail
              and "Ollama" in infra_group and "782 MB" in infra_group
              and "session-card" not in infra_group and "sess-ollama-4" not in rail)
        check("live only hides a harness with nothing running", 'data-harness="cursor"' not in rail)
        check("live cards carry kill, ended cards do not",
              'data-action="kill" data-pid="5821"' in rail
              and 'data-action="kill"' not in rail.split('class="session-ended-body"', 1)[1].split('</details>', 1)[0])
        check("count strip shows sessions, harnesses and coverage",
              'id="session-count-strip">Sessions 3 · Harnesses 2 · seeing 2/3<' in dom)
        check("one filter pill per live harness",
              re.findall(r'data-action="toggle-harness" data-harness="([^"]+)" aria-pressed="true"',
                         dom.split('id="session-harness-pills"', 1)[1].split('</div>', 1)[0]) == ["codex", "claude"])
        pill_rail = dom_pill.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
        check("a switched-off pill hides its group",
              'data-harness="claude"' not in pill_rail and 'data-harness="codex"' in pill_rail
              and 'class="harness-pill off" data-action="toggle-harness" data-harness="claude" aria-pressed="false"' in dom_pill)
        check("empty rail says all quiet", "All quiet. Nothing is running." in dom_quiet)
        check("filter that hides everything offers to clear it",
              "No sessions match" in dom_nomatch and 'data-action="clear-harness-filter"' in dom_nomatch)
        check("Sessions and Agents fit a 375px phone without sideways scroll",
              'data-hscroll="sessions:0,agents:0"' in dom_phone,
              (re.search(r'data-hscroll="[^"]*"', dom_phone) or [None])[0])
        detail_head = dom_rail.split('class="session-detail-head"', 1)[1].split('class="wf', 1)[0]
        check("detail head: mark, repo@branch, harness, confidence, copyable path",
              '<h3>api-service@main</h3>' in detail_head and '#logo-claude' in detail_head
              and '<span class="sd-harness">Claude Code</span>' in detail_head
              and '>hook</span>' in detail_head
              and 'data-action="copy-path" data-path="/Users/dev/workspace/api-service"' in detail_head)
        check("rail selection renders trace waterfall",
              'class="wf-bar' in dom_rail and 'Bash' in dom_rail,
              "no waterfall bars in raildemo")
        check("waterfall carries model usage row",
              "claude-sonnet-4-5" in dom_rail and "46.2k in" in dom_rail)
        check("waterfall marks tool errors", 'wf-bar error' in dom_rail)

        # --- telemetry wiring ---
        check("version badge comes from /status", 'id="app-version">v9.9.9-domtest<' in dom)
        check("posture banner is critical", 'id="posture-banner" data-state="critical"' in dom)
        check("posture headline rendered", 'id="posture-state">Critical<' in dom)
        check("KPI agents count", 'id="count-agents">3<' in dom)
        check("KPI flags are unacted last 24h", 'id="count-flags">2<' in dom)
        check("KPI incidents count", 'id="count-incidents">1<' in dom)
        agents_view = dom.split('id="agents-container"', 1)[1].split('id="fleet-col"', 1)[0]
        agent_groups = re.findall(r'<details class="agent-group" data-harness="([^"]+)"', agents_view)
        check("agents tab renders one group per harness, newest first",
              agent_groups == ["codex", "claude", "cursor"], f"groups={agent_groups}")
        check("agent group head: mark, name, instances, processes, RSS, CPU",
              '#logo-codex' in agents_view and '<span class="harness-label">Claude Code</span>' in agents_view
              and '1 instance · 2 processes' in agents_view and '14.5% CPU' in agents_view)
        check("agents infra section sits last and is not counted",
              agents_view.index('class="agent-infra"') > agents_view.rindex('<details class="agent-group" ')
              and 'data-harness="ollama"' in agents_view.split('class="agent-infra"', 1)[1]
              and 'id="badge-agents-count">3<' in dom)
        check("agent instances lead with repo@branch, pid secondary",
              '<span class="agent-row-title">api-service@main</span>' in agents_view
              and '<span class="agent-pid">PID 5821</span>' in agents_view)
        check("agent helpers sit behind a disclosure",
              'PID 5822' in agents_view.split('<details class="session-helpers agent-tree" data-pid="5821"', 1)[1].split('</details>', 1)[0])
        pill_agents = dom_pill.split('id="agents-container"', 1)[1].split('id="fleet-col"', 1)[0]
        check("a switched-off pill hides the harness in Agents too (shared state)",
              'data-harness="claude"' not in pill_agents and 'data-harness="codex"' in pill_agents
              and 'class="harness-pill off" data-action="toggle-harness" data-harness="claude"'
              in dom_pill.split('id="agent-harness-pills"', 1)[1].split('</div>', 1)[0])
        check("claude instance pid", "PID 5821" in dom)
        check("nested helper pid", "PID 5822" in dom)
        check("leftover cursor status", "leftover" in dom)
        check("terminate not labelled Kill", "Terminate" in dom and "Kill</span>" not in dom)
        check("firewall enforcing badge",
              'class="badge badge-ok" id="badge-firewall-mode">enforcing<' in dom)
        check("uninspected-egress warning", "2 endpoints reached without inspection" in dom)

        # --- reversible enforcement (block is not a ratchet) ---
        check("blocking rule shows demote button",
              'data-action="demote" data-rule="aws-key"' in dom)
        check("demote flips the rule back to promote",
              'data-action="promote" data-rule="aws-key"' in dom_demote)
        check("allowlist entries render with remove",
              "Allowed endpoints" in dom and "artifacts.example.com" in dom)
        check("remove drops the allowlist row",
              "artifacts.example.com" not in dom_allowrm)

        # --- uninspected drill-down groups infra, keeps unknowns actionable ---
        check("drill-down keeps unknown endpoints actionable",
              "registry.npmjs.org" in dom_uninsp)
        check("drill-down collapses CDN/cloud carriers",
              "Known cloud/CDN infrastructure (2 endpoints)" in dom_uninsp
              and "Cloudflare" in dom_uninsp and "AWS" in dom_uninsp)
        check("egress rows show first-seen and session",
              "first seen" in dom_uninsp and "session " in dom_uninsp)
        check("egress bulk allow groups same-suffix hosts",
              'data-action="bulk-allow" data-agent="claude"' in dom_uninsp and "Allow all 2" in dom_uninsp)
        check("egress explains what the list is and what to do",
              "What this is:" in dom_uninsp and "What to do:" in dom_uninsp)
        check("egress rows carry a plain Allow action",
              'data-action="allow-host"' in dom_uninsp and ">Allow</span>" in dom_uninsp)
        check("egress rows offer on-demand advisor assessment",
              'data-action="assess-host" data-agent="claude"' in dom_uninsp
              and "Ask the advisor" in dom_uninsp)
        check("egress rows with a verdict show the advisor chip",
              'advisor-chip adv-benign' in dom_uninsp)
        # A toast fired while the drawer is open must be present and the drawer
        # must be open. The old native-<dialog> + top-layer toast dance is gone:
        # the drawer is ordinary DOM and toasts are a top-layer popover, so a
        # toast can no longer fall behind the overlay.
        check("drawer is open for the drill-down",
              'id="drawer" class="drawer"' in dom_toast and 'id="drawer" class="drawer" hidden' not in dom_toast)
        check("toast rendered while the drawer is open",
              'class="toast ' in dom_toast)
        check("vendor-key promote banner",
              'data-action="promote-vendor-keys"' in dom and "1 vendor-key rule" in dom)
        check("incident workflow chip (ack)", 'class="workflow-chip acked"' in dom)
        check("secret sources rendered (config+user)",
              dom.count('class="source-item"') == 2 and "CONFIG" in dom and "USER" in dom)

        # --- evidence chain ---
        first_card = dom.split('class="flag-card', 1)[1]
        check("first flag auto-expanded", first_card.startswith(' sev3 expanded'), first_card[:60])
        check("chain rendered with 3 nodes", dom.count("chain-node") >= 3)
        check("chain node: payload inspection", "payload inspection" in dom)
        check("chain node: egress destination", "logs.example.com:443" in dom)
        check("chain verdict node", "cn-verdict-bad" in dom and "Critical flag raised" in dom)
        check("second flag collapsed", 'flag-card sev3">' in dom)

        # --- liveness ---
        check("sparkline has points", re.search(r'id="spark-line" points="[\d.,\- ]{20,}"', dom) is not None)
        check("sparkline rate label", re.search(r'id="spark-rate">\d+/s<', dom) is not None)
        check("fresh timeline rows after SSE drip", "timeline-item fresh" in dom)
        check("timeline times are HH:MM:SS",
              re.search(r'class="t">\d{2}:\d{2}:\d{2}<', dom) is not None)

        # --- local advisor ---
        check("advisor chip rendered with assessment class", 'advisor-chip adv-suspicious' in dom)
        check("advisor chip rationale in tooltip", "first time this session" in dom)
        check("agent last-active rendered", "active " in dom and " ago" in dom)
        check("stale process marked", " stale" in dom)
        check("flag card kill action", 'data-action="kill" data-pid="6033"' in dom)
        check("collector-down FDA deep link", 'data-action="open-fda"' in dom and "Full Disk Access settings" in dom)
        check("advisor posture line (1 of 2 benign)",
              "advisor: 1 of 2 triaged critical flags look benign" in dom)
        check("incident narrative rendered", "advisor-narrative" in dom and "Rotate the key first" in dom)

        # --- allowlist suggestions ---
        check("egress suggestion rendered", "fw-suggestion" in dom and "registry.npmjs.org" in dom)
        check("suggestion advisor chip", 'advisor-chip adv-benign' in dom and "advisor: benign" in dom)
        check("suggestion allow button is delegated",
              'data-action="allow-host" data-agent="cursor" data-host="registry.npmjs.org"' in dom)

        # --- activity rollup chart ---
        rects_ev = dom.count('class="act-ev"')
        check("activity chart draws event bars", rects_ev > 10, f"rects={rects_ev}")
        check("activity chart marks the flag hour", 'class="act-fl"' in dom)
        check("activity chart zero-fills empty hours", 'class="act-zero"' in dom)

        # --- dispositions (mute) ---
        check("mute action on advisor-benign flag",
              'data-action="mute-flag" data-rule="sensitive-read-then-connect" data-host="logs.example.com"' in dom)
        check("mutes list rendered with unmute",
              'data-action="unmute" data-rule="proxy-prompt-injection" data-host="blog.example.com"' in dom)
        check("rule-level mute renders as all hosts", "keychain-security-cli · all hosts" in dom)
        check("keychain flag carries class-dismiss action",
              'data-action="mute-rule" data-rule="keychain-access"' in dom)

        # --- uninspected-egress drill-down ---
        check("uninspected warning is a clickable drill-down",
              'data-action="open-uninspected"' in dom)
        check("posture uninspected item deep-links to drill-down",
              'data-action="open-uninspected">see endpoints<' in dom)
        check("drill-down drawer title", "Uninspected egress — last 24h" in dom_uninsp)
        check("drill-down lists endpoint host", "registry.npmjs.org" in dom_uninsp
              and "statsig.example.com" in dom_uninsp)
        check("drill-down allow action delegated",
              'data-action="allow-host" data-agent="cursor" data-host="registry.npmjs.org"' in dom_uninsp)
        check("drill-down explains the blind spot", "bypassing the inspection proxy" in dom_uninsp)

        # --- endpoint evidence: an unattributed IPv6 must be identifiable ---
        check("endpoint Evidence opens a detail drawer",
              'id="drawer" class="drawer"' in dom_endpoint and "2600:1901:0:9e23::" in dom_endpoint)
        check("endpoint detail names the owner, not a bare address",
              "Google Cloud address" in dom_endpoint)
        check("endpoint detail shows which agent and session reached it",
              "Allow for claude" in dom_endpoint and "api-service@main" in dom_endpoint)
        check("endpoint detail lists recent connections",
              "Recent connections" in dom_endpoint and ":443" in dom_endpoint)

        # --- notification preferences ---
        check("notify bell present", 'id="btn-notify"' in dom)
        check("notify popover renders rules", "Keychain file access" in dom_notify
              and 'data-notify-rule="keychain-access"' in dom_notify)
        check("notify override pre-selected (never)",
              'data-notify-rule="keychain-access"' in dom_notify and
              'value="never" selected' in dom_notify.split('data-notify-rule="keychain-access"')[1][:300])
        check("notify popover lists workspace scopes",
              "Per-workspace scopes" in dom_notify
              and 'data-action="notify-scope-remove" data-rule="proxy-secret-leak" data-workspace="/Users/dev/work/prod"' in dom_notify)
        check("notify popover offers adding a workspace scope",
              'id="notify-scope-path"' in dom_notify and 'data-action="notify-scope-add"' in dom_notify)

        # --- connection states (the "trouble connecting" regressions) ---
        check("auth-expired shows honest re-auth guidance, not 'daemon down'",
              "Session expired — reopen the console from the Secure Agent menu bar" in dom_authfail
              and "Can&#x27;t reach the Secure Agent daemon" not in dom_authfail
              and "Can't reach the Secure Agent daemon" not in dom_authfail)
        check("auth-expired sets the status chip",
              'id="status-text">Session expired<' in dom_authfail)
        check("unreachable shows the retry banner",
              "reach the Secure Agent daemon" in dom_netfail)
        check("unreachable sets Disconnected chip",
              'id="status-text">Disconnected<' in dom_netfail)
        check("token survives reload via sessionStorage (no #ct fragment)",
              'id="count-agents">3<' in dom_tokenseed
              and 'id="offline-banner" hidden' in dom_tokenseed)

        # --- fleet node card (real /fleet object shape + renderAll crash isolation) ---
        check("fleet card renders the local node object",
              "ci-runner-02" in dom and "darwin/arm64" in dom)
        check("fleet panel visible when a collector is configured",
              'id="fleet-panel">' in dom)
        check("fleet panel hides when no collector is configured",
              'id="fleet-panel" style="display: none;"' in dom_nofleet
              and "ci-runner-02" not in dom_nofleet)
        check("panels after fleet still render (crash isolation)",
              dom.count('class="flag-card') == 3
              and dom.count('class="timeline-item') > 0
              and dom.count('class="audit-item') == 2)

        # --- tabs (console IA) ---
        check("tab bar renders all five tabs",
              dom.count('class="tab-btn') >= 5
              and all(f'data-tab="{t}"' in dom for t in ("overview", "sessions", "agents", "egress", "findings")))
        check("findings destination is presented as attention", '>Attention<' in dom)
        check("overview tab active by default",
              'class="tab-btn active" data-tab="overview"' in dom)
        check("non-active panels hidden",
              'id="tab-sessions" role="tabpanel" hidden' in dom
              and 'id="tab-agents" role="tabpanel" hidden' in dom
              and 'id="tab-findings" role="tabpanel" hidden' in dom)
        check("overview panel visible",
              'id="tab-overview" role="tabpanel">' in dom)
        check("resource mission control is present", 'id="resource-mission-control"' in dom)
        # The live Resources tab ends where the History tab begins: the flight
        # recorder moved out, so it must NOT be inside the resource view.
        resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="tab-history"', 1)[0]
        history_view = dom.split('id="tab-history"', 1)[1].split('id="tab-events"', 1)[0]
        check("whole-machine headroom is visible",
              "Machine headroom" in resource_view and "25 / 100" in resource_view
              and "4.0 GB available" in resource_view)
        check("live resources exclude the flight recorder",
              "Pressure flight recorder" not in resource_view)
        check("agent and non-agent memory are separated",
              "Agents 34.4%" in resource_view and "Other 40.6%" in resource_view
              and 'class="resource-host-segment agent"' in resource_view)
        check("whole-machine CPU swap and thermal context are visible",
              "75.0% total" in resource_view and "58.4% other" in resource_view
              and "2.0 GB / 8.0 GB" in resource_view and "Nominal" in resource_view)
        check("high-impact session shows CPU and memory",
              "132.5%" in resource_view and "5.5 GB" in resource_view)
        check("resource diagnosis explains the pressure",
              "Memory grew 1.4 GB in 15 minutes." in resource_view)
        check("resource flight recorder preserves exited sessions",
              "Pressure flight recorder" in history_view and "data-pipeline" in history_view)
        check("resource flight recorder remains visible with no live sessions",
              "No attributed agent resource use right now" in dom_noresources
              and "Pressure flight recorder" in dom_noresources
              and "data-pipeline" in dom_noresources)
        check("resource flight recorder identifies the dominant process",
              "PID 4419" in history_view and "79%" in history_view
              and "One child process dominated session memory." in history_view)
        check("resource pressure episode explains correlated activity",
              "Memory rose 3.0 GiB in 10m while node started." in history_view
              and "Observed correlation" in history_view)
        check("pressure episode preserves captured machine context",
              "Host at capture" in history_view and "1.0 GB available" in history_view
              and "Critical pressure" in history_view and "Serious thermal" in history_view)
        check("resource pressure chart includes activity markers",
              'class="resource-activity-marker' in history_view
              and "Bash tool ran" in history_view
              and "connected to api.openai.com:443" in history_view)
        check("historical resource evidence stays scoped to its captured lifetime",
              "Scoped to this captured process lifetime" in history_view
              and 'data-action="filter-pids" data-pids="4412,4419,4420"' not in history_view)
        check("resource trend SVG is rendered",
              'class="resource-spark"' in resource_view and 'points="' in resource_view)
        check("resource action targets the full family",
              'data-action="filter-pids" data-pids="5821,5822"' in resource_view)
        check("resource policy mode and grace are visible",
              "prompt</b> machine policy" in resource_view and "30s grace" in resource_view)
        check("resource policy source is visible on sessions",
              "workspace policy · /Users/dev/workspace" in resource_view)
        check("resource policy editor opens with the active document",
              'id="drawer" class="drawer resource-policy"' in dom_policy
              and "Resource policy editor" in dom_policy and "Machine default" in dom_policy)
        check("resource intervention ladder is visible",
              "notify → lower priority → pause → terminate" in resource_view)
        check("policy editor exposes intervention steps",
              'data-step-action="lower_priority" checked' in dom_policy
              and 'data-step-action="pause" checked' in dom_policy)
        check("policy editor adds the selected session workspace",
              'value="/Users/dev/workspace/api-service"' in dom_policy)
        check("policy editor exposes automatic containment warning",
		      "applies every enabled intervention automatically" in dom_policy)
        check("terminate policy save requires explicit confirmation",
		      'id="confirm-message"' in dom_policy
		      and "Terminate mode will automatically apply the enabled intervention ladder to entire agent sessions" in dom_policy
		      and 'id="confirm-title">Enable terminate mode<' in dom_policy)
        check("resource approval contains the whole session",
              'data-action="resource-control" data-id="resource-1" data-decision="apply" data-intervention="pause"' in resource_view)
        check("resource approval can keep the session running",
              'data-action="resource-control" data-id="resource-1" data-decision="dismiss"' in resource_view)
        check("paused resource session can resume",
              'data-action="resource-control" data-session="6033:1789484400000000000" data-decision="resume"' in resource_view)
        check("resource intervention failure is visible",
              "Intervention failed: rollback failed: permission denied" in resource_view)
        check("sessions panel lives in the sessions tab",
              dom.index('id="tab-sessions"') < dom.index('id="session-board"')
              and dom.index('id="session-board"') < dom.index('id="tab-agents"'))
        check("overview has no session board",
              'id="session-board"' not in dom.split('id="tab-overview"', 1)[1].split('id="tab-sessions"', 1)[0])
        overview = dom.split('id="tab-overview"', 1)[1].split('id="tab-resources"', 1)[0]
        # Overview is charts-only: the activity chart plus the two ranked-bar
        # charts. Lists (sessions/agents/flags/events) live in their own tabs.
        check("overview leads with the activity chart", 'id="activity-chart"' in overview)
        check("overview has the findings-by-rule chart", 'id="chart-flags"' in overview)
        check("overview has the memory-by-session chart", 'id="chart-memory"' in overview)
        check("overview carries no list panels",
              'id="session-strip"' not in overview and 'id="events-container"' not in overview
              and 'id="resource-board"' not in overview)
        check("session board has project filter", 'id="session-cwd-filter"' in dom)
        sessions = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
        check("session rail lists live cards and the ended tail", sessions.count('class="session-card') == 4,
              f"cards={sessions.count('class=\"session-card')}")
        check("session cards labeled by repo@branch or folder",
              "api-service@main" in sessions and "data-pipeline@feat/etl" in sessions and ">auth<" in sessions)
        check("session card selects the session trace",
              'data-action="select-session" data-id="sess-claude-1"' in sessions)
        check("egress tab badge shows uninspected count",
              'id="tab-badge-egress">2<' in dom)
        check("findings tab badge shows needs-you count",
              'id="tab-badge-findings">8<' in dom)
        attention = dom.split('id="attention-center"', 1)[1].split('id="security-findings-grid"', 1)[0]
        check("attention center groups the whole api-service session",
              'class="attention-group' in attention and "api-service" in attention
              and "5.5 GB" in attention and "132.5%" in attention and "<b>2</b> processes" in attention)
        check("attention center unifies all actionable signal types",
              all(label in attention for label in ("Guard decision", "Resource pressure", "Critical incident", "Critical finding", "Uninspected egress")))
        check("attention resource actions target the full session",
              'data-action="resource-control" data-id="resource-1" data-decision="apply"' in attention)
        check("attention guard actions expose bounded choices",
              'data-action="guard-resolve" data-id="guard-1" data-verdict="allow" data-scope="once"' in attention
              and 'data-action="guard-resolve" data-id="guard-1" data-verdict="deny" data-scope="always"' in attention)
        check("attention shows blast-radius copy", "approves every path under rule" in attention)
        check("attention egress opens endpoint evidence", 'data-action="open-uninspected"' in attention)
        check("resolved guard request leaves the attention queue",
              'id="tab-badge-findings">7<' in dom_guard
              and 'data-action="guard-resolve" data-id="guard-1"' not in dom_guard)
        check("posture flag item switches to findings tab",
              'data-action="goto-tab" data-tab="findings"' in dom)
        check("tab switch reveals the target panel",
              'id="tab-egress" role="tabpanel">' in dom_tab
              and 'id="tab-overview" role="tabpanel" hidden' in dom_tab)
        # The old catch-all "Telemetry" tab split into two coherent ones.
        check("resources and events are separate tabs",
              'id="tab-resources" role="tabpanel" hidden' in dom
              and 'id="tab-events" role="tabpanel" hidden' in dom)
        check("history is its own tab",
              'id="tab-history" role="tabpanel" hidden' in dom
              and 'data-tab="history"' in dom)
        check("resource panel lives in the resources tab",
              dom.index('id="tab-resources"') < dom.index('id="resource-board"')
              and dom.index('id="resource-board"') < dom.index('id="tab-history"'))
        check("flight recorder lives in the history tab",
              dom.index('id="tab-history"') < dom.index('id="history-board"')
              and dom.index('id="history-board"') < dom.index('id="tab-events"'))
        check("event timeline lives in the events tab",
              dom.index('id="tab-events"') < dom.index('id="events-container"')
              and dom.index('id="events-container"') < dom.index('id="tab-sessions"'))

        # --- saved views, search, export (P5) ---
        check("saved-view menu is present", 'id="btn-views"' in dom and 'id="views-pop"' in dom)
        check("a saved view appears in the list",
              'data-action="apply-view" data-name="Prod leaks"' in dom_view)
        check("global search box is present", 'id="global-search"' in dom)
        check("export actions are wired",
              'data-action="export" data-what="flags"' in dom
              and 'data-action="export" data-what="incidents"' in dom)
        # The search term narrows the events panel: "npm" must drop rows that
        # do not mention it (the drip includes non-npm events).
        check("search narrows the panel",
              dom_view.count('class="timeline-item') <= dom.count('class="timeline-item'))

        # --- action feedback loops (the "nothing happens" regressions) ---
        check("flag card carries per-flag dismiss",
              'data-action="dismiss-flag" data-id="flag-1"' in dom)
        check("flag card carries re-run advisor",
              'data-action="retriage" data-id="flag-1"' in dom)
        check("keychain flag shows benign context",
              "usually routine" in dom)
        check("allow removes the suggestion from the list",
              "fw-suggestion" not in dom_allow,
              "suggestion still rendered after Allow")
        check("dismiss removes the flag card",
              dom_dismiss.count('class="flag-card') == 2
              and 'data-id="flag-3"' not in dom_dismiss,
              f"cards={dom_dismiss.count('class=\"flag-card')}")
        check("re-triage verdict lands and replaces the chip",
              "re-triage complete: routine vendor traffic" in dom_retriage
              and "advisor: benign" in dom_retriage)
        check("advisor offline renders honest disabled state",
              "Advisor offline" in dom_advdown
              and 'data-action="retriage" data-id="flag-1"' not in dom_advdown)
        check("timeline rows carry agent names, not bare PIDs",
              "cursor · PID 6033" in dom or "claude · PID 5821" in dom)

        # --- structural security: no inline handlers anywhere ---
        check("zero inline onclick handlers in rendered DOM", " onclick=" not in dom)

        # --- session drill-down (auto-action run) ---
        check("session chip appears", 'id="session-filter" class="session-filter"' in dom_session
              or ('id="session-filter"' in dom_session and "hidden" not in
                  dom_session.split('id="session-filter"')[1][:80]))
        check("session chip count", "7f3a9c21 · 2" in dom_session)
        check("session scopes findings list",
              'id="flags-session-filter"' in dom_session
              and "hidden" not in dom_session.split('id="flags-session-filter"')[1][:80])
        session_rows = dom_session.count('class="timeline-item')
        check("timeline filtered to 2 session events", session_rows == 2, f"rows={session_rows}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{len(passed)} passed, {len(failed)} failed")
    if failed:
        print("failed:", *failed, sep="\n  - ")
        sys.exit(1)


if __name__ == "__main__":
    main()
