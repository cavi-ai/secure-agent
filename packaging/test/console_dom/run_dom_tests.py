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
        dom_toast = dump_dom(chrome, tmp, "?toastdemo")
        dom_notify = dump_dom(chrome, tmp, "?notifydemo")
        dom_allow = dump_dom(chrome, tmp, "?allowdemo")
        dom_dismiss = dump_dom(chrome, tmp, "?dismissdemo")
        dom_retriage = dump_dom(chrome, tmp, "?retriagedemo")
        dom_tab = dump_dom(chrome, tmp, "?tabdemo")
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

        # --- session-first tab (P3) ---
        check("session rail renders durable sessions", dom.count('class="session-card') >= 2,
              f"cards={dom.count('class=\"session-card')}")
        check("rail shows names not pids", "claude · api-service@main" in dom)
        check("ended session marked", 'session-card ended' in dom)
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
        check("agent families grouped", dom.count('class="agent-group"') == 2)
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
        # A toast fired while the egress modal is open must render ABOVE it.
        # Native <dialog> lives in the browser top layer, which no root-level
        # z-index can beat — so the toast is hosted inside the dialog. This is
        # the "toast goes in the background, everything fails" regression.
        dialog_start = dom_toast.find('id="report-modal"')
        dialog_block = dom_toast[dialog_start:dialog_start + 6000] if dialog_start >= 0 else ''
        check("toast renders inside the open modal (top layer)",
              'class="toast-host"' in dialog_block and 'class="toast ' in dialog_block)
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
        check("drill-down modal title", "Uninspected egress — last 24h" in dom_uninsp)
        check("drill-down lists endpoint host", "registry.npmjs.org" in dom_uninsp
              and "statsig.example.com" in dom_uninsp)
        check("drill-down allow action delegated",
              'data-action="allow-host" data-agent="cursor" data-host="registry.npmjs.org"' in dom_uninsp)
        check("drill-down explains the blind spot", "bypassing the inspection proxy" in dom_uninsp)

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
        resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="session-strip-panel"', 1)[0]
        check("whole-machine headroom is visible",
              "Machine headroom" in resource_view and "25 / 100" in resource_view
              and "4.0 GB available" in resource_view)
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
              "Pressure flight recorder" in resource_view and "data-pipeline" in resource_view)
        check("resource flight recorder remains visible with no live sessions",
              "No attributed agent resource use right now" in dom_noresources
              and "Pressure flight recorder" in dom_noresources
              and "data-pipeline" in dom_noresources)
        check("resource flight recorder identifies the dominant process",
              "PID 4419" in resource_view and "79%" in resource_view
              and "One child process dominated session memory." in resource_view)
        check("resource pressure episode explains correlated activity",
              "Memory rose 3.0 GiB in 10m while node started." in resource_view
              and "Observed correlation" in resource_view)
        check("pressure episode preserves captured machine context",
              "Host at capture" in resource_view and "1.0 GB available" in resource_view
              and "Critical pressure" in resource_view and "Serious thermal" in resource_view)
        check("resource pressure chart includes activity markers",
              'class="resource-activity-marker' in resource_view
              and "Bash tool ran" in resource_view
              and "connected to api.openai.com:443" in resource_view)
        check("historical resource evidence stays scoped to its captured lifetime",
              "Scoped to this captured process lifetime" in resource_view
              and 'data-action="filter-pids" data-pids="4412,4419,4420"' not in resource_view)
        check("resource trend SVG is rendered",
              'class="resource-spark"' in resource_view and 'points="' in resource_view)
        check("resource action targets the full family",
              'data-action="filter-pids" data-pids="5821,5822"' in resource_view)
        check("resource policy mode and grace are visible",
              "prompt</b> machine policy" in resource_view and "30s grace" in resource_view)
        check("resource policy source is visible on sessions",
              "workspace policy · /Users/dev/workspace" in resource_view)
        check("resource policy editor opens with the active document",
              'id="resource-policy-modal" class="modal resource-policy-modal" open' in dom_policy
              and "Policy editor" in dom_policy and "Machine default" in dom_policy)
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
        overview = dom.split('id="tab-overview"', 1)[1].split('id="tab-sessions"', 1)[0]
        check("overview session strip is present", 'id="session-strip"' in overview)
        check("overview strip names the live projects",
              "api-service" in overview and "web-app" in overview)
        check("overview strip opens the sessions tab",
              'data-action="goto-tab" data-tab="sessions"' in overview)
        check("session board has project filter", 'id="session-cwd-filter"' in dom)
        sessions = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
        check("session rail lists two sessions", sessions.count('class="session-card') == 2,
              f"cards={sessions.count('class=\"session-card')}")
        check("session cards labeled by project folder",
              "api-service" in sessions and "web-app" in sessions)
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
