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
VIRTUAL_TIME_MS = 9000

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
              "tab-overview.js", "tab-agents.js", "tab-egress.js", "tab-findings.js"):
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
        dom_uninsp = dump_dom(chrome, tmp, "?uninspecteddemo")
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
        check("tab bar renders all four tabs",
              dom.count('class="tab-btn') >= 4
              and all(f'data-tab="{t}"' in dom for t in ("overview", "agents", "egress", "findings")))
        check("overview tab active by default",
              'class="tab-btn active" data-tab="overview"' in dom)
        check("non-active panels hidden",
              'id="tab-agents" role="tabpanel" hidden' in dom
              and 'id="tab-findings" role="tabpanel" hidden' in dom)
        check("overview panel visible",
              'id="tab-overview" role="tabpanel">' in dom)
        check("overview session board is present", 'id="session-board"' in dom)
        check("session board has project filter", 'id="session-cwd-filter"' in dom)
        overview = dom.split('id="session-board"', 1)[1].split('id="tab-agents"', 1)[0]
        check("session board lists two sessions", overview.count('class="session-row') == 2)
        check("session rows labeled by project folder",
              "api-service" in overview and "web-app" in overview)
        check("session row filters timeline by pids",
              'data-action="filter-pids" data-pids="5821,5822"' in overview)
        check("egress tab badge shows uninspected count",
              'id="tab-badge-egress">2<' in dom)
        check("findings tab badge shows needs-you count",
              'id="tab-badge-findings">4<' in dom)
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
