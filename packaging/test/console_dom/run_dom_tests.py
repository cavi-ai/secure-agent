#!/usr/bin/env python3
"""DOM-level console tests: render the real console (index.html + lib.js +
app.js + style.css) against stubbed telemetry in headless Chrome and assert
on the final DOM. Zero dependencies — Chrome's --dump-dom plus stdlib checks.

Covers the layer lib.test.mjs cannot: fetch orchestration, panel renderers,
the delegation dispatch, liveness classes, and the structural guarantee that
no inline handlers exist in the rendered page.

Usage: python3 packaging/test/console_dom/run_dom_tests.py [--screenshot DIR]
       --screenshot DIR also writes the mock-rendered Sessions and Agents
       tabs at 1280x800 in both themes: DIR/{sessions,agents}-{dark,light}.png,
       and the Overview tab as DIR/overview-dark.png. Screenshots load under
       the daemon's Content-Security-Policy header, as the console is served.
Env:   CHROME_BIN overrides Chrome detection.
"""

import argparse
import http.server
import json
import os
import html
import re
import shutil
import subprocess
import sys
import tempfile
import threading

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
              "tab-overview.js", "tab-sessions.js", "tab-agents.js", "tab-egress.js", "tab-findings.js",
              "tab-worktrees.js", "theme-init.js", "icon.svg"):
        os.symlink(os.path.join(WEB_DIST, f), os.path.join(tmp, f))
    os.symlink(MOCK, os.path.join(tmp, "mock_dom.js"))
    html = open(os.path.join(WEB_DIST, "index.html")).read()
    needle = '<script src="lib.js"></script>'
    assert needle in html, "lib.js script tag not found in index.html"
    html = html.replace(needle, needle + '\n  <script src="mock_dom.js"></script>')
    with open(os.path.join(tmp, "harness.html"), "w") as f:
        f.write(html)


def csp_header():
    """The Content-Security-Policy value the daemon sends, read from web.go so
    the served harness and the daemon cannot drift."""
    src = open(os.path.join(REPO, "daemon", "internal", "api", "web.go")).read()
    m = re.search(r'"Content-Security-Policy",\s*"([^"]+)"', src)
    assert m, "Content-Security-Policy header not found in web.go"
    return m.group(1)


def serve_with_csp(tmp):
    """Serve the harness on loopback HTTP with the daemon's CSP header. A
    file:// load applies no policy, so markup the policy drops (inline style
    attributes) renders there and passes."""
    policy = csp_header()

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=tmp, **kw)

        def end_headers(self):
            self.send_header("Content-Security-Policy", policy)
            super().end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def dump_dom(chrome, tmp, query="", origin=None, window_size=None):
    url = f"{origin or 'file://' + tmp}/harness.html{query}"
    size = [f"--window-size={window_size[0]},{window_size[1]}"] if window_size else []
    out = subprocess.run(
        [chrome, "--headless=new", "--disable-gpu", "--no-sandbox", *size,
         "--virtual-time-budget=" + str(VIRTUAL_TIME_MS), "--dump-dom", url],
        capture_output=True, text=True, timeout=120,
    )
    if out.returncode != 0:
        print(out.stderr[-2000:], file=sys.stderr)
        raise SystemExit("chrome --dump-dom failed")
    return out.stdout


SHOT_SIZE = (1280, 800)
SHOTS = (
    ("sessions", "?tab=sessions&shot&raildemo", ("dark", "light")),
    ("agents", "?tab=agents&shot", ("dark", "light")),
    ("overview", "?tab=overview&shot", ("dark",)),
)


def screenshot(chrome, origin, query, path):
    out = subprocess.run(
        [chrome, "--headless=new", "--disable-gpu", "--no-sandbox", "--hide-scrollbars",
         f"--window-size={SHOT_SIZE[0]},{SHOT_SIZE[1]}",
         "--virtual-time-budget=" + str(VIRTUAL_TIME_MS), f"--screenshot={path}",
         f"{origin}/harness.html{query}"],
        capture_output=True, text=True, timeout=120,
    )
    if out.returncode != 0 or not os.path.isfile(path) or os.path.getsize(path) == 0:
        print(out.stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"chrome --screenshot failed: {path}")


def main():
    ap = argparse.ArgumentParser(description="DOM-level console tests")
    ap.add_argument("--screenshot", metavar="DIR",
                    help="also write {sessions,agents}-{dark,light}.png and overview-dark.png of the mock-rendered tabs to DIR")
    args = ap.parse_args()
    chrome = find_chrome()
    if not chrome:
        raise SystemExit("no Chrome found (set CHROME_BIN)")
    print(f"console dom tests (chrome: {chrome})")

    tmp = tempfile.mkdtemp(prefix="console-dom-")
    srv = None
    try:
        build_harness(tmp)
        srv, origin = serve_with_csp(tmp)
        dom_csp = dump_dom(chrome, tmp, "?cspdemo&raildemo", origin)
        dom_themefirst = dump_dom(chrome, tmp, "?themefirst", origin)
        dom = dump_dom(chrome, tmp)
        dom_session = dump_dom(chrome, tmp, "?sessiondemo")
        dom_guard = dump_dom(chrome, tmp, "?guarddemo")
        dom_resolve = dump_dom(chrome, tmp, "?resolvedemo")
        dom_uninsp = dump_dom(chrome, tmp, "?uninspecteddemo")
        dom_keepopen = dump_dom(chrome, tmp, "?keepopendemo")
        dom_endpoint = dump_dom(chrome, tmp, "?endpointdemo")
        dom_file = dump_dom(chrome, tmp, "?filedemo")
        dom_filedeep = dump_dom(chrome, tmp, "#file=%2FUsers%2Fdev%2F.codex%2Fsessions%2F2026%2F09%2F23%2Frollout-2026-09-23T12-53-26-demo.jsonl")
        dom_toast = dump_dom(chrome, tmp, "?toastdemo")
        dom_notify = dump_dom(chrome, tmp, "?notifydemo")
        dom_notifyfocus = dump_dom(chrome, tmp, "?notifyfocusdemo")
        dom_allow = dump_dom(chrome, tmp, "?allowdemo")
        dom_dismiss = dump_dom(chrome, tmp, "?dismissdemo")
        dom_retriage = dump_dom(chrome, tmp, "?retriagedemo")
        dom_tab = dump_dom(chrome, tmp, "?tabdemo")
        dom_view = dump_dom(chrome, tmp, "?viewdemo")
        dom_advdown = dump_dom(chrome, tmp, "?advisordown")
        dom_authfail = dump_dom(chrome, tmp, "?authfail")
        dom_notoken = dump_dom(chrome, tmp, "?notoken")
        dom_hashagents = dump_dom(chrome, tmp, "#agents")
        dom_hashfindings = dump_dom(chrome, tmp, "#findings")
        dom_trends = dump_dom(chrome, tmp, "?trendsprobe")
        dom_hiddenrender = dump_dom(chrome, tmp, "?hiddenrenderprobe")
        dom_policylists = dump_dom(chrome, tmp, "?policylists")
        dom_policyempty = dump_dom(chrome, tmp, "?policylists&emptypolicy")
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
        dom_nocosts = dump_dom(chrome, tmp, "?nocostsdemo")
        dom_memfam = dump_dom(chrome, tmp, "?memfamilydemo")
        dom_memprobe = dump_dom(chrome, tmp, "?memprobe")
        dom_spend = dump_dom(chrome, tmp, "?spenddemo")
        dom_plans = dump_dom(chrome, tmp, "?plansdemo")
        dom_spendday = dump_dom(chrome, tmp, "?spenddaydemo")
        dom_spendphone = dump_dom(chrome, tmp, "?phonedemo&spenddaydemo")
        dom_spendkeep = dump_dom(chrome, tmp, "?tab=overview&spenddaydemo&spendkeepdemo")
        dom_events = dump_dom(chrome, tmp, "?tab=events")
        dom_burst = dump_dom(chrome, tmp, "?burstdemo")
        dom_railburst = dump_dom(chrome, tmp, "?railburst")
        dom_focus = dump_dom(chrome, tmp, "?focusburst")
        dom_click = dump_dom(chrome, tmp, "?clickburst")
        dom_rawmute = dump_dom(chrome, tmp, "?rawmute")
        dom_act = dump_dom(chrome, tmp, "?actdemo")
        dom_actfail = dump_dom(chrome, tmp, "?actdemo&postfail")
        dom_export = dump_dom(chrome, tmp, "?raildemo&exportdemo")
        dom_explain = dump_dom(chrome, tmp, "?explaindemo")
        dom_explainact = dump_dom(chrome, tmp, "?explaindemo&explainact")
        dom_allowpathact = dump_dom(chrome, tmp, "?explaindemo&allowpathact")
        dom_explainfail = dump_dom(chrome, tmp, "?explaindemo&explainact&postfail")
        dom_detailsprobe = dump_dom(chrome, tmp, "?explaindemo&detailsprobe")
        dom_fam = dump_dom(chrome, tmp, "?familiesdemo&tab=resources")
        dom_famev = dump_dom(chrome, tmp, "?familiesdemo&familyevents&tab=resources")
        dom_evcap = dump_dom(chrome, tmp, "?tab=events&manyevents")
        dom_evtrace = dump_dom(chrome, tmp, "?tab=events&traceevents")
        dom_duptrace = dump_dom(chrome, tmp, "?tab=events&duptrace")
        dom_evorder = dump_dom(chrome, tmp, "?tab=events&eventsorderdemo")
        dom_sesslink = dump_dom(chrome, tmp, "?sessionlinkdemo")
        dom_sticky = dump_dom(chrome, tmp, "?stickydemo")
        dom_drawerback = dump_dom(chrome, tmp, "?drawerbackdemo")
        dom_wt = dump_dom(chrome, tmp, "?tab=worktrees")
        dom_wtremove = dump_dom(chrome, tmp, "?tab=worktrees&worktreedemo")
        dom_wtsizing = dump_dom(chrome, tmp, "?tab=worktrees&sizingdemo")
        dom_clutter = dump_dom(chrome, tmp, "?tab=worktrees&clutterdemo")
        dom_clutteradvise = dump_dom(chrome, tmp, "?tab=worktrees&clutteradvise")
        dom_scope = dump_dom(chrome, tmp, "?scopedemo")
        dom_pattern = dump_dom(chrome, tmp, "?patterndemo")
        dom_patternact = dump_dom(chrome, tmp, "?patterndemo&patternact")
        dom_patternphone = dump_dom(chrome, tmp, "?phonedemo&patterndemo")
        dom_patternstream = dump_dom(chrome, tmp, "?patterndemo&patternstream")
        dom_attnkeep = dump_dom(chrome, tmp, "?patterndemo&attnkeep")
        dom_posturemore = dump_dom(chrome, tmp, "?posturemoredemo")
        dom_fold = dump_dom(chrome, tmp, "?folddemo")
        dom_procwidth = dump_dom(chrome, tmp, "?procwidthdemo", window_size=(1440, 900))

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
        check("the page, posture banner included, fits a 375px phone on Sessions, Agents and Resources",
              'data-hscroll="sessions:0,agents:0,resources:0"' in dom_phone,
              (re.search(r'data-hscroll="[^"]*"', dom_phone) or [None])[0])
        detail_head = dom_rail.split('class="session-detail-head"', 1)[1].split('class="wf', 1)[0]
        check("detail head: mark, repo@branch, harness, confidence, copyable path",
              '<h3>api-service@main</h3>' in detail_head and '#logo-claude' in detail_head
              and '<span class="sd-harness">Claude Code</span>' in detail_head
              and '>hook</span>' in detail_head
              and 'data-action="copy-path" data-path="/Users/dev/workspace/api-service"' in detail_head)
        check("detail head carries the Export button next to the path",
              'data-action="copy-path"' in detail_head
              and detail_head.index('data-action="copy-path"')
              < detail_head.index('data-action="copy-report" data-id="sess-claude-1"')
              and '>Export</button>' in detail_head)
        clip = (re.search(r'data-clipboard="([^"]*)"', dom_export) or [None, ""])[1]
        check("Export copies the markdown session report and toasts",
              clip.startswith("# claude · api-service@main") and "## Summary" in clip
              and 'class="toast success">Session report copied (markdown)<' in dom_export,
              f"clipboard={clip[:60]!r}")
        check("rail selection renders trace waterfall",
              'class="wf-bar' in dom_rail and 'Bash' in dom_rail,
              "no waterfall bars in raildemo")
        check("waterfall carries model usage row",
              "claude-sonnet-4-5" in dom_rail and "46.2k in" in dom_rail)
        check("waterfall marks tool errors", 'wf-bar error' in dom_rail)
        theme_first = (re.search(r'<pre id="theme-first"[^>]*>([^<]*)<', dom_themefirst) or [None, ""])[1]
        check("theme: a stored light theme is on <html> before app.js runs, under the served CSP",
              theme_first == "before-app=light", theme_first)
        csp_widths = (re.search(r'data-csp-widths="([^"]*)"', dom_csp) or [None, ""])[1]
        widths = {k: float(v) for k, v in (kv.split(":") for kv in csp_widths.split(",") if kv)}
        # Bash spans 31s of the 90s trace; agents hold 34.4% of memory; the
        # smallest memory-ranked bar is 85 MB of the 782 MB leader. A dropped width
        # renders the bar at its 2px floor, the segment at 0, the fill full.
        check("under the daemon CSP the waterfall bar, ranked bar and memory segment keep their widths",
              abs(widths.get("wf-bar", 0) - 34.4) < 1
              and abs(widths.get("hbar-fill", 0) - 10.9) < 1
              and abs(widths.get("resource-host-segment", 0) - 34.4) < 1, f"widths={csp_widths!r}")

        # --- telemetry wiring ---
        check("version badge comes from /status", 'id="app-version">v9.9.9-domtest<' in dom)
        check("posture banner is critical", 'id="posture-banner" data-state="critical"' in dom)
        check("posture headline rendered", 'id="posture-state">Critical<' in dom)
        check("KPI agents count", 'id="count-agents">3<' in dom)
        check("KPI flags are unacted last 24h", 'id="count-flags">2<' in dom)
        check("KPI incidents count", 'id="count-incidents">1<' in dom)
        check("spend tile shows the 24h total", 'id="count-spend">$36.67<' in dom)
        check("spend tile sub-line counts calls and unpriced calls",
              'id="hint-spend">40 calls · 2 unpriced<' in dom)
        def pre(dom_text, pid):
            m = re.search(r'<pre id="%s"[^>]*>(.*?)</pre>' % pid, dom_text, re.S)
            return m.group(1) if m else ""

        def spend_card_of(d):
            return d.split('id="spend-card"', 1)[1].split('</section>', 1)[0]
        spend_key_re = r'<span class="spend-key" title="[^"]*">([^<]+)</span>'
        spend_card = spend_card_of(dom)
        spend_keys = re.findall(spend_key_re, spend_card)
        check("spend card defaults to repos by cost over 24h",
              spend_keys == ["api-service", "web-console", "infra-tools", "scratch", "(no repo)", "docs"]
              and '<span class="spend-cost">$24.50</span>' in spend_card
              and '#logo-claude' in spend_card, f"keys={spend_keys}")
        check("empty spend report: tile reads an em dash, card shows its empty state",
              'id="count-spend">—<' in dom_nocosts and 'id="hint-spend"><' in dom_nocosts
              and "No priced model calls in this window." in spend_card_of(dom_nocosts))
        plans_card = spend_card_of(dom_plans)
        check("spend: a /costs/plans entry renders its plan line and a bar at used_percent above the rows; none when empty",
              re.search(r'<div class="spend-plans"><div class="spend-plan">\s*<span class="spend-plan-text">'
                        r'Codex Pro · codex · weekly 52% used · resets (Sun|Mon|Tue|Wed|Thu|Fri|Sat) \d{1,2}:\d{2} (AM|PM)</span>'
                        r'<span class="hbar-track" title="weekly"><span class="hbar-fill" data-w="52.0"', plans_card) is not None
              and plans_card.index('class="spend-plans"') < plans_card.index('class="spend-key"')
              and '<div class="spend-plans"></div>' in spend_card, plans_card[:600])
        check("spend: the stat strip counts calls on plans before unpriced",
              'id="hint-spend">40 calls · 12 on plans · 2 unpriced<' in dom_plans)
        spend_q = html.unescape(pre(dom_spend, "mock-costs")).split("\n")
        tz_ok = all(re.search(r"&tz=-?\d+$", q) for q in spend_q if q != "since=24h&by=repo")
        check("spend: switching the dimension fetches by=provider and renders the provider rows",
              any(q.startswith("since=24h&by=provider&tz=") for q in spend_q) and tz_ok
              and re.findall(spend_key_re, spend_card_of(dom_spend)) == ["anthropic", "openai-codex", "openai", "(unknown)"]
              and "provider not recorded" in spend_card_of(dom_spend), f"queries={spend_q}")
        check("spend: the tile keeps its 24h by-repo fetch and meaning",
              "since=24h&by=repo" in spend_q and 'id="count-spend">$36.67<' in dom_spend, f"queries={spend_q}")
        check("spend: the chosen view survives a full re-render and is saved for the tab",
              pre(dom_spend, "spend-probe") == 'select=provider saved={"by":"provider","since":"24h"}'
              and spend_q[-1].startswith("since=24h&by=provider&tz="),
              f"probe={pre(dom_spend, 'spend-probe')!r} last={spend_q[-1]!r}")
        day_card = spend_card_of(dom_spendday)
        day_labels = re.findall(r'<span class="spend-day-label">([^<]+)</span>', day_card)
        check("spend: a saved by-day view renders one column per day, oldest first, the costliest at full height",
              day_labels == ["Thu 17", "Fri 18", "Sat 19", "Sun 20", "Mon 21", "Tue 22", "Wed 23"]
              and 'data-h="100.0"' in day_card.split("Tue 22", 1)[0].rsplit('class="spend-day"', 1)[1]
              and any(q.startswith("since=7d&by=day&tz=") for q in html.unescape(pre(dom_spendday, "mock-costs")).split("\n")),
              f"labels={day_labels}")
        keep = html.unescape(pre(dom_spendkeep, "spend-keep-probe")).split("\n")
        keep_day = re.fullmatch(r"day same=(\w+) left=(-?\d+)->(-?\d+) refetched=(\w+)", keep[0])
        check("spend: a slow refresh keeps the day column nodes and the day bars' scrollLeft",
              bool(keep_day) and keep_day.group(1) == "true" and int(keep_day.group(2)) > 0
              and keep_day.group(2) == keep_day.group(3) and keep_day.group(4) == "true", f"probe={keep}")
        check("spend: a slow refresh keeps the list row nodes",
              len(keep) > 1 and keep[1] == "list same=true refetched=true", f"probe={keep}")
        check("spend: the Overview tab with the day bars fits a 375px phone",
              'data-hscroll="sessions:0,agents:0,resources:0,overview:0"' in dom_spendphone,
              (re.search(r'data-hscroll="[^"]*"', dom_spendphone) or [None])[0])
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
        # status.uninspected_egress is 2 (it excludes the 2 infrastructure
        # endpoints); the title must count what the panel renders instead: 4
        # unknown + 1 vendor rollup (covering 1 endpoint) + 2 infrastructure = 7.
        check("uninspected-egress title counts rendered endpoints, not the status counter",
              "7 endpoints reached without inspection" in dom)

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
        uninsp_unknown = dom_uninsp.split('class="uninspected-expl"', 1)[-1].split("Vendor APIs", 1)[0]
        check("drill-down rolls vendor APIs up per agent and vendor",
              "Vendor APIs" in dom_uninsp and "openclaw → Anthropic" in dom_uninsp and "94×" in dom_uninsp
              and 'data-action="bulk-allow" data-agent="openclaw" data-hosts="2607:6bc0::10"' in dom_uninsp)
        check("unknown section does not list vendor endpoints",
              "2607:6bc0::10" not in uninsp_unknown and "statsig.example.com" in uninsp_unknown)
        check("unknown section keeps cloud hosts, named",
              re.search(r'2600:1901:0:9e23::</span> <span class="fw-metric dim">Google Cloud</span>', uninsp_unknown) is not None)
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
        flag1_card = dom.split('class="flag-card', 1)[1].split('class="flag-card', 1)[0]
        flags_region = dom.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
        check("legacy card evidence rows render as text, not [object Object]",
              '<div>proxy-secret-leak: anthropic-key (payload inspection)</div>' in flag1_card
              and '<div>logs.example.com:443 (destination)</div>' in flag1_card
              and "[object Object]" not in flags_region)

        # --- liveness ---
        check("sparkline has points", re.search(r'id="spark-line" points="[\d.,\- ]{20,}"', dom) is not None)
        check("sparkline rate label", re.search(r'id="spark-rate">\d+/s<', dom) is not None)
        # Hidden panels do not render; the Events tab is open for this one.
        check("fresh timeline rows after SSE drip", "timeline-item fresh" in dom_events)
        check("timeline times are HH:MM:SS",
              re.search(r'class="t">\d{2}:\d{2}:\d{2}<', dom) is not None)

        # --- local advisor ---
        check("advisor chip rendered with assessment class", 'advisor-chip adv-suspicious' in dom)
        check("advisor chip rationale in tooltip", "first time this session" in dom)
        check("agent last-active rendered", "active " in dom and " ago" in dom)
        check("stale process marked", " stale" in dom)
        check("flag card kill action", 'data-action="kill" data-pid="6033"' in dom)
        check("collector-down FDA deep link", 'data-action="open-fda"' in dom and "Full Disk Access settings" in dom)
        check("advisor posture line (1 of 2 benign) off Home",
              "advisor: 1 of 2 triaged critical flags look benign" in dom_tab)
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
        # --- screen hygiene: the banner summarises, the queue lists ---
        check("Home: the posture banner lists no items; the attention queue lists them",
              re.search(r'<ul class="posture-items" id="posture-items" hidden(="")?></ul>', dom) is not None
              and 'class="posture-item"' not in dom and 'data-action="guard-resolve" data-id="guard-1"' in dom)
        posture_egress = (re.search(r'<pre id="posture-egress"[^>]*>([^<]*)<', dom_posturemore) or [None, ""])[1]
        check("Egress: the posture banner lists 3 content rows (2 items + the advisor line) and \"and 8 more\"",
              posture_egress == "items=2 more=and 8 more hidden=0", posture_egress)
        posture_home = (re.search(r'<pre id="posture-home"[^>]*>([^<]*)<', dom_posturemore) or [None, ""])[1]
        check("\"and N more\" lands on Home, where the banner lists nothing",
              posture_home == "tab=home items=0 more=none hidden=1", posture_home)
        # --- screen hygiene: Egress leads with where traffic went ---
        fold_before = (re.search(r'<pre id="fold-before"[^>]*>([^<]*)<', dom_fold) or [None, ""])[1]
        check("Egress: 2 rules with hits listed, 20 quiet rules fold into one row with their Promote buttons",
              fold_before == "top=2 fold=20 rules with no hits in 24 h inside=20 open=0 rebuilt=1", fold_before)
        fold_after = (re.search(r'<pre id="fold-after"[^>]*>([^<]*)<', dom_fold) or [None, ""])[1]
        check("Egress: the open fold stays open, and its outer node is never rebuilt, across an SSE-driven patch that changes its count",
              fold_after == "top=3 fold=19 rules with no hits in 24 h inside=19 open=1 rebuilt=0", fold_after)
        fold_focus = (re.search(r'<pre id="fold-focus"[^>]*>([^<]*)<', dom_fold) or [None, ""])[1]
        check("Egress: an unchanged quiet rule's focused Promote button keeps its node identity and focus across the patch",
              fold_focus == "kept=1", fold_focus)
        endpoints = dom_fold.split('id="endpoints-container"', 1)[-1].split('id="firewall-panel"', 1)[0]
        check("Egress: the endpoints list is the first panel, inline, with a vendor rollup and row actions",
              dom_fold.index('id="endpoints-panel"') < dom_fold.index('id="firewall-panel"')
              and 'class="egress-vendor"' in endpoints and 'data-action="bulk-allow" data-agent="openclaw"' in endpoints
              and 'data-action="allow-host"' in endpoints and 'data-action="endpoint-detail"' in endpoints
              and re.search(r'id="endpoints-title">\d+ endpoints? reached without inspection in 24 h<', dom_fold) is not None)
        firewall = dom_fold.split('id="firewall-container"', 1)[-1].split('id="sources-container"', 1)[0]
        check("Egress: the firewall panel has no view-endpoints link",
              'data-action="open-uninspected"' not in firewall and "fw-uninspected" not in dom_fold
              and "hit-a" in firewall)
        proc_width = (re.search(r'<pre id="proc-width"[^>]*>([^<]*)<', dom_procwidth) or [None, ""])[1]
        pw = re.match(r"panel=(\d+) content=(\d+) viewport=(\d+)", proc_width)
        check("Processes panel fills the content width at 1440 px",
              pw is not None and pw.group(3) == "1440" and pw.group(1) == pw.group(2), proc_width)
        check("drill-down drawer title", "Uninspected egress — last 24h" in dom_uninsp)
        check("drill-down lists endpoint host", "registry.npmjs.org" in dom_uninsp
              and "statsig.example.com" in dom_uninsp)
        check("drill-down allow action delegated",
              'data-action="allow-host" data-agent="cursor" data-host="registry.npmjs.org"' in dom_uninsp)
        check("drill-down explains the blind spot", "bypassing the inspection proxy" in dom_uninsp)
        keepopen = (re.search(r'<pre id="keepopen"[^>]*>([^<]*)<', dom_keepopen) or [None, ""])[1]
        check("drill-down vendor disclosure stays open across an Allow refill",
              "key=vendor:openclaw|Anthropic rebuilt=1 open=1" in keepopen, keepopen)
        check("drill-down Allow refill posted and dropped the row",
              "POST /allowlist" in dom_keepopen and 'data-host="statsig.example.com"' not in dom_keepopen.split('id="drawer-body"', 1)[-1].split("</details>", 1)[0], keepopen)

        # --- evidence file: an incident's accessed file opens the file drawer ---
        check("incident Accessed Files path is a file link",
              'id="file-link"' in dom_file and "rollout-2026-09-23T12-53-26-demo.jsonl" in dom_file)
        check("file drawer shows the masked excerpt, never an unmasked value",
              "Around the secret" in dom_file and "[REDACTED:fp1]" in dom_file)
        check("file drawer offers Reveal in Finder and Open in editor",
              'data-action="file-reveal"' in dom_file and 'data-action="file-open"' in dom_file)
        check("file drawer lists findings, agent access and the session",
              "Agent access" in dom_file and "api-service@main" in dom_file and 'data-action="open-incident"' in dom_file)
        check("file drawer goes back to the incident report",
              'id="btn-drawer-back"' in dom_file and "Incident report" in dom_file)
        check("file drawer shows the advisor plan and the playbook",
              "What to do" in dom_file and "Codex printed an API key from an env dump." in dom_file
              and "Playbook: Secret in an agent transcript" in dom_file and 'data-action-id="dismiss"' in dom_file)
        check("finding cards offer What to do", 'data-action="open-plan" data-subject="flag:flag-2"' in dom_explain)
        check("finding cards offer Mark as routine / not ok",
              'data-action="mark-label" data-subject="flag:flag-2" data-label="ok"' in dom_explain)
        check("file drawer shows the operator's history and suggestion",
              "Your history" in dom_file and "You marked similar cases 3 as routine." in dom_file
              and "You marked this 3 times as routine for codex." in dom_file and "my own test key" in dom_file)
        check("menubar deep link #file= opens the file drawer",
              'data-action="file-reveal"' in dom_filedeep and "Around the secret" in dom_filedeep)
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
        nfp = pre(dom_notifyfocus, "notify-focus-probe")
        check("notify add-scope input survives a reconcile that changes notifyCfg: same node, value and focus",
              nfp == "same=true value=in-progress-edit focused=true probe=1", f"probe={nfp!r}")

        # --- connection states (the "trouble connecting" regressions) ---
        check("auth-expired shows the ended state, not 'daemon down'",
              'id="session-ended" role="alert">' in dom_authfail
              and "Console session ended." in dom_authfail
              and "Open it again from the Secure Agent menu bar." in dom_authfail
              and "Can&#x27;t reach the Secure Agent daemon" not in dom_authfail.split('id="session-ended"', 1)[1].split('</section>', 1)[0])
        check("a 403 hides the posture, counts and panels and closes the stream",
              'class="is-ended"' in dom_authfail
              and re.search(r'<section class="posture" id="posture-banner"[^>]*\bhidden\b', dom_authfail) is not None
              and re.search(r'<main[^>]*\bhidden\b', dom_authfail) is not None
              and '<pre id="sse-state" hidden="">closed</pre>' in dom_authfail,
              (re.search(r'<pre id="sse-state"[^>]*>[^<]*</pre>', dom_authfail) or [None])[0])
        nt_fetches = (re.search(r'<pre id="fetch-count"[^>]*>(\d+)</pre>', dom_notoken) or [None, "missing"])[1]
        check("no token at load: only the ended state, no posture, zero fetches, no stream",
              'id="session-ended" role="alert">' in dom_notoken
              and re.search(r'<section class="posture" id="posture-banner"[^>]*\bhidden\b', dom_notoken) is not None
              and re.search(r'<section class="statstrip"[^>]*\bhidden\b', dom_notoken) is not None
              and nt_fetches == "0" and 'id="sse-state"' not in dom_notoken,
              f"fetches={nt_fetches}")
        check("a token at load: the console renders, the ended state stays hidden",
              'id="session-ended" role="alert" hidden' in dom and 'id="count-agents">3<' in dom)
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
        tab_ids = re.findall(r'class="tab-btn[^"]*" data-tab="(\w+)"', dom)
        tab_labels = re.findall(r'data-tab="\w+" role="tab"[^>]*>\s*<svg[^>]*>.*?</svg><span>([^<]+)</span>', dom, re.S)
        check("tab bar renders exactly four tabs, Home first",
              dom.count('class="tab-btn') == 4 and tab_ids == ["home", "sessions", "egress", "policy"]
              and tab_labels == ["Home", "Sessions", "Egress", "Policy"], f"ids={tab_ids} labels={tab_labels}")
        check("the attention panel lives in Home, first",
              dom.index('id="tab-home"') < dom.index('id="attention-center"') < dom.index('id="spend-card"')
              < dom.index('id="home-findings"') < dom.index('id="home-trends"') < dom.index('id="tab-sessions"'))
        check("home tab active by default",
              'class="tab-btn active" data-tab="home"' in dom)
        check("non-active panels hidden",
              'id="tab-sessions" role="tabpanel" hidden' in dom
              and 'id="tab-egress" role="tabpanel" hidden' in dom
              and 'id="tab-policy" role="tabpanel" hidden' in dom)
        check("home panel visible",
              'id="tab-home" role="tabpanel">' in dom)
        check("home groups are closed by default",
              '<details class="home-group" id="home-findings" data-group="findings">' in dom
              and '<details class="home-group" id="home-trends" data-group="trends">' in dom)
        check("hash #agents opens Sessions on the Processes sub-view",
              'class="tab-btn active" data-tab="sessions"' in dom_hashagents
              and 'class="subtab-btn active" data-subtab="processes"' in dom_hashagents
              and 'id="sub-processes" role="tabpanel">' in dom_hashagents
              and 'id="sub-board" role="tabpanel" hidden' in dom_hashagents
              and 'id="tab-sessions" role="tabpanel">' in dom_hashagents)
        check("hash #findings opens Home",
              'class="tab-btn active" data-tab="home"' in dom_hashfindings
              and 'id="tab-home" role="tabpanel">' in dom_hashfindings)
        trends = (re.search(r'<pre id="trends-probe"[^>]*>(.*?)</pre>', dom_trends, re.S) or [None, ""])[1]
        tm = re.match(r"closed\(open=false\):activity=(\d+),chart-flags=(\d+),chart-memory=(\d+) \| opened:activity=(\d+),chart-flags=(\d+),chart-memory=(\d+)$", trends)
        check("Trends closed: its chart panels render 0 times through a burst, then render when opened",
              tm is not None and tm.group(1, 2, 3) == ("0", "0", "0") and all(int(x) >= 1 for x in tm.group(4, 5, 6)),
              f"probe={trends!r}")
        # renderAll() (boot, Refresh, search) must not paint a panel that
        # isn't on screen: absolute render count 0 for the Trends charts and
        # the Sessions/Resources sub-view through all three, then >= 1 once
        # each is actually shown.
        hrp = (re.search(r'<pre id="hidden-render-probe"[^>]*>(.*?)</pre>', dom_hiddenrender, re.S) or [None, ""])[1]
        hrp_stages = dict(re.findall(r'(boot|refresh|search|shown):((?:[a-z-]+=\d+,?)+)', hrp))
        def hrp_zero(stage):
            counts = dict(re.findall(r'([a-z-]+)=(\d+)', hrp_stages.get(stage, '')))
            return len(counts) == 4 and all(v == '0' for v in counts.values())
        def hrp_shown():
            counts = dict(re.findall(r'([a-z-]+)=(\d+)', hrp_stages.get('shown', '')))
            return len(counts) == 4 and all(int(v) >= 1 for v in counts.values())
        check("hidden panels (Trends charts, Sessions/Resources) render 0 times across boot, Refresh and search, then render once shown",
              hrp_zero('boot') and hrp_zero('refresh') and hrp_zero('search') and hrp_shown(),
              f"probe={hrp!r}")
        def policy_rows(kind):
            block = dom_policylists.split(f'data-policy="{kind}"', 1)
            return block[1].split('</div></div></div>', 1)[0].count('class="policy-row"') if len(block) == 2 else -1
        check("Policy lists guard decisions, file exceptions and muted classes from their endpoints",
              'class="tab-btn active" data-tab="policy"' in dom_policylists
              and policy_rows("guard") == 2 and policy_rows("path") == 1 and policy_rows("mute") == 2
              and 'id="badge-guard-rules">2<' in dom_policylists and 'id="badge-path-allows">1<' in dom_policylists
              and '.env.example</code>' in dom_policylists and "keychain-security-cli" in dom_policylists.split('data-policy="mute"', 1)[-1],
              f"guard={policy_rows('guard')} path={policy_rows('path')} mute={policy_rows('mute')}")
        check("Policy empty lists say what fills them",
              "No guard decisions yet." in dom_policyempty and "No file exceptions yet." in dom_policyempty
              and "No muted flag classes." in dom_policyempty)
        check("notification rules live in the Policy tab; the bell links there",
              dom.index('id="tab-policy"') < dom.index('id="notify-rules-list"')
              and 'id="btn-notify" data-action="goto-tab" data-tab="policy"' in dom
              and dom.index('id="tab-policy"') < dom.index('id="audit-panel"'))
        check("resource mission control is present", 'id="resource-mission-control"' in dom)
        # The live Resources tab ends where the History tab begins: the flight
        # recorder moved out, so it must NOT be inside the resource view.
        resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
        history_view = dom.split('id="history-panel"', 1)[1].split('id="sub-worktrees"', 1)[0]
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
        check("resource action opens the family in place",
              'data-action="view-family" data-key="5821:1789480800000000000"' in resource_view
              and 'data-action="filter-pids"' not in resource_view)
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
        # --- resources v2: strip, needs attention, harness groups, family drawer ---
        board = dom_fam.split('id="resource-board"', 1)[1].split('id="history-panel"', 1)[0]
        check("resources: the machine strip renders four tiles",
              'class="machine-strip' in board and board.count('class="machine-tile') == 4,
              f"tiles={board.count('class=\"machine-tile')}")
        attn = board.split('class="needs-attention"', 1)[1].split('</section>', 1)[0] if 'class="needs-attention"' in board else ''
        attn_keys = re.findall(r'class="resource-session-card needs-attention-card[^"]*" data-key="([^"]+)"', attn)
        check("resources: needs attention holds exactly the two diagnosed families, highest impact first",
              attn_keys == ["5821:1789480800000000000", "6033:1789484400000000000"], f"keys={attn_keys}")
        fam_groups = re.findall(r'<details class="family-group( infra)?" data-harness="([^"]+)"', board)
        check("resources: infra is the one trailing group",
              bool(fam_groups) and fam_groups[-1] == (" infra", "infra") and sum(1 for g in fam_groups if g[0]) == 1,
              f"groups={fam_groups}")
        infra_grp = board.split('data-harness="infra"', 1)[1] if 'data-harness="infra"' in board else ''
        check("resources: infra families sit in Infrastructure and are not counted as families",
              all(f'data-key="{p}:1789470000000000000"' in infra_grp for p in (7001, 7100, 7200))
              and '9 families' in board and '12 families' not in board)
        oc_grp = board.split('data-harness="openclaw"', 1)[1].split('<details', 1)[0] if 'data-harness="openclaw"' in board else ''
        oc_kids = oc_grp.split('class="family-children"', 1)[1] if 'class="family-children"' in oc_grp else ''
        codex_grp = board.split('data-harness="codex"', 1)[1].split('<details', 1)[0] if 'data-harness="codex"' in board else ''
        check("resources: orchestrated children nest under their OpenClaw parent, not as codex rows",
              'data-key="8100:1789470000000000000"' in oc_grp.split('class="family-children"', 1)[0]
              and 'data-key="8201:1789470000000000000"' in oc_kids and 'data-key="8202:1789470000000000000"' in oc_kids
              and '8201:' not in codex_grp and 'Codex · career-ops@main' in oc_kids)
        check("resources: rows and cards carry names, never root PID",
              'root PID' not in board and 'Claude Code · api-service@main' in board
              and 'Codex · data-pipeline@feat/etl' in board)
        check("resources: a group opens by default only when a family in it needs attention",
              '<details class="family-group" data-harness="claude" open=""' in board
              and '<details class="family-group" data-harness="codex">' in board
              and '<details class="family-group infra" data-harness="infra">' in board)
        check("resources: policy line sits below the groups",
              'data-harness="infra"' in board and 'class="resource-policy"' in board
              and board.index('data-harness="infra"') < board.index('class="resource-policy"'))
        fam_drawer = dom_fam.split('<div id="drawer"', 1)[1].split('id="confirm-layer"', 1)[0]
        fam_probe = (re.search(r'<pre id="family-probe"[^>]*>(.*?)</pre>', dom_fam, re.S) or [None, ""])[1]
        check("View family opens the drawer with the family name; the tab stays Resources",
              dom_fam.count('<div id="drawer" class="drawer">') == 1
              and 'id="drawer-title-text">Codex · data-pipeline@feat/etl<' in fam_drawer
              and 'class="tab-btn active" data-tab="sessions"' in dom_fam
              and 'class="subtab-btn active" data-subtab="resources"' in dom_fam)
        check("family drawer: the process table shows 12 rows and Show 8 more, then expands in place",
              fam_probe == "rows=12 more=Show 8 more" and fam_drawer.count('class="family-proc-row') == 20
              and 'data-action="show-more"' not in fam_drawer, f"probe={fam_probe!r} rows={fam_drawer.count('class=\"family-proc-row')}")
        check("family drawer: leftover marked, recent activity and findings scoped to the family",
              'family-proc-row orphan' in fam_drawer and 'Bash → pytest -q' in fam_drawer
              and 'npm install' not in fam_drawer and 'Keychain file access' in fam_drawer)
        check("family drawer: footer offers Terminate orphans and Terminate family on the root",
              'data-action="kill-family-orphans" data-key="4412:1789470000000000000"' in fam_drawer
              and 'Terminate orphans (1)' in fam_drawer and 'data-action="kill" data-pid="4412"' in fam_drawer)
        ev_scoped = dom_famev.split('id="events-container"', 1)[1].split('</section>', 1)[0]
        ev_pids = set(int(x) for x in re.findall(r'<span class="pid" title="PID (\d+)"', ev_scoped))
        check("Open in Events switches to Events scoped to the family pids",
              'class="subtab-btn active" data-subtab="events"' in dom_famev
              and len(ev_pids) >= 2 and ev_pids <= set(range(4412, 4432)), f"pids={sorted(ev_pids)}")
        ev_cap = dom_evcap.split('id="events-container"', 1)[1].split('</section>', 1)[0]
        check("Events tab shows the newest 50 rows and a Show more button",
              ev_cap.count('class="timeline-item') == 50
              and re.search(r'data-action="show-more" data-key="events"[^>]*>Show \d+ more<', ev_cap) is not None,
              f"rows={ev_cap.count('class=\"timeline-item')}")
        ev_trace = dom_evtrace.split('id="events-container"', 1)[1].split('</section>', 1)[0]
        check("Events rows name trace kinds: MODEL and TOOL with their session, never PID 0",
              '>MODEL<' in ev_trace and '>TOOL<' in ev_trace and 'Bash · ok · 2.5s' in ev_trace
              and 'claude-sonnet-4-5 · 12.0k in / 340 out · $0.04' in ev_trace
              and 'api-service@main' in ev_trace and 'PID 0' not in ev_trace,
              f"model={'>MODEL<' in ev_trace} tool={'>TOOL<' in ev_trace} pid0={'PID 0' in ev_trace}")
        ev_dup = dom_duptrace.split('id="events-container"', 1)[1].split('</section>', 1)[0]
        check("Events: two tool calls at the same ts with different call ids render as two rows",
              ev_dup.count('class="timeline-item') >= 2 and 'Read · ok' in ev_dup and 'Write · ok' in ev_dup,
              f"rows={ev_dup.count('class=\"timeline-item')}")
        ev_order = dom_evorder.split('id="events-container"', 1)[1].split('</section>', 1)[0]
        # The SSE stub drips unrelated live rows (kinds 5/8/9) into every dump
        # regardless of fixture; keep only this fixture's three file rows and
        # check their relative order (the drip's own newer rows lead them).
        order_rows = re.findall(r'<div class="timeline-item[^"]*">.*?</div>', ev_order, re.S)
        order_names = [m.group(1) for r in order_rows if (m := re.search(r'/(\w+)\.ts<', r))]
        old_row = next((r for r in order_rows if 'old.ts' in r), '')
        old_dated = re.search(r'<span class="t">[A-Za-z]{3} \d{2} \d{2}:\d{2}</span>', old_row) is not None
        check("Events: out-of-order rows sort newest first and the 4-month-old row shows a date, not a clock time",
              order_names == ['new', 'mid', 'old'] and old_dated,
              f"order={order_names} old_dated={old_dated}")
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
              and dom.index('id="session-board"') < dom.index('id="sub-processes"'))
        check("home has no session board",
              'id="session-board"' not in dom.split('id="tab-home"', 1)[1].split('id="tab-sessions"', 1)[0])
        overview = dom.split('id="home-trends"', 1)[1].split('id="tab-sessions"', 1)[0]
        # Trends is charts-only: the activity chart plus the two ranked-bar
        # charts. Lists (sessions/agents/flags/events) live elsewhere.
        check("trends lead with the activity chart", 'id="activity-chart"' in overview)
        check("trends have the findings-by-rule chart", 'id="chart-flags"' in overview)
        check("trends have the memory-by-family chart", 'id="chart-memory"' in overview)
        mem_bars = dom_memfam.split('id="chart-memory"', 1)[1].split('</section>', 1)[0].split('class="hbar-row"')[1:]
        mem_badge = re.search(r'id="chart-mem-total">(\d+)<', dom_memfam)
        check("memory by family: three sessions on one root are one bar carrying 3 sessions",
              len(mem_bars) == 4 and sum('api-service@main · 3 sessions' in b for b in mem_bars) == 1,
              f"bars={len(mem_bars)}")
        mem_infra = sum('class="hbar-sub">infra<' in b for b in mem_bars)
        check("memory by family: the badge counts agent families, not sessions or infra",
              mem_badge is not None and mem_infra == 1 and int(mem_badge.group(1)) == len(mem_bars) - mem_infra == 3,
              f"{mem_badge.group(0) if mem_badge else 'no badge'} infra={mem_infra}")
        check("trends carry no list panels",
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
        needs_you = int(re.search(r"needs_you: (\d+),", open(MOCK).read()).group(1))
        check("home tab badge shows needs-you count",
              f'id="tab-badge-home">{needs_you}<' in dom)
        check("sessions and processes counts sit on the sub-view buttons; the Sessions tab keeps the live count",
              re.search(r'id="subtab-badge-board">\d+<', dom) is not None
              and re.search(r'id="subtab-badge-processes">\d+<', dom) is not None
              and (re.search(r'id="tab-badge-sessions">(\d+)<', dom) or [None, "a"])[1]
              == (re.search(r'id="subtab-badge-board">(\d+)<', dom) or [None, "b"])[1])
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
              f'id="tab-badge-home">{needs_you - 1}<' in dom_guard
              and 'data-action="guard-resolve" data-id="guard-1"' not in dom_guard)
        resolve_probe = (re.search(r'<pre id="resolve-probe"[^>]*>(.*?)</pre>', dom_resolve, re.S) or [None, ""])[1]
        check("resolved incident leaves the attention count before reconciliation",
              resolve_probe == f"badge={needs_you - 1} tab={needs_you - 1} queued=false", f"probe={resolve_probe!r}")
        check("posture flag item opens Home with Findings history",
              'data-action="goto-tab" data-tab="home" data-group="findings"' in dom_tab)
        check("tab switch reveals the target panel",
              'id="tab-egress" role="tabpanel">' in dom_tab
              and 'id="tab-home" role="tabpanel" hidden' in dom_tab)
        # Sessions holds one sub-view at a time.
        check("resources and events are separate sub-views",
              'id="sub-resources" role="tabpanel" hidden' in dom
              and 'id="sub-events" role="tabpanel" hidden' in dom
              and 'class="subtabs" role="tablist"' in dom)
        check("pressure history sits in the Resources sub-view",
              dom.index('id="sub-resources"') < dom.index('id="history-panel"') < dom.index('id="sub-worktrees"'))
        check("resource panel lives in the resources sub-view",
              dom.index('id="sub-resources"') < dom.index('id="resource-board"')
              and dom.index('id="resource-board"') < dom.index('id="history-panel"'))
        check("flight recorder lives in the resources sub-view",
              dom.index('id="history-panel"') < dom.index('id="history-board"')
              and dom.index('id="history-board"') < dom.index('id="sub-worktrees"'))
        check("event timeline lives in the events sub-view",
              dom.index('id="sub-events"') < dom.index('id="events-container"')
              and dom.index('id="events-container"') < dom.index('id="tab-egress"'))

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
        link_rail = dom_sesslink.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
        check("View session in timeline opens the session in the Sessions tab: card selected, trace rendered",
              'class="tab-btn active" data-tab="sessions"' in dom_sesslink
              and re.search(r'<div class="session-card active selected">\s*<button type="button" class="sc-main" '
                            r'data-action="select-session" data-id="sess-claude-1" aria-pressed="true"', link_rail) is not None
              and '<h3>api-service@main</h3>' in dom_sesslink.split('id="session-detail"', 1)[1]
              and 'class="wf-bar' in dom_sesslink)
        check("session chip appears", 'id="session-filter" class="session-filter"' in dom_session
              or ('id="session-filter"' in dom_session and "hidden" not in
                  dom_session.split('id="session-filter"')[1][:80]))
        check("session chip count", "7f3a9c21 · 2" in dom_session)
        check("session scopes findings list",
              'id="flags-session-filter"' in dom_session
              and "hidden" not in dom_session.split('id="flags-session-filter"')[1][:80])
        session_rows = dom_session.count('class="timeline-item')
        check("timeline filtered to 2 session events", session_rows == 2, f"rows={session_rows}")

        # --- render engine: dirty, visible panels only; patch in place ---
        counts_raw = pre(dom_burst, "render-counts")
        try:
            counts = json.loads(counts_raw)
        except ValueError:
            counts = None
        check("burst: hidden-tab panels never render (sessions, agents, firewall = 0)",
              counts is not None and all(counts.get(k, 0) == 0 for k in ("sessions", "agents", "firewall")),
              f"counts={counts_raw[:200]}")
        check("burst: flags renders at most once per flag frame (1..3)",
              counts is not None and 1 <= counts.get("flags", 0) <= 3, f"counts={counts_raw[:200]}")

        infra_tag = re.search(r'<details class="session-group infra"[^>]*>', dom_railburst)
        infra_tag = infra_tag.group(0) if infra_tag else ""
        check("burst: an opened rail <details> is the same node and still open",
              ' open=""' in infra_tag and 'data-probe="1"' in infra_tag, f"tag={infra_tag}")

        flags_focus = dom_focus.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
        check("burst: a focused flag-card button keeps identity and focus",
              'data-probe="1"' in flags_focus and pre(dom_focus, "focus-probe") == "kept",
              f"probe={pre(dom_focus, 'focus-probe')!r}")

        mem_probe = re.match(r"renders=(\d+) kept=(\d+)/(\d+)$", pre(dom_memprobe, "mem-probe"))
        check("memory by family: a re-render keeps every unchanged family row as the same node",
              mem_probe is not None and int(mem_probe.group(1)) >= 1 and int(mem_probe.group(3)) == 4
              and mem_probe.group(2) == mem_probe.group(3),
              f"probe={pre(dom_memprobe, 'mem-probe')!r}")

        flags_click = dom_click.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
        check("burst: a click spanning renders lands (POST /flags/acknowledge, card gone)",
              "POST /flags/acknowledge" in pre(dom_click, "mock-requests") and 'data-id="flag-3"' not in flags_click,
              f"requests={pre(dom_click, 'mock-requests')!r}")

        raw_reqs = pre(dom_rawmute, "mock-requests")
        check("raw card mute carries the flag's agent (no global mute)",
              'POST /mute body={"rule":"keychain-access","host":"*","agent":"codex"}' in raw_reqs,
              f"requests={raw_reqs!r}")
        check("mutes ledger: a new scoped mute keeps the focused unmute button",
              pre(dom_rawmute, "mute-focus-probe") == "kept rows=3",
              f"probe={pre(dom_rawmute, 'mute-focus-probe')!r}")

        act_row = dom_act.split("registry.npmjs.org · cursor", 1)[-1].split("</div>", 1)[0] \
            if "registry.npmjs.org · cursor" in dom_act else ""
        check("act in place: allowlist row on screen when the request leaves, with an inline note",
              "POST /allowlist row=1" in pre(dom_act, "mock-requests") and 'class="card-note"' in act_row,
              f"requests={pre(dom_act, 'mock-requests')!r} row={act_row[:160]!r}")
        check("act in place: a failed allow reverts the row and toasts danger",
              "POST /allowlist row=1" in pre(dom_actfail, "mock-requests")
              and "registry.npmjs.org · cursor" not in dom_actfail
              and 'class="toast danger"' in dom_actfail
              and 'data-action="allow-host" data-agent="cursor" data-host="registry.npmjs.org"' in dom_actfail,
              f"requests={pre(dom_actfail, 'mock-requests')!r}")

        # --- finding card v2: the daemon's served explanation ---
        def visible(markup):
            return re.sub(r"<[^>]*>", " ", markup)

        card = (re.search(r'<article class="finding [^"]*" data-flag-id="flag-2">.*?</article>', dom_explain, re.S)
                or [""])[0]
        head = (re.search(r"<header[^>]*>(.*?)</header>", card, re.S) or [None, ""])[1]
        outside = re.sub(r"<details.*?</details>", "", card, flags=re.S)
        check("finding card: header shows the title, never the rule id; no pid or IPv6 outside Details",
              card != "" and "Agent read a secret, then connected out" in head
              and "sensitive-read-then-connect" not in visible(head)
              and not re.search(r"\bpid\b", visible(outside), re.I) and "6033" not in visible(outside)
              and "2606:" not in visible(outside), f"card={card[:240]!r}")
        check("finding card carries no inline handlers or styles",
              card != "" and " onclick=" not in card and " style=" not in card)
        buttons = re.findall(r'<button class="btn ([a-z-]+) btn-sm" data-action="explain-act" '
                             r'data-flag-id="flag-2" data-action-id="([a-z-]+)"', card)
        check("finding card: who, what and verdict lines; the recommended action is the first, primary button",
              "cursor · web-app@main" in head and "3 s gap" in head
              and '<p class="finding-what">Cursor read AWS credentials (~/.aws/credentials), then reached Cloudflare 3 s later.</p>' in card
              and '<p class="finding-verdict">Likely benign (advisor 93 %): Cloudflare fronts the package registry this project installs from.</p>' in card
              and buttons == [("btn-primary", "allow-host"), ("btn-ghost", "allow-path"), ("btn-ghost", "dismiss"), ("btn-danger", "kill")],
              f"buttons={buttons}")
        details = (re.search(r'<details class="finding-details">(.*?)</details>', card, re.S) or [None, ""])[1]
        check("finding card: Details is closed by default and holds the chain, pid, full address and ISO timestamp",
              details != "" and 'class="chain"' in details and "2026-09-22T16:05:01Z" in details
              and "6033" in details and "[2606:4700::6810:84e5]:443" in details
              and "/Users/dev/.aws/credentials" in details, f"details={details[:200]!r}")

        act_reqs = pre(dom_explainact, "mock-requests")
        flags_act = dom_explainact.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
        check("finding card: the recommended action sends the served request; the card leaves with an inline note",
              'POST /allowlist' in act_reqs
              and 'body={"agent":"cursor","host":"2606:4700::6810:84e5"}' in act_reqs
              and 'POST /flags/acknowledge' in act_reqs
              and 'data-flag-id="flag-2"' not in flags_act
              and 'class="card-note">allowlisted<' in dom_explainact, f"requests={act_reqs!r}")
        allowpath_reqs = pre(dom_allowpathact, "mock-requests")
        check("finding card: the allow-path action (not the first/recommended button) sends its own served request",
              'POST /guard/path-allow body={"agent":"cursor","rule_id":"cloud-creds","path":"/Users/dev/.aws/credentials"}' in allowpath_reqs
              and 'POST /allowlist' not in allowpath_reqs,
              f"requests={allowpath_reqs!r}")
        fail_reqs = pre(dom_explainfail, "mock-requests")
        flags_fail = dom_explainfail.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
        check("finding card: a failed allow puts the card back and toasts danger",
              'POST /allowlist' in fail_reqs and 'POST /flags/acknowledge' not in fail_reqs
              and '<article class="finding disp-benign" data-flag-id="flag-2">' in flags_fail
              and 'class="toast danger"' in dom_explainfail, f"requests={fail_reqs!r}")

        attn = dom_explain.split('id="attention-center"', 1)[-1].split('id="security-findings-grid"', 1)[0]
        attn_groups = re.findall(r'<article class="attention-group([^"]*)">(.*?)</article>', attn, re.S)
        flag2_groups = [(cls, body) for cls, body in attn_groups if 'data-flag-id="flag-2"' in body]
        check("attention: the flag item shows who, what, verdict and the served actions; benign-likely is not urgent",
              len(flag2_groups) == 1 and "urgent" not in flag2_groups[0][0]
              and 'class="attention-item kind-flag finding-item disp-benign"' in flag2_groups[0][1]
              and "cursor · web-app@main" in flag2_groups[0][1]
              and "Cursor read AWS credentials (~/.aws/credentials), then reached Cloudflare 3 s later." in flag2_groups[0][1]
              and "Likely benign (advisor 93 %): Cloudflare fronts" in flag2_groups[0][1]
              and 'data-action="explain-act" data-flag-id="flag-2" data-action-id="allow-host"' in flag2_groups[0][1]
              and 'data-action="dismiss-flag" data-id="flag-2"' not in flag2_groups[0][1],
              f"groups={[c for c, _ in attn_groups]}")
        probe = pre(dom_detailsprobe, "details-probe")
        ages = re.match(r"kept (.+) \| (.+)$", probe)
        check("finding card: an open Details survives re-renders while the age ticks in place",
              ages is not None and ages.group(1) != ages.group(2) and ages.group(2).endswith(" ago"),
              f"probe={probe!r}")
        check("finding card: flags without explain keep the legacy card",
              dom_explain.count('class="flag-card') == 2
              and "proxy-secret-leak — cursor (PID 6033)" in dom_explain
              and 'data-action="dismiss-flag" data-id="flag-3"' in dom_explain)

        # --- navigation: sticky tabs, drawer back-stack, scope bar, one count ---
        sticky = pre(dom_sticky, "sticky-probe")
        m = re.match(r"top=(-?\d+) scroll=(\d+) stuck=(\w+) pill=(\w+):(.*)$", sticky)
        check("sticky tabs: after scrolling 5000 px on Attention the tablist sits at the top with the posture pill",
              m is not None and 0 <= int(m.group(1)) < 60 and int(m.group(2)) > 0 and m.group(3) == "true"
              and m.group(4) == "visible" and m.group(5) == f"{needs_you} need you", f"probe={sticky!r}")
        back = pre(dom_drawerback, "drawer-back-probe")
        m = re.match(r"chained: back=(.*) title=(.*) \| back: title=(.*) rows=(\d+) button=(\w+) open=(\w+)$", back)
        check("drawer back: Evidence from the Uninspected drawer shows ‹ Uninspected egress; Back reopens the list",
              m is not None and m.group(1) == "‹ Uninspected egress" and m.group(2) == "Endpoint detail"
              and m.group(3) == "Uninspected egress — last 24h" and int(m.group(4)) > 0
              and m.group(5) == "absent" and m.group(6) == "true", f"probe={back!r}")
        scope = pre(dom_scope, "scope-probe")
        m = re.match(r"tab=(\w+) bar=(\w+):(.*) \| scoped rows=(\d+) \| cleared bar=(\w+):(.*) rows=(\d+) chip=(\w+)$", scope)
        check("scope bar: View session shows the scope on Sessions; Clear hides it and Events shows every row",
              m is not None and m.group(1) == "sessions" and m.group(2) == "visible"
              and m.group(3).startswith("Scoped to session ") and re.search(r" · \d+ events? · \d+ flags?Clear$", m.group(3))
              and m.group(5) == "hidden" and m.group(6) == "" and int(m.group(7)) > int(m.group(4))
              and m.group(8) == "hidden", f"probe={scope!r}")
        attention_badge = (re.search(r'id="badge-attention-count"[^>]*>(\d+)<', dom) or [None, ""])[1]
        tab_badge = (re.search(r'id="tab-badge-home"[^>]*>(\d+)<', dom) or [None, ""])[1]
        check("attention badge and tab badge equal posture.needs_you; the machine group renders",
              attention_badge == str(needs_you) and tab_badge == str(needs_you)
              and '<strong>This machine</strong>' in dom and 'data-action="open-fda"' in attention
              and 'data-action="dismiss-flag" data-id="flag-5"' in attention,
              f"badge={attention_badge!r} tab={tab_badge!r} needs_you={needs_you}")

        # --- patterns: a repeating finding is one card ---
        pat_attn = dom_pattern.split('id="attention-center"', 1)[-1].split('id="security-findings-grid"', 1)[0]
        pat_cards = re.findall(r'<article class="finding pattern-card [^"]*" data-pattern-key="([^"]+)">(.*?)</article>', pat_attn, re.S)
        check("patterns: Attention shows the storm as one pattern card with its count, summary, 24 bars and open count",
              len(pat_cards) == 1 and "323×" in pat_cards[0][1]
              and "codex touched the login keychain 323 times" in pat_cards[0][1]
              and len(re.findall(r'<i class="h\d"></i>', pat_cards[0][1])) == 24
              and '<b class="pattern-open">323 open</b>' in pat_cards[0][1]
              and 'data-id="flag-6"' not in pat_attn and 'data-id="flag-7"' not in pat_attn,
              f"cards={len(pat_cards)}")
        pat_flags = dom_pattern.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
        check("patterns: the Flags list leads with the pattern and has no card for a covered flag",
              'data-pattern-key="codex|keychain-access|' in pat_flags
              and pat_flags.index('data-pattern-key=') < pat_flags.index('class="flag-card')
              and not any(f'data-id="{fid}"' in pat_flags or f'data-flag-id="{fid}"' in pat_flags for fid in ("flag-6", "flag-7"))
              and "(PID 40844)" not in pat_flags and "(PID 51364)" not in pat_flags
              and 'data-id="flag-3"' in pat_flags)
        pat_reqs = pre(dom_patternact, "mock-requests")
        check("patterns: dismiss-all posts the served flag_ids and the card shows 0 open",
              'POST /flags/acknowledge body={"flag_ids":["flag-7","flag-6"]}' in pat_reqs
              and re.search(r'<article class="finding pattern-card [^"]*"[^>]*>.*?<b class="pattern-open">0 open</b>', dom_patternact, re.S) is not None
              and '<b class="pattern-open">323 open</b>' not in dom_patternact,
              f"requests={pat_reqs!r}")
        check("patterns: the page still fits a 375px phone, the pattern card's tab included",
              'data-hscroll="sessions:0,agents:0,resources:0,findings:0"' in dom_patternphone,
              (re.search(r'data-hscroll="[^"]*"', dom_patternphone) or [None])[0])
        stream = pre(dom_patternstream, "pattern-stream-probe")
        check("patterns: a streamed flag the pattern covers folds into its one card after the debounced reconcile",
              stream == "mid cards=1 covered=0 row=1 | end cards=1 covered=1 row=0", f"probe={stream!r}")
        keep = pre(dom_attnkeep, "attn-probe")
        check("attention: an open pattern disclosure and a focused button survive a group RSS change",
              keep.startswith("open=true focus=true metrics=") and "memory" in keep, f"probe={keep!r}")

        # --- worktrees: the hunter's report, one row per worktree ---
        def wt_block(dom_text):
            return dom_text.split('id="worktrees-container"', 1)[-1].split('data-action="clutter-rescan"', 1)[0]

        def cl_block(dom_text):
            return dom_text.split('id="clutter-container"', 1)[-1].split('id="sub-events"', 1)[0]
        wt = wt_block(dom_wt)
        wt_rows = wt.count('class="wt-row')
        wt_remove = wt.count('data-action="worktree-remove"')
        wt_prune = wt.count('data-action="worktree-prune"')
        check("worktrees: tab opens and renders a row per non-main worktree with its state",
              'class="subtab-btn active" data-subtab="worktrees"' in dom_wt and wt_rows == 4
              and all(f'class="wt-row wt-{s}"' in wt for s in ("remove", "review", "keep", "prune"))
              and "main worktree of the repository" not in wt,
              f"rows={wt_rows}")
        check("worktrees: Remove only on the remove row, Prune only on the prune row",
              wt_remove == 1 and wt_prune == 1
              and 'data-action="worktree-remove" data-path="/Users/dev/workspace/api-service/.worktrees/done"' in wt,
              f"remove={wt_remove} prune={wt_prune}")
        check("worktrees: reasons render as text, paths inside the repo read relative",
              "&lt;b&gt;not bold&lt;/b&gt;" in wt and "<b>not bold</b>" not in wt
              and '<span class="wt-path" title="/Users/dev/workspace/api-service/.worktrees/done">.worktrees/done</span>' in wt)
        check("worktrees: state pills carry counts and the summary line reads the scan",
              'data-state="" aria-pressed="true">All <b>4</b></button>' in dom_wt
              and 'data-state="remove" aria-pressed="false">Remove <b>1</b></button>' in dom_wt
              and "1 repo · 4 worktrees · stale after 14 idle days · scanned in 4.2s" in dom_wt)
        check("worktrees: the advisor note renders escaped under its row; Ask advisor sits on review and keep rows only",
              '<p class="wt-advice"><b>Advisor: review</b> 60% · &lt;i&gt;look&lt;/i&gt; at .tmp before removing</p>' in wt
              and wt.count('data-action="worktree-advise"') == 2)
        check("worktrees: Ask the agent sits on review and keep rows; the latest answer shows under its row",
              wt.count('data-action="worktree-ask"') == 2
              and '<p class="wt-ask wt-ask-answered"><b>Asked claude:</b> pr — https://github.com/o/r/pull/9 ($0.21)</p>' in wt)
        check("worktrees: the disk card shows the volume, worktree and removable totals and what cleanups reclaimed",
              "512.0 GB free of 2.0 TB" in dom_wt and 'data-w="75"' in dom_wt
              and "<b>Worktrees</b> 1.5 GB" in dom_wt and "<b>Removable</b> 1.5 GB" in dom_wt
              and "<b>Reclaimed</b> 3.0 GB over 3 cleanups · 1.0 GB in 30 days" in dom_wt
              and '<span class="wt-size">1.5 GB</span>' in wt)
        check("worktrees: while the daemon is still measuring, the tab re-reads until sizes land",
              '<span class="wt-size">1.5 GB</span>' in wt_block(dom_wtsizing) and "measuring…" not in dom_wtsizing
              and "<b>Worktrees</b> 1.5 GB" in dom_wtsizing)
        cl = cl_block(dom_wt)
        check("clutter: items grouped by project with kind, size, idle; Trash and Run only where the item offers them",
              cl.count('class="wt-row cl-row') == 3
              and 'data-action="clutter-trash" data-path="/Users/dev/workspace/api-service/.tmp">Move to Trash</button>' in cl
              and 'data-action="clutter-clean" data-name="go build" title="go clean -cache">Run go clean -cache</button>' in cl
              and cl.count('data-action="clutter-trash"') + cl.count('data-action="clutter-clean"') == 2
              and "&lt;i&gt;downloaded&lt;/i&gt; models" in cl and "<i>downloaded</i>" not in cl
              and '<span class="wt-repo-path" title="This machine">This machine</span>' in cl)
        check("clutter: each project has Ask advisor; its plan renders escaped under the header with one step per line",
              cl.count('data-action="clutter-advise"') == 2
              and 'data-action="clutter-advise" data-project="machine">Ask advisor</button>' in cl
              and '<div class="wt-advice cl-plan"><b>Advisor:</b> &lt;b&gt;Old&lt;/b&gt; scratch holds most of it.'
                  '<ol><li>Move .tmp to the Trash</li><li>Ask the agent about feat/x</li></ol></div>' in cl
              and "Caches are small" not in cl)
        cla = cl_block(dom_clutteradvise)
        check("clutter: Ask advisor posts /cleanup/advise and the plan appears once the re-read has it",
              "POST /cleanup/advise" in pre(dom_clutteradvise, "mock-requests")
              and '<b>Advisor:</b> Caches are small; nothing urgent.<ol><li>Run go clean -cache</li></ol>' in cla)
        clr = cl_block(dom_clutter)
        check("clutter: Move to Trash posts after the dialog, drops the row and counts it as in the Trash",
              "POST /cleanup/trash" in pre(dom_clutter, "mock-requests") and "/api-service/.tmp" not in clr
              and "1.0 MB moved to the Trash by cleanups" in dom_clutter)
        wtr = wt_block(dom_wtremove)
        wtr_rows = wtr.count('class="wt-row')
        wt_reqs = pre(dom_wtremove, "mock-requests")
        check("worktrees: Remove posts /worktrees/remove after the dialog and drops the row in place",
              "POST /worktrees/remove" in wt_reqs and ".worktrees/done" not in wtr and wtr_rows == 3
              and "<b>Reclaimed</b> 4.5 GB over 4 cleanups" in dom_wtremove and "<b>Removable</b> 0 B" in dom_wtremove,
              f"requests={wt_reqs!r} rows={wtr_rows}")

        if args.screenshot:
            shot_dir = os.path.abspath(args.screenshot)
            os.makedirs(shot_dir, exist_ok=True)
            for name, query, themes in SHOTS:
                for theme in themes:
                    path = os.path.join(shot_dir, f"{name}-{theme}.png")
                    screenshot(chrome, origin, f"{query}&theme={theme}", path)
                    print(f"  shot  {path}")
    finally:
        if srv:
            srv.shutdown()
            srv.server_close()
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{len(passed)} passed, {len(failed)} failed")
    if failed:
        print("failed:", *failed, sep="\n  - ")
        sys.exit(1)


if __name__ == "__main__":
    main()
