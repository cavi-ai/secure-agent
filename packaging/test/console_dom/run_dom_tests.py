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
from html.parser import HTMLParser
from urllib.parse import parse_qsl
from dom_query import query as dom_query, starts_with
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import payload_cases

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


def pre(dom_text, pid):
    node = dom_query(dom_text).find('pre', {'id': pid})
    return node.inner_html if node else ''


def log_rows(dom_text):
    return {node.attrs['data-row-key']: node.html for node in dom_query(dom_text).find_all('li', {'class': 'log-row', 'data-row-key': None})}


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
    for f in ("index.html", "style.css", "lib.js", "event-history.js", "live-updates.js", "console-auth.js", "report-health.js", "telemetry-validation.js", "app.js",
              "tab-overview.js", "tab-sessions.js", "tab-agents.js", "tab-egress.js", "tab-findings.js",
              "tab-worktrees.js", "tab-agent.js", "theme-init.js", "icon.svg"):
        os.symlink(os.path.join(WEB_DIST, f), os.path.join(tmp, f))
    os.symlink(MOCK, os.path.join(tmp, "mock_dom.js"))
    os.symlink(os.path.join(os.path.dirname(MOCK), "fixtures.js"), os.path.join(tmp, "fixtures.js"))
    write_fixture(tmp, "")
    html = open(os.path.join(WEB_DIST, "index.html")).read()
    needle = '<script src="lib.js"></script>'
    assert needle in html, "lib.js script tag not found in index.html"
    html = html.replace(needle, needle + '\n  <script src="fixture-config.js"></script>\n  <script src="fixtures.js"></script>\n  <script src="mock_dom.js"></script>')
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


def write_fixture(tmp, query_string, fixture=None):
    # Legacy interaction probes select named scenarios. Payloads and scripted
    # responses are test-owned and can be declared without a driver edit.
    scenarios = []
    for key, value in parse_qsl(query_string.split('#', 1)[0].lstrip('?'), keep_blank_values=True):
        scenarios.append(key)
        if value:
            scenarios.append(f"{key}={value}")
    spec = {"scenarios": scenarios, **(fixture or {})}
    with open(os.path.join(tmp, "fixture-config.js"), "w") as stream:
        stream.write("window.CONSOLE_TEST = " + json.dumps(spec) + ";\n"
                     "if (window.parent !== window) {\n"
                     "  window.CONSOLE_TEST.scenarios = Array.from(new URLSearchParams(location.search), "
                     "([key, value]) => value ? [key, key + '=' + value] : [key]).flat();\n"
                     "}\n")


def dump_dom(chrome, tmp, query="", origin=None, window_size=None, reduced_motion=False, fixture=None):
    write_fixture(tmp, query, fixture)
    url = f"{origin or 'file://' + tmp}/harness.html{query}"
    size = [f"--window-size={window_size[0]},{window_size[1]}"] if window_size else []
    # Exercise both motion modes explicitly, independent of host accessibility settings.
    motion = "--force-prefers-reduced-motion" if reduced_motion else "--force-prefers-no-reduced-motion"
    with tempfile.TemporaryDirectory(prefix="chrome-profile-", dir=tmp) as profile:
        out = subprocess.run(
            [chrome, f"--user-data-dir={profile}", "--no-first-run", "--disable-background-networking", "--headless=new", "--disable-gpu", "--no-sandbox", *size, motion,
             "--virtual-time-budget=" + str(VIRTUAL_TIME_MS), "--dump-dom", url],
            capture_output=True, text=True, timeout=120,
        )
    if out.returncode != 0:
        print(out.stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"chrome --dump-dom failed ({out.returncode}): {url}")
    return out.stdout


SHOT_SIZE = (1280, 800)
SHOTS = (
    ("sessions", "?tab=sessions&shot&raildemo", ("dark", "light")),
    ("agents", "?tab=agents&shot", ("dark", "light")),
    ("overview", "?tab=overview&shot", ("dark",)),
    ("agent", "?tab=agent&shot", ("dark", "light")),
    ("worktrees-removing", "?tab=worktrees&shot&worktreedemo&removerunning", ("dark", "light")),
    ("worktrees-history", "?tab=worktrees&shot&historydemo", ("dark", "light")),
)


def screenshot(chrome, origin, query, path, tmp):
    write_fixture(tmp, query)
    with tempfile.TemporaryDirectory(prefix="chrome-profile-", dir=tmp) as profile:
        out = subprocess.run(
            [chrome, f"--user-data-dir={profile}", "--no-first-run", "--disable-background-networking", "--headless=new", "--disable-gpu", "--no-sandbox", "--hide-scrollbars",
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
                    help="also write {sessions,agents,agent}-{dark,light}.png and overview-dark.png of the mock-rendered tabs to DIR")
    ap.add_argument('--session-workbench-only', action='store_true', help='run bounded Sessions workbench interaction probes only')
    ap.add_argument('--auth-recovery-only', action='store_true', help='run console access recovery probes only')
    ap.add_argument('--spend-only', action='store_true', help='run bounded spend cache and refresh probes only')
    ap.add_argument('--session-results-only', action='store_true', help='run bounded session result and stale-read probes only')
    ap.add_argument('--context-handoff-only', action='store_true', help='run native record handoff probes only')
    ap.add_argument('--session-permissions-only', action='store_true', help='run bounded decision permission drawer probes only')
    ap.add_argument('--session-investigation-only', action='store_true', help='run bounded session investigation return probes only')
    ap.add_argument('--session-activity-only', action='store_true', help='run retained session activity probes only')
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
        if args.session_activity_only or not any((args.session_investigation_only, args.session_permissions_only, args.context_handoff_only, args.session_results_only, args.spend_only, args.auth_recovery_only, args.session_workbench_only)):
            for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
                dom = dump_dom(chrome, tmp, '?activitydemo', origin, window_size=size)
                receipt = re.search(r'data-activity-probe="([^"]+)"', dom)
                state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
                for name in ('endedEntry', 'outsideSnapshot', 'scopedRead', 'recordedRows', 'limitVisible', 'kindFilter', 'staleRetained', 'returnContext', 'returnFilters', 'forwardFilters', 'pageBound', 'failedPage', 'earlierPage', 'lastPage', 'newerPage', 'latestPage', 'forwardPage', 'fits'):
                    check(f'session activity ({label}): {name}', state.get(name) is True, str(state))
            if args.session_activity_only:
                print(f'\n{len(passed)} passed, {len(failed)} failed')
                if failed:
                    raise SystemExit(1)
                return
        if args.session_investigation_only or not (args.session_permissions_only or args.context_handoff_only or args.session_results_only or args.spend_only or args.auth_recovery_only or args.session_workbench_only):
            for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
                dom = dump_dom(chrome, tmp, '?investigationdemo', origin, window_size=size)
                receipt = re.search(r'data-investigation-probe="([^"]+)"', dom)
                state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
                for name in ('resourceEntry', 'resourceBack', 'evidenceEntry', 'evidenceBack', 'memoryFinding', 'memoryFindingBack', 'memoryIncident', 'memoryIncidentBack', 'memoryMissingflag', 'memoryMissingBackflag', 'memoryMissingincident', 'memoryMissingBackincident', 'memoryReadOnly', 'familyEvents', 'eventsBack', 'findings', 'clearRetainsReturn', 'findingsBack', 'forward', 'returnButton', 'fits', 'selectionCloses'):
                    check(f'session investigation ({label}): {name}', state.get(name) is True, str(state))
            if args.session_investigation_only:
                print(f'\n{len(passed)} passed, {len(failed)} failed')
                if failed:
                    raise SystemExit(1)
                return
        if args.session_permissions_only or not (args.session_investigation_only or args.context_handoff_only or args.session_results_only or args.spend_only or args.auth_recovery_only or args.session_workbench_only):
            for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
                dom = dump_dom(chrome, tmp, '?permissionsdemo', origin, window_size=size)
                receipt = re.search(r'data-permissions-probe="([^"]+)"', dom)
                state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
                check(f'session permissions ({label}): receipt produced', bool(state), str(state))
                for name in ('scoped', 'entryFocus', 'refreshFocus', 'refreshScroll', 'compactScroll', 'stale', 'cancel', 'revoked', 'fits', 'back', 'selectionCloses'):
                    result = state.get(name)
                    check(f'session permissions ({label}): {name}', result is True, str(state.get('scrollMismatch', result)) if name in ('refreshScroll', 'compactScroll') else str(result))
            if args.session_permissions_only:
                print(f'\n{len(passed)} passed, {len(failed)} failed')
                if failed:
                    raise SystemExit(1)
                return
        if args.context_handoff_only:
            for label, query, size in [('cold', '?contexthandoff&cold', (1280, 800)),
                                       ('reused narrow', '?contexthandoff', (375, 800))]:
                dom = dump_dom(chrome, tmp, query, origin, window_size=size)
                receipt = re.search(r'data-context-handoff="([^"]+)"', dom)
                state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
                check(f'context handoff ({label}): receipt produced', bool(state), str(state))
                for name, result in state.items():
                    check(f'context handoff ({label}): {name}', result is True, str(result))
            print(f'\n{len(passed)} passed, {len(failed)} failed')
            if failed:
                raise SystemExit(1)
            return
        if args.session_results_only or not (args.spend_only or args.auth_recovery_only or args.session_workbench_only):
            for label, query, size in [('desktop', '?resultsdemo', (1280, 800)), ('narrow stale', '?resultsdemo&resultsstale', (375, 800))]:
                dom = dump_dom(chrome, tmp, query, origin, window_size=size)
                detail = dom.split('id="session-detail"', 1)[1].split('id="session-board"', 1)[0]
                check(f'session results ({label}): receipts retain evidence and verification limits',
                      all(text in detail for text in ['Reviewed', 'revision 1', 'newer evidence', 'possible-exposure',
                                                     'Source evidence unavailable', 'Applied', 'Resource samples observed',
                                                     'External action reported', 'unverified']))
                check(f'session results ({label}): update preserves focused open receipt', dom_query(dom).has(None, {'data-results-focus': 'true'}))
                check(f'session results ({label}): layout fits viewport', dom_query(dom).has(None, {'data-results-fits': 'true'}))
                if 'stale' in label:
                    check('session results: failed refresh retains receipts with a visible retry', 'Last known results' in detail and 'Retry results' in detail)
            if args.session_results_only:
                print(f'\n{len(passed)} passed, {len(failed)} failed')
                if failed:
                    sys.exit(1)
                return
        if args.spend_only:
            cached = dump_dom(chrome, tmp, '?spendcachedemo', origin)
            check('spend: saved rows remain visible during a quiet cache refresh',
                  'notice=Refreshing usage… · saved 3h ago' in html.unescape(pre(cached, 'spend-cache-probe')))
            check('spend: fresh data replaces cached data and clears the indicator',
                  'id="count-spend">$37.67<' in cached
                  and dom_query(cached).has(None, {'id': 'spend-cache', 'class': 'spend-cache', 'role': 'status', 'hidden': ''}))
            delayed = dump_dom(chrome, tmp, '?spendshape', origin, fixture=payload_cases.delayed_spend())
            check('spend: delayed refresh retains totals and rows without warning banners',
                  'Refresh delayed · showing saved usage' in delayed
                  and 'id="count-spend">$36.67<' in delayed and 'api-service' in delayed
                  and 'Spend detail: Stale' not in delayed and 'Spend plans: Stale' not in delayed)
            first = dump_dom(chrome, tmp, '?spendshape&firstload', origin, fixture=payload_cases.delayed_spend())
            check('spend: unavailable first response retries without claiming empty computed usage',
                  'Usage is taking longer to load · retrying…' in first
                  and 'Refreshing usage…' in first and 'No priced model calls' not in first)
            recovered = dump_dom(chrome, tmp, '?spendshape&recover', origin, fixture=payload_cases.delayed_spend())
            check('spend: valid recovery clears the delayed state',
                  'Refresh delayed' in pre(recovered, 'spend-shape-before-recovery')
                  and dom_query(recovered).has(None, {'id': 'spend-cache', 'class': 'spend-cache', 'role': 'status', 'hidden': ''})
                  and 'id="count-spend">$36.67<' in recovered)
            cold = dump_dom(chrome, tmp, '?spendslowdemo', origin)
            check('spend: cold loading leaves sibling panels available',
                  html.unescape(pre(cold, 'spend-slow-probe')) == 'agents=3 spend=Refreshing usage…')
            print(f'\n{len(passed)} passed, {len(failed)} failed')
            if failed:
                sys.exit(1)
            return
        if not args.session_workbench_only:
            for label, query, size in [('memory', '?authrecover&authhistory', (1280, 800)),
                                       ('trace', '?authrecover&authtrace', (900, 768))]:
                recovery_dom = dump_dom(chrome, tmp, query, origin, window_size=size)
                receipt = re.search(r'data-auth-recovery="([^"]+)"', recovery_dom)
                state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
                check(f'console recovery ({label}): receipt produced', bool(state), str(state))
                for name, result in state.items():
                    check(f'console recovery ({label}): {name}', result is True, str(result))
            first_connect = dump_dom(chrome, tmp, '?notokenrecover', origin)
            check('credential handoff connects an initially unauthenticated tab without reload',
                  'id="count-agents">3<' in first_connect and not dom_query(first_connect).has(None, {'class': 'is-ended'})
                  and re.search(r'<section[^>]*id="session-ended"[^>]*\bhidden\b', first_connect) is not None)
            network_recovery = dump_dom(chrome, tmp, '?networkrecover', origin)
            check('connection failure retains cached data with a last-connected time; Retry now reconnects',
                  '<pre id="network-retained" hidden="">true</pre>' in network_recovery
                  and '<pre id="network-recovered" hidden="">true</pre>' in network_recovery)
            permission_denial = dump_dom(chrome, tmp, '?permissiondeny', origin)
            check('permission denial retains console authentication and its live stream',
                  '<pre id="permission-retained" hidden="">true</pre>' in permission_denial)
        if args.auth_recovery_only:
            print(f"\n{len(passed)} passed, {len(failed)} failed")
            if failed:
                raise SystemExit(1)
            return
        for label, size in [('desktop', (1280, 800)), ('narrow', (900, 768))]:
            workbench_dom = dump_dom(chrome, tmp, '?sessionworkbench', origin, window_size=size)
            receipt = re.search(r'data-session-workbench="([^"]+)"', workbench_dom)
            state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
            check(f'sessions workbench ({label}): interaction receipt produced', bool(state), str(state))
            for name, result in state.items():
                check(f'sessions workbench ({label}): {name}', result is True, str(result))
        if args.session_workbench_only:
            print(f"\n{len(passed)} passed, {len(failed)} failed")
            if failed:
                raise SystemExit(1)
            return
        dom_csp = dump_dom(chrome, tmp, "?cspdemo&raildemo", origin)
        dom_themefirst = dump_dom(chrome, tmp, "?themefirst", origin)
        dom = dump_dom(chrome, tmp)
        dom_payload = dump_dom(chrome, tmp, "?payloadoutcomes&tab=findings", origin, fixture=payload_cases.payload_outcomes())
        dom_resource_results = dump_dom(chrome, tmp, "?resourceoutcomes&tab=resources", origin, fixture={'patches': [{'route': '/resources', 'path': ['interventions'], 'value': [{'id': 'fixture-partial', 'kind': 'pause', 'status': 'partial', 'verification': 'unknown', 'error': 'One captured process could not be resumed.', 'before': {'rss_bytes': 8000000000, 'cpu_percent': 140, 'host_capacity': 'constrained'}, 'after': [], 'limits': ['Pause may stop growth without freeing memory. Resume may be needed.']}, {'id': 'fixture-termination', 'kind': 'terminate', 'status': 'applied', 'verification': 'verified', 'verified_by': 'captured-family-absent', 'before': {'rss_bytes': 8000000000, 'host_capacity': 'constrained'}, 'after': [{'captured_family_present': False, 'host_capacity': 'ample', 'host_available_bytes': 12000000000}], 'limits': ['Verification covers only the captured process family. Observations do not establish causation or task completion.']}]}]})
        check("resource results: partial application remains unknown with resume recourse", "Partially applied" in dom_resource_results and "Verification unknown" in dom_resource_results and "Resume may be needed" in dom_resource_results)
        check("resource results: termination verification names captured family limits", "Captured family absent" in dom_resource_results and "Verification covers only the captured process family" in dom_resource_results and "causation or task completion" in dom_resource_results)
        dom_session = dump_dom(chrome, tmp, "?sessiondemo")
        dom_guard = dump_dom(chrome, tmp, "?guarddemo")
        dom_resolve = dump_dom(chrome, tmp, "?resolvedemo")
        dom_expect = dump_dom(chrome, tmp, "?expectdemo")
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
        dom_retriage = dump_dom(chrome, tmp, "?retriagedemo", fixture=payload_cases.retriaged_finding())
        dom_tab = dump_dom(chrome, tmp, "?tabdemo")
        dom_view = dump_dom(chrome, tmp, "?viewdemo")
        dom_advdown = dump_dom(chrome, tmp, fixture=payload_cases.offline_advisor())
        dom_authfail = dump_dom(chrome, tmp, "?authfail")
        dom_authmixed = dump_dom(chrome, tmp, "?authmixed")
        dom_spendauth = dump_dom(chrome, tmp, "?spendauth")
        dom_refreshrace = dump_dom(chrome, tmp, "?refreshrace")
        dom_health = dump_dom(chrome, tmp, "?healthdemo")
        dom_healthrecover = dump_dom(chrome, tmp, "?healthdemo&recover")
        dom_slowshape = dump_dom(chrome, tmp, "?slowshape")
        dom_slowshapefirst = dump_dom(chrome, tmp, "?slowshape&firstload")
        dom_slowshaperecover = dump_dom(chrome, tmp, "?slowshape&recover")
        dom_historyflags = dump_dom(chrome, tmp, "?filteredscope&historyflags")
        dom_historyevents = dump_dom(chrome, tmp, "?filteredscope&historyevents")
        dom_historyflagschanged = dump_dom(chrome, tmp, "?filteredscope&historyflags&changed")
        dom_historyeventschanged = dump_dom(chrome, tmp, "?filteredscope&historyevents&changed")
        dom_historyrecover = dump_dom(chrome, tmp, "?filteredscope&historyflags&recover")
        dom_malformed = dump_dom(chrome, tmp, "?malformeddemo")
        dom_malformedrecover = dump_dom(chrome, tmp, "?malformeddemo&recover")
        dom_notoken = dump_dom(chrome, tmp, "?notoken")
        dom_hashagents = dump_dom(chrome, tmp, "#agents")
        dom_hashfindings = dump_dom(chrome, tmp, "#findings")
        dom_hashsessionswt = dump_dom(chrome, tmp, "#sessions/worktrees")
        dom_hashworktrees = dump_dom(chrome, tmp, "#worktrees")
        dom_trends = dump_dom(chrome, tmp, "?trendsprobe")
        dom_hiddenrender = dump_dom(chrome, tmp, "?hiddenrenderprobe")
        dom_policylists = dump_dom(chrome, tmp, "?policylists")
        dom_policyempty = dump_dom(chrome, tmp, "?policylists&emptypolicy", fixture={'payloads': {'/guard/rules': [], '/guard/path-allow': [], '/mute': [], '/expected': []}})
        dom_forget = dump_dom(chrome, tmp, "?policylists&forgetexpected")
        dom_scoped = dump_dom(chrome, tmp, "?scopedpermission", fixture=payload_cases.scoped_review())
        dom_scoped_revoke = dump_dom(chrome, tmp, "?scopedpermission&revokescope", fixture=payload_cases.scoped_review())
        dom_netfail = dump_dom(chrome, tmp, "?netfail")
        dom_tokenseed = dump_dom(chrome, tmp, "?requiretoken&tokenseed")
        dom_nofleet = dump_dom(chrome, tmp, "?nofleetdemo", fixture=payload_cases.unconfigured_fleet())
        dom_noresources = dump_dom(chrome, tmp, "?noresourcesdemo", fixture=payload_cases.postmortem_resources())
        dom_policy = dump_dom(chrome, tmp, "?policydemo")
        dom_demote = dump_dom(chrome, tmp, "?demotedemo")
        dom_allowrm = dump_dom(chrome, tmp, "?allowlistdemo")
        dom_rail = dump_dom(chrome, tmp, "?raildemo")
        dom_memory = dump_dom(chrome, tmp, "?raildemo&memorydemo")
        dom_overview = dump_dom(chrome, tmp, "?overviewdemo", origin)
        dom_overview_stale = dump_dom(chrome, tmp, "?overviewdemo&overviewstale", origin)
        dom_overview_race = dump_dom(chrome, tmp, "?overviewdemo&overviewrace", origin)
        dom_overview_focus = dump_dom(chrome, tmp, "?overviewdemo&overviewfocus", origin)
        dom_overview_decision = dump_dom(chrome, tmp, "?overviewdemo&overviewdecision", origin)
        dom_overview_return = dump_dom(chrome, tmp, "?overviewdemo&overviewreturn", origin)
        dom_memory_race = dump_dom(chrome, tmp, "?memoryrace")
        dom_trace_reactivation = dump_dom(chrome, tmp, "?tracereactivation")
        dom_pill = dump_dom(chrome, tmp, "?pilldemo")
        dom_quiet = dump_dom(chrome, tmp, "?quietdemo", fixture=payload_cases.quiet_sessions())
        dom_nomatch = dump_dom(chrome, tmp, "?nomatchdemo")
        dom_coverage = dump_dom(chrome, tmp, "?coveragedemo", fixture={'patches': [{'route': '/posture', 'path': ['state'], 'value': 'attention'}, {'route': '/posture', 'path': ['needs_you'], 'value': 0}, {'route': '/posture', 'path': ['items'], 'value': []}, {'route': '/posture', 'path': ['groups'], 'value': []}, {'route': '/posture', 'path': ['summary'], 'value': 'No decisions pending. Monitoring coverage needs attention.'}]})
        dom_session_coverage = dump_dom(chrome, tmp, "?sessionvisibility", fixture=payload_cases.session_coverage())
        dom_phone = dump_dom(chrome, tmp, "?phonedemo")
        dom_memory_phone = dump_dom(chrome, tmp, "?phonedemo&memorydemo")
        dom_nocosts = dump_dom(chrome, tmp, fixture=payload_cases.empty_spend())
        dom_memfam = dump_dom(chrome, tmp, "?memfamilydemo", fixture=payload_cases.shared_root_sessions())
        dom_memprobe = dump_dom(chrome, tmp, "?memprobe")
        dom_spend = dump_dom(chrome, tmp, "?spenddemo")
        dom_plans = dump_dom(chrome, tmp, fixture=payload_cases.spend_plans())
        dom_spendday = dump_dom(chrome, tmp, "?spenddaydemo")
        dom_spendphone = dump_dom(chrome, tmp, "?phonedemo&spenddaydemo")
        dom_spendkeep = dump_dom(chrome, tmp, "?tab=overview&spenddaydemo&spendkeepdemo")
        dom_spendcache = dump_dom(chrome, tmp, "?spendcachedemo")
        dom_spendshape = dump_dom(chrome, tmp, "?spendshape", fixture=payload_cases.delayed_spend())
        dom_spendshapefirst = dump_dom(chrome, tmp, "?spendshape&firstload", fixture=payload_cases.delayed_spend())
        dom_spendshaperecover = dump_dom(chrome, tmp, "?spendshape&recover", fixture=payload_cases.delayed_spend())
        dom_spendslow = dump_dom(chrome, tmp, "?spendslowdemo")
        dom_events = dump_dom(chrome, tmp, "?tab=events")
        dom_burst = dump_dom(chrome, tmp, "?burstdemo")
        dom_railburst = dump_dom(chrome, tmp, "?railburst")
        dom_dup = dump_dom(chrome, tmp, "?dupdemo", fixture=payload_cases.grouped_sessions())
        dom_dupres = dump_dom(chrome, tmp, "?dupdemo&tab=resources", fixture=payload_cases.grouped_sessions())
        dom_foldpatch = dump_dom(chrome, tmp, "?dupdemo&foldpatch", fixture=payload_cases.grouped_sessions(ended=True))
        dom_familypatch = dump_dom(chrome, tmp, "?dupdemo&tab=resources&familypatch", fixture=payload_cases.grouped_sessions(sidecar=True))
        dom_focus = dump_dom(chrome, tmp, "?focusburst")
        dom_click = dump_dom(chrome, tmp, "?clickburst")
        dom_rawmute = dump_dom(chrome, tmp, "?rawmute")
        dom_act = dump_dom(chrome, tmp, "?actdemo")
        dom_actfail = dump_dom(chrome, tmp, "?actdemo&postfail")
        dom_export = dump_dom(chrome, tmp, "?raildemo&exportdemo")
        dom_explain = dump_dom(chrome, tmp, "?explaindemo", fixture=payload_cases.explained_finding())
        dom_explainact = dump_dom(chrome, tmp, "?explaindemo&explainact", fixture=payload_cases.explained_finding())
        dom_allowpathact = dump_dom(chrome, tmp, "?explaindemo&allowpathact", fixture=payload_cases.explained_finding())
        dom_orgallow = dump_dom(chrome, tmp, "?orgallowdemo", fixture=payload_cases.organization_allow())
        dom_routine = dump_dom(chrome, tmp, "?routinedemo", fixture=payload_cases.routine_review())
        dom_explainfail = dump_dom(chrome, tmp, "?explaindemo&explainact&postfail", fixture=payload_cases.explained_finding())
        dom_detailsprobe = dump_dom(chrome, tmp, "?explaindemo&detailsprobe", fixture=payload_cases.explained_finding())
        dom_fam = dump_dom(chrome, tmp, "?familiesdemo&tab=resources", fixture=payload_cases.resource_families())
        dom_famev = dump_dom(chrome, tmp, "?familiesdemo&familyevents&tab=resources", fixture=payload_cases.resource_families())
        dom_evcap = dump_dom(chrome, tmp, "?tab=events", fixture=payload_cases.many_events())
        dom_evtrace = dump_dom(chrome, tmp, "?tab=events", fixture=payload_cases.trace_events())
        dom_duptrace = dump_dom(chrome, tmp, "?tab=events", fixture=payload_cases.duplicate_trace_events())
        dom_evorder = dump_dom(chrome, tmp, "?tab=events", fixture=payload_cases.unordered_events())
        dom_sesslink = dump_dom(chrome, tmp, "?sessionlinkdemo")
        dom_sticky = dump_dom(chrome, tmp, "?stickydemo")
        dom_drawerback = dump_dom(chrome, tmp, "?drawerbackdemo")
        dom_wt = dump_dom(chrome, tmp, "?tab=worktrees")
        dom_wtreview = dump_dom(chrome, tmp, "?tab=worktrees&reviewdemo")
        dom_wtreviewtrash = dump_dom(chrome, tmp, "?tab=worktrees&reviewdemo&reviewtrash")
        dom_wtdiscuss = dump_dom(chrome, tmp, "?tab=worktrees&discussdemo")
        dom_wtdiscussoff = dump_dom(chrome, tmp, "?tab=worktrees&discussdemo&discussoff")
        dom_wtremove = dump_dom(chrome, tmp, "?tab=worktrees&worktreedemo")
        dom_wtorphan = dump_dom(chrome, tmp, "?tab=worktrees", fixture=payload_cases.orphan_worktrees())
        dom_wtbatch = dump_dom(chrome, tmp, "?tab=worktrees&batchdemo", fixture=payload_cases.batch_worktrees())
        dom_wtorphantrash = dump_dom(chrome, tmp, "?tab=worktrees&orphantrash", fixture=payload_cases.orphan_worktrees())
        dom_wtremoving = dump_dom(chrome, tmp, "?tab=worktrees&worktreedemo&removerunning")
        dom_wtremovefail = dump_dom(chrome, tmp, "?tab=worktrees&worktreedemo&removefaildemo")
        dom_wtsizing = dump_dom(chrome, tmp, "?tab=worktrees&sizingdemo")
        dom_wtrefresh = dump_dom(chrome, tmp, "?tab=worktrees&refreshdemo")
        dom_clutter = dump_dom(chrome, tmp, "?tab=worktrees&clutterdemo")
        dom_wtremovable = dump_dom(chrome, tmp, "?tab=worktrees&removeremovabledemo", fixture=payload_cases.batch_worktrees(multiple_repos=True))
        dom_wthistory = dump_dom(chrome, tmp, "?tab=worktrees&historydemo")
        dom_wtday = dump_dom(chrome, tmp, "?tab=worktrees&reclaimdaydemo")
        dom_wtday_midnight = dump_dom(chrome, tmp, "?tab=worktrees&reclaimdaydemo&cleanupmidnight")
        dom_wtsearch = dump_dom(chrome, tmp, "?tab=worktrees&wtsearchdemo")
        dom_wtadopt = dump_dom(chrome, tmp, "?tab=worktrees", fixture=payload_cases.running_worktree_removal())
        dom_wtcadence = dump_dom(chrome, tmp, "?tab=worktrees&removecadence")
        dom_clutteradvise = dump_dom(chrome, tmp, "?tab=worktrees&clutteradvise")
        dom_wtgroup = dump_dom(chrome, tmp, "?tab=worktrees&groupdemo")
        # The Agent tab is served under the daemon's CSP like the console.
        dom_agent = dump_dom(chrome, tmp, "?tab=agent", origin)
        dom_agentworkspace = dump_dom(chrome, tmp, "?tab=agent&agentworkspace", origin, window_size=(1280, 900), fixture=payload_cases.agent_queue())
        dom_agentworkspace_mobile = dump_dom(chrome, tmp, "?tab=agent&agentworkspace", origin, window_size=(390, 844), fixture=payload_cases.agent_queue())
        dom_agentoff = dump_dom(chrome, tmp, "?tab=agent", origin, fixture=payload_cases.disabled_agent())
        dom_agentchat = dump_dom(chrome, tmp, "?tab=agent&agentchat", origin)
        dom_agentlocal = dump_dom(chrome, tmp, "?tab=agent&agentlocal", origin)
        dom_agentlatency = dump_dom(chrome, tmp, "?tab=agent&agentlatency", origin)
        dom_agentthinking = dump_dom(chrome, tmp, "?tab=agent&agentthinking", origin)
        dom_agentreduced = dump_dom(chrome, tmp, "?tab=agent&agentthinking", origin, reduced_motion=True)
        dom_agentreject = dump_dom(chrome, tmp, "?tab=agent&agentreject", origin)
        dom_agentdispatch = dump_dom(chrome, tmp, "?tab=agent&agentdispatch", origin)
        dom_headroomwide = dump_dom(chrome, tmp, "?tab=sessions&headroomhint", origin, window_size=(1280, 800))
        dom_headroomphone = dump_dom(chrome, tmp, "?phonedemo&headroomhint")
        dom_scope = dump_dom(chrome, tmp, "?scopedemo")
        dom_pattern = dump_dom(chrome, tmp, "?patterndemo", fixture=payload_cases.keychain_pattern())
        dom_gh = dump_dom(chrome, tmp, "?ghdemo", fixture=payload_cases.github_reader_pattern())
        dom_ghapprove = dump_dom(chrome, tmp, "?ghdemo&ghapprove", fixture=payload_cases.github_reader_pattern())
        dom_patternact = dump_dom(chrome, tmp, "?patterndemo&patternact", fixture=payload_cases.keychain_pattern())
        dom_patternphone = dump_dom(chrome, tmp, "?phonedemo&patterndemo", fixture=payload_cases.keychain_pattern())
        dom_patternstream = dump_dom(chrome, tmp, "?patterndemo&patternstream", fixture=payload_cases.keychain_pattern())
        dom_attnkeep = dump_dom(chrome, tmp, "?patterndemo&attnkeep", fixture=payload_cases.keychain_pattern())
        dom_patternbig = dump_dom(chrome, tmp, "?patternbigdemo&logsclosed", fixture=payload_cases.large_keychain_pattern())
        dom_bulk = dump_dom(chrome, tmp, "?bulkdemo&logsclosed")
        dom_empty = dump_dom(chrome, tmp, "?emptyposture", fixture={'patches': [{'route': '/posture', 'path': ['state'], 'value': 'all-clear'}, {'route': '/posture', 'path': ['needs_you'], 'value': 0}, {'route': '/posture', 'path': ['coverage_count'], 'value': 0}, {'route': '/posture', 'path': ['coverage_items'], 'value': []}, {'route': '/posture', 'path': ['items'], 'value': []}, {'route': '/posture', 'path': ['groups'], 'value': []}, {'route': '/posture', 'path': ['summary'], 'value': 'Agents monitored, no action needed'}]})
        dom_posturemore = dump_dom(chrome, tmp, "?posturemoredemo")
        dom_fold = dump_dom(chrome, tmp, "?folddemo", fixture=payload_cases.firewall_fold())
        dom_procwidth = dump_dom(chrome, tmp, "?procwidthdemo", window_size=(1440, 900))

        # --- session-first tab (P3) ---
        rail = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
        check("session rail renders durable sessions", len(dom_query(dom).find_all(None, {'class': 'session-card'})) >= 2,
              f"cards={len(dom_query(dom).find_all(None, {'class': 'session-card'}))}")
        check("rail titles are repo@branch, not harness · repo",
              '>api-service@main<' in rail and 'claude · ' not in rail)
        check("ended session marked", 'session-card ended' in dom)

        # --- sessions: harness-first rail ---
        rail_groups = re.findall(r'<details class="session-group[^"]*" data-harness="([^"]+)"', rail)
        check("sessions rail renders one group per live harness, newest first, infra last",
              rail_groups == ["codex", "claude", "infra"], f"groups={rail_groups}")
        check("group head carries mark, display name and counts",
              '<span class="harness-label">Claude Code</span>' in rail
              and '1 active · 1 idle · 1 ended' in rail
              and dom_query(rail).has(None, {'data-harness': 'codex', 'open': ''})
              and dom_query(rail).has(None, {'class': 'session-card active selected'}))
        logo_refs = set(re.findall(r'<use href="#(logo-[a-z-]+)"', rail))
        check("harness marks resolve to sprite symbols",
              logo_refs >= {"logo-claude", "logo-codex", "logo-ollama"}
              and all(f'<symbol id="{ref}"' in dom for ref in logo_refs), f"refs={sorted(logo_refs)}")
        claude_group = rail.split('data-harness="claude"', 1)[1].split('<details', 1)[0]
        check("sub-session nests under its parent",
              claude_group.index('data-id="sess-claude-1"') < claude_group.index('session-card idle nested')
              < claude_group.index('data-id="sess-claude-sub"'))
        check("ended tail is collapsed by default",
              dom_query(claude_group).has('div', {'class': 'session-ended'})
              and 'data-action="toggle-ended-sessions" data-harness="claude" aria-expanded="false">Ended (1)' in claude_group)
        infra_group = rail.split('data-harness="infra"', 1)[1]
        check("infra sits in the last group, collapsed, with RSS totals only",
              dom_query(rail).has('details', {'class': 'session-group infra', 'data-harness': 'infra'})
              and "Ollama" in infra_group and "782 MB" in infra_group
              and "session-card" not in infra_group and "sess-ollama-4" not in rail)
        check("live only hides a harness with nothing running", not dom_query(rail).has(None, {'data-harness': 'cursor'}))
        check("live cards carry kill, ended cards do not",
              dom_query(rail).has(None, {'data-action': 'kill', 'data-pid': '5821'})
              and 'data-action="kill"' not in rail.split('class="session-ended-body"', 1)[1].split('</details>', 1)[0])
        check("count strip shows sessions, harnesses and coverage",
              re.search(r'id="session-count-strip"[^>]*>Sessions 3 · Harnesses 2 · seeing 2/3<', dom) is not None)
        check("one filter pill per live harness",
              re.findall(r'data-action="toggle-harness" data-harness="([^"]+)" aria-pressed="true"',
                         dom.split('id="session-harness-pills"', 1)[1].split('</div>', 1)[0]) == ["codex", "claude"])
        pill_rail = dom_pill.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
        check("a switched-off pill hides its group",
              not dom_query(pill_rail).has(None, {'data-harness': 'claude'}) and dom_query(pill_rail).has(None, {'data-harness': 'codex'})
              and dom_query(dom_pill).has(None, {'class': 'harness-pill off', 'data-action': 'toggle-harness', 'data-harness': 'claude', 'aria-pressed': 'false'}))
        check("empty rail says all quiet", "All quiet. Nothing is running." in dom_quiet)
        check("filter that hides everything offers to clear it",
              "No sessions match" in dom_nomatch and dom_query(dom_nomatch).has(None, {'data-action': 'clear-harness-filter'}))
        check("the page, posture banner included, fits a 375px phone on Sessions, Agents and Resources",
              dom_query(dom_phone).has(None, {'data-hscroll': 'sessions:0,agents:0,resources:0'}),
              (re.search(r'data-hscroll="[^"]*"', dom_phone) or [None])[0])
        check("Memory detail fits a 375px phone without horizontal page overflow",
              dom_query(dom_memory_phone).has(None, {'data-hscroll': 'sessions:0,agents:0,resources:0'}),
              (re.search(r'data-hscroll="[^"]*"', dom_memory_phone) or [None])[0])
        detail_head = dom_rail.split('class="session-detail-head"', 1)[1].split('class="wf', 1)[0]
        check("detail head: mark, repo@branch, harness, confidence, copyable path",
              re.search(r'<h3[^>]*>api-service@main</h3>', detail_head) is not None and '#logo-claude' in detail_head
              and '<span class="sd-harness">Claude Code</span>' in detail_head
              and '>hook</span>' in detail_head
              and dom_query(detail_head).has(None, {'data-action': 'copy-path', 'data-path': '/Users/dev/workspace/api-service'}))
        detail_chrome = dom_rail.split('class="session-detail-chrome"', 1)[1].split('class="session-detail-body"', 1)[0]
        metadata = detail_chrome.split('class="session-metadata"', 1)[1].split('</details>', 1)[0]
        check("detail chrome keeps Copy report reachable and the copyable path in expandable Details",
              'data-action="copy-report" data-id="sess-claude-1"' in detail_chrome.split('class="sd-detail-controls"', 1)[0]
              and '>Copy report</button>' in detail_chrome
              and '<summary>Details</summary>' in metadata
              and dom_query(metadata).has(None, {'data-action': 'copy-path', 'data-path': '/Users/dev/workspace/api-service'}))
        clip = (re.search(r'data-clipboard="([^"]*)"', dom_export) or [None, ""])[1]
        check("Export copies the markdown session report and toasts",
              clip.startswith("# claude · api-service@main") and "## Summary" in clip
              and 'class="toast success">Session report copied (markdown)<' in dom_export,
              f"clipboard={clip[:60]!r}")
        check("rail selection renders trace waterfall",
              dom_query(dom_rail).has(None, {'class': 'wf-bar'}) and 'Bash' in dom_rail,
              "no waterfall bars in raildemo")
        memory_detail = dom_memory.split('id="session-detail"', 1)[1].split('id="session-board"', 1)[0]
        check("Memory opens first and earlier rows prepend once",
              dom_query(dom_memory).has(None, {'data-action': 'session-view', 'data-view': 'memory', 'aria-pressed': 'true'})
              and memory_detail.count('Earlier activity') == 1
              and memory_detail.count('Recent activity') == 1
              and memory_detail.index('Earlier activity') < memory_detail.index('Recent activity')
              and not dom_query(memory_detail).has(None, {'data-action': 'memory-earlier'}),
              memory_detail[:700])
        current = dom_overview.split('id="session-detail"', 1)[1].split('id="session-board"', 1)[0]
        check("Home session opens its current controls, evidence, and observed coverage",
              'Read wants access to .env' in current and 'Own session finding' in current
              and 'Reviewed' in current and 'Model exposure' in current
              and 'Other traffic may be uninspected.' in current
              and current.index('Current session status') < current.index('class="session-memory"'))
        check("Home session opens current status in the workbench viewport", dom_query(dom_overview).has(None, {'data-overview-visible': 'true'}))
        stale = dom_overview_stale.split('id="session-detail"', 1)[1].split('id="session-board"', 1)[0]
        check("failed overview refresh preserves facts with disabled controls and a visible stale warning",
              'Last known session status' in stale and 'Own session finding' in stale
              and re.search(r'<fieldset[^>]*class="sd-request"[^>]*disabled', stale) is not None)
        race = dom_overview_race.split('id="session-detail"', 1)[1].split('id="session-board"', 1)[0]
        check("late session overview cannot overwrite the newly selected session",
              re.search(r'<h3[^>]*>data-pipeline@feat/etl</h3>', race) is not None and 'Own session finding' not in race
              and 'Read wants access to .env' not in race)
        check("new findings preserve the focused guard control", dom_query(dom_overview_focus).has(None, {'data-overview-focus': 'true'}))
        check("session guard decision uses the existing handler and refreshes its result", dom_query(dom_overview_decision).has(None, {'data-overview-resolved': 'true'}))
        check("session findings history retains scope and returns to the same session", dom_query(dom_overview_return).has(None, {'data-overview-scoped': 'true'}) and dom_query(dom_overview_return).has(None, {'data-overview-returned': 'true'}))
        check("late response from previous selection cannot replace Memory",
              dom_query(dom_memory_race).has(None, {'data-memory-race': 'B'})
              and re.search(r'<h3[^>]*>data-pipeline@feat/etl</h3>', dom_memory_race.split('id="session-detail"', 1)[1]) is not None
              and 'A-only memory' not in dom_memory_race.split('id="session-detail"', 1)[1],
              dom_memory_race.split('id="session-detail"', 1)[1][:700])
        check("Trace refetches after an event arrives while Memory is active",
              dom_query(dom_trace_reactivation).has(None, {'data-trace-was-cached': 'true'})
              and dom_query(dom_trace_reactivation).has(None, {'data-trace-reactivated': 'true'}),
              (re.search(r'data-trace-(?:was-cached|reactivated)="[^"]*"', dom_trace_reactivation) or [None])[0])
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
        check("posture banner is critical", dom_query(dom).has(None, {'id': 'posture-banner', 'data-state': 'critical'}))
        check("posture headline rendered", 'id="posture-state">Critical<' in dom)
        check("KPI agents count", 'id="count-agents">3<' in dom)
        check("KPI flags are unacted last 24h", 'id="count-flags">2<' in dom)
        check("KPI incidents count", 'id="count-incidents">1<' in dom)
        check("spend tile shows the 24h total", 'id="count-spend">$36.67<' in dom)
        check("spend tile sub-line counts calls and unpriced calls",
              'id="hint-spend">40 calls · 2 unpriced<' in dom)
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
        tz_ok = all(re.search(r"&tz=-?\d+&cached=1$", q) for q in spend_q if q != "since=24h&by=repo&cached=1")
        check("spend: switching the dimension fetches by=provider and renders the provider rows",
              any(q.startswith("since=24h&by=provider&tz=") for q in spend_q) and tz_ok
              and re.findall(spend_key_re, spend_card_of(dom_spend)) == ["anthropic", "openai-codex", "openai", "(unknown)"]
              and "provider not recorded" in spend_card_of(dom_spend), f"queries={spend_q}")
        check("spend: the tile keeps its 24h by-repo fetch and meaning",
              "since=24h&by=repo&cached=1" in spend_q and 'id="count-spend">$36.67<' in dom_spend, f"queries={spend_q}")
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
              dom_query(dom_spendphone).has(None, {'data-hscroll': 'sessions:0,agents:0,resources:0,overview:0'}),
              (re.search(r'data-hscroll="[^"]*"', dom_spendphone) or [None])[0])
        cache_probe = html.unescape(pre(dom_spendcache, "spend-cache-probe"))
        check("spend: a report from the usage cache shows at once with the updating notice and its age",
              cache_probe == "notice=Refreshing usage… · saved 3h ago hint=40 calls · 2 unpriced · updating…",
              f"probe={cache_probe!r}")
        cache_q = html.unescape(pre(dom_spendcache, "mock-costs")).split("\n")
        check("spend: the card re-reads until the fresh report lands, then the notice goes",
              len(cache_q) == 6 and 'id="count-spend">$37.67<' in dom_spendcache
              and 'id="hint-spend">40 calls · 2 unpriced<' in dom_spendcache
              and dom_query(dom_spendcache).has(None, {'id': 'spend-cache', 'class': 'spend-cache', 'role': 'status', 'hidden': ''}),
              f"queries={cache_q}")
        slow_probe = html.unescape(pre(dom_spendslow, "spend-slow-probe"))
        check("spend: a report computed cold never holds the first render of the other panels",
              slow_probe == "agents=3 spend=Refreshing usage…" and 'id="count-spend">$36.67<' in dom_spendslow,
              f"probe={slow_probe!r}")
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
              not dom_query(pill_agents).has(None, {'data-harness': 'claude'}) and dom_query(pill_agents).has(None, {'data-harness': 'codex'})
              and 'class="harness-pill off" data-action="toggle-harness" data-harness="claude"'
              in dom_pill.split('id="agent-harness-pills"', 1)[1].split('</div>', 1)[0])
        check("claude instance pid", "PID 5821" in dom)
        check("nested helper pid", "PID 5822" in dom)
        check("leftover cursor status", "leftover" in dom)
        check("terminate not labelled Kill", "Terminate" in dom and "Kill</span>" not in dom)
        check("firewall enforcing badge",
              'class="badge badge-ok" id="badge-firewall-mode">enforcing<' in dom)
        # Coverage is informational; the displayed sample includes carriers.
        check("Egress coverage names the displayed sample without implying findings",
              "Connection coverage · last 24 h" in dom
              and "7 endpoints shown · 2 known infrastructure" in dom
              and "Connection coverage alone is not a security finding." in dom)

        # --- reversible enforcement (block is not a ratchet) ---
        check("blocking rule shows demote button",
              dom_query(dom).has(None, {'data-action': 'demote', 'data-rule': 'aws-key'}))
        check("demote flips the rule back to promote",
              dom_query(dom_demote).has(None, {'data-action': 'promote', 'data-rule': 'aws-key'}))
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
              and dom_query(dom_uninsp).has(None, {'data-action': 'bulk-allow', 'data-agent': 'openclaw', 'data-hosts': '2607:6bc0::10'}))
        check("unknown section does not list vendor endpoints",
              "2607:6bc0::10" not in uninsp_unknown and "statsig.example.com" in uninsp_unknown)
        check("unknown section keeps cloud hosts, named",
              re.search(r'2600:1901:0:9e23::</span> <span class="fw-metric dim">Google Cloud</span>', uninsp_unknown) is not None)
        check("egress rows show first-seen and session",
              "first seen" in dom_uninsp and "session " in dom_uninsp)
        check("egress bulk allow groups same-suffix hosts",
              dom_query(dom_uninsp).has(None, {'data-action': 'bulk-allow', 'data-agent': 'claude'}) and "Allow all 2" in dom_uninsp)
        check("egress explains what the list is and what to do",
              "What this is:" in dom_uninsp and "What to do:" in dom_uninsp)
        check("egress rows carry a plain Allow action",
              dom_query(dom_uninsp).has(None, {'data-action': 'allow-host'}) and ">Allow</span>" in dom_uninsp)
        check("egress rows offer on-demand advisor assessment",
              dom_query(dom_uninsp).has(None, {'data-action': 'assess-host', 'data-agent': 'claude'})
              and "Ask the advisor" in dom_uninsp)
        check("egress rows with a verdict show the advisor chip",
              'advisor-chip adv-benign' in dom_uninsp)
        # A toast fired while the drawer is open must be present and the drawer
        # must be open. The old native-<dialog> + top-layer toast dance is gone:
        # the drawer is ordinary DOM and toasts are a top-layer popover, so a
        # toast can no longer fall behind the overlay.
        check("drawer is open for the drill-down",
              dom_query(dom_toast).has(None, {'id': 'drawer', 'class': 'drawer'}) and 'id="drawer" class="drawer" hidden' not in dom_toast)
        check("toast rendered while the drawer is open",
              dom_query(dom_toast).has(None, {'class': 'toast '}))
        check("vendor-key promote banner",
              dom_query(dom).has(None, {'data-action': 'promote-vendor-keys'}) and "1 vendor-key rule" in dom)
        check("incident row reads its risk and workflow (ack)",
              '<span class="c-verdict-text">CRITICAL · acknowledged</span>' in dom)
        payload_row = log_rows(dom_payload).get("incident:inc-20260907-6033-a1b2", "")
        check("payload incident preserves mixed results after reported resolution",
              "2 blocked before forwarding" in payload_row
              and "1 observed only" in payload_row and "3 outcome unknown" in payload_row
              and "Operator reported credential revocation" in payload_row
              and "revocation are not verified" in payload_row)
        check("payload finding names the local forwarding gate and registered match",
              "Blocked before forwarding" in dom_payload and "Registered secret fingerprint" in dom_payload)
        check("secret sources rendered (config+user)",
              len(dom_query(dom).find_all(None, {'class': 'source-item'})) == 2 and "CONFIG" in dom and "USER" in dom)

        # --- evidence chain ---
        check("chain rendered with 3 nodes", dom.count("chain-node") >= 3)
        check("chain node: payload inspection", "payload inspection" in dom)
        check("chain node: egress destination", "logs.example.com:443" in dom)
        check("chain verdict node", "cn-verdict-bad" in dom and "Critical flag raised" in dom)
        history_rows = re.findall(r'<li class="log-row[^"]*" data-row-key="(flag:[^"]+)"', dom)
        check("history lists every flag as one log row, the critical ones first",
              sorted(history_rows) == ["flag:flag-1", "flag:flag-2", "flag:flag-3"] and history_rows[-1] == "flag:flag-3",
              f"rows={history_rows}")
        flag1_card = log_rows(dom).get("flag:flag-1", "")
        flags_region = dom.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
        check("an unexplained flag's evidence rows render as text, not [object Object]",
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
        check("flag card kill action", dom_query(dom).has(None, {'data-action': 'kill', 'data-pid': '6033'}))
        check("collector-down FDA deep link", dom_query(dom).has(None, {'data-action': 'open-fda'}) and "Full Disk Access" in dom)
        check("advisor posture line separates opinion from evidence and risk off Home",
              "Advisor opinion: 1 of 2 triaged critical flags may be benign. Evidence and risk are unchanged." in dom_tab)
        check("incident narrative rendered in its row's body", "Rotate the key first" in log_rows(dom).get("incident:inc-20260907-6033-a1b2", ""),
              sorted(k for k in log_rows(dom) if k.startswith("incident:")))

        # --- allowlist suggestions ---
        check("egress suggestion rendered", "fw-suggestion" in dom and "registry.npmjs.org" in dom)
        check("suggestion advisor chip", 'advisor-chip adv-benign' in dom and "advisor: benign" in dom)
        check("suggestion allow button is delegated",
              dom_query(dom).has(None, {'data-action': 'allow-host', 'data-agent': 'cursor', 'data-host': 'registry.npmjs.org'}))

        # --- activity rollup chart ---
        rects_ev = len(dom_query(dom).find_all(None, {'class': 'act-ev'}))
        check("activity chart draws event bars", rects_ev > 10, f"rects={rects_ev}")
        check("activity chart marks the flag hour", dom_query(dom).has(None, {'class': 'act-fl'}))
        check("activity chart zero-fills empty hours", dom_query(dom).has(None, {'class': 'act-zero'}))

        # --- dispositions (mute) ---
        check("mute action on advisor-benign flag",
              dom_query(dom).has(None, {'data-action': 'mute-flag', 'data-rule': 'sensitive-read-then-connect', 'data-host': 'logs.example.com'}))
        check("mutes list rendered with unmute",
              dom_query(dom).has(None, {'data-action': 'unmute', 'data-rule': 'proxy-prompt-injection', 'data-host': 'blog.example.com'}))
        check("rule-level mute renders as all hosts", "keychain-security-cli · all hosts" in dom)
        check("keychain flag carries class-dismiss action",
              dom_query(dom).has(None, {'data-action': 'mute-rule', 'data-rule': 'keychain-access'}))

        # --- uninspected-egress drill-down ---
        check("uninspected warning is a clickable drill-down",
              dom_query(dom).has(None, {'data-action': 'open-uninspected'}))
        # --- screen hygiene: the banner summarises, the queue lists ---
        check("Home: the posture banner lists no items; the attention queue lists them",
              re.search(r'<ul class="posture-items" id="posture-items" hidden(="")?></ul>', dom) is not None
              and not dom_query(dom).has(None, {'class': 'posture-item'}) and dom_query(dom).has(None, {'data-action': 'guard-resolve', 'data-id': 'guard-1'}))
        posture_egress = (re.search(r'<pre id="posture-egress"[^>]*>([^<]*)<', dom_posturemore) or [None, ""])[1]
        check("Egress: the posture banner lists 3 content rows (2 items + the advisor line) and \"and 4 more\"",
              posture_egress == "items=2 more=and 4 more hidden=0", posture_egress)
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
              and dom_query(endpoints).has(None, {'class': 'egress-vendor'}) and dom_query(endpoints).has(None, {'data-action': 'bulk-allow', 'data-agent': 'openclaw'})
              and dom_query(endpoints).has(None, {'data-action': 'allow-host'}) and dom_query(endpoints).has(None, {'data-action': 'endpoint-detail'})
              and 'id="endpoints-title">Connection coverage · last 24 h<' in dom_fold)
        firewall = dom_fold.split('id="firewall-container"', 1)[-1].split('id="sources-container"', 1)[0]
        check("Egress: the firewall panel has no view-endpoints link",
              not dom_query(firewall).has(None, {'data-action': 'open-uninspected'}) and "fw-uninspected" not in dom_fold
              and "hit-a" in firewall)
        proc_width = (re.search(r'<pre id="proc-width"[^>]*>([^<]*)<', dom_procwidth) or [None, ""])[1]
        pw = re.match(r"panel=(\d+) content=(\d+) viewport=(\d+)", proc_width)
        check("Processes panel fills the content width at 1440 px",
              pw is not None and pw.group(3) == "1440" and pw.group(1) == pw.group(2), proc_width)
        check("drill-down drawer title", "Uninspected egress — last 24h" in dom_uninsp)
        check("drill-down lists endpoint host", "registry.npmjs.org" in dom_uninsp
              and "statsig.example.com" in dom_uninsp)
        check("drill-down allow action delegated",
              dom_query(dom_uninsp).has(None, {'data-action': 'allow-host', 'data-agent': 'cursor', 'data-host': 'registry.npmjs.org'}))
        check("drill-down explains the blind spot", "bypassing the inspection proxy" in dom_uninsp)
        keepopen = (re.search(r'<pre id="keepopen"[^>]*>([^<]*)<', dom_keepopen) or [None, ""])[1]
        check("drill-down vendor disclosure stays open across an Allow refill",
              "key=vendor:openclaw|Anthropic rebuilt=1 open=1" in keepopen, keepopen)
        check("drill-down Allow refill posted and dropped the row",
              "POST /allowlist" in dom_keepopen and 'data-host="statsig.example.com"' not in dom_keepopen.split('id="drawer-body"', 1)[-1].split("</details>", 1)[0], keepopen)

        # --- evidence file: an incident's accessed file opens the file drawer ---
        check("incident Accessed Files path is a file link",
              dom_query(dom_file).has(None, {'id': 'file-link'}) and "rollout-2026-09-23T12-53-26-demo.jsonl" in dom_file)
        check("file drawer shows the masked excerpt, never an unmasked value",
              "Around the secret" in dom_file and "[REDACTED:fp1]" in dom_file)
        check("file drawer offers Reveal in Finder and Open in editor",
              dom_query(dom_file).has(None, {'data-action': 'file-reveal'}) and dom_query(dom_file).has(None, {'data-action': 'file-open'}))
        check("file drawer lists findings, agent access and the session",
              "Agent access" in dom_file and "api-service@main" in dom_file and dom_query(dom_file).has(None, {'data-action': 'open-incident'}))
        check("file drawer goes back to the incident report",
              dom_query(dom_file).has(None, {'id': 'btn-drawer-back'}) and "Incident report" in dom_file)
        check("file drawer shows the advisor plan and the playbook",
              "What to do" in dom_file and "Codex printed an API key from an env dump." in dom_file
              and "Playbook: Secret in an agent transcript" in dom_file and dom_query(dom_file).has(None, {'data-action-id': 'dismiss'}))
        check("finding cards offer What to do", dom_query(dom_explain).has(None, {'data-action': 'open-plan', 'data-subject': 'flag:flag-2'}))
        check("finding cards offer Mark as routine / not ok",
              dom_query(dom_explain).has(None, {'data-action': 'mark-label', 'data-subject': 'flag:flag-2', 'data-label': 'ok'}))
        check("file drawer shows the operator's history and suggestion",
              "Your history" in dom_file and "You marked similar cases 3 as routine." in dom_file
              and "You marked this 3 times as routine for codex." in dom_file and "my own test key" in dom_file)
        check("menubar deep link #file= opens the file drawer",
              dom_query(dom_filedeep).has(None, {'data-action': 'file-reveal'}) and "Around the secret" in dom_filedeep)
        # --- endpoint evidence: an unattributed IPv6 must be identifiable ---
        check("endpoint Evidence opens a detail drawer",
              dom_query(dom_endpoint).has(None, {'id': 'drawer', 'class': 'drawer'}) and "2600:1901:0:9e23::" in dom_endpoint)
        check("endpoint detail names the owner, not a bare address",
              "Google Cloud address" in dom_endpoint)
        check("endpoint detail shows which agent and session reached it",
              "Allow for claude" in dom_endpoint and "api-service@main" in dom_endpoint)
        check("endpoint detail lists recent connections",
              "Recent connections" in dom_endpoint and ":443" in dom_endpoint)

        # --- notification preferences ---
        check("notify bell present", dom_query(dom).has(None, {'id': 'btn-notify'}))
        check("notify popover renders rules", "Keychain file access" in dom_notify
              and dom_query(dom_notify).has(None, {'data-notify-rule': 'keychain-access'}))
        check("notify override pre-selected (never)",
              dom_query(dom_notify).has(None, {'data-notify-rule': 'keychain-access'}) and
              'value="never" selected' in dom_notify.split('data-notify-rule="keychain-access"')[1][:300])
        check("notify popover lists workspace scopes",
              "Per-workspace scopes" in dom_notify
              and dom_query(dom_notify).has(None, {'data-action': 'notify-scope-remove', 'data-rule': 'proxy-secret-leak', 'data-workspace': '/Users/dev/work/prod'}))
        check("notify popover offers adding a workspace scope",
              dom_query(dom_notify).has(None, {'id': 'notify-scope-path'}) and dom_query(dom_notify).has(None, {'data-action': 'notify-scope-add'}))
        nfp = pre(dom_notifyfocus, "notify-focus-probe")
        check("notify add-scope input survives a reconcile that changes notifyCfg: same node, value and focus",
              nfp == "same=true value=in-progress-edit focused=true probe=1", f"probe={nfp!r}")

        # Report health is separate from the daemon connection and retained rows.
        def health_notice(dom, report):
            match = re.search(r'<p class="report-health" data-reports="' + re.escape(report) + r'"[^>]*>[^<]*</p>', dom)
            return match.group(0) if match else ""
        resource_health = health_notice(dom_health, "resources")
        spend_health = health_notice(dom_spendshape, "spend|spend card|spend plans")
        check("delayed spend refresh retains totals, rows and plan headroom with a quiet status",
              not spend_health and "Refresh delayed · showing saved usage" in dom_spendshape
              and 'id="count-spend">$36.67<' in dom_spendshape
              and "api-service" in spend_card_of(dom_spendshape) and "shape-plan" in spend_card_of(dom_spendshape))
        first_spend = health_notice(dom_spendshapefirst, "spend|spend card|spend plans")
        check("first-load malformed spend reports retry quietly without inventing empty results",
              not first_spend and "Usage is taking longer to load · retrying…" in dom_spendshapefirst
              and "Refreshing usage…" in spend_card_of(dom_spendshapefirst)
              and "No priced model calls" not in spend_card_of(dom_spendshapefirst)
              and 'id="count-agents">3<' in dom_spendshapefirst)
        check("valid spend recovery clears the delayed refresh status",
              "Refresh delayed" in pre(dom_spendshaperecover, "spend-shape-before-recovery")
              and dom_query(dom_spendshaperecover).has(None, {'id': 'spend-cache', 'class': 'spend-cache', 'role': 'status', 'hidden': ''})
              and 'id="count-spend">$36.67<' in dom_spendshaperecover)
        for report in ("resources", "audit", "notification rules", "recurring egress"):
            check(f"malformed {report} containers retain prior results with a stale warning",
                  "Stale" in health_notice(dom_slowshape, report)
                  and "Invalid response" in health_notice(dom_slowshape, report)
                  and "hidden" not in health_notice(dom_slowshape, report))
            check(f"first-load malformed {report} containers show unavailable",
                  "Unavailable" in health_notice(dom_slowshapefirst, report)
                  and "Invalid response" in health_notice(dom_slowshapefirst, report))
            check(f"valid {report} recovery clears malformed-response warning",
                  "Stale" in pre(dom_slowshaperecover, "slow-shape-before-recovery")
                  and "hidden" in health_notice(dom_slowshaperecover, report))
        slow_board = dom_slowshape.split('id="resource-board"', 1)[1].split('id="history-panel"', 1)[0]
        check("malformed slow reports preserve resource rendering and healthy live telemetry",
              'id="count-agents">3<' in dom_slowshape
              and "Families by harness" in slow_board and "api-service" in slow_board
              and "Disconnected" not in dom_slowshape)
        check("resource request failure preserves data with a persistent stale notice",
              "Stale" in resource_health and "last refreshed at" in resource_health
              and "hidden" not in resource_health and 'id="count-agents">3<' in dom_health
              and "4.0 GB available of 16.0 GB" in dom_health)
        audit_health = health_notice(dom_health, "audit")
        check("first-load audit failure is explicitly unavailable",
              "Unavailable" in audit_health and "HTTP 503" in audit_health and "hidden" not in audit_health)
        check("unreadable guard response shows stale decisions despite a healthy snapshot",
              "Guard decisions: Stale" in dom_health and "response unreadable" in dom_health
              and "Disconnected" not in dom_health)
        check("successful recovery clears stale and unavailable notices",
              "Stale" in pre(dom_healthrecover, "health-before-recovery")
              and "Unavailable" in pre(dom_healthrecover, "health-before-recovery")
              and "hidden" in health_notice(dom_healthrecover, "resources")
              and "hidden" in health_notice(dom_healthrecover, "audit")
              and "Stale" not in health_notice(dom_healthrecover, "resources"))

        def history_content(dom, flags):
            anchor = 'id="flags-list"' if flags else 'id="events-container"'
            return dom.split(anchor, 1)[1].split('</section>', 1)[0]
        for flags, retained, changed in ((True, dom_historyflags, dom_historyflagschanged),
                                          (False, dom_historyevents, dom_historyeventschanged)):
            name = 'findings' if flags else 'events'
            marker = 'history-filtered-match' if flags else 'Filtered-history match'
            keys = 'snapshot|flags' if flags else 'snapshot|events'
            check(f"failed filtered {name} refresh preserves matching rows and warns stale",
                  marker in history_content(retained, flags)
                  and 'history-broad-only' not in history_content(retained, flags)
                  and 'Broad-only history row' not in history_content(retained, flags)
                  and 'Stale' in health_notice(retained, keys))
            check(f"changed {name} filters show unavailable results without leaking old or live rows",
                  marker not in history_content(changed, flags)
                  and 'history-broad-only' not in history_content(changed, flags)
                  and 'Broad-only history row' not in history_content(changed, flags)
                  and 'not loaded yet' in history_content(changed, flags)
                  and 'Unavailable' in health_notice(changed, keys))
        check("empty filtered findings recover successfully and clear the stale warning",
              'Stale' in pre(dom_historyrecover, 'history-before-recovery')
              and 'No flags match the current filter' in history_content(dom_historyrecover, True)
              and 'hidden' in health_notice(dom_historyrecover, 'snapshot|flags'))

        hot_health = health_notice(dom_malformed, "snapshot|guard decisions")
        check("malformed snapshot and guard containers retain last-good metrics with persistent warnings",
              pre(dom_malformed, "malformed-returned") == "yes"
              and 'id="count-agents">3<' in dom_malformed
              and "Live telemetry: Stale" in hot_health
              and "Guard decisions: Unavailable" in hot_health and "Invalid response" in hot_health
              and "hidden" not in hot_health
              and "The daemon returned invalid telemetry" in dom_malformed
              and 'id="status-text">Telemetry unavailable<' in dom_malformed)
        hot_recovered = health_notice(dom_malformedrecover, "snapshot|guard decisions")
        check("valid hot responses recover from malformed containers",
              pre(dom_malformedrecover, "malformed-before-recovery").startswith("3 ")
              and "Stale" in pre(dom_malformedrecover, "malformed-before-recovery")
              and 'id="count-agents">3<' in dom_malformedrecover
              and "hidden" in hot_recovered and "Invalid response" not in hot_recovered)

        # --- connection states (the "trouble connecting" regressions) ---
        check("a delayed older snapshot cannot replace a newer manual refresh",
              '<pre id="race-old-returned" hidden="">yes</pre>' in dom_refreshrace
              and 'id="count-agents">3<' in dom_refreshrace)
        check("auth-expired shows the ended state, not 'daemon down'",
              re.search(r'<section[^>]*id="session-ended"[^>]*>', dom_authfail) is not None
              and "Reconnect this console" in dom_authfail
              and dom_query(dom_authfail).has(None, {'href': 'secure-agent://console/reconnect'})
              and "Can&#x27;t reach the Secure Agent daemon" not in dom_authfail.split('id="session-ended"', 1)[1].split('</section>', 1)[0])
        check("a 403 hides the posture, counts and panels and closes the stream",
              dom_query(dom_authfail).has(None, {'class': 'is-ended'})
              and re.search(r'<section class="posture" id="posture-banner"[^>]*\bhidden\b', dom_authfail) is not None
              and re.search(r'<main[^>]*\bhidden\b', dom_authfail) is not None
              and '<pre id="sse-state" hidden="">closed</pre>' in dom_authfail,
              (re.search(r'<pre id="sse-state"[^>]*>[^<]*</pre>', dom_authfail) or [None])[0])
        nt_fetches = (re.search(r'<pre id="fetch-count"[^>]*>(\d+)</pre>', dom_notoken) or [None, "missing"])[1]
        for label, expired in (("guard", dom_authmixed), ("spend", dom_spendauth)):
            check(f"{label} endpoint 403 ends the console even when snapshot succeeds",
                  dom_query(expired).has(None, {'class': 'is-ended'})
                  and re.search(r'<main[^>]*\bhidden\b', expired) is not None
                  and '<pre id="sse-state" hidden="">closed</pre>' in expired)
        check("no token at load: only the ended state, no posture, zero fetches, no stream",
              re.search(r'<section[^>]*id="session-ended"[^>]*>', dom_notoken) is not None
              and re.search(r'<section class="posture" id="posture-banner"[^>]*\bhidden\b', dom_notoken) is not None
              and re.search(r'<section class="statstrip"[^>]*\bhidden\b', dom_notoken) is not None
              and nt_fetches == "0" and not dom_query(dom_notoken).has(None, {'id': 'sse-state'}),
              f"fetches={nt_fetches}")
        check("a token at load: the console renders, the ended state stays hidden",
              re.search(r'<section[^>]*id="session-ended"[^>]*\bhidden\b', dom) is not None and 'id="count-agents">3<' in dom)
        check("unreachable shows the retry banner",
              "Waiting for Secure Agent. No live data received" in dom_netfail
              and dom_query(dom_netfail).has(None, {'id': 'btn-retry-connection'}))
        check("unreachable sets Disconnected chip",
              'id="status-text">Disconnected<' in dom_netfail)
        check("token survives reload via sessionStorage (no #ct fragment)",
              'id="count-agents">3<' in dom_tokenseed
              and 'id="offline-banner" hidden' in dom_tokenseed)

        # --- fleet node card (real /fleet object shape + renderAll crash isolation) ---
        check("fleet card renders the local node object",
              "ci-runner-02" in dom and "darwin/arm64" in dom)
        check("fleet panel visible when a collector is configured",
              dom_query(dom).has(None, {'id': 'fleet-panel'}))
        check("fleet panel hides when no collector is configured",
              dom_query(dom_nofleet).has(None, {'id': 'fleet-panel', 'style': 'display: none;'})
              and "ci-runner-02" not in dom_nofleet)
        check("panels after fleet still render (crash isolation)",
              len([k for k in log_rows(dom) if k.startswith("flag:")]) == 3
              and len(dom_query(dom).find_all(None, {'class': 'timeline-item'})) > 0
              and len(dom_query(dom).find_all(None, {'class': 'audit-item'})) == 2)

        # --- tabs (console IA) ---
        tab_ids = re.findall(r'class="tab-btn[^"]*" data-tab="(\w+)"', dom)
        tab_labels = re.findall(r'data-tab="\w+" role="tab"[^>]*>\s*<svg[^>]*>.*?</svg><span>([^<]+)</span>', dom, re.S)
        check("tab bar renders exactly six tabs, Home first, System after Egress, Agent last",
              len(dom_query(dom).find_all(None, {'class': 'tab-btn'})) == 6 and tab_ids == ["home", "sessions", "egress", "system", "policy", "agent"]
              and tab_labels == ["Home", "Sessions", "Egress", "System", "Policy", "Agent"], f"ids={tab_ids} labels={tab_labels}")
        check("Sessions has no Cleanup sub-view; its panels live in the System tab",
              not dom_query(dom).has(None, {'data-subtab': 'worktrees'}) and not dom_query(dom).has(None, {'id': 'sub-worktrees'})
              and dom.index('id="tab-system"') < dom.index('id="worktrees-container"') < dom.index('id="clutter-container"') < dom.index('id="tab-policy"')
              and dom.index('id="tab-egress"') < dom.index('id="tab-system"'))
        check("the attention panel lives in Home, first",
              dom.index('id="tab-home"') < dom.index('id="attention-center"') < dom.index('id="spend-card"')
              < dom.index('id="home-findings"') < dom.index('id="home-trends"') < dom.index('id="tab-sessions"'))
        check("home tab active by default",
              dom_query(dom).has(None, {'class': 'tab-btn active', 'data-tab': 'home'}))
        check("non-active panels hidden",
              'id="tab-sessions" role="tabpanel" hidden' in dom
              and 'id="tab-egress" role="tabpanel" hidden' in dom
              and 'id="tab-system" role="tabpanel" hidden' in dom
              and 'id="tab-policy" role="tabpanel" hidden' in dom)
        check("home panel visible",
              dom_query(dom).has(None, {'id': 'tab-home', 'role': 'tabpanel'}))
        check("home groups are closed by default",
              dom_query(dom).has('details', {'class': 'home-group', 'id': 'home-spend', 'data-group': 'spend'})
              and dom_query(dom).has('details', {'class': 'home-group', 'id': 'home-findings', 'data-group': 'findings'})
              and dom_query(dom).has('details', {'class': 'home-group', 'id': 'home-trends', 'data-group': 'trends'}))
        check("hash #agents opens Sessions on the Processes sub-view",
              dom_query(dom_hashagents).has(None, {'class': 'tab-btn active', 'data-tab': 'sessions'})
              and dom_query(dom_hashagents).has(None, {'class': 'subtab-btn active', 'data-subtab': 'processes'})
              and dom_query(dom_hashagents).has(None, {'id': 'sub-processes', 'role': 'tabpanel'})
              and 'id="sub-board" role="tabpanel" hidden' in dom_hashagents
              and dom_query(dom_hashagents).has(None, {'id': 'tab-sessions', 'role': 'tabpanel'}))
        for old_hash, dom_old in (("#sessions/worktrees", dom_hashsessionswt), ("#worktrees", dom_hashworktrees)):
            check(f"hash {old_hash} opens the System tab",
                  dom_query(dom_old).has(None, {'class': 'tab-btn active', 'data-tab': 'system'})
                  and dom_query(dom_old).has(None, {'id': 'tab-system', 'role': 'tabpanel'})
                  and 'id="tab-sessions" role="tabpanel" hidden' in dom_old)
        check("hash #findings opens Home",
              dom_query(dom_hashfindings).has(None, {'class': 'tab-btn active', 'data-tab': 'home'})
              and dom_query(dom_hashfindings).has(None, {'id': 'tab-home', 'role': 'tabpanel'}))
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
        class PolicyRowCounter(HTMLParser):
            def __init__(self):
                super().__init__()
                self.scopes = []
                self.counts = {}

            def handle_starttag(self, tag, attrs):
                if tag != "div":
                    return
                attributes = dict(attrs)
                scope = attributes.get("data-policy") or (self.scopes[-1] if self.scopes else None)
                self.scopes.append(scope)
                if scope and "policy-row" in attributes.get("class", "").split():
                    self.counts[scope] = self.counts.get(scope, 0) + 1

            def handle_endtag(self, tag):
                if tag == "div" and self.scopes:
                    self.scopes.pop()

        policy_counter = PolicyRowCounter()
        policy_counter.feed(dom_policylists)

        def policy_rows(kind):
            return policy_counter.counts.get(kind, -1)
        check("Policy lists guard decisions, file exceptions and muted classes from their endpoints",
              dom_query(dom_policylists).has(None, {'class': 'tab-btn active', 'data-tab': 'policy'})
              and policy_rows("guard") == 2 and policy_rows("path") == 1 and policy_rows("mute") == 2
              and 'id="badge-guard-rules">2<' in dom_policylists and 'id="badge-path-allows">1<' in dom_policylists
              and '.env.example</code>' in dom_policylists and "keychain-security-cli" in dom_policylists.split('data-policy="mute"', 1)[-1],
              f"guard={policy_rows('guard')} path={policy_rows('path')} mute={policy_rows('mute')}")
        check("Policy empty lists say what fills them",
              "No guard decisions yet." in dom_policyempty and "No file exceptions yet." in dom_policyempty
              and "No muted flag classes." in dom_policyempty and "No expected secret reads." in dom_policyempty)
        check("Policy lists expected secret reads with a Forget button",
              policy_rows("expected") == 1 and 'id="badge-expected">1<' in dom_policylists
              and "<b>gh</b> reads <code>/Users/dev/.config/gh/hosts.yml</code>, then reaches <b>GitHub</b>" in dom_policylists
              and dom_query(dom_policylists).has(None, {'data-action': 'forget-expected'}),
              f"expected={policy_rows('expected')}")
        forget_reqs = pre(dom_forget, "mock-requests")
        scoped_reqs = pre(dom_scoped, "mock-requests")
        check("scoped expectation submits the displayed revision and explicit expiry",
              'POST /reviews/decision' in scoped_reqs and '"revision":3' in scoped_reqs
              and '"scope":{"kind":"exact","expiry":"24h"}' in scoped_reqs)
        check("scoped permission shows the exact endpoint and executable with revocation",
              'api.example.com:443' in dom_scoped and '/usr/bin/cat' in dom_scoped
              and dom_query(dom_scoped).has(None, {'data-action': 'revoke-scope', 'data-id': 'scope-browser'}))
        check("scoped permission revoke uses its ID and updates the visible state",
              'DELETE /decision-scopes?id=scope-browser' in pre(dom_scoped_revoke,"mock-requests")
              and 'Revoked' in dom_scoped_revoke
              and not dom_query(dom_scoped_revoke).has(None, {'data-action': 'revoke-scope', 'data-id': 'scope-browser'}))
        check("Forget deletes the expected pattern and the list reloads without it",
              "DELETE /expected?key=claude%7Cgh%7C%2FUsers%2Fdev%2F.config%2Fgh%2Fhosts.yml%7CGitHub" in forget_reqs
              and 'id="badge-expected">0<' in dom_forget and "No expected secret reads." in dom_forget,
              f"requests={forget_reqs!r}")
        check("notification rules live in the Policy tab; the bell links there",
              dom.index('id="tab-policy"') < dom.index('id="notify-rules-list"')
              and dom_query(dom).has(None, {'id': 'btn-notify', 'data-action': 'goto-tab', 'data-tab': 'policy'})
              and dom.index('id="tab-policy"') < dom.index('id="audit-panel"'))
        check("resource mission control is present", dom_query(dom).has(None, {'id': 'resource-mission-control'}))
        # The live Resources tab ends where the History tab begins: the flight
        # recorder moved out, so it must NOT be inside the resource view.
        resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
        history_view = dom.split('id="history-panel"', 1)[1].split('id="sub-events"', 1)[0]
        check("whole-machine headroom is visible",
              "Machine headroom" in resource_view and "25 / 100" in resource_view
              and "4.0 GB available" in resource_view)
        check("headroom hint explains the score is the tightest limit",
              dom_query(resource_view).has(None, {'class': 'headroom-hint'})
              and dom_query(resource_view).has(None, {'aria-label': 'What machine headroom means'})
              and "tightest limit, not free RAM" in resource_view
              and "Under 15 is critical" in resource_view)
        phone_headroom = re.search(r'data-headroom="(\d+):true"', dom_headroomphone)
        check("headroom hint fits its panel at desktop and phone widths",
              dom_query(dom_headroomwide).has(None, {'data-inside': 'true'}) and dom_query(dom_headroomwide).has(None, {'data-width': '380'})
              and phone_headroom is not None and 250 <= int(phone_headroom.group(1)) <= 320
              and dom_query(dom_headroomphone).has(None, {'data-hscroll': 'sessions:0,agents:0,resources:0'}))
        check("live resources exclude the flight recorder",
              "Pressure flight recorder" not in resource_view)
        check("agent and non-agent memory are separated",
              "Agents 34.4%" in resource_view and "Other 40.6%" in resource_view
              and dom_query(resource_view).has(None, {'class': 'resource-host-segment agent'}))
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
              dom_query(history_view).has(None, {'class': 'resource-activity-marker'})
              and "Bash tool ran" in history_view
              and "connected to api.openai.com:443" in history_view)
        check("historical resource evidence stays scoped to its captured lifetime",
              "Scoped to this captured process lifetime" in history_view
              and not dom_query(history_view).has(None, {'data-action': 'filter-pids', 'data-pids': '4412,4419,4420'}))
        check("resource trend SVG is rendered",
              dom_query(resource_view).has(None, {'class': 'resource-spark'}) and dom_query(resource_view).has(None, {'points': None}))
        check("resource action opens the family in place",
              dom_query(resource_view).has(None, {'data-action': 'view-family', 'data-key': '5821:1789480800000000000'})
              and not dom_query(resource_view).has(None, {'data-action': 'filter-pids'}))
        check("resource policy mode and grace are visible",
              "prompt</b> machine policy" in resource_view and "30s grace" in resource_view)
        check("resource policy source is visible on sessions",
              "workspace policy · /Users/dev/workspace" in resource_view)
        check("resource policy editor opens with the active document",
              dom_query(dom_policy).has(None, {'id': 'drawer', 'class': 'drawer resource-policy'})
              and "Resource policy editor" in dom_policy and "Machine default" in dom_policy)
        check("resource intervention ladder is visible",
              "notify → lower priority → pause → terminate" in resource_view)
        check("policy editor exposes intervention steps",
              'data-step-action="lower_priority" checked' in dom_policy
              and 'data-step-action="pause" checked' in dom_policy)
        check("policy editor adds the selected session workspace",
              dom_query(dom_policy).has(None, {'value': '/Users/dev/workspace/api-service'}))
        # --- resources v2: strip, needs attention, harness groups, family drawer ---
        board = dom_fam.split('id="resource-board"', 1)[1].split('id="history-panel"', 1)[0]
        check("resources: the machine strip renders four tiles",
              dom_query(board).has(None, {'class': 'machine-strip'}) and len(dom_query(board).find_all(None, {'class': 'machine-tile'})) == 4,
              f"tiles={len(dom_query(board).find_all(None, {'class': 'machine-tile'}))}")
        attn = board.split('class="needs-attention"', 1)[1].split('</section>', 1)[0] if dom_query(board).has(None, {'class': 'needs-attention'}) else ''
        attn_keys = re.findall(r'class="resource-session-card needs-attention-card[^"]*" data-key="([^"]+)"', attn)
        check("resources: needs attention holds exactly the two diagnosed families, highest impact first",
              attn_keys == ["5821:1789480800000000000", "6033:1789484400000000000"], f"keys={attn_keys}")
        fam_groups = re.findall(r'<details class="family-group( infra)?" data-harness="([^"]+)"', board)
        check("resources: infra is the one trailing group",
              bool(fam_groups) and fam_groups[-1] == (" infra", "infra") and sum(1 for g in fam_groups if g[0]) == 1,
              f"groups={fam_groups}")
        infra_grp = board.split('data-harness="infra"', 1)[1] if dom_query(board).has(None, {'data-harness': 'infra'}) else ''
        check("resources: infra families sit in Infrastructure and are not counted as families",
              all(f'data-key="{p}:1789470000000000000"' in infra_grp for p in (7001, 7100, 7200))
              and '9 families' in board and '12 families' not in board)
        oc_grp = board.split('data-harness="openclaw"', 1)[1].split('<details', 1)[0] if dom_query(board).has(None, {'data-harness': 'openclaw'}) else ''
        oc_kids = oc_grp.split('class="family-children"', 1)[1] if dom_query(oc_grp).has(None, {'class': 'family-children'}) else ''
        codex_grp = board.split('data-harness="codex"', 1)[1].split('<details', 1)[0] if dom_query(board).has(None, {'data-harness': 'codex'}) else ''
        check("resources: orchestrated children nest under their OpenClaw parent, not as codex rows",
              'data-key="8100:1789470000000000000"' in oc_grp.split('class="family-children"', 1)[0]
              and dom_query(oc_kids).has(None, {'data-key': '8201:1789470000000000000'}) and dom_query(oc_kids).has(None, {'data-key': '8202:1789470000000000000'})
              and '8201:' not in codex_grp and 'Codex · demo-app@main' in oc_kids)
        check("resources: rows and cards carry names, never root PID",
              'root PID' not in board and 'Claude Code · api-service@main' in board
              and 'Codex · data-pipeline@feat/etl' in board)
        check("resources: a group opens by default only when a family in it needs attention",
              dom_query(board).has('details', {'class': 'family-group', 'data-harness': 'claude', 'open': ''})
              and dom_query(board).has('details', {'class': 'family-group', 'data-harness': 'codex'})
              and dom_query(board).has('details', {'class': 'family-group infra', 'data-harness': 'infra'}))
        check("resources: policy line sits below the groups",
              dom_query(board).has(None, {'data-harness': 'infra'}) and dom_query(board).has(None, {'class': 'resource-policy'})
              and board.index('data-harness="infra"') < board.index('class="resource-policy"'))
        fam_drawer = dom_fam.split('<div id="drawer"', 1)[1].split('id="confirm-layer"', 1)[0]
        fam_probe = (re.search(r'<pre id="family-probe"[^>]*>(.*?)</pre>', dom_fam, re.S) or [None, ""])[1]
        check("View family opens the drawer with the family name; the tab stays Resources",
              len(dom_query(dom_fam).find_all('div', {'id': 'drawer', 'class': 'drawer'})) == 1
              and 'id="drawer-title-text">Codex · data-pipeline@feat/etl<' in fam_drawer
              and dom_query(dom_fam).has(None, {'class': 'tab-btn active', 'data-tab': 'sessions'})
              and dom_query(dom_fam).has(None, {'class': 'subtab-btn active', 'data-subtab': 'resources'}))
        check("family drawer: the process table shows 12 rows and Show 8 more, then expands in place",
              fam_probe == "rows=12 more=Show 8 more" and len(dom_query(fam_drawer).find_all(None, {'class': 'family-proc-row'})) == 20
              and not dom_query(fam_drawer).has(None, {'data-action': 'show-more'}), f"probe={fam_probe!r} rows={len(dom_query(fam_drawer).find_all(None, {'class': 'family-proc-row'}))}")
        check("family drawer: leftover marked, recent activity and findings scoped to the family",
              'family-proc-row orphan' in fam_drawer and 'Bash → pytest -q' in fam_drawer
              and 'npm install' not in fam_drawer and 'Keychain file access' in fam_drawer)
        check("family drawer: footer offers Terminate orphans and Terminate family on the root",
              dom_query(fam_drawer).has(None, {'data-action': 'kill-family-orphans', 'data-key': '4412:1789470000000000000'})
              and 'Terminate orphans (1)' in fam_drawer and dom_query(fam_drawer).has(None, {'data-action': 'kill', 'data-pid': '4412'}))
        ev_scoped = dom_famev.split('id="events-container"', 1)[1].split('</section>', 1)[0]
        ev_pids = set(int(x) for x in re.findall(r'<span class="pid" title="PID (\d+)"', ev_scoped))
        check("Open in Events switches to Events scoped to the family pids",
              dom_query(dom_famev).has(None, {'class': 'subtab-btn active', 'data-subtab': 'events'})
              and len(ev_pids) >= 2 and ev_pids <= set(range(4412, 4432)), f"pids={sorted(ev_pids)}")
        ev_cap = dom_evcap.split('id="events-container"', 1)[1].split('</section>', 1)[0]
        check("Events tab shows the newest 50 rows and a Show more button",
              len(dom_query(ev_cap).find_all(None, {'class': 'timeline-item'})) == 50
              and re.search(r'data-action="show-more" data-key="events"[^>]*>Show \d+ more<', ev_cap) is not None,
              f"rows={len(dom_query(ev_cap).find_all(None, {'class': 'timeline-item'}))}")
        ev_trace = dom_evtrace.split('id="events-container"', 1)[1].split('</section>', 1)[0]
        check("Events rows name trace kinds: MODEL and TOOL with their session, never PID 0",
              '>MODEL<' in ev_trace and '>TOOL<' in ev_trace and 'Bash · ok · 2.5s' in ev_trace
              and 'claude-sonnet-4-5 · 12.0k in / 340 out · $0.04' in ev_trace
              and 'api-service@main' in ev_trace and 'PID 0' not in ev_trace,
              f"model={'>MODEL<' in ev_trace} tool={'>TOOL<' in ev_trace} pid0={'PID 0' in ev_trace}")
        ev_dup = dom_duptrace.split('id="events-container"', 1)[1].split('</section>', 1)[0]
        check("Events: two tool calls at the same ts with different call ids render as two rows",
              len(dom_query(ev_dup).find_all(None, {'class': 'timeline-item'})) >= 2 and 'Read · ok' in ev_dup and 'Write · ok' in ev_dup,
              f"rows={len(dom_query(ev_dup).find_all(None, {'class': 'timeline-item'}))}")
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
		      dom_query(dom_policy).has(None, {'id': 'confirm-message'})
		      and "Terminate mode will automatically apply the enabled intervention ladder to entire agent sessions" in dom_policy
		      and 'id="confirm-title">Enable terminate mode<' in dom_policy)
        check("resource approval contains the whole session",
              dom_query(resource_view).has(None, {'data-action': 'resource-control', 'data-id': 'resource-1', 'data-decision': 'apply', 'data-intervention': 'pause'}))
        check("resource approval can keep the session running",
              dom_query(resource_view).has(None, {'data-action': 'resource-control', 'data-id': 'resource-1', 'data-decision': 'dismiss'}))
        check("paused resource session can resume",
              dom_query(resource_view).has(None, {'data-action': 'resource-control', 'data-session': '6033:1789484400000000000', 'data-decision': 'resume'}))
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
        check("trends lead with the activity chart", dom_query(overview).has(None, {'id': 'activity-chart'}))
        check("trends have the findings-by-rule chart", dom_query(overview).has(None, {'id': 'chart-flags'}))
        check("trends have the memory-by-family chart", dom_query(overview).has(None, {'id': 'chart-memory'}))
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
              not dom_query(overview).has(None, {'id': 'session-strip'}) and not dom_query(overview).has(None, {'id': 'events-container'})
              and not dom_query(overview).has(None, {'id': 'resource-board'}))
        check("session board has project filter", dom_query(dom).has(None, {'id': 'session-cwd-filter'}))
        sessions = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
        check("session rail lists live cards and the ended tail", len(dom_query(sessions).find_all(None, {'class': 'session-card'})) == 4,
              f"cards={len(dom_query(sessions).find_all(None, {'class': 'session-card'}))}")
        check("session cards labeled by repo@branch or folder",
              "api-service@main" in sessions and "data-pipeline@feat/etl" in sessions and ">auth<" in sessions)
        check("session card selects the session trace",
              dom_query(sessions).has(None, {'data-action': 'select-session', 'data-id': 'sess-claude-1'}))
        check("the Egress tab carries no decision badge: recurring egress is never queued",
              not dom_query(dom).has(None, {'id': 'tab-badge-egress'}) and not dom_query(dom).has(None, {'data-kind': 'recurring_egress'}))
        needs_you = json.loads(html.unescape(pre(dom, "fixture-posture")))["needs_you"]
        check("home tab badge shows needs-you count",
              f'id="tab-badge-home">{needs_you}<' in dom)
        check("sessions and processes counts sit on the sub-view buttons; the Sessions tab keeps the live count",
              re.search(r'id="subtab-badge-board">\d+<', dom) is not None
              and re.search(r'id="subtab-badge-processes">\d+<', dom) is not None
              and (re.search(r'id="tab-badge-sessions">(\d+)<', dom) or [None, "a"])[1]
              == (re.search(r'id="subtab-badge-board">(\d+)<', dom) or [None, "b"])[1])
        attention = dom.split('id="attention-center"', 1)[1].split('id="security-findings-grid"', 1)[0]
        decisions = attention.split('id="coverage-center"', 1)[0]
        coverage = attention.split('id="coverage-center"', 1)[1].split('id="home-spend"', 1)[0]
        check("Needs you shows the api-service session's decisions as flat rows with its memory, CPU and process count",
              'attention-group' not in dom and "api-service" in decisions
              and "5.5 GB memory · 132.5% CPU · 2 processes" in decisions)
        pat_need = dom_pattern.split('id="attention-center"', 1)[-1].split('id="coverage-center"', 1)[0]
        pat_row = log_rows(dom_pattern).get("pattern:codex|keychain-access|/Users/dev/Library/Keychains/login.keychain-db", "")
        check("a pattern never reaches Needs you; it is one history row with its count",
              'data-pattern-key' not in pat_need and not dom_query(pat_need).has(None, {'data-kind': 'pattern'}) and "codex activity" not in dom_pattern
              and '<span class="c-count">323×</span>' in pat_row, f"row={pat_row[:200]!r}")
        need_kinds = re.findall(r'<li class="need [^"]*" data-kind="(\w+)"', decisions)
        check("Needs you unifies guard, resource, incident and critical-finding rows, highest priority first",
              need_kinds == ["guard", "resource", "incident", "flag", "flag", "flag"], f"kinds={need_kinds}")
        check("Home keeps coverage outside the decisions count",
              'id="badge-coverage-count">2<' in coverage
              and 'File monitoring is off' in coverage
              and '2 connections bypassed inspection' in coverage
              and 'Uninspected egress' not in decisions)
        check("Home with only coverage gaps hides Needs you and shows the gap",
              re.search(r'<section[^>]*id="attention-center"[^>]*\bhidden', dom_coverage) is not None
              and 'No pending decisions' not in dom_coverage.split('id="attention-center"', 1)[-1].split('id="home-spend"', 1)[0]
              and 'id="posture-state">Monitoring needs attention<' in dom_coverage
              and 'id="coverage-center" hidden' not in dom_coverage
              and 'id="badge-coverage-count">2<' in dom_coverage)
        check("attention resource actions target the full session",
              dom_query(attention).has(None, {'data-action': 'resource-control', 'data-id': 'resource-1', 'data-decision': 'apply'}))
        check("session coverage remains available without a global monitoring gap",
              'Per-session coverage · 2' in dom_session_coverage
              and re.search(r'id="coverage-center"[^>]*\bhidden', dom_session_coverage) is None)
        check("same-agent sessions keep independent guard evidence and closed details",
              dom_query(dom_session_coverage).has(None, {'data-session-id': 'session-observed'})
              and dom_query(dom_session_coverage).has(None, {'data-session-id': 'session-silent'})
              and '/work/observed · Guard: activity observed' in dom_session_coverage
              and '/work/&lt;silent&gt; · Guard: not observed' in dom_session_coverage
              and re.search(r'<details[^>]*class="coverage-session"[^>]*\bopen', dom_session_coverage) is None)
        check("an invalidated installed-hook check stays separate from session evidence",
              'Installed hook checks' in dom_session_coverage
              and 'claude · changed' in dom_session_coverage
              and 'Configuration changed. Run the check again.' in dom_session_coverage)
        check("attention guard actions expose bounded choices",
              dom_query(attention).has(None, {'data-action': 'guard-resolve', 'data-id': 'guard-1', 'data-verdict': 'allow', 'data-scope': 'once'})
              and dom_query(attention).has(None, {'data-action': 'guard-resolve', 'data-id': 'guard-1', 'data-verdict': 'deny', 'data-scope': 'once'})
              and dom_query(attention).has(None, {'data-scope': 'exact', 'data-expiry': '24h'})
              and not dom_query(attention).has(None, {'data-scope': 'always'}))
        check("attention keeps scope disclosure compact", "Future access requires a chosen limit" in attention)
        check("coverage egress opens endpoint evidence", dom_query(coverage).has(None, {'data-action': 'open-uninspected'}))
        check("resolved guard request leaves the attention queue",
              f'id="tab-badge-home">{needs_you - 1}<' in dom_guard
              and not dom_query(dom_guard).has(None, {'data-action': 'guard-resolve', 'data-id': 'guard-1'}))
        resolve_probe = (re.search(r'<pre id="resolve-probe"[^>]*>(.*?)</pre>', dom_resolve, re.S) or [None, ""])[1]
        check("resolved incident leaves the attention count before reconciliation",
              resolve_probe == f"badge={needs_you - 1} tab={needs_you - 1} queued=false", f"probe={resolve_probe!r}")
        expect_before = (re.search(r'<pre id="expect-before"[^>]*>(.*?)</pre>', dom_expect, re.S) or [None, ""])[1]
        expect_probe = (re.search(r'<pre id="expect-probe"[^>]*>(.*?)</pre>', dom_expect, re.S) or [None, ""])[1]
        check("an expected connection leaves Egress before the daemon answers; the banner and Needs you count never held it",
              expect_before == f"choices=true listed=false needs={needs_you}"
              and expect_probe == f"choices=false listed=false needs={needs_you}",
              f"before={expect_before!r} probe={expect_probe!r}")
        check("posture flag item opens Home with Findings history",
              dom_query(dom_tab).has(None, {'data-action': 'goto-tab', 'data-tab': 'home', 'data-group': 'findings'}))
        check("tab switch reveals the target panel",
              dom_query(dom_tab).has(None, {'id': 'tab-egress', 'role': 'tabpanel'})
              and 'id="tab-home" role="tabpanel" hidden' in dom_tab)
        recurring = dom_tab.split('id="recurring-egress-container"', 1)[-1].split('id="endpoints-panel"', 1)[0]
        check("Egress explains scheduled calls as observed facts and labeled advisor inference",
              'updates.example.com:443' in recurring
              and 'about every 30–31 min' in recurring
              and 'Advisor inference' in recurring
              and 'Possibly an update check' in recurring)
        check("Egress offers broad scope only with complete attribution",
              dom_query(recurring).has(None, {'data-episode-id': 'episode-routine', 'data-kind': 'scope'})
              and dom_query(recurring).has(None, {'data-episode-id': 'episode-ambiguous', 'data-kind': 'destination'})
              and not dom_query(recurring).has(None, {'data-episode-id': 'episode-ambiguous', 'data-kind': 'scope'}))
        check("Egress opens linked session and can revoke an expected episode",
              dom_query(recurring).has(None, {'data-action': 'filter-session', 'data-session': 'sess-claude-1'})
              and dom_query(recurring).has(None, {'data-action': 'revoke-expected-egress', 'data-id': 'expected-older'})
              and 'First ' in recurring and 'Last ' in recurring)
        check("Policy lists reversible expected connections",
              'old.example.com:443' in dom_policylists
              and dom_query(dom_policylists).has(None, {'data-action': 'revoke-expected-egress', 'data-id': 'expected-older'}))
        # Sessions holds one sub-view at a time.
        check("resources and events are separate sub-views",
              'id="sub-resources" role="tabpanel" hidden' in dom
              and 'id="sub-events" role="tabpanel" hidden' in dom
              and dom_query(dom).has(None, {'class': 'subtabs', 'role': 'tablist'}))
        check("pressure history sits in the Resources sub-view",
              dom.index('id="sub-resources"') < dom.index('id="history-panel"') < dom.index('id="sub-events"'))
        check("resource panel lives in the resources sub-view",
              dom.index('id="sub-resources"') < dom.index('id="resource-board"')
              and dom.index('id="resource-board"') < dom.index('id="history-panel"'))
        check("flight recorder lives in the resources sub-view",
              dom.index('id="history-panel"') < dom.index('id="history-board"')
              and dom.index('id="history-board"') < dom.index('id="sub-events"'))
        check("event timeline lives in the events sub-view",
              dom.index('id="sub-events"') < dom.index('id="events-container"')
              and dom.index('id="events-container"') < dom.index('id="tab-egress"'))

        # --- saved views, search, export (P5) ---
        check("saved-view menu is present", dom_query(dom).has(None, {'id': 'btn-views'}) and dom_query(dom).has(None, {'id': 'views-pop'}))
        check("a saved view appears in the list",
              dom_query(dom_view).has(None, {'data-action': 'apply-view', 'data-name': 'Prod leaks'}))
        check("global search box is present", dom_query(dom).has(None, {'id': 'global-search'}))
        check("export actions are wired",
              dom_query(dom).has(None, {'data-action': 'export', 'data-what': 'flags'})
              and dom_query(dom).has(None, {'data-action': 'export', 'data-what': 'incidents'}))
        # The search term narrows the events panel: "npm" must drop rows that
        # do not mention it (the drip includes non-npm events).
        check("search narrows the panel",
              len(dom_query(dom_view).find_all(None, {'class': 'timeline-item'})) <= len(dom_query(dom).find_all(None, {'class': 'timeline-item'})))

        # --- action feedback loops (the "nothing happens" regressions) ---
        check("flag card carries per-flag dismiss",
              dom_query(dom).has(None, {'data-action': 'dismiss-flag', 'data-id': 'flag-1'}))
        check("flag card carries re-run advisor",
              dom_query(dom).has(None, {'data-action': 'retriage', 'data-id': 'flag-1'}))
        check("keychain flag shows benign context",
              "usually routine" in dom)
        check("allow removes the suggestion from the list",
              "fw-suggestion" not in dom_allow,
              "suggestion still rendered after Allow")
        dismiss_rows = [k for k in log_rows(dom_dismiss) if k.startswith("flag:")]
        check("dismiss removes the flag's row",
              len(dismiss_rows) == 2 and not dom_query(dom_dismiss).has(None, {'data-id': 'flag-3'}),
              f"rows={dismiss_rows}")
        check("re-triage verdict lands and replaces the chip",
              "re-triage complete: routine vendor traffic" in dom_retriage
              and "advisor: benign" in dom_retriage)
        check("fresh identical re-triage verdict clears pending and reports completion",
              pre(dom_retriage, 'retriage-complete') == 'true'
              and 'POST /advisor/retriage' in dom_retriage)
        check("advisor offline renders honest disabled state",
              "Advisor offline" in dom_advdown
              and not dom_query(dom_advdown).has(None, {'data-action': 'retriage', 'data-id': 'flag-1'}))
        check("timeline rows carry agent names, not bare PIDs",
              "cursor · PID 6033" in dom or "claude · PID 5821" in dom)

        # --- structural security: no inline handlers anywhere ---
        check("zero inline onclick handlers in rendered DOM", not dom_query(dom).has(None, {'onclick': None}))

        # --- session drill-down (auto-action run) ---
        link_rail = dom_sesslink.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
        check("View session in timeline opens the session in the Sessions tab: card selected, trace rendered",
              dom_query(dom_sesslink).has(None, {'class': 'tab-btn active', 'data-tab': 'sessions'})
              and re.search(r'<div class="session-card active selected">\s*<button type="button" class="sc-main" '
                            r'data-action="select-session" data-id="sess-claude-1" aria-pressed="true"', link_rail) is not None
              and re.search(r'<h3[^>]*>api-service@main</h3>', dom_sesslink.split('id="session-detail"', 1)[1]) is not None
              and dom_query(dom_sesslink).has(None, {'class': 'wf-bar'}))
        check("session chip appears", dom_query(dom_session).has(None, {'id': 'session-filter', 'class': 'session-filter'})
              or (dom_query(dom_session).has(None, {'id': 'session-filter'}) and "hidden" not in
                  dom_session.split('id="session-filter"')[1][:80]))
        check("session chip count", "7f3a9c21 · 2" in dom_session)
        check("session scopes findings list",
              dom_query(dom_session).has(None, {'id': 'flags-session-filter'})
              and "hidden" not in dom_session.split('id="flags-session-filter"')[1][:80])
        session_rows = len(dom_query(dom_session).find_all(None, {'class': 'timeline-item'}))
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

        # --- session origin: identical rows fold into one "×N" row ---
        dup_rail = dom_dup.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
        quill_key = 'group:codex|demo-app@main · quill'
        check("identical-title sessions fold into one row titled with the spawning agent",
              dup_rail.count(f'data-action="toggle-session-dup" data-key="{quill_key}"') == 1
              and '<span class="sc-label">demo-app@main · quill</span><span class="session-dup-count">×5</span>' in dup_rail
              and '<span class="sc-label">.openclaw · fennel</span><span class="session-dup-count">×3</span>' in dup_rail)
        dup_row = dup_rail.split(f'data-key="{quill_key}"', 1)[1].split('toggle-session-dup', 1)[0]
        dup_ids = re.findall(r'data-action="select-session" data-id="(sess-dup-\d)"', dup_row)
        dup_labels = re.findall(r'<span class="sc-label">(\d\d:\d\d)</span>', dup_row)
        check("an expanded folded row lists its five sessions newest first with HH:MM start times",
              dup_ids == [f"sess-dup-{i}" for i in range(1, 6)] and len(dup_labels) == 5
              and f'data-key="{quill_key}" aria-expanded="true"' in dup_rail,
              f"ids={dup_ids} labels={dup_labels}")
        try:
            dup_probe = json.loads(pre(dom_dup, "dup-probe") or "null")
        except ValueError:
            dup_probe = None
        check("a selected member of a folded row keeps its selection across a patch",
              dup_probe == {"key": quill_key, "open": True, "selected": ["sess-dup-3"]}, f"probe={dup_probe}")
        dup_board = dom_dupres.split('id="resource-board"', 1)[1]
        check("Resources folds identical family labels into one row with summed memory, CPU and processes",
              re.search(r'data-action="toggle-family-dup" data-key="group:codex\|Codex · fennel" aria-expanded="false">'
                        r'<strong>Codex · fennel</strong><span class="family-dup-count">×3</span>', dup_board) is not None
              and '<b>600 MB</b><small>memory</small>' in dup_board and '<b>6</b><small>processes</small>' in dup_board)
        try:
            fold_probe = json.loads(pre(dom_foldpatch, "fold-probe") or "null")
        except ValueError:
            fold_probe = None
        check("a status change patches a session group in place: a focused row keeps identity and focus, the group stays open, the counts update",
              isinstance(fold_probe, dict) and fold_probe.get("focus") is True and fold_probe.get("group") is True
              and fold_probe.get("before") and fold_probe.get("after") and fold_probe.get("before") != fold_probe.get("after"),
              f"probe={fold_probe}")
        check("a live and an ended fold with one title expand independently",
              isinstance(fold_probe, dict) and fold_probe.get("live") == "false" and fold_probe.get("ended") == "true",
              f"probe={fold_probe}")
        try:
            family_probe = json.loads(pre(dom_familypatch, "family-probe") or "null")
        except ValueError:
            family_probe = None
        check("a metric update patches a Resources group per row: a focused family control keeps identity and focus, the fold stays expanded",
              isinstance(family_probe, dict) and family_probe.get("focus") is True and family_probe.get("group") is True
              and family_probe.get("fold") == "true"
              and family_probe.get("before") and family_probe.get("after") and family_probe.get("before") != family_probe.get("after"),
              f"probe={family_probe}")

        infra_tag = re.search(r'<details class="session-group infra"[^>]*>', dom_railburst)
        infra_tag = infra_tag.group(0) if infra_tag else ""
        check("burst: an opened rail <details> is the same node and still open",
              dom_query(infra_tag).has(None, {'open': ''}) and dom_query(infra_tag).has(None, {'data-probe': '1'}), f"tag={infra_tag}")

        flags_focus = dom_focus.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
        check("burst: a focused history row head keeps identity and focus",
              dom_query(flags_focus).has(None, {'data-probe': '1'}) and pre(dom_focus, "focus-probe") == "kept",
              f"probe={pre(dom_focus, 'focus-probe')!r}")

        mem_probe = re.match(r"renders=(\d+) kept=(\d+)/(\d+)$", pre(dom_memprobe, "mem-probe"))
        check("memory by family: a re-render keeps every unchanged family row as the same node",
              mem_probe is not None and int(mem_probe.group(1)) >= 1 and int(mem_probe.group(3)) == 4
              and mem_probe.group(2) == mem_probe.group(3),
              f"probe={pre(dom_memprobe, 'mem-probe')!r}")

        flags_click = dom_click.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
        check("burst: a click spanning renders lands (POST /flags/acknowledge, card gone)",
              "POST /flags/acknowledge" in pre(dom_click, "mock-requests") and not dom_query(flags_click).has(None, {'data-id': 'flag-3'}),
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
              "POST /allowlist row=1" in pre(dom_act, "mock-requests") and dom_query(act_row).has(None, {'class': 'card-note'}),
              f"requests={pre(dom_act, 'mock-requests')!r} row={act_row[:160]!r}")
        check("act in place: a failed allow reverts the row and toasts danger",
              "POST /allowlist row=1" in pre(dom_actfail, "mock-requests")
              and "registry.npmjs.org · cursor" not in dom_actfail
              and dom_query(dom_actfail).has(None, {'class': 'toast danger'})
              and dom_query(dom_actfail).has(None, {'data-action': 'allow-host', 'data-agent': 'cursor', 'data-host': 'registry.npmjs.org'}),
              f"requests={pre(dom_actfail, 'mock-requests')!r}")

        # --- finding card v2: the daemon's served explanation ---
        def visible(markup):
            return re.sub(r"<[^>]*>", " ", markup)

        card = log_rows(dom_explain).get("flag:flag-2", "")
        head = (re.search(r'<button type="button" class="log-head".*?</button>', card, re.S) or [""])[0]
        outside = re.sub(r"<details.*?</details>", "", card, flags=re.S)
        check("finding row: the head shows the title, never the rule id; no pid or IPv6 outside Evidence",
              card != "" and "Sensitive file read near an outside connection" in head
              and "sensitive-read-then-connect" not in visible(head)
              and not re.search(r"\bpid\b", visible(outside), re.I) and "6033" not in visible(outside)
              and "2606:" not in visible(outside), f"card={card[:240]!r}")
        check("finding row carries no inline handlers or styles",
              card != "" and not dom_query(card).has(None, {'onclick': None}) and not dom_query(card).has(None, {'style': None}))
        buttons = re.findall(r'<button class="btn ([a-z-]+) btn-sm" data-action="explain-act" '
                             r'data-flag-id="flag-2" data-action-id="([a-z-]+)"', card)
        menu = re.findall(r'<button class="act-menu-item( danger)?" data-action="explain-act" '
                          r'data-flag-id="flag-2" data-action-id="([a-z-]+)"', card)
        check("finding row: who, what and verdict; the recommended action leads the bar, the rest sit under More",
              ">cursor · web-app@main</span>" in card
              and '<p class="body-lead">Cursor read AWS credentials (~/.aws/credentials), then reached Cloudflare 3 s later.</p>' in card
              and '<p class="body-verdict">Likely benign (advisor 93 %): Cloudflare fronts the package registry this project installs from.</p>' in card
              and buttons == [("btn-primary", "allow-host"), ("btn-ghost", "dismiss")]
              and menu == [("", "allow-path"), (" danger", "kill")],
              f"buttons={buttons} menu={menu}")
        details = (re.search(r'<details class="body-evidence">(.*?)</details></div>', card, re.S) or [None, ""])[1]
        check("finding row: Evidence is closed by default and holds the chain, pid, full address and ISO timestamp",
              details != "" and dom_query(details).has(None, {'class': 'chain'}) and "2026-09-22T16:05:01Z" in details
              and "6033" in details and "[2606:4700::6810:84e5]:443" in details
              and "/Users/dev/.aws/credentials" in details, f"details={details[:200]!r}")

        act_reqs = pre(dom_explainact, "mock-requests")
        flags_act = dom_explainact.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
        check("finding card: the recommended action sends the served request; the card leaves with an inline note",
              'POST /allowlist' in act_reqs
              and 'body={"agent":"cursor","host":"2606:4700::6810:84e5"}' in act_reqs
              and 'POST /flags/acknowledge' in act_reqs
              and not dom_query(flags_act).has(None, {'data-flag-id': 'flag-2'})
              and 'class="card-note">allowlisted<' in dom_explainact, f"requests={act_reqs!r}")
        allowpath_reqs = pre(dom_allowpathact, "mock-requests")
        check("finding card: the allow-path action (not the first/recommended button) sends its own served request",
              'POST /guard/path-allow body={"agent":"cursor","rule_id":"cloud-creds","path":"/Users/dev/.aws/credentials"}' in allowpath_reqs
              and 'POST /allowlist' not in allowpath_reqs,
              f"requests={allowpath_reqs!r}")
        org_card = pre(dom_orgallow, "org-allow-card")
        org_reqs = pre(dom_orgallow, "mock-requests")
        check("finding card: three Google addresses are one Allow Google choice that allows each host, then marks the flag reviewed",
              org_card == "bar=1 org=1 hosts=0"
              and org_reqs.count("POST /allowlist") == 3
              and 'body={"agent":"cursor","host":"2607:f8b0:4002:c08::54"}' in org_reqs
              and org_reqs.rstrip().endswith('POST /flags/acknowledge body={"flag_id":"flag-1"}'),
              f"card={org_card!r} requests={org_reqs!r}")
        routine_before = pre(dom_routine, "routine-before")
        routine_after = pre(dom_routine, "routine-after")
        check("routine: gh across three agents is one history row, never a decision; Treat as routine sends the served ids and the row leaves before the answer",
              routine_before == "queued=false count=145× buttons=2"
              and routine_after == f"card=false needs={needs_you}"
              and 'POST /expected body={"flag_ids":["r1","r2"]}' in pre(dom_routine, "mock-requests"),
              f"before={routine_before!r} after={routine_after!r} requests={pre(dom_routine, 'mock-requests')!r}")
        fail_reqs = pre(dom_explainfail, "mock-requests")
        flags_fail = dom_explainfail.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
        check("finding card: a failed allow puts the card back and toasts danger",
              'POST /allowlist' in fail_reqs and 'POST /flags/acknowledge' not in fail_reqs
              and dom_query(flags_fail).has('div', {'class': 'row-body', 'data-flag-id': 'flag-2'})
              and dom_query(dom_explainfail).has(None, {'class': 'toast danger'}), f"requests={fail_reqs!r}")

        attn = dom_explain.split('id="attention-center"', 1)[-1].split('id="coverage-center"', 1)[0]
        flag2_row = log_rows(dom_explain).get("flag:flag-2", "")
        check("attention: a benign-likely explained finding is not a decision; it is a history row with its verdict",
              'flag-2' not in attn
              and 'Sensitive file read near an outside connection' in flag2_row
              and '<span class="c-verdict-text">Likely benign (advisor 93 %)</span>' in flag2_row
              and dom_query(flag2_row).has(None, {'data-action': 'explain-act', 'data-flag-id': 'flag-2', 'data-action-id': 'allow-host'}),
              f"row={flag2_row[:200]!r}")
        probe = pre(dom_detailsprobe, "details-probe")
        check("finding row: an open Evidence section survives a burst of re-renders",
              probe == "kept", f"probe={probe!r}")
        flag3 = log_rows(dom_explain).get("flag:flag-3", "")
        check("finding row: a flag without explain opens to its evidence lines and the console's Dismiss and Kill",
              dom_query(flag3).has(None, {'class': 'flag-evidence'}) and dom_query(flag3).has(None, {'data-action': 'dismiss-flag', 'data-id': 'flag-3'})
              and dom_query(flag3).has(None, {'data-action': 'kill'}), f"row={flag3[:200]!r}")

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
              and m.group(3).startswith("Scoped to session ") and re.search(r" · \d+ events? · \d+ flags?Back to sessionClear$", m.group(3))
              and m.group(5) == "hidden" and m.group(6) == "" and int(m.group(7)) > int(m.group(4))
              and m.group(8) == "hidden", f"probe={scope!r}")
        attention_badge = (re.search(r'id="badge-attention-count"[^>]*>(\d+)<', dom) or [None, ""])[1]
        tab_badge = (re.search(r'id="tab-badge-home"[^>]*>(\d+)<', dom) or [None, ""])[1]
        check("attention badge and tab badge equal posture.needs_you; coverage stays separate",
              attention_badge == str(needs_you) and tab_badge == str(needs_you)
              and '<strong>File monitoring is off</strong>' in coverage and dom_query(coverage).has(None, {'data-action': 'open-fda'})
              and not dom_query(attention).has(None, {'data-id': 'flag-3'}) and dom_query(dom).has(None, {'data-row-key': 'flag:flag-3'}),
              f"badge={attention_badge!r} tab={tab_badge!r} needs_you={needs_you}")

        # --- patterns: a repeating finding is one card ---
        gh_cards = dom_gh.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
        check("GitHub grouped finding exposes approval, local review and inspection",
              all(f'data-action-id="{action}"' in gh_cards for action in ('expect', 'review-local', 'inspect-file')))
        check("GitHub approval posts the served exact scope and reconciles to reviewed",
              'POST /expected body={"flag_id":"gh-flag","path":"/Users/dev/.config/gh/hosts.yml","host":"140.82.114.6"}' in pre(dom_ghapprove, "mock-requests")
              and '<b class="pattern-open">0 open</b>' in dom_ghapprove)
        pat_flags = dom_pattern.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
        pat_rows = log_rows(pat_flags)
        pat_cards = [(k, v) for k, v in pat_rows.items() if k.startswith("pattern:")]
        # Covered flags are intentionally clickable inside the disclosure;
        # only a separate top-level flag row would be a duplicate.
        check("patterns: History shows the storm as one row, its body with the count, summary, 24 bars and open count",
              len(pat_cards) == 1 and "323×" in pat_cards[0][1]
              and "codex touched the login keychain 323 times" in pat_cards[0][1]
              and len(re.findall(r'<i class="h\d"></i>', (re.search(r'<span class="pattern-bars" role="img"[^>]*>(.*?)</span>', pat_cards[0][1], re.S) or [None, ""])[1])) == 24
              and '<b class="pattern-open">323 open</b>' in pat_cards[0][1]
              and not dom_query(pat_flags).has(None, {'data-row-key': 'flag:flag-6'}) and not dom_query(pat_flags).has(None, {'data-row-key': 'flag:flag-7'})
              and all(f'data-action="open-flag" data-id="{fid}"' in pat_cards[0][1] for fid in ("flag-6", "flag-7")),
              f"cards={len(pat_cards)}")
        pat_standalone = "".join(v for k, v in pat_rows.items() if not k.startswith("pattern:"))
        check("patterns: critical individual flags lead warnings without duplicating covered flags",
              dom_query(pat_flags).has(None, {'data-pattern-key': starts_with('codex|keychain-access|')})
              and pat_flags.index('data-id="flag-1"') < pat_flags.index('data-pattern-key=') < pat_flags.index('data-id="flag-3"')
              and not any(f'data-id="{fid}"' in pat_standalone or f'data-flag-id="{fid}"' in pat_standalone for fid in ("flag-6", "flag-7"))
              and "(PID 40844)" not in pat_flags and "(PID 51364)" not in pat_flags
              and dom_query(pat_flags).has(None, {'data-id': 'flag-3'}))
        pat_reqs = pre(dom_patternact, "mock-requests")
        check("patterns: dismiss-all posts the served flag_ids and the row shows 0 open",
              'POST /flags/acknowledge body={"flag_ids":["flag-7","flag-6"]}' in pat_reqs
              and re.search(r'<div class="row-body" data-pattern-key="[^"]+">.*?<b class="pattern-open">0 open</b>', dom_patternact, re.S) is not None
              and '<b class="pattern-open">323 open</b>' not in dom_patternact,
              f"requests={pat_reqs!r}")
        check("patterns: the page still fits a 375px phone, the pattern card's tab included",
              dom_query(dom_patternphone).has(None, {'data-hscroll': 'sessions:0,agents:0,resources:0,findings:0'}),
              (re.search(r'data-hscroll="[^"]*"', dom_patternphone) or [None])[0])
        stream = pre(dom_patternstream, "pattern-stream-probe")
        check("patterns: a streamed flag the pattern covers folds into its one card after the debounced reconcile",
              stream == "mid cards=1 covered=0 row=1 | end cards=1 covered=1 row=0", f"probe={stream!r}")
        keep = pre(dom_attnkeep, "attn-probe")
        check("history: an open pattern disclosure and a focused button survive a session RSS change; Needs you shows the new memory and never the pattern",
              keep.startswith("open=true focus=true queued=false metrics=") and "700 MB memory" in keep, f"probe={keep!r}")

        big_rows = log_rows(dom_patternbig)
        big_pattern = [k for k in big_rows if k.startswith("pattern:")]
        check("a 61-flag pattern is exactly one history row reading 61×",
              len(big_pattern) == 1 and '<span class="c-count">61×</span>' in big_rows[big_pattern[0]]
              and not [k for k in big_rows if k.startswith("flag:kc-")], f"rows={list(big_rows)[:6]}")
        bulk_reqs = pre(dom_bulk, "mock-requests")
        check("bulk Mark reviewed on two selected rows asks one confirm and sends one acknowledge batch",
              pre(dom_bulk, "bulk-probe") == "confirms=1" and bulk_reqs.count("POST /flags/acknowledge") == 1
              and re.search(r'POST /flags/acknowledge body=\{"flag_ids":\["flag-[13]","flag-[13]"\]\}', bulk_reqs) is not None,
              f"probe={pre(dom_bulk, 'bulk-probe')!r} requests={bulk_reqs!r}")
        empty_need = dom_empty.split('id="attention-center"', 1)[-1].split('id="home-spend"', 1)[0]
        check("empty posture: Needs you, the Monitoring gap and the Home tab badge are all hidden",
              re.search(r'<section[^>]*id="attention-center"[^>]*\bhidden', dom_empty) is not None
              and re.search(r'id="coverage-center"[^>]*\bhidden', dom_empty) is not None
              and re.search(r'id="tab-badge-home"[^>]*\bhidden', dom_empty) is not None
              and 'No pending decisions' not in empty_need and not dom_query(empty_need).has(None, {'class': 'need '}))

        # --- worktrees: the hunter's report, one row per worktree ---
        def wt_block(dom_text):
            return dom_text.split('id="worktrees-container"', 1)[-1].split('data-action="clutter-rescan"', 1)[0]

        def cl_block(dom_text):
            return dom_text.split('id="clutter-container"', 1)[-1].split('id="tab-policy"', 1)[0]
        wt = wt_block(dom_wt)
        wt_rows = len(dom_query(wt).find_all(None, {'class': 'wt-row'}))
        wt_remove = len(dom_query(wt).find_all(None, {'data-action': 'worktree-remove'}))
        wt_prune = len(dom_query(wt).find_all(None, {'data-action': 'worktree-prune'}))
        check("worktrees: the System tab opens and renders a row per non-main worktree with its state",
              dom_query(dom_wt).has(None, {'class': 'tab-btn active', 'data-tab': 'system'}) and not dom_query(dom_wt).has(None, {'data-subtab': 'worktrees'})
              and dom_wt.index('data-tab="egress" role="tab"') < dom_wt.index('data-tab="system" role="tab"') < dom_wt.index('data-tab="policy" role="tab"')
              and wt_rows == 4
              and all(f'class="wt-row wt-{s}"' in wt for s in ("remove", "review", "keep", "prune"))
              and "main worktree of the repository" not in wt,
              f"rows={wt_rows}")
        check("worktrees: git Remove only on the remove row, Prune only on the prune row",
              wt_remove == 1 and wt_prune == 1
              and dom_query(wt).has(None, {'data-action': 'worktree-remove', 'data-path': '/Users/dev/workspace/api-service/.worktrees/done'}),
              f"remove={wt_remove} prune={wt_prune}")
        check("worktrees: reasons render as text, paths inside the repo read relative",
              "&lt;b&gt;not bold&lt;/b&gt;" in wt and "<b>not bold</b>" not in wt
              and '<button type="button" class="wt-path" data-action="copy-path" data-path="/Users/dev/workspace/api-service/.worktrees/done"'
                  ' title="/Users/dev/workspace/api-service/.worktrees/done — click to copy">.worktrees/done</button>' in wt)
        check("worktrees: state pills carry counts and the summary line reads the scan",
              'data-state="" aria-pressed="true">All <b>4</b></button>' in dom_wt
              and 'data-state="remove" aria-pressed="false">Remove <b>1</b></button>' in dom_wt
              and "1 repo · 4 worktrees · stale after 14 idle days · scanned in 4.2s" in dom_wt)
        check("worktrees: the advisor note renders escaped under its row and ends in Discuss; Ask advisor sits on review and keep rows only",
              '<p class="wt-advice"><b>Advisor: review</b> 60% · &lt;i&gt;look&lt;/i&gt; at .tmp before removing '
              '<button type="button" class="link-btn" data-action="worktree-discuss" data-path="/Users/dev/workspace/api-service/.worktrees/evidence">Discuss</button></p>' in wt
              and len(dom_query(wt).find_all(None, {'data-action': 'worktree-advise'})) == 2)
        check("worktrees: Discuss sits on the remove, review and keep rows and the note, not on the prune row",
              len(dom_query(wt).find_all(None, {'data-action': 'worktree-discuss'})) == 4
              and not dom_query(wt).has(None, {'data-action': 'worktree-discuss', 'data-path': '/Users/dev/workspace/api-service/.worktrees/gone'}))
        check("worktrees: Ask <harness> appears only for the active agent; no review drawer button remains",
              len(dom_query(wt).find_all(None, {'data-action': 'worktree-ask'})) == 1
              and dom_query(wt).has(None, {'class': 'btn btn-primary btn-sm', 'data-action': 'worktree-ask'}) and '>Ask codex</button>' in wt
              and 'Ask the agent' not in wt
              and not dom_query(wt).has(None, {'data-action': 'worktree-review'})
              and '<p class="wt-ask wt-ask-answered"><b>Asked claude:</b> pr — https://github.com/o/r/pull/9 ($0.21)</p>' in wt)
        check("worktrees: review and keep rows carry Remove; the row with a live agent session is disabled and says why",
              len(dom_query(wt).find_all(None, {'data-action': 'worktree-review-trash'})) == 1
              and dom_query(wt).has(None, {'data-action': 'worktree-review-trash', 'data-path': '/Users/dev/workspace/api-service/.worktrees/evidence'})
              and wt.count('>Remove</button>') == 2 and wt.count('>Remove…</button>') == 1
              and 'disabled="" title="Cannot remove: an agent session is live here">Remove</button>' in wt)
        check("worktrees: Remove has three looks: solid red when confirmed safe, amber outline when not confirmed, greyed when blocked; a legend explains them",
              '<button type="button" class="btn btn-danger-solid btn-sm" data-action="worktree-remove" data-path="/Users/dev/workspace/api-service/.worktrees/done" data-branch="feat/done" title="Safe to remove: merged into origin/main (squash)">Remove</button>' in wt
              and dom_query(wt).has('button', {'type': 'button', 'class': 'btn btn-warn-outline btn-sm', 'data-action': 'worktree-review-trash', 'data-path': '/Users/dev/workspace/api-service/.worktrees/evidence'})
              and dom_query(wt).has(None, {'title': starts_with('Not confirmed safe: ignored files that only live here: .tmp/ (3 files, 1.2 MB); ')})
              and 'not bold' in wt and '. Moves the folder to the Trash; the branch stays in git">Remove…</button>' in wt
              and '<button type="button" class="btn btn-sm" disabled="" title="Cannot remove: an agent session is live here">Remove</button>' in wt
              and 'btn btn-danger btn-sm" data-action="worktree-review-trash"' not in wt
              and 'btn btn-danger btn-sm" disabled' not in wt)
        check("worktrees: the legend under the summary names the three Remove looks and is visible with a scan",
              '<p class="wt-legend" id="worktrees-legend">Remove: confirmed safe · Remove…: not confirmed, goes to the Trash · greyed: blocked</p>' in dom_wt
              and '<p class="wt-legend" id="worktrees-legend" hidden' not in dom_wt)
        check("worktrees: the repository group offers Ask advisor about all and Discuss all beside Hide repo, counted over every row",
              len(dom_query(wt).find_all(None, {'data-action': 'worktree-advise-all', 'data-repo': '/Users/dev/workspace/api-service'})) == 1
              and len(dom_query(wt).find_all(None, {'data-action': 'worktree-discuss-all', 'data-repo': '/Users/dev/workspace/api-service'})) == 1
              and '>Ask advisor about all 3</button>' in wt and '>Discuss all 4</button>' in wt
              and wt.index('worktree-advise-all') < wt.index('worktree-discuss-all') < wt.index('data-action="worktree-hide"'))
        check("worktrees: Remove on a review row confirms what goes to the Trash and what stays in git, with no drawer",
              'Move /Users/dev/workspace/api-service/.worktrees/evidence to the Trash and unregister the worktree?' in dom_wtreview
              and 'Goes with it: ignored files that only live here: .tmp/ (3 files, 1.2 MB)' in dom_wtreview
              and 'Stays in git: branch feat/evidence, its commits and stashes.' in dom_wtreview
              and 'Its files stay in the Trash until you empty it; putting them back does not register the worktree again.' in dom_wtreview
              and 'id="confirm-layer" class="confirm-layer" hidden' not in dom_wtreview
              and 'Review worktree' not in dom_wtreview)
        dw_agent = dom_wtdiscuss.split('id="tab-agent"', 1)[-1].split('id="drawer"', 1)[0]
        check("worktrees: Discuss posts the worktree to the agent, opens the Agent tab and shows the question as a card",
              'POST /agent/worktree' in pre(dom_wtdiscuss, 'mock-requests')
              and dom_query(dom_wtdiscuss).has(None, {'class': 'tab-btn active', 'data-tab': 'agent'})
              and dw_agent.count('agent-worktree-card') == 1
              and '<b>Can I delete this worktree?</b>' in dw_agent
              and 'branch feat/evidence' in dw_agent and 'Only ignored scratch files would be lost.' in dw_agent)
        check("worktrees: Discuss with the agent off toasts the server's text and stays on System",
              'class="toast danger">the system agent is off: set system_agent.enabled: true in the config file<' in dom_wtdiscussoff
              and dom_query(dom_wtdiscussoff).has(None, {'class': 'tab-btn active', 'data-tab': 'system'}))
        check("worktrees: reviewed folder leaves the list after explicit Trash confirmation",
              'POST /worktrees/review-trash' in pre(dom_wtreviewtrash, 'mock-requests')
              and '.worktrees/evidence' not in wt_block(dom_wtreviewtrash))
        check("worktrees: the disk card shows the volume and what worktrees occupy",
              "512.0 GB free of 2.0 TB" in dom_wt and dom_query(dom_wt).has(None, {'data-w': '75'})
              and "<b>Worktrees</b> 1.5 GB" in dom_wt
              and '<span class="wt-size">1.5 GB</span>' in wt)

        def rc_block(dom_text):
            return dom_text.split('id="worktrees-reclaim"', 1)[-1].split('id="reclaim-tip"', 1)[0]

        def tile(dom_text, cls):
            return rc_block(dom_text).split(f'class="rc-tile {cls}"', 1)[-1].split('</div>', 1)[0]
        rc = rc_block(dom_wt)
        check("worktrees: tiles lead the tab: freed in 30 days, all time, removable now, in the Trash",
              "Freed · last 30 days" in tile(dom_wt, "rc-freed") and "1.0 GB" in tile(dom_wt, "rc-freed")
              and "1 cleanup<" in tile(dom_wt, "rc-freed")
              and "3.0 GB" in tile(dom_wt, "rc-alltime") and "2 cleanups" in tile(dom_wt, "rc-alltime")
              and "1.5 GB" in tile(dom_wt, "rc-removable") and "1 worktree<" in tile(dom_wt, "rc-removable")
              and "worktrees-remove-removable" not in rc
              and "50 MB" in tile(dom_wt, "rc-trash"),
              rc[:600])
        check("worktrees: the reclaimed chart has a column per day; only days with cleanups are buttons, labeled with their numbers",
              len(dom_query(rc).find_all(None, {'class': 'rc-col'})) == 30 and len(dom_query(rc).find_all(None, {'data-action': 'reclaim-day'})) == 1
              and dom_query(rc).has(None, {'aria-label': 'Space reclaimed per day, last 30 days'})
              and ': 1.0 GB freed by 1 cleanup, 50 MB moved to the Trash by 1 cleanup"' in rc
              and dom_query(rc).has(None, {'class': 'rc-seg rc-seg-trash', 'data-h': '5'})
              and "<span>2.0 GB</span><span>1.0 GB</span><span>0</span>" in rc,
              f"cols={len(dom_query(rc).find_all(None, {'class': 'rc-col'}))} days={len(dom_query(rc).find_all(None, {'data-action': 'reclaim-day'}))}")
        check("worktrees: an old cached scan shows at once and the tab re-reads until the rescan lands",
              "gone-since" not in wt_block(dom_wtrefresh) and "refreshing…" not in dom_wtrefresh
              and "scanned in 4.2s" in dom_wtrefresh)
        check("worktrees: while the daemon is still measuring, the tab re-reads until sizes land",
              '<span class="wt-size">1.5 GB</span>' in wt_block(dom_wtsizing) and "measuring…" not in dom_wtsizing
              and "<b>Worktrees</b> 1.5 GB" in dom_wtsizing)
        cl = cl_block(dom_wt)
        check("clutter: items grouped by project with kind, size, idle; Trash and Run only where the item offers them",
              len(dom_query(cl).find_all(None, {'class': 'wt-row cl-row'})) == 3
              and 'data-action="clutter-trash" data-path="/Users/dev/workspace/api-service/.tmp">Move to Trash</button>' in cl
              and 'data-action="clutter-clean" data-name="go build" title="go clean -cache">Run go clean -cache</button>' in cl
              and len(dom_query(cl).find_all(None, {'data-action': 'clutter-trash'})) + len(dom_query(cl).find_all(None, {'data-action': 'clutter-clean'})) == 2
              and "&lt;i&gt;downloaded&lt;/i&gt; models" in cl and "<i>downloaded</i>" not in cl
              and '<span class="wt-repo-path" title="This machine">This machine</span>' in cl)
        check("clutter: each project has Ask advisor; its plan renders escaped under the header with one step per line",
              len(dom_query(cl).find_all(None, {'data-action': 'clutter-advise'})) == 2
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
        wtr_rows = len(dom_query(wtr).find_all(None, {'class': 'wt-row'}))
        wt_reqs = pre(dom_wtremove, "mock-requests")
        check("worktrees: Remove starts a background removal after the dialog; when it lands the row leaves and the tiles move",
              "POST /worktrees/remove" in wt_reqs and ".worktrees/done" not in wtr and wtr_rows == 3
              and "4.5 GB" in tile(dom_wtremove, "rc-alltime") and "3 cleanups" in tile(dom_wtremove, "rc-alltime")
              and "2.5 GB" in tile(dom_wtremove, "rc-freed") and "0 B" in tile(dom_wtremove, "rc-removable")
              and "wt-removal" not in wtr,
              f"requests={wt_reqs!r} rows={wtr_rows}")

        def toast_block(dom_text):
            return dom_text.split('id="removal-toast"', 1)[-1].split('</ul>', 1)[0] if dom_query(dom_text).has(None, {'id': 'removal-toast'}) else ''
        tr = dom_wtremove.split('id="removal-toast"', 1)[-1].split('id="drawer"', 1)[0] if dom_query(dom_wtremove).has(None, {'id': 'removal-toast'}) else ''
        check("worktrees: when the removal lands its toast names what it reclaimed and links the history",
              dom_query(dom_wtremove).has(None, {'class': 'toast toast-sticky removal-toast success'})
              and '<p class="rt-title" role="status">Removed feat/done</p>' in tr
              and '<p class="rt-sub">1.5 GB reclaimed</p>' in tr
              and 'data-action="worktrees-history">View cleanup history</button>' in tr
              and dom_query(tr).has(None, {'aria-valuenow': '100'}),
              tr[:400])
        wtb = wt_block(dom_wtbatch)
        batch_posts = pre(dom_wtbatch, "mock-requests").count("POST /worktrees/remove")
        check("worktrees: Remove all removes every removable row of the repository after one dialog",
              batch_posts == 3 and "old-a" not in wtb and "old-b" not in wtb and ".worktrees/done" not in wtb
              and "worktree-remove-all" not in wtb,
              f"posts={batch_posts}")
        wto = wt_block(dom_wtorphan)
        check("worktrees: a missing repository's folders are listed first with the reason and Open folder / Move to Trash",
              wto.index('/Users/dev/gone-app') < wto.index('/Users/dev/workspace/api-service')
              and 'repository not found (moved or deleted) — the folders below still point to it' in wto
              and 'data-action="worktree-reveal" data-path="/Users/dev/.cursor/worktrees/gone-app/ctnj">Open folder</button>' in wto
              and dom_query(wto).has(None, {'data-action': 'worktree-trash-orphan'})
              and "1 folder still points to it (listed first below)" in dom_wtorphan)
        wtot = wt_block(dom_wtorphantrash)
        check("worktrees: Move to Trash on an orphan posts /worktrees/trash after the dialog and the group and its error leave",
              "POST /worktrees/trash" in pre(dom_wtorphantrash, "mock-requests")
              and "gone-app" not in wtot and "1 folder still points to it" not in dom_wtorphantrash)
        wtg = wt_block(dom_wtremoving)
        tg = toast_block(dom_wtremoving)
        check("worktrees: while a removal runs a toast follows it: phase, size and files, time in the phase, the bar",
              dom_query(dom_wtremoving).has(None, {'class': 'toast toast-sticky removal-toast info'})
              and '<p class="rt-title" role="status">Removing feat/done</p>' in tg
              and '<span class="rt-step">deleting · 1.5 GB · 184,203 files</span>' in tg
              and dom_query(tg).has(None, {'role': 'progressbar'}) and dom_query(tg).has(None, {'aria-valuenow': '50'}) and "rt-bar-running" in tg
              and dom_query(tg).has('span', {'class': 'rt-elapsed', 'data-since': None}) and "s</span>" in tg,
              tg[:600])
        check("worktrees: while a removal runs its row shows the phase marks, step and size, and Remove is disabled",
              '<span class="wt-steps" aria-hidden="true"><i class="on"></i><i class="on"></i><i class="on"></i><i class="on"></i></span>'
              '<b>Removing…</b> deleting · 1.5 GB · 184,203 files</p>' in wtg
              and '<button type="button" class="btn btn-danger btn-sm" disabled="">Removing…</button>' in wtg
              and not dom_query(wtg).has(None, {'data-action': 'worktree-remove'}))
        wtf = wt_block(dom_wtremovefail)
        check("worktrees: a failed removal keeps the row with the error as text and offers Try again",
              '.worktrees/done' in wtf
              and '<p class="wt-removal wt-removal-failed" role="alert"><b>Removal failed:</b> git worktree: &lt;b&gt;fatal&lt;/b&gt; could not remove' in wtf
              and '>Try again</button>' in wtf)
        tf = toast_block(dom_wtremovefail)
        check("worktrees: a failed removal's toast stays with the error as text",
              dom_query(dom_wtremovefail).has(None, {'class': 'toast toast-sticky removal-toast danger'})
              and '<p class="rt-title" role="status">Not removed: feat/done</p>' in tf
              and 'git worktree: &lt;b&gt;fatal&lt;/b&gt; could not remove' in tf and "<b>fatal</b>" not in tf
              and "rt-bar-failed" in tf,
              tf[:400])
        tb = dom_wtbatch.split('id="removal-toast"', 1)[-1].split('id="drawer"', 1)[0] if dom_query(dom_wtbatch).has(None, {'id': 'removal-toast'}) else ''
        check("worktrees: Remove all runs under one toast that ends with the count and bytes",
              '<p class="rt-title" role="status">Removed 3 of 3 worktrees</p>' in tb and "4.5 GB reclaimed" in tb,
              tb[:300])
        rm_posts = pre(dom_wtremovable, "mock-requests").count("POST /worktrees/remove")
        check("worktrees: Removable now counts every repository's removable rows and Remove all there removes all of them",
              "6.0 GB" in pre(dom_wtremovable, "removable-tile") and "4 worktrees" in pre(dom_wtremovable, "removable-tile")
              and "Remove all 4" in pre(dom_wtremovable, "removable-tile")
              and rm_posts == 4 and "web-app/.worktrees/landed" not in wt_block(dom_wtremovable),
              f"tile={pre(dom_wtremovable, 'removable-tile')!r} posts={rm_posts}")
        hx_all = html.unescape(pre(dom_wthistory, "history-all"))
        hx = dom_wthistory.split('id="drawer-body"', 1)[-1].split('id="drawer-foot"', 1)[0]
        check("worktrees: History opens the ledger in the drawer by day, escaped; the Removed chip filters it",
              'id="drawer-title-text">Cleanup history<' in dom_wthistory
              and "3 entries · 3.0 GB freed · 50 MB moved to the Trash" in hx_all
              and "Moved an orphan folder to the Trash" in hx_all
              and "&lt;b&gt;branch&lt;/b&gt; feat/old kept" in hx_all and "<b>branch</b>" not in hx_all
              and "2 entries · 3.0 GB freed" in hx and "Moved an orphan folder" not in hx
              and dom_query(hx).has(None, {'data-kind': 'removed', 'aria-pressed': 'true'}),
              hx_all[:300])
        for clock, day_dom in [("current time", dom_wtday), ("midnight", dom_wtday_midnight)]:
            hd = day_dom.split('id="drawer-body"', 1)[-1].split('id="drawer-foot"', 1)[0]
            check(f"worktrees: a chart column shows its numbers on hover and opens the history at that day ({clock})",
                  "1.0 GB freed by 1 cleanup50 MB moved to the Trash by 1 cleanup" in pre(day_dom, "reclaim-tip-probe")
                  and "2 entries · 1.0 GB freed · 50 MB moved to the Trash" in hd and dom_query(hd).has(None, {'data-action': 'history-day', 'data-day': None})
                  and "feat/old" not in hd,
                  f"tip={pre(day_dom, 'reclaim-tip-probe')!r} {hd[:200]}")
        ws = wt_block(dom_wtsearch)
        check("worktrees: the search box keeps rows whose branch, folder or repository matches, any case",
              len(dom_query(ws).find_all(None, {'class': 'wt-row'})) == 1 and ".worktrees/evidence" in ws,
              f"rows={len(dom_query(ws).find_all(None, {'class': 'wt-row'}))}")
        def gd(pid):
            try:
                return json.loads(html.unescape(pre(dom_wtgroup, pid)) or "{}")
            except ValueError:
                return {}
        gd_before, gd_evidence, gd_clutter, gd_cleared = gd("gd-before"), gd("gd-evidence"), gd("gd-clutter"), gd("gd-cleared")
        check("worktrees: the header Search… box narrows the System tab's worktree rows in any case, the summary says how many are shown, clearing it restores them",
              gd_before.get("rows") == 4 and " shown" not in gd_before.get("summary", "")
              and gd_evidence.get("rows") == 1 and gd_evidence.get("summary", "").endswith("· 1 shown")
              and gd_cleared.get("rows") == 4 and " shown" not in gd_cleared.get("summary", ""),
              f"before={gd_before} evidence={gd_evidence} cleared={gd_cleared}")
        check("worktrees: the header search narrows the clutter list too, and each empty list says why",
              gd_before.get("clutter") == 3 and gd_evidence.get("clutter") == 0
              and "No clutter matches the search." in gd_evidence.get("empty", [])
              and gd_clutter.get("clutter") == 1 and gd_clutter.get("rows") == 0
              and gd_clutter.get("summary", "").endswith("· 0 shown")
              and "No worktree matches this filter." in gd_clutter.get("empty", [])
              and gd_cleared.get("clutter") == 3,
              f"evidence={gd_evidence} clutter={gd_clutter}")
        gd_reqs = html.unescape(pre(dom_wtgroup, "mock-requests"))
        gd_agent = dom_wtgroup.split('id="tab-agent"', 1)[-1].split('id="drawer"', 1)[0]
        check("worktrees: Ask advisor about all posts the repository and toasts how many worktrees it will work through",
              'POST /worktrees/advise body={"repo":"/Users/dev/workspace/api-service"}' in gd_reqs
              and "Asking the advisor about 3 worktrees, one at a time — notes appear under each row as it answers" in html.unescape(pre(dom_wtgroup, "gd-toast")),
              gd_reqs)
        check("worktrees: Discuss all posts the repository and opens the Agent tab on the group question",
              'POST /agent/worktree body={"repo":"/Users/dev/workspace/api-service"}' in gd_reqs
              and dom_query(dom_wtgroup).has(None, {'class': 'tab-btn active', 'data-tab': 'agent'})
              and gd_agent.count("agent-worktree-card") == 1
              and "<b>Which of these worktrees in this repository can I delete?</b>" in gd_agent
              and "feat/evidence · review · merged: no" in gd_agent,
              gd_reqs)
        gap = pre(dom_wtcadence, "remove-cadence")
        check("worktrees: a removal started while a 5 s sizing re-read waits is re-read on its own 1.5 s cadence",
              gap.isdigit() and int(gap) < 2000, f"gap={gap!r}ms")
        ta = toast_block(dom_wtadopt)
        check("worktrees: a removal already running when the tab opens gets the progress toast without a click",
              '<p class="rt-title" role="status">Removing feat/done</p>' in ta and "checking it is still safe to remove" in ta,
              ta[:300])

        # --- Agent tab: the system agent chat, plans, runs, harnesses ---
        def agent_block(dom_text):
            return dom_text.split('id="tab-agent"', 1)[-1].split('id="drawer"', 1)[0]

        def agent_count(dom_text, cls):
            return agent_block(dom_text).count(f'class="{cls}')

        ag = agent_block(dom_agent)
        for viewport, workspace_dom in [("desktop", dom_agentworkspace), ("mobile", dom_agentworkspace_mobile)]:
            receipt = re.search(r'data-agent-workspace="([^"]+)"', workspace_dom)
            checks = json.loads(html.unescape(receipt.group(1))) if receipt else {}
            check(f"agent workspace ({viewport}): interaction receipt was produced", bool(checks))
            for name, result in checks.items():
                check(f"agent workspace ({viewport}): {name}", result is True)
        check("agent: the tab opens with the conversation, plans, runs and the model state",
              dom_query(dom_agent).has(None, {'class': 'tab-btn active', 'data-tab': 'agent'})
              and agent_count(dom_agent, "agent-msg ") == 5 and len(dom_query(ag).find_all(None, {'class': 'agent-plan', 'data-plan': None})) == 2
              and len(dom_query(ag).find_all(None, {'class': 'agent-run', 'data-run': None})) == 2
              and 'qwen3:latest on Ollama 0.15.1 · stays on this machine' in ag)
        check("agent: message text, proposal tasks, plan titles and run output render escaped",
              "<img src=x" not in ag and "&lt;img src=x onerror=alert(1)&gt;" in ag)
        check("agent: local chat and optional harness handoff are separate; unavailable harnesses are marked for later",
              'Local Ollama · no harness' in ag and dom_query(ag).has(None, {'id': 'agent-handoff-panel'})
              and 'id="agent-harness"' not in ag.split('id="agent-composer"', 1)[1].split('</form>', 1)[0]
              and '<option value="openclaw">OpenClaw (plan for later)</option>' in ag
              and '<option value="codex">Codex</option>' in ag and '<option value="pi">Pi runner (plan for later)</option>' in ag
              and ag.count("<option ") == 5)
        check("agent: a plan whose harness cannot run says why and its dispatch buttons are disabled",
              'agent-plan-reason">OpenClaw is not installed where the daemon can find it (openclaw)</div>' in ag
              and dom_query(ag).has(None, {'data-plan': '2', 'data-mode': 'headless', 'disabled': ''}))
        check("agent: a proposal offers Save plan and dispatch; a saved one names its plan",
              'data-action="agent-save-proposal" data-message="2">Save plan</button>' in ag
              and 'Saved as plan #2' in ag)
        check("agent: a manual terminal dispatch offers its command to copy",
              dom_query(ag).has(None, {'data-action': 'agent-copy', 'data-text': "sh '/Users/dev/.config/secure-agent/sysagent/terminal-1-1.sh'"}))
        check("agent: harnesses show ready or the reason; skills are listed",
              ag.count('badge badge-ok">ready</span>') == 2 and dom_query(ag).has(None, {'data-action': 'agent-skill', 'data-skill': 'signing'}))
        ago = agent_block(dom_agentoff)
        check("agent: off, the tab says how to turn it on and the composer is disabled",
              'Secure Agent chat is off' in ago and 'system_agent:\n  enabled: true' in ago
              and dom_query(ago).has('textarea', {'id': 'agent-input'}) and ago.split('<textarea id="agent-input"', 1)[1].split('>', 1)[0].count('disabled') == 1)
        for label, progress_dom, expected, animation in [
            ("delivery", dom_agentlatency, "Sending your message", "spin"),
            ("Ollama wait", dom_agentthinking, "Waiting for local Ollama", "spin"),
            ("reduced motion", dom_agentreduced, "Waiting for local Ollama", "none"),
        ]:
            receipt = re.search(r'data-agent-feedback-state="([^"]+)"', progress_dom)
            state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
            check(f"agent: {label} is visible immediately, disables Send, and handles repeated Enter once",
                  expected in state.get("pending", "") and state.get("animation") == animation
                  and state.get("sendDisabled") and pre(progress_dom, "mock-requests").count("POST /agent/chat") == 1,
                  str(state))
        receipt = re.search(r'data-agent-feedback-state="([^"]+)"', dom_agentreject)
        rejected = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        check("agent: failed send keeps the draft and renders a persistent error",
              rejected.get("errorVisible") and "Model unavailable" in rejected.get("error", "")
              and rejected.get("draft") == "Keep my Git token in the keychain" and not rejected.get("sendDisabled"), str(rejected))
        agc = agent_block(dom_agentchat)
        check("agent: a message sent from the composer gets a direct local command proposal",
              "POST /agent/chat" in pre(dom_agentchat, "mock-requests")
              and "Keep my Git token in the keychain" in agc and "git config --global credential.helper osxkeychain" in agc
              and dom_query(agc).has(None, {'data-action': 'agent-run-local'})
              and "The local model is answering" not in agc and agent_count(dom_agentchat, "agent-msg ") == 7)
        agl = agent_block(dom_agentlocal)
        check("agent: confirmed local command runs once and its output stays expanded in chat",
              "POST /agent/actions" in pre(dom_agentlocal, "mock-requests")
              and 'Git credential helper configured.' in agl and not dom_query(agl).has(None, {'data-action': 'agent-run-local'})
              and len(dom_query(agl).find_all(None, {'class': 'agent-run', 'data-run': None})) == 3
              and 'agent-inline-output' in agl.split('class="agent-chat-foot"', 1)[0]
              and 'Completed · exit 0' in agl.split('class="agent-chat-foot"', 1)[0]
              and dom_query(agl).has('aside', {'class': 'agent-inspector', 'id': 'agent-side', 'aria-label': 'Agent tools', 'hidden': None}))
        agd = agent_block(dom_agentdispatch)
        reqs = pre(dom_agentdispatch, "mock-requests")
        check("agent: Run headless dispatches after the dialog; the run lands under Runs and finishes",
              "POST /agent/dispatch" in reqs and 'Credentials now live in the keychain.' in agd
              and len(dom_query(agd).find_all(None, {'class': 'agent-run', 'data-run': None})) == 3 and 'badge badge-ok">done</span>' in agd.split('id="agent-runs"', 1)[1])
        check("agent: Save plan on a proposal saves it and the reply names the plan",
              "POST /agent/plans" in reqs and len(dom_query(agd).find_all(None, {'class': 'agent-plan', 'data-plan': None})) == 3
              and agd.count("Saved as plan #") == 2 and not dom_query(agd).has(None, {'data-action': 'agent-save-proposal'}))

        if args.screenshot:
            shot_dir = os.path.abspath(args.screenshot)
            os.makedirs(shot_dir, exist_ok=True)
            for name, query, themes in SHOTS:
                for theme in themes:
                    path = os.path.join(shot_dir, f"{name}-{theme}.png")
                    screenshot(chrome, origin, f"{query}&theme={theme}", path, tmp)
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
