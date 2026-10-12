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
import time
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
              "telemetry-refresh.js", "spend-controller.js", "agent-controller.js", "history-controller.js", "console-lifecycle.js", "policy-controller.js", "staged-write.js", "finding-actions.js", "worktree-controller.js",
              "tab-overview.js", "session-workbench.js", "decision-permissions.js", "tab-agents.js", "tab-egress.js", "tab-findings.js",
              "tab-worktrees.js", "tab-agent.js", "theme-init.js", "icon.svg"):
        os.symlink(os.path.join(WEB_DIST, f), os.path.join(tmp, f))
    os.symlink(MOCK, os.path.join(tmp, "mock_dom.js"))
    os.symlink(os.path.join(os.path.dirname(MOCK), "fixtures.js"), os.path.join(tmp, "fixtures.js"))
    write_fixture(tmp, "")
    html = open(os.path.join(WEB_DIST, "index.html")).read()
    needle = '<script src="lib.js"></script>'
    assert needle in html, "lib.js script tag not found in index.html"
    html = html.replace(needle, needle + '\n  <script src="fixture-config.js"></script>\n  <script src="fixtures.js"></script>\n  <script src="mock_dom.js"></script>\n  <script src="case-script.js"></script>')
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

        def do_GET(self):
            if self.path == '/__console_frame_checkpoint':
                time.sleep(0.05)
                self.send_response(204)
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                return
            super().do_GET()

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
    from fixture_catalog import scenario_payload
    spec = {**scenario_payload(spec["scenarios"], spec.get("now")), **spec}
    script = spec.pop("script", "")
    with open(os.path.join(tmp, "case-script.js"), "w") as stream:
        stream.write(open(os.path.join(os.path.dirname(MOCK), script)).read() if script else "")
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
    with tempfile.TemporaryDirectory(prefix="chrome-profile-", dir=tmp, ignore_cleanup_errors=True) as profile, \
            tempfile.TemporaryFile("w+", dir=tmp) as errors:
        proc = subprocess.Popen(
            [chrome, f"--user-data-dir={profile}", "--no-first-run", "--disable-background-networking", "--headless=new", "--disable-gpu", "--no-sandbox", *size, motion,
             "--virtual-time-budget=" + str(VIRTUAL_TIME_MS), "--dump-dom", url],
            stdout=subprocess.PIPE, stderr=errors,
        )
        out, complete = read_dump(proc, url, timeout=120)
        errors.seek(0)
        stderr = errors.read()
    if not complete and proc.returncode != 0:
        print(stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"chrome --dump-dom failed ({proc.returncode}): {url}")
    return out


def read_dump(proc, url, timeout):
    """Collect Chrome's --dump-dom output. Chrome can stay alive after printing
    the whole document; it is stopped then instead of waited on."""
    chunks = []

    def read():
        while chunk := os.read(proc.stdout.fileno(), 1 << 16):
            chunks.append(chunk)

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout
    while reader.is_alive() and not b"".join(chunks).rstrip().endswith(b"</html>"):
        if time.monotonic() > deadline:
            proc.kill()
            proc.wait()
            raise SystemExit(f"chrome --dump-dom timed out after {timeout}s: {url}")
        time.sleep(0.05)
    out = b"".join(chunks).decode()
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    reader.join(5)
    return out, out.rstrip().endswith("</html>")


SHOT_SIZE = (1280, 800)
SHOTS = (
    ("sessions", "?tab=sessions&shot&raildemo", ("dark", "light")),
    ("agents", "?tab=agents&shot", ("dark", "light")),
    ("overview", "?tab=overview&shot", ("dark",)),
    ("agent", "?tab=agent&shot", ("dark", "light")),
    ("worktrees-removing", "?tab=worktrees&shot&worktreedemo&removerunning", ("dark", "light")),
    ("worktrees-history", "?tab=worktrees&shot&historydemo", ("dark", "light")),
)


def screenshot(chrome, origin, query, path, tmp, fixture=None):
    write_fixture(tmp, query, fixture)
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



class CasePage:
    def __init__(self, chrome, tmp, origin, fixtures):
        self.chrome, self.tmp, self.origin = chrome, tmp, origin
        self.fixtures, self.cache = fixtures, {}

    def dom(self, query="", *, served=False, **kwargs):
        return dump_dom(self.chrome, self.tmp, query, self.origin if served else None, **kwargs)

    def fixture(self, name):
        if name not in self.cache:
            self.cache[name] = self.fixtures[name].load(self)
        return self.cache[name]

    def check(self, name, ok, detail=""):
        check(name, ok, detail)


def select_cases(cases, args):
    names = list(args.only)
    aliases = ("review_results", "session_activity", "session_investigation", "session_permissions", "context_handoff", "session_results", "spend", "auth_recovery", "session_workbench", "policy_permissions")
    names.extend("spend_refresh" if name == "spend" else name for name in aliases if getattr(args, name + "_only", False))
    available = {case.name: case for case in cases}
    unknown = set(names) - available.keys()
    if unknown:
        raise SystemExit("unknown case: " + ", ".join(sorted(unknown)))
    return [available[name] for name in dict.fromkeys(names)] if names else list(cases)


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
    ap.add_argument('--review-results-only', action='store_true', help='run bounded review result interaction probes only')
    ap.add_argument('--policy-permissions-only', action='store_true', help='run bounded global permission revocation probes only')
    ap.add_argument('--only', action='append', default=[], help='run a named case (repeatable)')
    ap.add_argument('--list', action='store_true', help='list case names without launching a browser')
    args = ap.parse_args()
    if args.list:
        from cases import CASES
        print('\n'.join(case.name for case in CASES))
        return
    chrome = find_chrome()
    if not chrome:
        raise SystemExit("no Chrome found (set CHROME_BIN)")
    print(f"console dom tests (chrome: {chrome})")

    tmp = tempfile.mkdtemp(prefix="console-dom-")
    srv = None
    try:
        build_harness(tmp)
        srv, origin = serve_with_csp(tmp)
        from cases import CASES, FIXTURES
        selected = select_cases(CASES, args)
        page = CasePage(chrome, tmp, origin, FIXTURES)
        for case in selected:
            print(f"case: {case.name}", flush=True)
            case.run(page)
        if args.screenshot:
            shot_dir = os.path.abspath(args.screenshot)
            os.makedirs(shot_dir, exist_ok=True)
            if args.review_results_only:
                screenshot(chrome, origin, '?reviewresult&resultcard', os.path.join(shot_dir, 'review-result-card.png'), tmp, payload_cases.review_result())
                screenshot(chrome, origin, '?reviewresult', os.path.join(shot_dir, 'review-result-detail.png'), tmp, payload_cases.review_result())
                screenshot(chrome, origin, '?reviewresult=expect&resultpermissions', os.path.join(shot_dir, 'review-result-permissions.png'), tmp, payload_cases.review_result())
            for name, query, themes in (() if args.review_results_only else SHOTS):
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
