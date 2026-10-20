"""Console sessions cases."""
from case_support import html, json, re, HTMLParser, dom_query, starts_with, payload_cases, pre, log_rows, PolicyRowCounter
from case_types import Case

def run_session_rail_renders_durable_sessions(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'session rail renders durable sessions',
        len(dom_query(dom).find_all(None, {'class': 'session-card'})) >= 2,
        f"cards={len(dom_query(dom).find_all(None, {'class': 'session-card'}))}",
    )

def run_rail_titles_are_repo_branch_not_harness_repo(page):
    check = page.check
    dom = page.fixture('dom')
    rail = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
    check(
        'rail titles are repo@branch, not harness · repo',
        (
            '>api-service@main<' in rail
            and 'claude · ' not in rail
        ),
    )

def run_ended_session_marked(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'ended session marked',
        dom_query(dom).has(None, {'class': 'session-card ended'}),
    )

def run_sessions_rail_renders_one_group_per_live_harness_newest_first_infra_last(page):
    check = page.check
    dom = page.fixture('dom')
    rail = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
    rail_groups = re.findall('<details class="session-group[^"]*" data-harness="([^"]+)"', rail)
    check(
        'sessions rail renders one group per live harness, newest first, infra last',
        rail_groups == ['codex', 'claude', 'infra'],
        f'groups={rail_groups}',
    )

def run_harness_marks_resolve_to_sprite_symbols(page):
    check = page.check
    dom = page.fixture('dom')
    rail = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
    logo_refs = set(re.findall('<use href="#(logo-[a-z-]+)"', rail))
    check(
        'harness marks resolve to sprite symbols',
        (
            logo_refs >= {'logo-claude', 'logo-codex', 'logo-ollama'}
            and all((f'<symbol id="{ref}"' in dom for ref in logo_refs))
        ),
        f'refs={sorted(logo_refs)}',
    )

def run_ended_tail_is_collapsed_by_default(page):
    check = page.check
    dom = page.fixture('dom')
    rail = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
    claude_group = rail.split('data-harness="claude"', 1)[1].split('<details', 1)[0]
    check(
        'ended tail is collapsed by default',
        (
            dom_query(claude_group).has('div', {'class': 'session-ended'})
            and 'data-action="toggle-ended-sessions" data-harness="claude" aria-expanded="false">Ended (1)' in claude_group
        ),
    )

def run_infra_sits_in_the_last_group_collapsed_with_rss_totals_only(page):
    check = page.check
    dom = page.fixture('dom')
    rail = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
    infra_group = rail.split('data-harness="infra"', 1)[1]
    check(
        'infra sits in the last group, collapsed, with RSS totals only',
        (
            dom_query(rail).has('details', {'class': 'session-group infra', 'data-harness': 'infra'})
            and 'Ollama' in infra_group
            and '782 MB' in infra_group
            and 'session-card' not in infra_group
            and 'sess-ollama-4' not in rail
        ),
    )

def run_memory_detail_fits_a_375px_phone_without_horizontal_page_overflow(page):
    check = page.check
    dom_memory_phone = page.fixture('dom_memory_phone')
    check(
        'Memory detail fits a 375px phone without horizontal page overflow',
        dom_query(dom_memory_phone).has(None, {'data-hscroll': 'sessions:0,agents:0,resources:0'}),
        (re.search('data-hscroll="[^"]*"', dom_memory_phone) or [None])[0],
    )

def run_rail_selection_renders_trace_waterfall(page):
    check = page.check
    dom_rail = page.fixture('dom_rail')
    check(
        'rail selection renders trace waterfall',
        (
            dom_query(dom_rail).has(None, {'class': 'wf-bar'})
            and (
                'Bash' in dom_query(dom_rail).text
                or dom_query(dom_rail).has(None, {'title': lambda value: 'Bash' in (value or '')})
            )
        ),
        'no waterfall bars in raildemo',
    )

def run_memory_opens_first_and_earlier_rows_prepend_once(page):
    check = page.check
    dom_memory = page.fixture('dom_memory')
    memory_detail = dom_memory.split('id="session-detail"', 1)[1].split('id="session-board"', 1)[0]
    check(
        'Memory opens first and earlier rows prepend once',
        (
            dom_query(dom_memory).has(None, {'data-action': 'session-view', 'data-view': 'memory', 'aria-pressed': 'true'})
            and memory_detail.count('Earlier activity') == 1
            and memory_detail.count('Recent activity') == 1
            and memory_detail.index('Earlier activity') < memory_detail.index('Recent activity')
            and not dom_query(memory_detail).has(None, {'data-action': 'memory-earlier'})
        ),
        memory_detail[:700],
    )

def run_session_guard_decision_uses_the_existing_handler_and_refreshes_its_result(page):
    check = page.check
    dom_overview_decision = page.fixture('dom_overview_decision')
    check(
        'session guard decision uses the existing handler and refreshes its result',
        dom_query(dom_overview_decision).has(None, {'data-overview-resolved': 'true'}),
    )

def run_session_findings_history_retains_scope_and_returns_to_the_same_session(page):
    check = page.check
    dom_overview_return = page.fixture('dom_overview_return')
    check(
        'session findings history retains scope and returns to the same session',
        (
            dom_query(dom_overview_return).has(None, {'data-overview-scoped': 'true'})
            and dom_query(dom_overview_return).has(None, {'data-overview-returned': 'true'})
        ),
    )

def run_sessions_has_no_cleanup_sub_view_its_panels_live_in_the_system_tab(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'Sessions has no Cleanup sub-view; its panels live in the System tab',
        (
            not dom_query(dom).has(None, {'data-subtab': 'worktrees'})
            and not dom_query(dom).has(None, {'id': 'sub-worktrees'})
            and dom.index('id="tab-system"') < dom.index('id="worktrees-container"') < dom.index('id="clutter-container"') < dom.index('id="tab-policy"')
            and dom.index('id="tab-egress"') < dom.index('id="tab-system"')
        ),
    )

def run_sessions_panel_lives_in_the_sessions_tab(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'sessions panel lives in the sessions tab',
        (
            dom.index('id="tab-sessions"') < dom.index('id="session-board"')
            and dom.index('id="session-board"') < dom.index('id="sub-processes"')
        ),
    )

def run_memory_by_family(page):
    check = page.check
    dom_memfam = page.fixture('dom_memfam')
    mem_bars = dom_memfam.split('id="chart-memory"', 1)[1].split('</section>', 1)[0].split('class="hbar-row"')[1:]
    mem_badge = re.search('id="chart-mem-total">(\\d+)<', dom_memfam)
    check(
        'memory by family: three sessions on one root are one bar carrying 3 sessions',
        (
            len(mem_bars) == 4
            and sum(('api-service@main · 3 sessions' in b for b in mem_bars)) == 1
        ),
        f'bars={len(mem_bars)}',
    )
    mem_infra = sum(('class="hbar-sub">infra<' in b for b in mem_bars))
    check(
        'memory by family: the badge counts agent families, not sessions or infra',
        (
            mem_badge is not None
            and mem_infra == 1
            and int(mem_badge.group(1)) == len(mem_bars) - mem_infra == 3
        ),
        f"{(mem_badge.group(0) if mem_badge else 'no badge')} infra={mem_infra}",
    )

def run_session_board_has_project_filter(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'session board has project filter',
        dom_query(dom).has(None, {'id': 'session-cwd-filter'}),
    )

def run_session_rail_lists_live_cards_and_the_ended_tail(page):
    check = page.check
    dom = page.fixture('dom')
    sessions = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
    check(
        'session rail lists live cards and the ended tail',
        len(dom_query(sessions).find_all(None, {'class': 'session-card'})) == 4,
        f"cards={len(dom_query(sessions).find_all(None, {'class': 'session-card'}))}",
    )

def run_session_cards_labeled_by_repo_branch_or_folder(page):
    check = page.check
    dom = page.fixture('dom')
    sessions = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
    check(
        'session cards labeled by repo@branch or folder',
        (
            'api-service@main' in sessions
            and 'data-pipeline@feat/etl' in sessions
            and '>auth<' in sessions
        ),
    )

def run_session_card_selects_the_session_trace(page):
    check = page.check
    dom = page.fixture('dom')
    sessions = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
    check(
        'session card selects the session trace',
        dom_query(sessions).has(None, {'data-action': 'select-session', 'data-id': 'sess-claude-1'}),
    )

def run_sessions_and_processes_counts_sit_on_the_sub_view_buttons_the_sessions_tab_keeps_the_live_count(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'sessions and processes counts sit on the sub-view buttons; the Sessions tab keeps the live count',
        (
            re.search('id="subtab-badge-board">\\d+<', dom) is not None
            and re.search('id="subtab-badge-processes">\\d+<', dom) is not None
            and (re.search('id="tab-badge-sessions">(\\d+)<', dom) or [None, 'a'])[1] == (re.search('id="subtab-badge-board">(\\d+)<', dom) or [None, 'b'])[1]
        ),
    )

def run_session_coverage_remains_available_without_a_global_monitoring_gap(page):
    check = page.check
    dom_session_coverage = page.fixture('dom_session_coverage')
    check(
        'session coverage remains available without a global monitoring gap',
        (
            (
                'Per-session coverage · 2' in dom_query(dom_session_coverage).text
                or dom_query(dom_session_coverage).has(None, {'title': lambda value: 'Per-session coverage · 2' in (value or '')})
            )
            and dom_query(dom_session_coverage).has(None, {'id': 'coverage-center', 'hidden': None})
            and re.search('id="monitoring-diagnostics"[^>]*\\bhidden', dom_session_coverage) is None
        ),
    )

def run_session_chip_appears(page):
    check = page.check
    dom_session = page.fixture('dom_session')
    check(
        'session chip appears',
        (
            dom_query(dom_session).has(None, {'id': 'session-filter', 'class': 'session-filter'})
            or (
                dom_query(dom_session).has(None, {'id': 'session-filter'})
                and 'hidden' not in dom_session.split('id="session-filter"')[1][:80]
            )
        ),
    )

def run_session_chip_count(page):
    check = page.check
    dom_session = page.fixture('dom_session')
    check(
        'session chip count',
        (
            '7f3a9c21 · 2' in dom_query(dom_session).text
            or dom_query(dom_session).has(None, {'title': lambda value: '7f3a9c21 · 2' in (value or '')})
        ),
    )

def run_session_scopes_findings_list(page):
    check = page.check
    dom_session = page.fixture('dom_session')
    check(
        'session scopes findings list',
        (
            dom_query(dom_session).has(None, {'id': 'flags-session-filter'})
            and 'hidden' not in dom_session.split('id="flags-session-filter"')[1][:80]
        ),
    )

def run_memory_by_family_2(page):
    check = page.check
    dom_memprobe = page.fixture('dom_memprobe')
    mem_probe = re.match('renders=(\\d+) kept=(\\d+)/(\\d+)$', pre(dom_memprobe, 'mem-probe'))
    check(
        'memory by family: a re-render keeps every unchanged family row as the same node',
        (
            mem_probe is not None
            and int(mem_probe.group(1)) >= 1
            and int(mem_probe.group(3)) == 4
            and mem_probe.group(2) == mem_probe.group(3)
        ),
        f"probe={pre(dom_memprobe, 'mem-probe')!r}",
    )

def run_session_activity(page):
    check = page.check
    for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
        dom = page.dom('?activitydemo', window_size=size, served=True)
        receipt = re.search('data-activity-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('endedEntry', 'outsideSnapshot', 'scopedRead', 'recordedRows', 'limitVisible', 'kindFilter', 'staleRetained', 'returnContext', 'returnFilters', 'forwardFilters', 'pageBound', 'failedPage', 'earlierPage', 'lastPage', 'newerPage', 'latestPage', 'forwardPage', 'fits'):
            check(
                f'session activity ({label}): {name}',
                state.get(name) is True,
                str(state),
            )

def run_session_investigation(page):
    check = page.check
    for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
        dom = page.dom('?investigationdemo', window_size=size, served=True)
        receipt = re.search('data-investigation-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('resourceEntry', 'resourceBack', 'evidenceEntry', 'evidenceBack', 'memoryFinding', 'memoryFindingBack', 'memoryIncident', 'memoryIncidentBack', 'memoryMissingflag', 'memoryMissingBackflag', 'memoryMissingincident', 'memoryMissingBackincident', 'memoryReadOnly', 'familyEvents', 'eventsBack', 'findings', 'clearRetainsReturn', 'findingsBack', 'forward', 'returnButton', 'fits', 'selectionCloses'):
            check(
                f'session investigation ({label}): {name}',
                state.get(name) is True,
                str(state),
            )

def run_session_permissions(page):
    check = page.check
    for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
        dom = page.dom('?permissionsdemo', window_size=size, served=True)
        receipt = re.search('data-permissions-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        check(
            f'session permissions ({label}): receipt produced',
            bool(state),
            str(state),
        )
        for name in ('scoped', 'entryFocus', 'refreshFocus', 'refreshScroll', 'compactScroll', 'stale', 'cancel', 'revoked', 'fits', 'back', 'selectionCloses'):
            result = state.get(name)
            check(
                f'session permissions ({label}): {name}',
                result is True,
                str(state.get('scrollMismatch', result)) if name in ('refreshScroll', 'compactScroll') else str(result),
            )

def run_context_handoff(page):
    check = page.check
    for label, query, size in [('cold', '?contexthandoff&cold', (1280, 800)), ('reused narrow', '?contexthandoff', (375, 800))]:
        dom = page.dom(query, window_size=size, fixture=payload_cases.context_handoff(), served=True)
        receipt = re.search('data-context-handoff="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        check(
            f'context handoff ({label}): receipt produced',
            bool(state),
            str(state),
        )
        for name, result in state.items():
            check(
                f'context handoff ({label}): {name}',
                result is True,
                str(result),
            )

def run_hook_monitoring(page):
    for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
        dom = page.dom('?hookmonitoring', window_size=size, served=True,
                       fixture={'script': 'cases_hook_monitoring.js'})
        receipt = re.search(r'data-monitoring-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('usedOnly','neutral','receipt','unknown','limits','reading','sessionLink','mixed','allSupported','gapStyle','unattributed','truncated','hostLink','setup','stale','retry','restart','malformed','fits'):
            page.check(f'hook monitoring ({label}): {name}', state.get(name) is True, str(state))

def run_hook_history(page):
    for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
        dom = page.dom('?hookhistory', window_size=size, served=True,
                       fixture={'script': 'cases_hook_history.js'})
        receipt = re.search(r'data-history-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('initial', 'errors', 'blocks', 'cancelled', 'runtime', 'chars', 'search', 'empty', 'refresh', 'stale', 'retry', 'clear', 'mobile', 'fits', 'selection'):
            page.check(f'hook history ({label}): {name}', state.get(name) is True, str(state))

def run_session_coverage(page):
    for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
        dom = page.dom('?coverageactions', window_size=size, served=True,
                       fixture={'script': 'cases_session_coverage.js'})
        receipt = re.search(r'data-session-coverage-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('paths', 'guard', 'guideBack', 'traffic', 'trafficBack', 'forward', 'events', 'eventsBack', 'unattributed', 'stale', 'retry', 'unknown', 'unsupported', 'fits', 'selection'):
            page.check(f'session coverage ({label}): {name}', state.get(name) is True, str(state))

def run_session_follow_up(page):
    viewports = [('desktop', (1280, 800)), ('dock-start', (1180, 800)),
                 ('dock-above', (1190, 800)), ('narrow', (375, 800))]
    for label, size in viewports:
        query = '?followup'
        dom = page.dom(query, window_size=size, served=True,
                       fixture={'script': 'cases_session_follow_up.js'})
        receipt = re.search(r'data-follow-up-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('initial', 'groups', 'reading', 'back', 'scoped', 'permissions', 'revoked', 'independent', 'stale', 'retry', 'fits', 'selection'):
            page.check(f'session follow-up ({label}): {name}', state.get(name) is True, str(state))
        viewport = state.get('viewport', {})
        width, height = viewport.get('innerWidth', 0), viewport.get('innerHeight', 0)
        client_width = viewport.get('clientWidth', 0)
        client_height = viewport.get('clientHeight', 0)
        page.check(f'session follow-up ({label}): actual viewport',
                   width > 0 and height > 0
                   and client_width > 0 and client_height > 0
                   and abs(viewport.get('visualViewportWidth', 0) - client_width) <= 1
                   and abs(viewport.get('visualViewportHeight', 0) - client_height) <= 1
                   and (width <= 600 if size[0] <= 600 else abs(width - size[0]) <= 1),
                   f"requested={size[0]}x{size[1]} inner={width}x{height} client={client_width}x{client_height} visual={viewport.get('visualViewportWidth')}x{viewport.get('visualViewportHeight')} dpr={viewport.get('devicePixelRatio')}")
        closed = state.get('closedHeader', {})
        closed_font = float(str(closed.get('titleFont', '0px')).removesuffix('px') or 0)
        page.check(f'session follow-up ({label}): title readable after drawer back',
                   closed.get('sessionId') == 'sess-claude-1'
                   and closed.get('titleWidth', 0) >= max(120, 8 * closed_font) - 1,
                   f"session={closed.get('sessionId')} title={closed.get('title')} width={closed.get('titleWidth')} detail={closed.get('detailWidth')} font={closed.get('titleFont')}")
        layout = state.get('layout', {})
        title_font = float(str(layout.get('titleFont', '0px')).removesuffix('px') or 0)
        drawer_font = float(str(layout.get('drawerTitleFont', '0px')).removesuffix('px') or 0)
        page.check(f'session follow-up ({label}): selected title readable',
                   layout.get('sessionId') == 'sess-claude-1'
                   and layout.get('titleWidth', 0) >= max(120, 8 * title_font) - 1,
                   f"session={layout.get('sessionId')} title={layout.get('title')} width={layout.get('titleWidth')} detail={layout.get('detail')} font={layout.get('titleFont')}")
        page.check(f'session follow-up ({label}): permission drawer title readable',
                   layout.get('drawerTitleWidth', 0) >= max(120, 8 * drawer_font) - 1,
                   f"title={layout.get('drawerTitle')} width={layout.get('drawerTitleWidth')} font={layout.get('drawerTitleFont')}")
        page.check(f'session follow-up ({label}): permission drawer keeps session identity visible',
                   layout.get('sessionIdentityVisible') is True,
                   f"session={layout.get('sessionId')} board={layout.get('board')} split={layout.get('split')} rail={layout.get('rail')} detail={layout.get('detail')}")
        controls = layout.get('controls', [])
        page.check(f'session follow-up ({label}): permission controls remain reachable',
                   len(controls) == 3 and all(
                       not control.get('missing') and not control.get('hidden')
                       and control.get('hittable') is True
                       and control.get('left', -1) >= 0 and control.get('right', client_width + 1) <= client_width
                       and control.get('top', -1) >= 0 and control.get('bottom', client_height + 1) <= client_height
                       and (width > 600 or control.get('height', 0) >= 44)
                       for control in controls)
                   and layout.get('panelLeft', -1) >= 0 and layout.get('panelRight', client_width + 1) <= client_width,
                   f"panel={layout.get('panelLeft')}..{layout.get('panelRight')} width={layout.get('panelWidth')} viewport={client_width} controls={controls}")
        print(f"session follow-up geometry ({label}): " + json.dumps({
            'requested': size, 'viewport': viewport, 'closedHeader': closed,
            'open': {key: layout.get(key) for key in ('sessionId', 'title', 'titleWidth', 'titleFont', 'board', 'split', 'rail', 'detail', 'panelLeft', 'panelRight', 'panelWidth', 'controls')},
        }, sort_keys=True), flush=True)

def run_recent_work(page):
    for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
        dom = page.dom('?recentwork', window_size=size, served=True,
                       fixture={'script': 'cases_recent_work.js'})
        receipt = re.search(r'data-recent-work-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('ended', 'direct', 'back', 'forward', 'browserBack', 'quiet', 'refreshFocus', 'empty', 'clear', 'fits', 'all'):
            page.check(f'recent work ({label}): {name}', state.get(name) is True, str(state))

def run_home_ux(page):
    for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
        dom = page.dom('?homeux', window_size=size, served=True,
                       fixture={'script': 'cases_home_ux.js'})
        receipt = re.search(r'data-home-ux-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('reading', 'focus', 'empty', 'clear', 'match', 'rail', 'railClear', 'fits'):
            page.check(f'Home UX ({label}): {name}', state.get(name) is True, str(state))

def run_attention_summary(page):
    for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
        dom = page.dom('?attentionsummary', window_size=size, served=True,
                       fixture={'script': 'cases_attention_summary.js'})
        receipt = re.search(r'data-attention-summary-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('categories', 'counts', 'identity', 'monitoring', 'stale', 'recovery', 'invalid', 'legacy', 'focus', 'fits'):
            page.check(f'attention summary ({label}): {name}', state.get(name) is True, str(state))
def run_hook_diagnostics(page):
    for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
        dom = page.dom('?hookdiagnostics', window_size=size, served=True,
                       fixture={'script': 'cases_hook_diagnostics.js'})
        receipt = re.search(r'data-diagnostic-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('copy', 'metadata', 'failure', 'retry', 'cleared', 'readFailure', 'readRetry', 'repair', 'delivery', 'fits', 'busy', 'copyOwnership', 'loading', 'readOwnership'):
            page.check(f'hook diagnostics ({label}): {name}', state.get(name) is True, str(state))

def run_guard_receipts(page):
    for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
        dom = page.dom('?guardreceipts', window_size=size, served=True,
                       fixture={'script': 'cases_guard_receipts.js'})
        receipt = re.search(r'data-guard-receipt-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('submitted', 'fits', 'permission', 'stale', 'revoked', 'history', 'historyPermission'):
            page.check(f'guard receipts ({label}): {name}', state.get(name) is True, str(state))

def run_guard_review(page):
    for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
        dom = page.dom('?guardreview', window_size=size, served=True,
                       fixture={'script': 'cases_guard_review.js'})
        receipt = re.search(r'data-guard-review-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('facts', 'inspect', 'return', 'confirm', 'cancelFocused', 'cancel', 'expired', 'fits'):
            page.check(f'guard review ({label}): {name}', state.get(name) is True, str(state))

def run_session_hooks(page):
    for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
        dom = page.dom('?sessionhooks', window_size=size, served=True,
                       fixture={'script': 'cases_session_hooks.js'})
        receipt = re.search(r'data-hooks-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('repairWaiting','repairFits','repairsuccess','repairfailure','repaircancel','repairchanged','repairexpired','repairReadFailure','repairRetry','repairOwnership','repairAttention','setupEntry','coverageDelivery','deliveryAttention','deliveryUnscoped','deliveryUnverified','evidence','evidenceFits','evidenceFailure','evidenceRetry','evidenceOwnership','setup','table', 'failedRow', 'unrecorded', 'cancelled', 'actionable', 'ingestion', 'hostHealth', 'harnessParity', 'hostStale', 'hostRecovery', 'healthRecovery', 'startsAtFindings', 'fits', 'unavailable', 'recovery', 'reloaded'):
            page.check(f'session hooks ({label}): {name}', state.get(name) is True, str(state))

def run_session_results(page):
    check = page.check
    for label, query, size in [('desktop', '?resultsdemo', (1280, 800)), ('narrow stale', '?resultsdemo&resultsstale', (375, 800))]:
        dom = page.dom(query, window_size=size, served=True)
        detail = dom.split('id="session-detail"', 1)[1].split('id="session-board"', 1)[0]
        check(
            f'session results ({label}): receipts retain evidence and verification limits',
            all((text in detail for text in ['Reviewed', 'revision 1', 'newer evidence', 'possible-exposure', 'Source evidence unavailable', 'Applied', 'Resource samples observed', 'External action reported', 'unverified'])),
        )
        check(
            f'session results ({label}): update preserves focused open receipt',
            dom_query(dom).has(None, {'data-results-focus': 'true'}),
        )
        check(
            f'session results ({label}): layout fits viewport',
            dom_query(dom).has(None, {'data-results-fits': 'true'}),
        )
        if 'stale' in label:
            check(
                'session results: failed refresh retains receipts with a visible retry',
                (
                    'Last known results' in detail
                    and 'Retry results' in detail
                ),
            )

def run_session_workbench(page):
    check = page.check
    for label, size in [('desktop', (1280, 800)), ('narrow', (900, 768))]:
        workbench_dom = page.dom('?sessionworkbench', window_size=size, fixture=payload_cases.session_workbench(), served=True)
        receipt = re.search('data-session-workbench="([^"]+)"', workbench_dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        check(
            f'sessions workbench ({label}): interaction receipt produced',
            bool(state),
            str(state),
        )
        for name, result in state.items():
            check(
                f'sessions workbench ({label}): {name}',
                result is True,
                str(result),
            )

def run_session_reading(page):
    check = page.check
    for label, size, query in [('desktop', (1280, 720), '?readingdemo'), ('long phone', (320, 800), '?readingdemo&readinglong'), ('short phone', (390, 800), '?readingdemo'), ('short viewport', (375, 480), '?readingdemo&readinglong')]:
        reading_dom = page.dom(query, window_size=size, fixture=payload_cases.session_workbench(), served=True)
        receipt = re.search(r'data-session-reading="([^"]+)"', reading_dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        check(f'session reading ({label}): receipt produced', bool(state), str(state))
        for name in ('memoryBudget', 'contextInBody', 'latest', 'currentContext', 'detailsBudget', 'detailsDoNotGrowChrome', 'fullTitleRow', 'toolbar', 'actions', 'resultsBudget', 'traceBudget', 'railToggle', 'alertsReachable', 'fits'):
            check(f'session reading ({label}): {name}', state.get(name) is True, str(state))

def run_session_discovery(page):
    for label, size in [('desktop', (1280, 800)), ('phone', (375, 800))]:
        dom = page.dom('?sessiondiscovery', served=True, window_size=size)
        receipt = re.search(r'data-session-discovery="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        page.check(f'session discovery ({label}): receipt produced', bool(state), str(state))
        for name in ('copy', 'reachable', 'filters', 'list', 'focus', 'ended', 'bounds'):
            page.check(f'session discovery ({label}): {name}', state.get(name) is True, str(state))


def run_session_empty_navigation(page):
    for width in (375, 900, 1280):
        dom = page.dom('?sessionemptynav', served=True, window_size=(width, 800),
                       fixture={'script': 'cases_session_empty_navigation.js'})
        receipt = re.search(r'data-session-empty-navigation="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        page.check(f'session empty navigation ({width}): receipt produced', bool(state), str(state))
        for name in ('missingBack', 'copy', 'searchFocus', 'preserved', 'unavailable', 'noData', 'noDataFocus', 'bounds'):
            page.check(f'session empty navigation ({width}): {name}', state.get(name) is True, str(state))


def run_session_latest_focus(page):
    for width in (375, 1280):
        dom = page.dom('?sessionlatestfocus', window_size=(width, 800), fixture=payload_cases.session_workbench(), served=True)
        receipt = re.search(r'data-session-latest-focus="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        page.check(f'session latest focus ({width}): receipt produced', bool(state), str(state))
        for mode in ('memory', 'trace', 'results'):
            for assertion in ('Ready', 'Focus', 'Latest', 'Page', 'Announcement', 'Outside'):
                name = mode + assertion
                page.check(f'session latest focus ({width}): {name}', state.get(name) is True, str(state))


def run_session_status_focus(page):
    for width in (375, 1280):
        dom = page.dom('?sessionstatusfocus', window_size=(width, 800), fixture=payload_cases.session_workbench(), served=True)
        receipt = re.search(r'data-session-status-focus="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        page.check(f'session status focus ({width}): receipt produced', bool(state), str(state))
        for mode in ('memory', 'trace'):
            for assertion in ('Ready', 'Unchanged', 'Failure', 'Reading', 'Recovery', 'Outside', 'OutsideRecovery'):
                name = mode + assertion
                page.check(f'session status focus ({width}): {name}', state.get(name) is True, str(state))
        for name in ('viewSwitch', 'sessionSwitch'):
            page.check(f'session status focus ({width}): {name}', state.get(name) is True, str(state))


def run_session_search_recovery(page):
    for width in (375, 1280):
        dom = page.dom('?sessionsearchrecovery', window_size=(width, 800), served=True,
                       fixture={'script': 'cases_session_search_recovery.js'})
        receipt = re.search(r'data-session-search-recovery="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        page.check(f'session search recovery ({width}): receipt produced', bool(state), str(state))
        for name in ('origin', 'recovery', 'reset', 'results', 'retry', 'empty', 'agents', 'agentResults', 'bounds'):
            page.check(f'session search recovery ({width}): {name}', state.get(name) is True, str(state))


CASES = (
    Case('session_search_recovery', run_session_search_recovery),
    Case('session_status_focus', run_session_status_focus),
    Case('session_latest_focus', run_session_latest_focus),
    Case('session_empty_navigation', run_session_empty_navigation),
    Case('session_discovery', run_session_discovery),
    Case('session_rail_renders_durable_sessions', run_session_rail_renders_durable_sessions, ('dom',)),
    Case('rail_titles_are_repo_branch_not_harness_repo', run_rail_titles_are_repo_branch_not_harness_repo, ('dom',)),
    Case('ended_session_marked', run_ended_session_marked, ('dom',)),
    Case('sessions_rail_renders_one_group_per_live_harness_newest_first_infra_last', run_sessions_rail_renders_one_group_per_live_harness_newest_first_infra_last, ('dom',)),
    Case('harness_marks_resolve_to_sprite_symbols', run_harness_marks_resolve_to_sprite_symbols, ('dom',)),
    Case('ended_tail_is_collapsed_by_default', run_ended_tail_is_collapsed_by_default, ('dom',)),
    Case('infra_sits_in_the_last_group_collapsed_with_rss_totals_only', run_infra_sits_in_the_last_group_collapsed_with_rss_totals_only, ('dom',)),
    Case('memory_detail_fits_a_375px_phone_without_horizontal_page_overflow', run_memory_detail_fits_a_375px_phone_without_horizontal_page_overflow, ('dom_memory_phone',)),
    Case('rail_selection_renders_trace_waterfall', run_rail_selection_renders_trace_waterfall, ('dom_rail',)),
    Case('memory_opens_first_and_earlier_rows_prepend_once', run_memory_opens_first_and_earlier_rows_prepend_once, ('dom_memory',)),
    Case('session_guard_decision_uses_the_existing_handler_and_refreshes_its_result', run_session_guard_decision_uses_the_existing_handler_and_refreshes_its_result, ('dom_overview_decision',)),
    Case('session_findings_history_retains_scope_and_returns_to_the_same_session', run_session_findings_history_retains_scope_and_returns_to_the_same_session, ('dom_overview_return',)),
    Case('sessions_has_no_cleanup_sub_view_its_panels_live_in_the_system_tab', run_sessions_has_no_cleanup_sub_view_its_panels_live_in_the_system_tab, ('dom',)),
    Case('sessions_panel_lives_in_the_sessions_tab', run_sessions_panel_lives_in_the_sessions_tab, ('dom',)),
    Case('memory_by_family', run_memory_by_family, ('dom_memfam',)),
    Case('session_board_has_project_filter', run_session_board_has_project_filter, ('dom',)),
    Case('session_rail_lists_live_cards_and_the_ended_tail', run_session_rail_lists_live_cards_and_the_ended_tail, ('dom',)),
    Case('session_cards_labeled_by_repo_branch_or_folder', run_session_cards_labeled_by_repo_branch_or_folder, ('dom',)),
    Case('session_card_selects_the_session_trace', run_session_card_selects_the_session_trace, ('dom',)),
    Case('sessions_and_processes_counts_sit_on_the_sub_view_buttons_the_sessions_tab_keeps_the_live_count', run_sessions_and_processes_counts_sit_on_the_sub_view_buttons_the_sessions_tab_keeps_the_live_count, ('dom',)),
    Case('session_coverage_remains_available_without_a_global_monitoring_gap', run_session_coverage_remains_available_without_a_global_monitoring_gap, ('dom_session_coverage',)),
    Case('session_chip_appears', run_session_chip_appears, ('dom_session',)),
    Case('session_chip_count', run_session_chip_count, ('dom_session',)),
    Case('session_scopes_findings_list', run_session_scopes_findings_list, ('dom_session',)),
    Case('memory_by_family_2', run_memory_by_family_2, ('dom_memprobe',)),
    Case('session_activity', run_session_activity, ()),
    Case('session_investigation', run_session_investigation, ()),
    Case('session_permissions', run_session_permissions, ()),
    Case('context_handoff', run_context_handoff, ()),
    Case('session_results', run_session_results, ()),
    Case('guard_receipts', run_guard_receipts, ()),
    Case('guard_review', run_guard_review, ()),
    Case('hook_monitoring', run_hook_monitoring, ()),
    Case('hook_history', run_hook_history, ()),
    Case('session_coverage', run_session_coverage, ()),
    Case('session_follow_up', run_session_follow_up, ()),
    Case('recent_work', run_recent_work, ()),
    Case('home_ux', run_home_ux, ()),
    Case('attention_summary', run_attention_summary, ()),
    Case('hook_diagnostics', run_hook_diagnostics, ()),
    Case('session_hooks', run_session_hooks, ()),
    Case('session_workbench', run_session_workbench, ()),
    Case('session_reading', run_session_reading, ()),
)
