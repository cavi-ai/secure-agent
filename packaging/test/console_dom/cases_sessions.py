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
            and re.search('id="coverage-center"[^>]*\\bhidden', dom_session_coverage) is None
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
    for label, size, query in [('long phone', (320, 800), '?readingdemo&readinglong'), ('short phone', (390, 800), '?readingdemo'), ('short viewport', (375, 480), '?readingdemo&readinglong')]:
        reading_dom = page.dom(query, window_size=size, fixture=payload_cases.session_workbench(), served=True)
        receipt = re.search(r'data-session-reading="([^"]+)"', reading_dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        check(f'session reading ({label}): receipt produced', bool(state), str(state))
        for name in ('memoryBudget', 'contextInBody', 'latest', 'currentContext', 'detailsBudget', 'detailsDoNotGrowChrome', 'fullTitleRow', 'toolbar', 'actions', 'resultsBudget', 'traceBudget', 'fits'):
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


CASES = (
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
    Case('session_workbench', run_session_workbench, ()),
    Case('session_reading', run_session_reading, ()),
)
