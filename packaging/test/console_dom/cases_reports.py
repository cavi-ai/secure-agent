"""Console reports cases."""
from case_support import html, json, re, HTMLParser, dom_query, starts_with, payload_cases, pre, log_rows, PolicyRowCounter
from case_types import Case

def run_resource_results(page):
    check = page.check
    dom_resource_results = page.fixture('dom_resource_results')
    check(
        'resource results: partial application remains unknown with resume recourse',
        (
            (
                'Partially applied' in dom_query(dom_resource_results).text
                or dom_query(dom_resource_results).has(None, {'title': lambda value: 'Partially applied' in (value or '')})
            )
            and (
                'Verification unknown' in dom_query(dom_resource_results).text
                or dom_query(dom_resource_results).has(None, {'title': lambda value: 'Verification unknown' in (value or '')})
            )
            and (
                'Resume may be needed' in dom_query(dom_resource_results).text
                or dom_query(dom_resource_results).has(None, {'title': lambda value: 'Resume may be needed' in (value or '')})
            )
        ),
    )
    check(
        'resource results: termination verification names captured family limits',
        (
            (
                'Captured family absent' in dom_query(dom_resource_results).text
                or dom_query(dom_resource_results).has(None, {'title': lambda value: 'Captured family absent' in (value or '')})
            )
            and (
                'Verification covers only the captured process family' in dom_query(dom_resource_results).text
                or dom_query(dom_resource_results).has(None, {'title': lambda value: 'Verification covers only the captured process family' in (value or '')})
            )
            and (
                'causation or task completion' in dom_query(dom_resource_results).text
                or dom_query(dom_resource_results).has(None, {'title': lambda value: 'causation or task completion' in (value or '')})
            )
        ),
    )

def run_group_head_carries_mark_display_name_and_counts(page):
    check = page.check
    dom = page.fixture('dom')
    rail = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
    check(
        'group head carries mark, display name and counts',
        (
            '<span class="harness-label">Claude Code</span>' in rail
            and '1 active · 1 idle · 1 ended' in rail
            and dom_query(rail).has(None, {'data-harness': 'codex', 'open': ''})
            and dom_query(rail).has(None, {'class': 'session-card active selected'})
        ),
    )

def run_sub_session_nests_under_its_parent(page):
    check = page.check
    dom = page.fixture('dom')
    rail = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
    claude_group = rail.split('data-harness="claude"', 1)[1].split('<details', 1)[0]
    check(
        'sub-session nests under its parent',
        claude_group.index('data-id="sess-claude-1"') < claude_group.index('session-card idle nested') < claude_group.index('data-id="sess-claude-sub"'),
    )

def run_live_only_hides_a_harness_with_nothing_running(page):
    check = page.check
    dom = page.fixture('dom')
    rail = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
    check(
        'live only hides a harness with nothing running',
        not dom_query(rail).has(None, {'data-harness': 'cursor'}),
    )

def run_live_cards_carry_kill_ended_cards_do_not(page):
    check = page.check
    dom = page.fixture('dom')
    rail = dom.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
    check(
        'live cards carry kill, ended cards do not',
        (
            dom_query(rail).has(None, {'data-action': 'kill', 'data-pid': '5821'})
            and 'data-action="kill"' not in rail.split('class="session-ended-body"', 1)[1].split('</details>', 1)[0]
        ),
    )

def run_count_strip_shows_sessions_harnesses_and_coverage(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'count strip shows sessions, harnesses and coverage',
        re.search('id="session-count-strip"[^>]*>Sessions 3 · Harnesses 2 · seeing 2/3<', dom) is not None,
    )

def run_one_filter_pill_per_live_harness(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'one filter pill per live harness',
        re.findall('data-action="toggle-harness" data-harness="([^"]+)" aria-pressed="true"', dom.split('id="session-harness-pills"', 1)[1].split('</div>', 1)[0]) == ['codex', 'claude'],
    )

def run_a_switched_off_pill_hides_its_group(page):
    check = page.check
    dom_pill = page.fixture('dom_pill')
    pill_rail = dom_pill.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
    check(
        'a switched-off pill hides its group',
        (
            not dom_query(pill_rail).has(None, {'data-harness': 'claude'})
            and dom_query(pill_rail).has(None, {'data-harness': 'codex'})
            and dom_query(dom_pill).has(None, {'class': 'harness-pill off', 'data-action': 'toggle-harness', 'data-harness': 'claude', 'aria-pressed': 'false'})
        ),
    )

def run_empty_rail_says_all_quiet(page):
    check = page.check
    dom_quiet = page.fixture('dom_quiet')
    check(
        'empty durable rail says no live sessions without offering ended recovery',
        (
            'No live sessions.' in dom_query(dom_quiet).text
            and not dom_query(dom_quiet).has(None, {'data-action': 'show-ended-sessions'})
        ),
    )

def run_filter_that_hides_everything_offers_to_clear_it(page):
    check = page.check
    dom_nomatch = page.fixture('dom_nomatch')
    check(
        'filter that hides everything offers to clear it',
        (
            (
                'No live sessions match these filters.' in dom_query(dom_nomatch).text
            )
            and dom_query(dom_nomatch).has(None, {'data-action': 'clear-harness-filter'})
            and not dom_query(dom_nomatch).has(None, {'data-action': 'show-ended-sessions'})
        ),
    )

def run_the_page_posture_banner_included_fits_a_375px_phone_on_sessions_agents_and_resources(page):
    check = page.check
    dom_phone = page.fixture('dom_phone')
    check(
        'the page, posture banner included, fits a 375px phone on Sessions, Agents and Resources',
        dom_query(dom_phone).has(None, {'data-hscroll': 'sessions:0,agents:0,resources:0'}),
        (re.search('data-hscroll="[^"]*"', dom_phone) or [None])[0],
    )

def run_phone_overflow_probe(page):
    check = page.check
    dom_phone = page.fixture('dom_phone')
    guard_node = dom_query(dom_phone).find(None, {'data-overflow-guard': None})
    try:
        overflow_guard = json.loads(guard_node.attrs['data-overflow-guard']) if guard_node else {}
    except (ValueError, TypeError):
        overflow_guard = {}
    for mode in ('auto', 'scroll', 'hidden', 'clip', 'unclipped', 'container', 'document'):
        check(
            f'phone overflow probe: {mode} clipping or overflow control',
            overflow_guard.get(mode) is True,
            str(overflow_guard),
        )

def run_detail_head(page):
    check = page.check
    dom_rail = page.fixture('dom_rail')
    detail_head = dom_rail.split('class="session-detail-head"', 1)[1].split('class="wf', 1)[0]
    check(
        'detail head: mark, repo@branch, harness, confidence, copyable path',
        (
            re.search('<h3[^>]*>api-service@main</h3>', detail_head) is not None
            and '#logo-claude' in detail_head
            and '<span class="sd-harness">Claude Code</span>' in detail_head
            and '>hook</span>' in detail_head
            and dom_query(detail_head).has(None, {'data-action': 'copy-path', 'data-path': '/Users/dev/workspace/api-service'})
        ),
    )

def run_detail_chrome_keeps_copy_report_reachable_and_the_copyable_path_in_expandable_details(page):
    check = page.check
    dom_rail = page.fixture('dom_rail')
    detail_node = dom_query(dom_rail).find(None, {'id': 'session-detail'})
    detail_chrome = detail_node.find(None, {'class': 'session-detail-chrome'})
    detail_body = detail_node.find(None, {'class': 'session-detail-body'})
    metadata = detail_body.find('details', {'class': 'session-metadata'})
    check(
        'detail chrome keeps Copy report reachable; scrolling context retains expandable Details and copyable path',
        (
            detail_chrome.has(None, {'data-action': 'copy-report', 'data-id': 'sess-claude-1'})
            and 'Copy report' in detail_chrome.text and not detail_chrome.has(None, {'class': 'session-metadata'})
            and metadata is not None and metadata.has('summary')
            and metadata.has(None, {'data-action': 'copy-path', 'data-path': '/Users/dev/workspace/api-service'})
        ),
    )

def run_export_copies_the_markdown_session_report_and_toasts(page):
    check = page.check
    dom_export = page.fixture('dom_export')
    clip = (re.search('data-clipboard="([^"]*)"', dom_export) or [None, ''])[1]
    check(
        'Export copies the markdown session report and toasts',
        (
            clip.startswith('# claude · api-service@main')
            and '## Summary' in clip
            and 'class="toast success">Session report copied (markdown)<' in dom_export
        ),
        f'clipboard={clip[:60]!r}',
    )

def run_home_session_opens_its_current_controls_evidence_and_observed_coverage(page):
    check = page.check
    dom_overview = page.fixture('dom_overview')
    current = dom_overview.split('id="session-detail"', 1)[1].split('id="session-board"', 1)[0]
    check(
        'Home session opens its current controls, evidence, and observed coverage',
        (
            'Read wants access to .env' in current
            and 'Own session finding' in current
            and 'Reviewed' in current
            and 'Model exposure' in current
            and 'Other traffic may be uninspected.' in current
            and current.index('Current session status') < current.index('class="session-memory"')
        ),
    )

def run_home_session_opens_current_status_in_the_workbench_viewport(page):
    check = page.check
    dom_overview = page.fixture('dom_overview')
    check(
        'Home session opens current status in the workbench viewport',
        dom_query(dom_overview).has(None, {'data-overview-visible': 'true'}),
    )

def run_failed_overview_refresh_preserves_facts_with_disabled_controls_and_a_visible_stale_warning(page):
    check = page.check
    dom_overview_stale = page.fixture('dom_overview_stale')
    stale = dom_overview_stale.split('id="session-detail"', 1)[1].split('id="session-board"', 1)[0]
    check(
        'failed overview refresh preserves facts with disabled controls and a visible stale warning',
        (
            'Last known session status' in stale
            and 'Own session finding' in stale
            and re.search('<fieldset[^>]*class="sd-request"[^>]*disabled', stale) is not None
        ),
    )

def run_late_session_overview_cannot_overwrite_the_newly_selected_session(page):
    check = page.check
    dom_overview_race = page.fixture('dom_overview_race')
    race = dom_overview_race.split('id="session-detail"', 1)[1].split('id="session-board"', 1)[0]
    check(
        'late session overview cannot overwrite the newly selected session',
        (
            re.search('<h3[^>]*>data-pipeline@feat/etl</h3>', race) is not None
            and 'Own session finding' not in race
            and 'Read wants access to .env' not in race
        ),
    )

def run_new_findings_preserve_the_focused_guard_control(page):
    check = page.check
    dom_overview_focus = page.fixture('dom_overview_focus')
    check(
        'new findings preserve the focused guard control',
        dom_query(dom_overview_focus).has(None, {'data-overview-focus': 'true'}),
    )

def run_late_response_from_previous_selection_cannot_replace_memory(page):
    check = page.check
    dom_memory_race = page.fixture('dom_memory_race')
    check(
        'late response from previous selection cannot replace Memory',
        (
            dom_query(dom_memory_race).has(None, {'data-memory-race': 'B'})
            and re.search('<h3[^>]*>data-pipeline@feat/etl</h3>', dom_memory_race.split('id="session-detail"', 1)[1]) is not None
            and 'A-only memory' not in dom_memory_race.split('id="session-detail"', 1)[1]
        ),
        dom_memory_race.split('id="session-detail"', 1)[1][:700],
    )

def run_trace_refetches_after_an_event_arrives_while_memory_is_active(page):
    check = page.check
    dom_trace_reactivation = page.fixture('dom_trace_reactivation')
    check(
        'Trace refetches after an event arrives while Memory is active',
        (
            dom_query(dom_trace_reactivation).has(None, {'data-trace-was-cached': 'true'})
            and dom_query(dom_trace_reactivation).has(None, {'data-trace-reactivated': 'true'})
        ),
        (re.search('data-trace-(?:was-cached|reactivated)="[^"]*"', dom_trace_reactivation) or [None])[0],
    )

def run_waterfall_carries_model_usage_row(page):
    check = page.check
    dom_rail = page.fixture('dom_rail')
    check(
        'waterfall carries model usage row',
        (
            (
                'claude-sonnet-4-5' in dom_query(dom_rail).text
                or dom_query(dom_rail).has(None, {'title': lambda value: 'claude-sonnet-4-5' in (value or '')})
            )
            and (
                '46.2k in' in dom_query(dom_rail).text
                or dom_query(dom_rail).has(None, {'title': lambda value: '46.2k in' in (value or '')})
            )
        ),
    )

def run_waterfall_marks_tool_errors(page):
    check = page.check
    dom_rail = page.fixture('dom_rail')
    check(
        'waterfall marks tool errors',
        dom_query(dom_rail).has(None, {'class': 'wf-bar error'}),
    )

def run_theme(page):
    check = page.check
    dom_themefirst = page.fixture('dom_themefirst')
    theme_first = (re.search('<pre id="theme-first"[^>]*>([^<]*)<', dom_themefirst) or [None, ''])[1]
    check(
        'theme: a stored light theme is on <html> before app.js runs, under the served CSP',
        theme_first == 'before-app=light',
        theme_first,
    )

def run_under_the_daemon_csp_the_waterfall_bar_ranked_bar_and_memory_segment_keep_their_widths(page):
    check = page.check
    dom_csp = page.fixture('dom_csp')
    csp_widths = (re.search('data-csp-widths="([^"]*)"', dom_csp) or [None, ''])[1]
    widths = {k: float(v) for k, v in (kv.split(':') for kv in csp_widths.split(',') if kv)}
    check(
        'under the daemon CSP the waterfall bar, ranked bar and memory segment keep their widths',
        (
            abs(widths.get('wf-bar', 0) - 34.4) < 1
            and abs(widths.get('hbar-fill', 0) - 10.9) < 1
            and abs(widths.get('resource-host-segment', 0) - 34.4) < 1
        ),
        f'widths={csp_widths!r}',
    )

def run_version_badge_comes_from_status(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'version badge comes from /status',
        'id="app-version">v9.9.9-domtest<' in dom,
    )

def run_posture_banner_is_critical(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'posture banner is critical',
        dom_query(dom).has(None, {'id': 'posture-banner', 'data-state': 'critical'}),
    )

def run_posture_headline_rendered(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'posture headline rendered',
        'id="posture-state">Urgent review<' in dom,
    )

def run_kpi_agents_count(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'KPI agents count',
        'id="count-agents">3<' in dom,
    )

def run_kpi_flags_are_unacted_last_24h(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'KPI flags are unacted last 24h',
        'id="count-flags">2<' in dom,
    )

def run_kpi_incidents_count(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'KPI incidents count',
        'id="count-incidents">1<' in dom,
    )

def run_empty_spend_report(page):
    check = page.check
    dom_nocosts = page.fixture('dom_nocosts')

    def spend_card_of(d):
        card = dom_query(d).find(None, {'id': 'spend-card'})
        return card.inner_html if card else ''
    check(
        'empty spend report: tile reads an em dash, card shows its empty state',
        (
            'id="count-spend">—<' in dom_nocosts
            and 'id="hint-spend"><' in dom_nocosts
            and 'No model calls in this window.' in spend_card_of(dom_nocosts)
        ),
    )

def run_console(page):
    check = page.check
    dom_attentionremodel = page.fixture('dom_attentionremodel')
    dom_remodelusage = page.fixture('dom_remodelusage')
    for label, rendered, pid, fields in (('attention inspector', dom_attentionremodel, 'attention-remodel-probe', ['initial', 'evidenceOpen', 'named', 'modal', 'pendingRetained', 'final', 'focus']), ('daily usage selection', dom_remodelusage, 'usage-remodel-probe', ['selected', 'matches', 'focus', 'detail', 'reset'])):
        raw = html.unescape(pre(rendered, pid))
        try:
            receipt = json.loads(raw)
        except (ValueError, TypeError):
            receipt = {}
        for field in fields:
            check(
                f'{label}: {field}',
                receipt.get(field) is True,
                raw,
            )

def run_a_switched_off_pill_hides_the_harness_in_agents_too(page):
    check = page.check
    dom_pill = page.fixture('dom_pill')
    pill_agents = dom_pill.split('id="agents-container"', 1)[1].split('id="fleet-col"', 1)[0]
    check(
        'a switched-off pill hides the harness in Agents too (shared state)',
        (
            not dom_query(pill_agents).has(None, {'data-harness': 'claude'})
            and dom_query(pill_agents).has(None, {'data-harness': 'codex'})
            and 'class="harness-pill off" data-action="toggle-harness" data-harness="claude"' in dom_pill.split('id="agent-harness-pills"', 1)[1].split('</div>', 1)[0]
        ),
    )

def run_claude_instance_pid(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'claude instance pid',
        (
            'PID 5821' in dom_query(dom).text
            or dom_query(dom).has(None, {'title': lambda value: 'PID 5821' in (value or '')})
        ),
    )

def run_nested_helper_pid(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'nested helper pid',
        (
            'PID 5822' in dom_query(dom).text
            or dom_query(dom).has(None, {'title': lambda value: 'PID 5822' in (value or '')})
        ),
    )

def run_leftover_cursor_status(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'leftover cursor status',
        (
            'leftover' in dom_query(dom).text
            or dom_query(dom).has(None, {'title': lambda value: 'leftover' in (value or '')})
        ),
    )

def run_terminate_not_labelled_kill(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'terminate not labelled Kill',
        (
            (
                'Terminate' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: 'Terminate' in (value or '')})
            )
            and 'Kill</span>' not in dom
        ),
    )

def run_firewall_enforcing_badge(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'firewall enforcing badge',
        'class="badge badge-ok" id="badge-firewall-mode">enforcing<' in dom,
    )

def run_egress_coverage_names_the_displayed_sample_without_implying_findings(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'Egress coverage names the displayed sample without implying findings',
        (
            (
                'Connection coverage · last 24 h' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: 'Connection coverage · last 24 h' in (value or '')})
            )
            and (
                '7 endpoints shown · 2 known infrastructure' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: '7 endpoints shown · 2 known infrastructure' in (value or '')})
            )
            and (
                'Connection coverage alone is not a security finding.' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: 'Connection coverage alone is not a security finding.' in (value or '')})
            )
        ),
    )

def run_blocking_rule_shows_demote_button(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'blocking rule shows demote button',
        dom_query(dom).has(None, {'data-action': 'demote', 'data-rule': 'aws-key'}),
    )

def run_demote_flips_the_rule_back_to_promote(page):
    check = page.check
    dom_demote = page.fixture('dom_demote')
    check(
        'demote flips the rule back to promote',
        dom_query(dom_demote).has(None, {'data-action': 'promote', 'data-rule': 'aws-key'}),
    )

def run_remove_drops_the_allowlist_row(page):
    check = page.check
    dom_allowrm = page.fixture('dom_allowrm')
    check(
        'remove drops the allowlist row',
        (
            'artifacts.example.com' not in dom_query(dom_allowrm).text
            and not dom_query(dom_allowrm).has(None, {'title': lambda value: 'artifacts.example.com' in (value or '')})
        ),
    )

def run_drill_down_keeps_unknown_endpoints_actionable(page):
    check = page.check
    dom_uninsp = page.fixture('dom_uninsp')
    check(
        'drill-down keeps unknown endpoints actionable',
        (
            'registry.npmjs.org' in dom_query(dom_uninsp).text
            or dom_query(dom_uninsp).has(None, {'title': lambda value: 'registry.npmjs.org' in (value or '')})
        ),
    )

def run_drill_down_collapses_cdn_cloud_carriers(page):
    check = page.check
    dom_uninsp = page.fixture('dom_uninsp')
    check(
        'drill-down collapses CDN/cloud carriers',
        (
            (
                'Known cloud/CDN infrastructure (2 endpoints)' in dom_query(dom_uninsp).text
                or dom_query(dom_uninsp).has(None, {'title': lambda value: 'Known cloud/CDN infrastructure (2 endpoints)' in (value or '')})
            )
            and (
                'Cloudflare' in dom_query(dom_uninsp).text
                or dom_query(dom_uninsp).has(None, {'title': lambda value: 'Cloudflare' in (value or '')})
            )
            and (
                'AWS' in dom_query(dom_uninsp).text
                or dom_query(dom_uninsp).has(None, {'title': lambda value: 'AWS' in (value or '')})
            )
        ),
    )

def run_drill_down_rolls_vendor_apis_up_per_agent_and_vendor(page):
    check = page.check
    dom_uninsp = page.fixture('dom_uninsp')
    check(
        'drill-down rolls vendor APIs up per agent and vendor',
        (
            (
                'Vendor APIs' in dom_query(dom_uninsp).text
                or dom_query(dom_uninsp).has(None, {'title': lambda value: 'Vendor APIs' in (value or '')})
            )
            and (
                'openclaw → Anthropic' in dom_query(dom_uninsp).text
                or dom_query(dom_uninsp).has(None, {'title': lambda value: 'openclaw → Anthropic' in (value or '')})
            )
            and (
                '94×' in dom_query(dom_uninsp).text
                or dom_query(dom_uninsp).has(None, {'title': lambda value: '94×' in (value or '')})
            )
            and dom_query(dom_uninsp).has(None, {'data-action': 'bulk-allow', 'data-agent': 'openclaw', 'data-hosts': '2607:6bc0::10'})
        ),
    )

def run_unknown_section_does_not_list_vendor_endpoints(page):
    check = page.check
    dom_uninsp = page.fixture('dom_uninsp')
    uninsp_unknown = dom_uninsp.split('class="uninspected-expl"', 1)[-1].split('Vendor APIs', 1)[0]
    check(
        'unknown section does not list vendor endpoints',
        (
            '2607:6bc0::10' not in uninsp_unknown
            and 'statsig.example.com' in uninsp_unknown
        ),
    )

def run_unknown_section_keeps_cloud_hosts_named(page):
    check = page.check
    dom_uninsp = page.fixture('dom_uninsp')
    uninsp_unknown = dom_uninsp.split('class="uninspected-expl"', 1)[-1].split('Vendor APIs', 1)[0]
    check(
        'unknown section keeps cloud hosts, named',
        re.search('2600:1901:0:9e23::</span> <span class="fw-metric dim">Google Cloud</span>', uninsp_unknown) is not None,
    )

def run_egress_rows_show_first_seen_and_session(page):
    check = page.check
    dom_uninsp = page.fixture('dom_uninsp')
    check(
        'egress rows show first-seen and session',
        (
            (
                'first seen' in dom_query(dom_uninsp).text
                or dom_query(dom_uninsp).has(None, {'title': lambda value: 'first seen' in (value or '')})
            )
            and (
                'session ' in dom_query(dom_uninsp).text
                or dom_query(dom_uninsp).has(None, {'title': lambda value: 'session ' in (value or '')})
            )
        ),
    )

def run_egress_bulk_allow_groups_same_suffix_hosts(page):
    check = page.check
    dom_uninsp = page.fixture('dom_uninsp')
    check(
        'egress bulk allow groups same-suffix hosts',
        (
            dom_query(dom_uninsp).has(None, {'data-action': 'bulk-allow', 'data-agent': 'claude'})
            and (
                'Allow all 2' in dom_query(dom_uninsp).text
                or dom_query(dom_uninsp).has(None, {'title': lambda value: 'Allow all 2' in (value or '')})
            )
        ),
    )

def run_egress_explains_what_the_list_is_and_what_to_do(page):
    check = page.check
    dom_uninsp = page.fixture('dom_uninsp')
    check(
        'egress explains what the list is and what to do',
        (
            (
                'What this is:' in dom_query(dom_uninsp).text
                or dom_query(dom_uninsp).has(None, {'title': lambda value: 'What this is:' in (value or '')})
            )
            and (
                'What to do:' in dom_query(dom_uninsp).text
                or dom_query(dom_uninsp).has(None, {'title': lambda value: 'What to do:' in (value or '')})
            )
        ),
    )

def run_egress_rows_carry_a_plain_allow_action(page):
    check = page.check
    dom_uninsp = page.fixture('dom_uninsp')
    check(
        'egress rows carry a plain Allow action',
        (
            dom_query(dom_uninsp).has(None, {'data-action': 'allow-host'})
            and '>Allow</span>' in dom_uninsp
        ),
    )

def run_egress_rows_offer_on_demand_advisor_assessment(page):
    check = page.check
    dom_uninsp = page.fixture('dom_uninsp')
    check(
        'egress rows offer on-demand advisor assessment',
        (
            dom_query(dom_uninsp).has(None, {'data-action': 'assess-host', 'data-agent': 'claude'})
            and (
                'Ask the advisor' in dom_query(dom_uninsp).text
                or dom_query(dom_uninsp).has(None, {'title': lambda value: 'Ask the advisor' in (value or '')})
            )
        ),
    )

def run_egress_rows_with_a_verdict_show_the_advisor_chip(page):
    check = page.check
    dom_uninsp = page.fixture('dom_uninsp')
    check(
        'egress rows with a verdict show the advisor chip',
        dom_query(dom_uninsp).has(None, {'class': 'advisor-chip adv-benign'}),
    )

def run_drawer_is_open_for_the_drill_down(page):
    check = page.check
    dom_toast = page.fixture('dom_toast')
    check(
        'drawer is open for the drill-down',
        (
            dom_query(dom_toast).has(None, {'id': 'drawer', 'class': 'drawer'})
            and 'id="drawer" class="drawer" hidden' not in dom_toast
        ),
    )

def run_toast_rendered_while_the_drawer_is_open(page):
    check = page.check
    dom_toast = page.fixture('dom_toast')
    check(
        'toast rendered while the drawer is open',
        dom_query(dom_toast).has(None, {'class': 'toast '}),
    )

def run_vendor_key_promote_banner(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'vendor-key promote banner',
        (
            dom_query(dom).has(None, {'data-action': 'promote-vendor-keys'})
            and (
                '1 vendor-key rule' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: '1 vendor-key rule' in (value or '')})
            )
        ),
    )

def run_incident_row_reads_its_risk_and_workflow(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'incident row reads its risk and workflow (ack)',
        '<span class="c-verdict-text">CRITICAL · acknowledged</span>' in dom,
    )

def run_payload_incident_preserves_mixed_results_after_reported_resolution(page):
    check = page.check
    dom_payload = page.fixture('dom_payload')
    payload_row = log_rows(dom_payload).get('incident:inc-20260907-6033-a1b2', '')
    check(
        'payload incident preserves mixed results after reported resolution',
        (
            '2 blocked before forwarding' in payload_row
            and '1 observed only' in payload_row
            and '3 outcome unknown' in payload_row
            and 'Operator reported credential revocation' in payload_row
            and 'revocation are not verified' in payload_row
        ),
    )

def run_payload_finding_names_the_local_forwarding_gate_and_registered_match(page):
    check = page.check
    dom_payload = page.fixture('dom_payload')
    check(
        'payload finding names the local forwarding gate and registered match',
        (
            (
                'Blocked before forwarding' in dom_query(dom_payload).text
                or dom_query(dom_payload).has(None, {'title': lambda value: 'Blocked before forwarding' in (value or '')})
            )
            and (
                'Registered secret fingerprint' in dom_query(dom_payload).text
                or dom_query(dom_payload).has(None, {'title': lambda value: 'Registered secret fingerprint' in (value or '')})
            )
        ),
    )

def run_secret_sources_rendered(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'secret sources rendered (config+user)',
        (
            len(dom_query(dom).find_all(None, {'class': 'source-item'})) == 2
            and (
                'CONFIG' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: 'CONFIG' in (value or '')})
            )
            and (
                'USER' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: 'USER' in (value or '')})
            )
        ),
    )

def run_chain_rendered_with_3_nodes(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'chain rendered with 3 nodes',
        dom.count('chain-node') >= 3,
    )

def run_chain_node(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'chain node: payload inspection',
        (
            'payload inspection' in dom_query(dom).text
            or dom_query(dom).has(None, {'title': lambda value: 'payload inspection' in (value or '')})
        ),
    )
    check(
        'chain node: egress destination',
        (
            'logs.example.com:443' in dom_query(dom).text
            or dom_query(dom).has(None, {'title': lambda value: 'logs.example.com:443' in (value or '')})
        ),
    )

def run_chain_verdict_node(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'chain verdict node',
        (
            dom_query(dom).has(None, {'class': 'cn-verdict-bad'})
            and (
                'Critical flag raised' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: 'Critical flag raised' in (value or '')})
            )
        ),
    )

def run_history_lists_every_flag_as_one_log_row_the_critical_ones_first(page):
    check = page.check
    dom = page.fixture('dom')
    history_rows = re.findall('<li class="log-row[^"]*" data-row-key="(flag:[^"]+)"', dom)
    check(
        'history lists every flag as one log row, the critical ones first',
        (
            sorted(history_rows) == ['flag:flag-1', 'flag:flag-2', 'flag:flag-3']
            and history_rows[-1] == 'flag:flag-3'
        ),
        f'rows={history_rows}',
    )

def run_an_unexplained_flag_s_evidence_rows_render_as_text_not_object_object(page):
    check = page.check
    dom = page.fixture('dom')
    flag1_card = log_rows(dom).get('flag:flag-1', '')
    flags_region = dom.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
    check(
        "an unexplained flag's evidence rows render as text, not [object Object]",
        (
            '<div>proxy-secret-leak: anthropic-key (payload inspection)</div>' in flag1_card
            and '<div>logs.example.com:443 (destination)</div>' in flag1_card
            and '[object Object]' not in flags_region
        ),
    )

def run_sparkline_has_points(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'sparkline has points',
        re.search('id="spark-line" points="[\\d.,\\- ]{20,}"', dom) is not None,
    )

def run_sparkline_rate_label(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'sparkline rate label',
        re.search('id="spark-rate">\\d+/s<', dom) is not None,
    )

def run_fresh_timeline_rows_after_sse_drip(page):
    check = page.check
    dom_events = page.fixture('dom_events')
    check(
        'fresh timeline rows after SSE drip',
        dom_query(dom_events).has(None, {'class': 'timeline-item fresh'}),
    )

def run_timeline_times_are_hh(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'timeline times are HH:MM:SS',
        re.search('class="t">\\d{2}:\\d{2}:\\d{2}<', dom) is not None,
    )

def run_advisor_chip_rendered_with_assessment_class(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'advisor chip rendered with assessment class',
        dom_query(dom).has(None, {'class': 'advisor-chip adv-suspicious'}),
    )

def run_advisor_chip_rationale_in_tooltip(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'advisor chip rationale in tooltip',
        (
            'first time this session' in dom_query(dom).text
            or dom_query(dom).has(None, {'title': lambda value: 'first time this session' in (value or '')})
        ),
    )

def run_stale_process_marked(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'stale process marked',
        dom_query(dom).has(None, {'class': 'stale'}),
    )

def run_flag_card_kill_action(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'flag card kill action',
        dom_query(dom).has(None, {'data-action': 'kill', 'data-pid': '6033'}),
    )

def run_collector_down_fda_deep_link(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'collector-down FDA deep link',
        (
            dom_query(dom).has(None, {'data-action': 'open-fda'})
            and (
                'Full Disk Access' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: 'Full Disk Access' in (value or '')})
            )
        ),
    )

def run_advisor_posture_line_separates_opinion_from_evidence_and_risk_off_home(page):
    check = page.check
    dom_tab = page.fixture('dom_tab')
    check(
        'advisor posture line separates opinion from evidence and risk off Home',
        (
            'Advisor opinion: 1 of 2 triaged critical flags may be benign. Evidence and risk are unchanged.' in dom_query(dom_tab).text
            or dom_query(dom_tab).has(None, {'title': lambda value: 'Advisor opinion: 1 of 2 triaged critical flags may be benign. Evidence and risk are unchanged.' in (value or '')})
        ),
    )

def run_incident_narrative_rendered_in_its_row_s_body(page):
    check = page.check
    dom = page.fixture('dom')
    dom_csp = page.fixture('dom_csp')
    csp_widths = (re.search('data-csp-widths="([^"]*)"', dom_csp) or [None, ''])[1]
    widths = {k: float(v) for k, v in (kv.split(':') for kv in csp_widths.split(',') if kv)}
    check(
        "incident narrative rendered in its row's body",
        'Rotate the key first' in log_rows(dom).get('incident:inc-20260907-6033-a1b2', ''),
        sorted((k for k in log_rows(dom) if k.startswith('incident:'))),
    )

def run_egress_suggestion_rendered(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'egress suggestion rendered',
        (
            dom_query(dom).has(None, {'class': 'fw-suggestion'})
            and 'registry.npmjs.org' in dom_query(dom).text
        ),
    )

def run_suggestion_advisor_chip(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'suggestion advisor chip',
        (
            dom_query(dom).has(None, {'class': 'advisor-chip adv-benign'})
            and (
                'advisor: benign' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: 'advisor: benign' in (value or '')})
            )
        ),
    )

def run_suggestion_allow_button_is_delegated(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'suggestion allow button is delegated',
        dom_query(dom).has(None, {'data-action': 'allow-host', 'data-agent': 'cursor', 'data-host': 'registry.npmjs.org'}),
    )

def run_activity_chart_draws_event_bars(page):
    check = page.check
    dom = page.fixture('dom')
    rects_ev = len(dom_query(dom).find_all(None, {'class': 'act-ev'}))
    check(
        'activity chart draws event bars',
        rects_ev > 10,
        f'rects={rects_ev}',
    )

def run_activity_chart_marks_the_flag_hour(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'activity chart marks the flag hour',
        dom_query(dom).has(None, {'class': 'act-fl'}),
    )

def run_activity_chart_zero_fills_empty_hours(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'activity chart zero-fills empty hours',
        dom_query(dom).has(None, {'class': 'act-zero'}),
    )

def run_rule_level_mute_renders_as_all_hosts(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'rule-level mute renders as all hosts',
        (
            'keychain-security-cli · all hosts' in dom_query(dom).text
            or dom_query(dom).has(None, {'title': lambda value: 'keychain-security-cli · all hosts' in (value or '')})
        ),
    )

def run_keychain_flag_carries_class_dismiss_action(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'keychain flag carries class-dismiss action',
        dom_query(dom).has(None, {'data-action': 'mute-rule', 'data-rule': 'keychain-access'}),
    )

def run_uninspected_warning_is_a_clickable_drill_down(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'uninspected warning is a clickable drill-down',
        dom_query(dom).has(None, {'data-action': 'open-uninspected'}),
    )

def run_home(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'Home: the posture banner lists no items; the attention queue lists them',
        (
            re.search('<ul class="posture-items" id="posture-items" hidden(="")?></ul>', dom) is not None
            and not dom_query(dom).has(None, {'class': 'posture-item'})
            and dom_query(dom).has(None, {'data-action': 'select-attention', 'data-need-kind': 'guard', 'data-need-id': 'guard-1'})
        ),
    )

def run_egress(page):
    check = page.check
    dom_posturemore = page.fixture('dom_posturemore')
    posture_egress = (re.search('<pre id="posture-egress"[^>]*>([^<]*)<', dom_posturemore) or [None, ''])[1]
    check(
        'Egress: the posture banner lists 3 content rows (2 items + the advisor line) and "and 4 more"',
        posture_egress == 'items=2 more=and 4 more hidden=0',
        posture_egress,
    )

def run_and_n_more_lands_on_home_where_the_banner_lists_nothing(page):
    check = page.check
    dom_posturemore = page.fixture('dom_posturemore')
    posture_home = (re.search('<pre id="posture-home"[^>]*>([^<]*)<', dom_posturemore) or [None, ''])[1]
    check(
        '"and N more" lands on Home, where the banner lists nothing',
        posture_home == 'tab=home items=0 more=none hidden=1',
        posture_home,
    )

def run_egress_2(page):
    check = page.check
    dom_fold = page.fixture('dom_fold')
    fold_before = (re.search('<pre id="fold-before"[^>]*>([^<]*)<', dom_fold) or [None, ''])[1]
    check(
        'Egress: 2 rules with hits listed, 20 quiet rules fold into one row with their Promote buttons',
        fold_before == 'top=2 fold=20 rules with no hits in 24 h inside=20 open=0 rebuilt=1',
        fold_before,
    )
    fold_after = (re.search('<pre id="fold-after"[^>]*>([^<]*)<', dom_fold) or [None, ''])[1]
    check(
        'Egress: the open fold stays open, and its outer node is never rebuilt, across an SSE-driven patch that changes its count',
        fold_after == 'top=3 fold=19 rules with no hits in 24 h inside=19 open=1 rebuilt=0',
        fold_after,
    )
    fold_focus = (re.search('<pre id="fold-focus"[^>]*>([^<]*)<', dom_fold) or [None, ''])[1]
    check(
        "Egress: an unchanged quiet rule's focused Promote button keeps its node identity and focus across the patch",
        fold_focus == 'kept=1',
        fold_focus,
    )
    endpoints = dom_fold.split('id="endpoints-container"', 1)[-1].split('id="firewall-panel"', 1)[0]
    check(
        'Egress: the endpoints list is the first panel, inline, with a vendor rollup and row actions',
        (
            dom_fold.index('id="endpoints-panel"') < dom_fold.index('id="firewall-panel"')
            and dom_query(endpoints).has(None, {'class': 'egress-vendor'})
            and dom_query(endpoints).has(None, {'data-action': 'bulk-allow', 'data-agent': 'openclaw'})
            and dom_query(endpoints).has(None, {'data-action': 'allow-host'})
            and dom_query(endpoints).has(None, {'data-action': 'endpoint-detail'})
            and 'id="endpoints-title">Connection coverage · last 24 h<' in dom_fold
        ),
    )
    firewall = dom_fold.split('id="firewall-container"', 1)[-1].split('id="sources-container"', 1)[0]
    check(
        'Egress: the firewall panel has no view-endpoints link',
        (
            not dom_query(firewall).has(None, {'data-action': 'open-uninspected'})
            and (
                'fw-uninspected' not in dom_query(dom_fold).text
                and not dom_query(dom_fold).has(None, {'title': lambda value: 'fw-uninspected' in (value or '')})
            )
            and 'hit-a' in firewall
        ),
    )

def run_processes_panel_fills_the_content_width_at_1440_px(page):
    check = page.check
    dom_procwidth = page.fixture('dom_procwidth')
    proc_width = (re.search('<pre id="proc-width"[^>]*>([^<]*)<', dom_procwidth) or [None, ''])[1]
    pw = re.match('panel=(\\d+) content=(\\d+) viewport=(\\d+)', proc_width)
    check(
        'Processes panel fills the content width at 1440 px',
        (
            pw is not None
            and pw.group(3) == '1440'
            and pw.group(1) == pw.group(2)
        ),
        proc_width,
    )

def run_drill_down_drawer_title(page):
    check = page.check
    dom_uninsp = page.fixture('dom_uninsp')
    check(
        'drill-down drawer title',
        (
            'Uninspected egress — last 24h' in dom_query(dom_uninsp).text
            or dom_query(dom_uninsp).has(None, {'title': lambda value: 'Uninspected egress — last 24h' in (value or '')})
        ),
    )

def run_drill_down_lists_endpoint_host(page):
    check = page.check
    dom_uninsp = page.fixture('dom_uninsp')
    check(
        'drill-down lists endpoint host',
        (
            (
                'registry.npmjs.org' in dom_query(dom_uninsp).text
                or dom_query(dom_uninsp).has(None, {'title': lambda value: 'registry.npmjs.org' in (value or '')})
            )
            and (
                'statsig.example.com' in dom_query(dom_uninsp).text
                or dom_query(dom_uninsp).has(None, {'title': lambda value: 'statsig.example.com' in (value or '')})
            )
        ),
    )

def run_drill_down_allow_action_delegated(page):
    check = page.check
    dom_uninsp = page.fixture('dom_uninsp')
    check(
        'drill-down allow action delegated',
        dom_query(dom_uninsp).has(None, {'data-action': 'allow-host', 'data-agent': 'cursor', 'data-host': 'registry.npmjs.org'}),
    )

def run_drill_down_explains_the_blind_spot(page):
    check = page.check
    dom_uninsp = page.fixture('dom_uninsp')
    check(
        'drill-down explains the blind spot',
        (
            'bypassing the inspection proxy' in dom_query(dom_uninsp).text
            or dom_query(dom_uninsp).has(None, {'title': lambda value: 'bypassing the inspection proxy' in (value or '')})
        ),
    )

def run_drill_down_vendor_disclosure_stays_open_across_an_allow_refill(page):
    check = page.check
    dom_keepopen = page.fixture('dom_keepopen')
    keepopen = (re.search('<pre id="keepopen"[^>]*>([^<]*)<', dom_keepopen) or [None, ''])[1]
    check(
        'drill-down vendor disclosure stays open across an Allow refill',
        'key=vendor:openclaw|Anthropic rebuilt=1 open=1' in keepopen,
        keepopen,
    )

def run_drill_down_allow_refill_posted_and_dropped_the_row(page):
    check = page.check
    dom_keepopen = page.fixture('dom_keepopen')
    keepopen = (re.search('<pre id="keepopen"[^>]*>([^<]*)<', dom_keepopen) or [None, ''])[1]
    check(
        'drill-down Allow refill posted and dropped the row',
        (
            (
                'POST /allowlist' in dom_query(dom_keepopen).text
                or dom_query(dom_keepopen).has(None, {'title': lambda value: 'POST /allowlist' in (value or '')})
            )
            and 'data-host="statsig.example.com"' not in dom_keepopen.split('id="drawer-body"', 1)[-1].split('</details>', 1)[0]
        ),
        keepopen,
    )

def run_incident_accessed_files_path_is_a_file_link(page):
    check = page.check
    dom_file = page.fixture('dom_file')
    check(
        'incident Accessed Files path is a file link',
        (
            dom_query(dom_file).has(None, {'id': 'file-link'})
            and (
                'rollout-2026-09-23T12-53-26-demo.jsonl' in dom_query(dom_file).text
                or dom_query(dom_file).has(None, {'title': lambda value: 'rollout-2026-09-23T12-53-26-demo.jsonl' in (value or '')})
            )
        ),
    )

def run_file_drawer_shows_the_masked_excerpt_never_an_unmasked_value(page):
    check = page.check
    dom_file = page.fixture('dom_file')
    check(
        'file drawer shows the masked excerpt, never an unmasked value',
        (
            (
                'Around the secret' in dom_query(dom_file).text
                or dom_query(dom_file).has(None, {'title': lambda value: 'Around the secret' in (value or '')})
            )
            and (
                '[REDACTED:fp1]' in dom_query(dom_file).text
                or dom_query(dom_file).has(None, {'title': lambda value: '[REDACTED:fp1]' in (value or '')})
            )
        ),
    )

def run_file_drawer_offers_reveal_in_finder_and_open_in_editor(page):
    check = page.check
    dom_file = page.fixture('dom_file')
    check(
        'file drawer offers Reveal in Finder and Open in editor',
        (
            dom_query(dom_file).has(None, {'data-action': 'file-reveal'})
            and dom_query(dom_file).has(None, {'data-action': 'file-open'})
        ),
    )

def run_file_drawer_lists_findings_agent_access_and_the_session(page):
    check = page.check
    dom_file = page.fixture('dom_file')
    check(
        'file drawer lists findings, agent access and the session',
        (
            (
                'Agent access' in dom_query(dom_file).text
                or dom_query(dom_file).has(None, {'title': lambda value: 'Agent access' in (value or '')})
            )
            and (
                'api-service@main' in dom_query(dom_file).text
                or dom_query(dom_file).has(None, {'title': lambda value: 'api-service@main' in (value or '')})
            )
            and dom_query(dom_file).has(None, {'data-action': 'open-incident'})
        ),
    )

def run_file_drawer_goes_back_to_the_incident_report(page):
    check = page.check
    dom_file = page.fixture('dom_file')
    check(
        'file drawer goes back to the incident report',
        (
            dom_query(dom_file).has(None, {'id': 'btn-drawer-back'})
            and (
                'Incident report' in dom_query(dom_file).text
                or dom_query(dom_file).has(None, {'title': lambda value: 'Incident report' in (value or '')})
            )
        ),
    )

def run_file_drawer_shows_the_advisor_plan_and_the_playbook(page):
    check = page.check
    dom_file = page.fixture('dom_file')
    check(
        'file drawer shows the advisor plan and the playbook',
        (
            (
                'What to do' in dom_query(dom_file).text
                or dom_query(dom_file).has(None, {'title': lambda value: 'What to do' in (value or '')})
            )
            and (
                'Codex printed an API key from an env dump.' in dom_query(dom_file).text
                or dom_query(dom_file).has(None, {'title': lambda value: 'Codex printed an API key from an env dump.' in (value or '')})
            )
            and (
                'Playbook: Secret in an agent transcript' in dom_query(dom_file).text
                or dom_query(dom_file).has(None, {'title': lambda value: 'Playbook: Secret in an agent transcript' in (value or '')})
            )
            and dom_query(dom_file).has(None, {'data-action-id': 'dismiss'})
        ),
    )

def run_finding_cards_offer_what_to_do(page):
    check = page.check
    dom_explain = page.fixture('dom_explain')
    check(
        'finding cards offer What to do',
        dom_query(dom_explain).has(None, {'data-action': 'open-plan', 'data-subject': 'flag:flag-2'}),
    )

def run_finding_cards_offer_mark_as_routine_not_ok(page):
    check = page.check
    dom_explain = page.fixture('dom_explain')
    check(
        'finding cards offer Mark as routine / not ok',
        dom_query(dom_explain).has(None, {'data-action': 'mark-label', 'data-subject': 'flag:flag-2', 'data-label': 'ok'}),
    )

def run_file_drawer_shows_the_operator_s_history_and_suggestion(page):
    check = page.check
    dom_file = page.fixture('dom_file')
    check(
        "file drawer shows the operator's history and suggestion",
        (
            (
                'Your history' in dom_query(dom_file).text
                or dom_query(dom_file).has(None, {'title': lambda value: 'Your history' in (value or '')})
            )
            and (
                'You marked similar cases 3 as routine.' in dom_query(dom_file).text
                or dom_query(dom_file).has(None, {'title': lambda value: 'You marked similar cases 3 as routine.' in (value or '')})
            )
            and (
                'You marked this 3 times as routine for codex.' in dom_query(dom_file).text
                or dom_query(dom_file).has(None, {'title': lambda value: 'You marked this 3 times as routine for codex.' in (value or '')})
            )
            and (
                'my own test key' in dom_query(dom_file).text
                or dom_query(dom_file).has(None, {'title': lambda value: 'my own test key' in (value or '')})
            )
        ),
    )

def run_menubar_deep_link_file_opens_the_file_drawer(page):
    check = page.check
    dom_filedeep = page.fixture('dom_filedeep')
    check(
        'menubar deep link #file= opens the file drawer',
        (
            dom_query(dom_filedeep).has(None, {'data-action': 'file-reveal'})
            and (
                'Around the secret' in dom_query(dom_filedeep).text
                or dom_query(dom_filedeep).has(None, {'title': lambda value: 'Around the secret' in (value or '')})
            )
        ),
    )

def run_endpoint_evidence_opens_a_detail_drawer(page):
    check = page.check
    dom_endpoint = page.fixture('dom_endpoint')
    check(
        'endpoint Evidence opens a detail drawer',
        (
            dom_query(dom_endpoint).has(None, {'id': 'drawer', 'class': 'drawer'})
            and (
                '2600:1901:0:9e23::' in dom_query(dom_endpoint).text
                or dom_query(dom_endpoint).has(None, {'title': lambda value: '2600:1901:0:9e23::' in (value or '')})
            )
        ),
    )

def run_endpoint_detail_names_the_owner_not_a_bare_address(page):
    check = page.check
    dom_endpoint = page.fixture('dom_endpoint')
    check(
        'endpoint detail names the owner, not a bare address',
        (
            'Google Cloud address' in dom_query(dom_endpoint).text
            or dom_query(dom_endpoint).has(None, {'title': lambda value: 'Google Cloud address' in (value or '')})
        ),
    )

def run_endpoint_detail_shows_which_agent_and_session_reached_it(page):
    check = page.check
    dom_endpoint = page.fixture('dom_endpoint')
    check(
        'endpoint detail shows which agent and session reached it',
        (
            (
                'Allow for claude' in dom_query(dom_endpoint).text
                or dom_query(dom_endpoint).has(None, {'title': lambda value: 'Allow for claude' in (value or '')})
            )
            and (
                'api-service@main' in dom_query(dom_endpoint).text
                or dom_query(dom_endpoint).has(None, {'title': lambda value: 'api-service@main' in (value or '')})
            )
        ),
    )

def run_endpoint_detail_lists_recent_connections(page):
    check = page.check
    dom_endpoint = page.fixture('dom_endpoint')
    check(
        'endpoint detail lists recent connections',
        (
            (
                'Recent connections' in dom_query(dom_endpoint).text
                or dom_query(dom_endpoint).has(None, {'title': lambda value: 'Recent connections' in (value or '')})
            )
            and (
                ':443' in dom_query(dom_endpoint).text
                or dom_query(dom_endpoint).has(None, {'title': lambda value: ':443' in (value or '')})
            )
        ),
    )

def run_notify_bell_present(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'notify bell present',
        dom_query(dom).has(None, {'id': 'btn-notify'}),
    )

def run_notify_popover_renders_rules(page):
    check = page.check
    dom_notify = page.fixture('dom_notify')
    check(
        'notify popover renders rules',
        (
            (
                'Keychain file access' in dom_query(dom_notify).text
                or dom_query(dom_notify).has(None, {'title': lambda value: 'Keychain file access' in (value or '')})
            )
            and dom_query(dom_notify).has(None, {'data-notify-rule': 'keychain-access'})
        ),
    )

def run_notify_override_pre_selected(page):
    check = page.check
    dom_notify = page.fixture('dom_notify')
    check(
        'notify override pre-selected (never)',
        (
            dom_query(dom_notify).has(None, {'data-notify-rule': 'keychain-access'})
            and 'value="never" selected' in dom_notify.split('data-notify-rule="keychain-access"')[1][:300]
        ),
    )

def run_notify_popover_lists_workspace_scopes(page):
    check = page.check
    dom_notify = page.fixture('dom_notify')
    check(
        'notify popover lists workspace scopes',
        (
            (
                'Per-workspace scopes' in dom_query(dom_notify).text
                or dom_query(dom_notify).has(None, {'title': lambda value: 'Per-workspace scopes' in (value or '')})
            )
            and dom_query(dom_notify).has(None, {'data-action': 'notify-scope-remove', 'data-rule': 'proxy-secret-leak', 'data-workspace': '/Users/dev/work/prod'})
        ),
    )

def run_notify_popover_offers_adding_a_workspace_scope(page):
    check = page.check
    dom_notify = page.fixture('dom_notify')
    check(
        'notify popover offers adding a workspace scope',
        (
            dom_query(dom_notify).has(None, {'id': 'notify-scope-path'})
            and dom_query(dom_notify).has(None, {'data-action': 'notify-scope-add'})
        ),
    )

def run_notify_add_scope_input_survives_a_reconcile_that_changes_notifycfg(page):
    check = page.check
    dom_notifyfocus = page.fixture('dom_notifyfocus')
    nfp = pre(dom_notifyfocus, 'notify-focus-probe')
    check(
        'notify add-scope input survives a reconcile that changes notifyCfg: same node, value and focus',
        nfp == 'same=true value=in-progress-edit focused=true probe=1',
        f'probe={nfp!r}',
    )

def run_delayed_spend_refresh_retains_totals_rows_and_plan_headroom_with_a_quiet_status(page):
    check = page.check
    dom = page.fixture('dom')
    dom_spendshape = page.fixture('dom_spendshape')

    def spend_card_of(d):
        card = dom_query(d).find(None, {'id': 'spend-card'})
        return card.inner_html if card else ''

    def health_notice(dom, report):
        match = re.search('<p class="report-health" data-reports="' + re.escape(report) + '"[^>]*>[^<]*</p>', dom)
        return match.group(0) if match else ''
    spend_health = health_notice(dom_spendshape, 'spend|spend card|spend plans')
    check(
        'delayed spend refresh retains totals, rows and plan headroom with a quiet status',
        (
            not spend_health
            and (
                'Refresh delayed · showing saved usage' in dom_query(dom_spendshape).text
                or dom_query(dom_spendshape).has(None, {'title': lambda value: 'Refresh delayed · showing saved usage' in (value or '')})
            )
            and 'id="count-spend">$36.67<' in dom_spendshape
            and 'api-service' in spend_card_of(dom_spendshape)
            and 'shape-plan' in spend_card_of(dom_spendshape)
        ),
    )

def run_first_load_malformed_spend_reports_retry_quietly_without_inventing_empty_results(page):
    check = page.check
    dom = page.fixture('dom')
    dom_spendshapefirst = page.fixture('dom_spendshapefirst')

    def spend_card_of(d):
        card = dom_query(d).find(None, {'id': 'spend-card'})
        return card.inner_html if card else ''

    def health_notice(dom, report):
        match = re.search('<p class="report-health" data-reports="' + re.escape(report) + '"[^>]*>[^<]*</p>', dom)
        return match.group(0) if match else ''
    first_spend = health_notice(dom_spendshapefirst, 'spend|spend card|spend plans')
    check(
        'first-load malformed spend reports retry quietly without inventing empty results',
        (
            not first_spend
            and (
                'Usage is taking longer to load · retrying…' in dom_query(dom_spendshapefirst).text
                or dom_query(dom_spendshapefirst).has(None, {'title': lambda value: 'Usage is taking longer to load · retrying…' in (value or '')})
            )
            and 'Refreshing usage…' in spend_card_of(dom_spendshapefirst)
            and 'No model calls' not in spend_card_of(dom_spendshapefirst)
            and 'id="count-agents">3<' in dom_spendshapefirst
        ),
    )

def run_valid_spend_recovery_clears_the_delayed_refresh_status(page):
    check = page.check
    dom_spendshaperecover = page.fixture('dom_spendshaperecover')
    check(
        'valid spend recovery clears the delayed refresh status',
        (
            'Refresh delayed' in pre(dom_spendshaperecover, 'spend-shape-before-recovery')
            and dom_query(dom_spendshaperecover).has(None, {'id': 'spend-cache', 'class': 'spend-cache', 'role': 'status', 'hidden': ''})
            and 'id="count-spend">$36.67<' in dom_spendshaperecover
        ),
    )

def run_malformed_containers_retain_prior_results_with_a_stale_warning(page):
    check = page.check
    dom = page.fixture('dom')
    dom_slowshape = page.fixture('dom_slowshape')
    dom_slowshapefirst = page.fixture('dom_slowshapefirst')
    dom_slowshaperecover = page.fixture('dom_slowshaperecover')

    def health_notice(dom, report):
        match = re.search('<p class="report-health" data-reports="' + re.escape(report) + '"[^>]*>[^<]*</p>', dom)
        return match.group(0) if match else ''
    for report in ('resources', 'audit', 'notification rules', 'recurring egress'):
        check(
            f'malformed {report} containers retain prior results with a stale warning',
            (
                'Stale' in health_notice(dom_slowshape, report)
                and 'Invalid response' in health_notice(dom_slowshape, report)
                and 'hidden' not in health_notice(dom_slowshape, report)
            ),
        )
        check(
            f'first-load malformed {report} containers show unavailable',
            (
                'Unavailable' in health_notice(dom_slowshapefirst, report)
                and 'Invalid response' in health_notice(dom_slowshapefirst, report)
            ),
        )
        check(
            f'valid {report} recovery clears malformed-response warning',
            (
                'Stale' in pre(dom_slowshaperecover, 'slow-shape-before-recovery')
                and 'hidden' in health_notice(dom_slowshaperecover, report)
            ),
        )

def run_malformed_slow_reports_preserve_resource_rendering_and_healthy_live_telemetry(page):
    check = page.check
    dom_slowshape = page.fixture('dom_slowshape')
    slow_board = dom_slowshape.split('id="resource-board"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'malformed slow reports preserve resource rendering and healthy live telemetry',
        (
            'id="count-agents">3<' in dom_slowshape
            and 'Families by harness' in slow_board
            and 'api-service' in slow_board
            and (
                'Disconnected' not in dom_query(dom_slowshape).text
                and not dom_query(dom_slowshape).has(None, {'title': lambda value: 'Disconnected' in (value or '')})
            )
        ),
    )

def run_resource_request_failure_preserves_data_with_a_persistent_stale_notice(page):
    check = page.check
    dom = page.fixture('dom')
    dom_health = page.fixture('dom_health')

    def health_notice(dom, report):
        match = re.search('<p class="report-health" data-reports="' + re.escape(report) + '"[^>]*>[^<]*</p>', dom)
        return match.group(0) if match else ''
    resource_health = health_notice(dom_health, 'resources')
    check(
        'resource request failure preserves data with a persistent stale notice',
        (
            'Stale' in resource_health
            and 'last refreshed at' in resource_health
            and 'hidden' not in resource_health
            and 'id="count-agents">3<' in dom_health
            and (
                '4.0 GB available of 16.0 GB' in dom_query(dom_health).text
                or dom_query(dom_health).has(None, {'title': lambda value: '4.0 GB available of 16.0 GB' in (value or '')})
            )
        ),
    )

def run_first_load_audit_failure_is_explicitly_unavailable(page):
    check = page.check
    dom = page.fixture('dom')
    dom_health = page.fixture('dom_health')

    def health_notice(dom, report):
        match = re.search('<p class="report-health" data-reports="' + re.escape(report) + '"[^>]*>[^<]*</p>', dom)
        return match.group(0) if match else ''
    audit_health = health_notice(dom_health, 'audit')
    check(
        'first-load audit failure is explicitly unavailable',
        (
            'Unavailable' in audit_health
            and 'HTTP 503' in audit_health
            and 'hidden' not in audit_health
        ),
    )

def run_unreadable_guard_response_shows_stale_decisions_despite_a_healthy_snapshot(page):
    check = page.check
    dom_health = page.fixture('dom_health')
    check(
        'unreadable guard response shows stale decisions despite a healthy snapshot',
        (
            (
                'Guard decisions: Stale' in dom_query(dom_health).text
                or dom_query(dom_health).has(None, {'title': lambda value: 'Guard decisions: Stale' in (value or '')})
            )
            and (
                'response unreadable' in dom_query(dom_health).text
                or dom_query(dom_health).has(None, {'title': lambda value: 'response unreadable' in (value or '')})
            )
            and (
                'Disconnected' not in dom_query(dom_health).text
                and not dom_query(dom_health).has(None, {'title': lambda value: 'Disconnected' in (value or '')})
            )
        ),
    )

def run_successful_recovery_clears_stale_and_unavailable_notices(page):
    check = page.check
    dom = page.fixture('dom')
    dom_healthrecover = page.fixture('dom_healthrecover')

    def health_notice(dom, report):
        match = re.search('<p class="report-health" data-reports="' + re.escape(report) + '"[^>]*>[^<]*</p>', dom)
        return match.group(0) if match else ''
    check(
        'successful recovery clears stale and unavailable notices',
        (
            'Stale' in pre(dom_healthrecover, 'health-before-recovery')
            and 'Unavailable' in pre(dom_healthrecover, 'health-before-recovery')
            and 'hidden' in health_notice(dom_healthrecover, 'resources')
            and 'hidden' in health_notice(dom_healthrecover, 'audit')
            and 'Stale' not in health_notice(dom_healthrecover, 'resources')
        ),
    )

def run_failed_filtered_refresh_preserves_matching_rows_and_warns_stale(page):
    check = page.check
    dom = page.fixture('dom')
    dom_historyevents = page.fixture('dom_historyevents')
    dom_historyeventschanged = page.fixture('dom_historyeventschanged')
    dom_historyflags = page.fixture('dom_historyflags')
    dom_historyflagschanged = page.fixture('dom_historyflagschanged')

    def health_notice(dom, report):
        match = re.search('<p class="report-health" data-reports="' + re.escape(report) + '"[^>]*>[^<]*</p>', dom)
        return match.group(0) if match else ''

    def history_content(dom, flags):
        anchor = 'id="flags-list"' if flags else 'id="events-container"'
        return dom.split(anchor, 1)[1].split('</section>', 1)[0]
    for flags, retained, changed in ((True, dom_historyflags, dom_historyflagschanged), (False, dom_historyevents, dom_historyeventschanged)):
        name = 'findings' if flags else 'events'
        marker = 'history-filtered-match' if flags else 'Filtered-history match'
        keys = 'snapshot|flags' if flags else 'snapshot|events'
        check(
            f'failed filtered {name} refresh preserves matching rows and warns stale',
            (
                marker in history_content(retained, flags)
                and 'history-broad-only' not in history_content(retained, flags)
                and 'Broad-only history row' not in history_content(retained, flags)
                and 'Stale' in health_notice(retained, keys)
            ),
        )
        check(
            f'changed {name} filters show unavailable results without leaking old or live rows',
            (
                marker not in history_content(changed, flags)
                and 'history-broad-only' not in history_content(changed, flags)
                and 'Broad-only history row' not in history_content(changed, flags)
                and 'not loaded yet' in history_content(changed, flags)
                and 'Unavailable' in health_notice(changed, keys)
            ),
        )

def run_empty_filtered_findings_recover_successfully_and_clear_the_stale_warning(page):
    check = page.check
    dom = page.fixture('dom')
    dom_historyrecover = page.fixture('dom_historyrecover')

    def health_notice(dom, report):
        match = re.search('<p class="report-health" data-reports="' + re.escape(report) + '"[^>]*>[^<]*</p>', dom)
        return match.group(0) if match else ''

    def history_content(dom, flags):
        anchor = 'id="flags-list"' if flags else 'id="events-container"'
        return dom.split(anchor, 1)[1].split('</section>', 1)[0]
    check(
        'empty filtered findings recover successfully and clear the stale warning',
        (
            'Stale' in pre(dom_historyrecover, 'history-before-recovery')
            and 'No flags match the current filter' in history_content(dom_historyrecover, True)
            and 'hidden' in health_notice(dom_historyrecover, 'snapshot|flags')
        ),
    )

def run_malformed_snapshot_and_guard_containers_retain_last_good_metrics_with_persistent_warnings(page):
    check = page.check
    dom = page.fixture('dom')
    dom_malformed = page.fixture('dom_malformed')

    def health_notice(dom, report):
        match = re.search('<p class="report-health" data-reports="' + re.escape(report) + '"[^>]*>[^<]*</p>', dom)
        return match.group(0) if match else ''
    hot_health = health_notice(dom_malformed, 'snapshot|guard decisions')
    check(
        'malformed snapshot and guard containers retain last-good metrics with persistent warnings',
        (
            pre(dom_malformed, 'malformed-returned') == 'yes'
            and 'id="count-agents">3<' in dom_malformed
            and 'Live telemetry:' not in hot_health
            and 'Guard decisions: Unavailable' in hot_health
            and 'Invalid response' in hot_health
            and 'hidden' not in hot_health
            and (
                'The daemon returned invalid telemetry' in dom_query(dom_malformed).text
                or dom_query(dom_malformed).has(None, {'title': lambda value: 'The daemon returned invalid telemetry' in (value or '')})
            )
            and 'id="status-text">Telemetry unavailable<' in dom_malformed
        ),
    )

def run_a_failed_snapshot_retains_critical_posture_with_a_visible_freshness_warning_and_retry(page):
    check = page.check
    dom_malformed = page.fixture('dom_malformed')
    retained_decisions = json.loads(html.unescape(pre(dom_malformed, 'fixture-posture')))['needs_you']
    check(
        'a failed snapshot retains critical posture with a visible freshness warning and Retry',
        (
            dom_query(dom_malformed).has(None, {'id': 'posture-banner', 'data-state': 'critical'})
            and (
                'Status stale — last complete telemetry' in dom_query(dom_malformed).text
                or dom_query(dom_malformed).has(None, {'title': lambda value: 'Status stale — last complete telemetry' in (value or '')})
            )
            and pre(dom_malformed, 'posture-visibility') == 'health=true retry=true'
            and f'id="tabs-posture-text">{retained_decisions} need you · refresh failed<' in dom_malformed
            and not dom_query(dom_malformed).has(None, {'id': 'posture-retry', 'hidden': ''})
        ),
    )

def run_snapshot_failure_is_not_repeated_in_panels_while_the_independent_guard_failure_remains_visible(page):
    check = page.check
    dom = page.fixture('dom')
    dom_malformed = page.fixture('dom_malformed')

    def health_notice(dom, report):
        match = re.search('<p class="report-health" data-reports="' + re.escape(report) + '"[^>]*>[^<]*</p>', dom)
        return match.group(0) if match else ''
    hot_health = health_notice(dom_malformed, 'snapshot|guard decisions')
    check(
        'snapshot failure is not repeated in panels while the independent guard failure remains visible',
        (
            dom_malformed.count('Status stale — last complete telemetry') == 1
            and all(('Live telemetry:' not in node.inner_html for node in dom_query(dom_malformed).find_all(None, {'class': 'report-health'})))
            and all(('hidden' in node.attrs for node in dom_query(dom_malformed).find_all(None, {'data-reports': 'snapshot'})))
            and 'Guard decisions: Unavailable' in hot_health
        ),
    )

def run_snapshot_recovery_clears_the_primary_freshness_warning_and_retry(page):
    check = page.check
    dom_malformed = page.fixture('dom_malformed')
    dom_malformedrecover = page.fixture('dom_malformedrecover')
    retained_decisions = json.loads(html.unescape(pre(dom_malformed, 'fixture-posture')))['needs_you']
    check(
        'snapshot recovery clears the primary freshness warning and Retry',
        (
            dom_query(dom_malformedrecover).has(None, {'id': 'posture-health', 'hidden': ''})
            and pre(dom_malformedrecover, 'posture-visibility') == 'health=false retry=false'
            and dom_query(dom_malformedrecover).has(None, {'id': 'posture-retry', 'hidden': ''})
            and f'id="tabs-posture-text">{retained_decisions} need you<' in dom_malformedrecover
        ),
    )

def run_valid_hot_responses_recover_from_malformed_containers(page):
    check = page.check
    dom = page.fixture('dom')
    dom_malformedrecover = page.fixture('dom_malformedrecover')

    def health_notice(dom, report):
        match = re.search('<p class="report-health" data-reports="' + re.escape(report) + '"[^>]*>[^<]*</p>', dom)
        return match.group(0) if match else ''
    hot_recovered = health_notice(dom_malformedrecover, 'snapshot|guard decisions')
    check(
        'valid hot responses recover from malformed containers',
        (
            pre(dom_malformedrecover, 'malformed-before-recovery').startswith('3 ')
            and 'Status stale — last complete telemetry' in pre(dom_malformedrecover, 'malformed-before-recovery')
            and 'id="count-agents">3<' in dom_malformedrecover
            and 'hidden' in hot_recovered
            and 'Invalid response' not in hot_recovered
        ),
    )

def run_a_delayed_older_snapshot_cannot_replace_a_newer_manual_refresh(page):
    check = page.check
    dom_refreshrace = page.fixture('dom_refreshrace')
    check(
        'a delayed older snapshot cannot replace a newer manual refresh',
        (
            '<pre id="race-old-returned" hidden="">yes</pre>' in dom_refreshrace
            and 'id="count-agents">3<' in dom_refreshrace
        ),
    )

def run_auth_expired_shows_the_ended_state_not_daemon_down(page):
    check = page.check
    dom_authfail = page.fixture('dom_authfail')
    check(
        "auth-expired shows the ended state, not 'daemon down'",
        (
            re.search('<section[^>]*id="session-ended"[^>]*>', dom_authfail) is not None
            and (
                'Reconnect this console' in dom_query(dom_authfail).text
                or dom_query(dom_authfail).has(None, {'title': lambda value: 'Reconnect this console' in (value or '')})
            )
            and dom_query(dom_authfail).has(None, {'href': 'secure-agent://console/reconnect'})
            and 'Can&#x27;t reach the Secure Agent daemon' not in dom_authfail.split('id="session-ended"', 1)[1].split('</section>', 1)[0]
        ),
    )

def run_a_403_hides_the_posture_counts_and_panels_and_closes_the_stream(page):
    check = page.check
    dom_authfail = page.fixture('dom_authfail')
    check(
        'a 403 hides the posture, counts and panels and closes the stream',
        (
            dom_query(dom_authfail).has(None, {'class': 'is-ended'})
            and re.search('<section class="posture" id="posture-banner"[^>]*\\bhidden\\b', dom_authfail) is not None
            and re.search('<main[^>]*\\bhidden\\b', dom_authfail) is not None
            and '<pre id="sse-state" hidden="">closed</pre>' in dom_authfail
        ),
        (re.search('<pre id="sse-state"[^>]*>[^<]*</pre>', dom_authfail) or [None])[0],
    )

def run_endpoint_403_ends_the_console_even_when_snapshot_succeeds(page):
    check = page.check
    dom_authmixed = page.fixture('dom_authmixed')
    dom_spendauth = page.fixture('dom_spendauth')
    for label, expired in (('guard', dom_authmixed), ('spend', dom_spendauth)):
        check(
            f'{label} endpoint 403 ends the console even when snapshot succeeds',
            (
                dom_query(expired).has(None, {'class': 'is-ended'})
                and re.search('<main[^>]*\\bhidden\\b', expired) is not None
                and '<pre id="sse-state" hidden="">closed</pre>' in expired
            ),
        )

def run_no_token_at_load(page):
    check = page.check
    dom_notoken = page.fixture('dom_notoken')
    nt_fetches = (re.search('<pre id="fetch-count"[^>]*>(\\d+)</pre>', dom_notoken) or [None, 'missing'])[1]
    check(
        'no token at load: only the ended state, no posture, zero fetches, no stream',
        (
            re.search('<section[^>]*id="session-ended"[^>]*>', dom_notoken) is not None
            and re.search('<section class="posture" id="posture-banner"[^>]*\\bhidden\\b', dom_notoken) is not None
            and re.search('<section class="statstrip"[^>]*\\bhidden\\b', dom_notoken) is not None
            and nt_fetches == '0'
            and not dom_query(dom_notoken).has(None, {'id': 'sse-state'})
        ),
        f'fetches={nt_fetches}',
    )

def run_a_token_at_load(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'a token at load: the console renders, the ended state stays hidden',
        (
            re.search('<section[^>]*id="session-ended"[^>]*\\bhidden\\b', dom) is not None
            and 'id="count-agents">3<' in dom
        ),
    )

def run_unreachable_shows_the_retry_banner(page):
    check = page.check
    dom_netfail = page.fixture('dom_netfail')
    check(
        'unreachable shows the retry banner',
        (
            (
                'Waiting for Secure Agent. No live data received' in dom_query(dom_netfail).text
                or dom_query(dom_netfail).has(None, {'title': lambda value: 'Waiting for Secure Agent. No live data received' in (value or '')})
            )
            and dom_query(dom_netfail).has(None, {'id': 'btn-retry-connection'})
        ),
    )

def run_unreachable_sets_disconnected_chip(page):
    check = page.check
    dom_netfail = page.fixture('dom_netfail')
    check(
        'unreachable sets Disconnected chip',
        'id="status-text">Disconnected<' in dom_netfail,
    )

def run_unavailable_first_telemetry_cannot_show_a_green_primary_status(page):
    check = page.check
    dom_netfail = page.fixture('dom_netfail')
    check(
        'unavailable first telemetry cannot show a green primary status',
        (
            dom_query(dom_netfail).has(None, {'id': 'posture-banner', 'data-state': 'unknown'})
            and 'id="posture-state">Telemetry unavailable<' in dom_netfail
            and 'id="tabs-posture-text">Telemetry unavailable<' in dom_netfail
            and (
                'No complete telemetry snapshot has loaded' in dom_query(dom_netfail).text
                or dom_query(dom_netfail).has(None, {'title': lambda value: 'No complete telemetry snapshot has loaded' in (value or '')})
            )
        ),
    )

def run_token_survives_reload_via_sessionstorage(page):
    check = page.check
    dom_tokenseed = page.fixture('dom_tokenseed')
    check(
        'token survives reload via sessionStorage (no #ct fragment)',
        (
            'id="count-agents">3<' in dom_tokenseed
            and 'id="offline-banner" hidden' in dom_tokenseed
        ),
    )

def run_fleet_card_renders_the_local_node_object(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'fleet card renders the local node object',
        (
            (
                'ci-runner-02' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: 'ci-runner-02' in (value or '')})
            )
            and (
                'darwin/arm64' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: 'darwin/arm64' in (value or '')})
            )
        ),
    )

def run_fleet_panel_visible_when_a_collector_is_configured(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'fleet panel visible when a collector is configured',
        dom_query(dom).has(None, {'id': 'fleet-panel'}),
    )

def run_fleet_panel_hides_when_no_collector_is_configured(page):
    check = page.check
    dom_nofleet = page.fixture('dom_nofleet')
    check(
        'fleet panel hides when no collector is configured',
        (
            dom_query(dom_nofleet).has(None, {'id': 'fleet-panel', 'style': 'display: none;'})
            and (
                'ci-runner-02' not in dom_query(dom_nofleet).text
                and not dom_query(dom_nofleet).has(None, {'title': lambda value: 'ci-runner-02' in (value or '')})
            )
        ),
    )

def run_panels_after_fleet_still_render(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'panels after fleet still render (crash isolation)',
        (
            len([k for k in log_rows(dom) if k.startswith('flag:')]) == 3
            and len(dom_query(dom).find_all(None, {'class': 'timeline-item'})) > 0
            and len(dom_query(dom).find_all(None, {'class': 'audit-item'})) == 2
        ),
    )

def run_tab_bar_renders_five_tabs_with_protection_grouping_and_agent_last(page):
    check = page.check
    dom = page.fixture('dom')
    tab_ids = re.findall('class="tab-btn[^"]*" data-tab="(\\w+)"', dom)
    tab_labels = re.findall('data-tab="\\w+" role="tab"[^>]*>\\s*<svg[^>]*>.*?</svg><span>([^<]+)</span>', dom, re.S)
    check(
        'tab bar renders five tabs with Protection grouping and Agent last',
        (
            len(dom_query(dom).find_all(None, {'class': 'tab-btn'})) == 5
            and tab_ids == ['home', 'sessions', 'protection', 'system', 'agent']
            and tab_labels == ['Home', 'Sessions', 'Protection', 'System', 'Agent']
        ),
        f'ids={tab_ids} labels={tab_labels}',
    )

def run_the_attention_panel_lives_in_home_first(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'the attention panel lives in Home, first',
        dom.index('id="tab-home"') < dom.index('id="attention-center"') < dom.index('id="spend-card"') < dom.index('id="home-findings"') < dom.index('id="home-trends"') < dom.index('id="tab-sessions"'),
    )

def run_home_tab_active_by_default(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'home tab active by default',
        dom_query(dom).has(None, {'class': 'tab-btn active', 'data-tab': 'home'}),
    )

def run_non_active_panels_hidden(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'non-active panels hidden',
        (
            'id="tab-sessions" role="tabpanel" hidden' in dom
            and 'id="tab-egress" role="tabpanel" hidden' in dom
            and 'id="tab-system" role="tabpanel" hidden' in dom
            and 'id="tab-policy" role="tabpanel" hidden' in dom
        ),
    )

def run_home_panel_visible(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'home panel visible',
        dom_query(dom).has(None, {'id': 'tab-home', 'role': 'tabpanel'}),
    )

def run_home_opens_usage_by_default_and_keeps_findings_and_trends_closed(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'Home opens Usage by default and keeps Findings and Trends closed',
        (
            dom_query(dom).has('details', {'class': 'home-group', 'id': 'home-spend', 'data-group': 'spend', 'open': ''})
            and dom_query(dom).has('details', {'class': 'home-group', 'id': 'home-findings', 'data-group': 'findings'})
            and dom_query(dom).has('details', {'class': 'home-group', 'id': 'home-trends', 'data-group': 'trends'})
            and not dom_query(dom).has('details', {'id': 'home-findings', 'open': ''})
            and not dom_query(dom).has('details', {'id': 'home-trends', 'open': ''})
        ),
    )

def run_hash_agents_opens_sessions_on_the_processes_sub_view(page):
    check = page.check
    dom_hashagents = page.fixture('dom_hashagents')
    check(
        'hash #agents opens Sessions on the Processes sub-view',
        (
            dom_query(dom_hashagents).has(None, {'class': 'tab-btn active', 'data-tab': 'sessions'})
            and dom_query(dom_hashagents).has(None, {'class': 'subtab-btn active', 'data-subtab': 'processes'})
            and dom_query(dom_hashagents).has(None, {'id': 'sub-processes', 'role': 'tabpanel'})
            and 'id="sub-board" role="tabpanel" hidden' in dom_hashagents
            and dom_query(dom_hashagents).has(None, {'id': 'tab-sessions', 'role': 'tabpanel'})
        ),
    )

def run_hash_opens_the_system_tab(page):
    check = page.check
    dom_hashsessionswt = page.fixture('dom_hashsessionswt')
    dom_hashworktrees = page.fixture('dom_hashworktrees')
    for old_hash, dom_old in (('#sessions/worktrees', dom_hashsessionswt), ('#worktrees', dom_hashworktrees)):
        check(
            f'hash {old_hash} opens the System tab',
            (
                dom_query(dom_old).has(None, {'class': 'tab-btn active', 'data-tab': 'system'})
                and dom_query(dom_old).has(None, {'id': 'tab-system', 'role': 'tabpanel'})
                and 'id="tab-sessions" role="tabpanel" hidden' in dom_old
                and dom_query(dom_old).has(None, {'data-system-subtab': 'worktrees', 'aria-selected': 'true'})
                and dom_query(dom_old).has(None, {'id': 'system-clutter', 'hidden': ''})
                and dom_query(dom_old).has(None, {'id': 'sub-resources', 'hidden': ''})
            ),
        )

def run_hash_findings_opens_home(page):
    check = page.check
    dom_hashfindings = page.fixture('dom_hashfindings')
    check(
        'hash #findings opens Home',
        (
            dom_query(dom_hashfindings).has(None, {'class': 'tab-btn active', 'data-tab': 'home'})
            and dom_query(dom_hashfindings).has(None, {'id': 'tab-home', 'role': 'tabpanel'})
        ),
    )

def run_trends_closed(page):
    check = page.check
    dom_trends = page.fixture('dom_trends')
    trends = (re.search('<pre id="trends-probe"[^>]*>(.*?)</pre>', dom_trends, re.S) or [None, ''])[1]
    tm = re.match('closed\\(open=false\\):activity=(\\d+),chart-flags=(\\d+),chart-memory=(\\d+) \\| opened:activity=(\\d+),chart-flags=(\\d+),chart-memory=(\\d+)$', trends)
    check(
        'Trends charts render only when opened; Memory stays hidden in System Resources',
        (
            tm is not None
            and tm.group(1, 2, 3) == ('0', '0', '0')
            and all((int(x) >= 1 for x in tm.group(4, 5)))
            and tm.group(6) == '0'
        ),
        f'probe={trends!r}',
    )

def run_hidden_panels(page):
    check = page.check
    dom_csp = page.fixture('dom_csp')
    dom_hiddenrender = page.fixture('dom_hiddenrender')
    csp_widths = (re.search('data-csp-widths="([^"]*)"', dom_csp) or [None, ''])[1]
    widths = {k: float(v) for k, v in (kv.split(':') for kv in csp_widths.split(',') if kv)}
    hrp = (re.search('<pre id="hidden-render-probe"[^>]*>(.*?)</pre>', dom_hiddenrender, re.S) or [None, ''])[1]
    hrp_stages = dict(re.findall('(boot|refresh|search|shown):((?:[a-z-]+=\\d+,?)+)', hrp))

    def hrp_zero(stage):
        counts = dict(re.findall('([a-z-]+)=(\\d+)', hrp_stages.get(stage, '')))
        return len(counts) == 4 and all((v == '0' for v in counts.values()))

    def hrp_shown():
        counts = dict(re.findall('([a-z-]+)=(\\d+)', hrp_stages.get('shown', '')))
        return len(counts) == 4 and all((int(v) >= 1 for v in counts.values()))
    check(
        'hidden panels (Trends charts, System/Resources) render 0 times across boot, Refresh and search, then render once shown',
        (
            hrp_zero('boot')
            and hrp_zero('refresh')
            and hrp_zero('search')
            and hrp_shown()
        ),
        f'probe={hrp!r}',
    )

def run_forget_deletes_the_expected_pattern_and_the_list_reloads_without_it(page):
    check = page.check
    dom_forget = page.fixture('dom_forget')
    forget_reqs = pre(dom_forget, 'mock-requests')
    check(
        'Forget deletes the expected pattern and the list reloads without it',
        (
            'DELETE /expected?key=claude%7Cgh%7C%2FUsers%2Fdev%2F.config%2Fgh%2Fhosts.yml%7CGitHub' in forget_reqs
            and 'id="badge-expected">0<' in dom_forget
            and (
                'No expected secret reads.' in dom_query(dom_forget).text
                or dom_query(dom_forget).has(None, {'title': lambda value: 'No expected secret reads.' in (value or '')})
            )
        ),
        f'requests={forget_reqs!r}',
    )

def run_resource_mission_control_is_present(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'resource mission control is present',
        dom_query(dom).has(None, {'id': 'resource-mission-control'}),
    )

def run_whole_machine_headroom_is_visible(page):
    check = page.check
    dom = page.fixture('dom')
    resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'whole-machine headroom is visible',
        (
            'Machine headroom' in resource_view
            and '25 / 100' in resource_view
            and '4.0 GB available' in resource_view
        ),
    )

def run_headroom_hint_explains_the_score_is_the_tightest_limit(page):
    check = page.check
    dom = page.fixture('dom')
    resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'headroom hint explains the score is the tightest limit',
        (
            dom_query(resource_view).has(None, {'class': 'headroom-hint'})
            and dom_query(resource_view).has(None, {'aria-label': 'What machine headroom means'})
            and 'tightest limit, not free RAM' in resource_view
            and 'Under 15 is critical' in resource_view
        ),
    )

def run_headroom_hint_fits_its_panel_at_desktop_and_phone_widths(page):
    check = page.check
    dom_headroomphone = page.fixture('dom_headroomphone')
    dom_headroomwide = page.fixture('dom_headroomwide')
    phone_headroom = re.search('data-headroom="(\\d+):true"', dom_headroomphone)
    check(
        'headroom hint fits its panel at desktop and phone widths',
        (
            dom_query(dom_headroomwide).has(None, {'data-inside': 'true'})
            and dom_query(dom_headroomwide).has(None, {'data-width': '380'})
            and phone_headroom is not None
            and 250 <= int(phone_headroom.group(1)) <= 320
            and dom_query(dom_headroomphone).has(None, {'data-hscroll': 'sessions:0,agents:0,resources:0'})
        ),
    )

def run_live_resources_exclude_the_flight_recorder(page):
    check = page.check
    dom = page.fixture('dom')
    resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'live resources exclude the flight recorder',
        'Pressure flight recorder' not in resource_view,
    )

def run_whole_machine_cpu_swap_and_thermal_context_are_visible(page):
    check = page.check
    dom = page.fixture('dom')
    resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'whole-machine CPU swap and thermal context are visible',
        (
            '75.0% total' in resource_view
            and '58.4% other' in resource_view
            and '2.0 GB / 8.0 GB' in resource_view
            and 'Nominal' in resource_view
        ),
    )

def run_high_impact_session_shows_cpu_and_memory(page):
    check = page.check
    dom = page.fixture('dom')
    resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'high-impact session shows CPU and memory',
        (
            '132.5%' in resource_view
            and '5.5 GB' in resource_view
        ),
    )

def run_resource_diagnosis_explains_the_pressure(page):
    check = page.check
    dom = page.fixture('dom')
    resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'resource diagnosis explains the pressure',
        'Memory grew 1.4 GB in 15 minutes.' in resource_view,
    )

def run_resource_flight_recorder_preserves_exited_sessions(page):
    check = page.check
    dom = page.fixture('dom')
    history_view = dom.split('id="history-panel"', 1)[1].split('id="sub-events"', 1)[0]
    check(
        'resource flight recorder preserves exited sessions',
        (
            'Pressure flight recorder' in history_view
            and 'data-pipeline' in history_view
        ),
    )

def run_resource_flight_recorder_remains_visible_with_no_live_sessions(page):
    check = page.check
    dom_noresources = page.fixture('dom_noresources')
    check(
        'resource flight recorder remains visible with no live sessions',
        (
            (
                'No attributed agent resource use right now' in dom_query(dom_noresources).text
                or dom_query(dom_noresources).has(None, {'title': lambda value: 'No attributed agent resource use right now' in (value or '')})
            )
            and (
                'Pressure flight recorder' in dom_query(dom_noresources).text
                or dom_query(dom_noresources).has(None, {'title': lambda value: 'Pressure flight recorder' in (value or '')})
            )
            and (
                'data-pipeline' in dom_query(dom_noresources).text
                or dom_query(dom_noresources).has(None, {'title': lambda value: 'data-pipeline' in (value or '')})
            )
        ),
    )

def run_resource_flight_recorder_identifies_the_dominant_process(page):
    check = page.check
    dom = page.fixture('dom')
    history_view = dom.split('id="history-panel"', 1)[1].split('id="sub-events"', 1)[0]
    check(
        'resource flight recorder identifies the dominant process',
        (
            'PID 4419' in history_view
            and '79%' in history_view
            and 'One child process dominated session memory.' in history_view
        ),
    )

def run_resource_pressure_episode_explains_correlated_activity(page):
    check = page.check
    dom = page.fixture('dom')
    history_view = dom.split('id="history-panel"', 1)[1].split('id="sub-events"', 1)[0]
    check(
        'resource pressure episode explains correlated activity',
        (
            'Memory rose 3.0 GiB in 10m while node started.' in history_view
            and 'Observed correlation' in history_view
        ),
    )

def run_pressure_episode_preserves_captured_machine_context(page):
    check = page.check
    dom = page.fixture('dom')
    history_view = dom.split('id="history-panel"', 1)[1].split('id="sub-events"', 1)[0]
    check(
        'pressure episode preserves captured machine context',
        (
            'Host at capture' in history_view
            and '1.0 GB available' in history_view
            and 'Critical pressure' in history_view
            and 'Serious thermal' in history_view
        ),
    )

def run_resource_pressure_chart_includes_activity_markers(page):
    check = page.check
    dom = page.fixture('dom')
    history_view = dom.split('id="history-panel"', 1)[1].split('id="sub-events"', 1)[0]
    check(
        'resource pressure chart includes activity markers',
        (
            dom_query(history_view).has(None, {'class': 'resource-activity-marker'})
            and 'Bash tool ran' in history_view
            and 'connected to api.openai.com:443' in history_view
        ),
    )

def run_historical_resource_evidence_stays_scoped_to_its_captured_lifetime(page):
    check = page.check
    dom = page.fixture('dom')
    history_view = dom.split('id="history-panel"', 1)[1].split('id="sub-events"', 1)[0]
    check(
        'historical resource evidence stays scoped to its captured lifetime',
        (
            'Scoped to this captured process lifetime' in history_view
            and not dom_query(history_view).has(None, {'data-action': 'filter-pids', 'data-pids': '4412,4419,4420'})
        ),
    )

def run_resource_trend_svg_is_rendered(page):
    check = page.check
    dom = page.fixture('dom')
    resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'resource trend SVG is rendered',
        (
            dom_query(resource_view).has(None, {'class': 'resource-spark'})
            and dom_query(resource_view).has(None, {'points': None})
        ),
    )

def run_resource_action_opens_the_family_in_place(page):
    check = page.check
    dom = page.fixture('dom')
    resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'resource action opens the family in place',
        (
            dom_query(resource_view).has(None, {'data-action': 'view-family', 'data-key': '5821:1789480800000000000'})
            and not dom_query(resource_view).has(None, {'data-action': 'filter-pids'})
        ),
    )

def run_resource_policy_mode_and_grace_are_visible(page):
    check = page.check
    dom = page.fixture('dom')
    resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'resource policy mode and grace are visible',
        (
            'prompt</b> machine policy' in resource_view
            and '30s grace' in resource_view
        ),
    )

def run_resource_policy_source_is_visible_on_sessions(page):
    check = page.check
    dom = page.fixture('dom')
    resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'resource policy source is visible on sessions',
        'workspace policy · /Users/dev/workspace' in resource_view,
    )

def run_resource_policy_editor_opens_with_the_active_document(page):
    check = page.check
    dom_policy = page.fixture('dom_policy')
    check(
        'resource policy editor opens with the active document',
        (
            dom_query(dom_policy).has(None, {'id': 'drawer', 'class': 'drawer resource-policy'})
            and (
                'Resource policy editor' in dom_query(dom_policy).text
                or dom_query(dom_policy).has(None, {'title': lambda value: 'Resource policy editor' in (value or '')})
            )
            and (
                'Machine default' in dom_query(dom_policy).text
                or dom_query(dom_policy).has(None, {'title': lambda value: 'Machine default' in (value or '')})
            )
        ),
    )

def run_resource_intervention_ladder_is_visible(page):
    check = page.check
    dom = page.fixture('dom')
    resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'resource intervention ladder is visible',
        'notify → lower priority → pause → terminate' in resource_view,
    )

def run_resources(page):
    check = page.check
    dom_fam = page.fixture('dom_fam')
    board = dom_fam.split('id="resource-board"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'resources: the machine strip renders four tiles',
        (
            dom_query(board).has(None, {'class': 'machine-strip'})
            and len(dom_query(board).find_all(None, {'class': 'machine-tile'})) == 4
        ),
        f"tiles={len(dom_query(board).find_all(None, {'class': 'machine-tile'}))}",
    )
    attn = board.split('class="needs-attention"', 1)[1].split('</section>', 1)[0] if dom_query(board).has(None, {'class': 'needs-attention'}) else ''
    attn_keys = re.findall('class="resource-session-card needs-attention-card[^"]*" data-key="([^"]+)"', attn)
    check(
        'resources: needs attention holds exactly the two diagnosed families, highest impact first',
        attn_keys == ['5821:1789480800000000000', '6033:1789484400000000000'],
        f'keys={attn_keys}',
    )
    fam_groups = re.findall('<details class="family-group( infra)?" data-harness="([^"]+)"', board)
    check(
        'resources: infra is the one trailing group',
        (
            bool(fam_groups)
            and fam_groups[-1] == (' infra', 'infra')
            and sum((1 for g in fam_groups if g[0])) == 1
        ),
        f'groups={fam_groups}',
    )
    infra_grp = board.split('data-harness="infra"', 1)[1] if dom_query(board).has(None, {'data-harness': 'infra'}) else ''
    check(
        'resources: infra families sit in Infrastructure and are not counted as families',
        (
            all((f'data-key="{p}:1789470000000000000"' in infra_grp for p in (7001, 7100, 7200)))
            and '9 families' in board
            and '12 families' not in board
        ),
    )
    oc_grp = board.split('data-harness="openclaw"', 1)[1].split('<details', 1)[0] if dom_query(board).has(None, {'data-harness': 'openclaw'}) else ''
    oc_kids = oc_grp.split('class="family-children"', 1)[1] if dom_query(oc_grp).has(None, {'class': 'family-children'}) else ''
    codex_grp = board.split('data-harness="codex"', 1)[1].split('<details', 1)[0] if dom_query(board).has(None, {'data-harness': 'codex'}) else ''
    check(
        'resources: orchestrated children nest under their OpenClaw parent, not as codex rows',
        (
            'data-key="8100:1789470000000000000"' in oc_grp.split('class="family-children"', 1)[0]
            and dom_query(oc_kids).has(None, {'data-key': '8201:1789470000000000000'})
            and dom_query(oc_kids).has(None, {'data-key': '8202:1789470000000000000'})
            and '8201:' not in codex_grp
            and 'Codex · demo-app@main' in oc_kids
        ),
    )
    check(
        'resources: rows and cards carry names, never root PID',
        (
            'root PID' not in board
            and 'Claude Code · api-service@main' in board
            and 'Codex · data-pipeline@feat/etl' in board
        ),
    )
    check(
        'resources: a group opens by default only when a family in it needs attention',
        (
            dom_query(board).has('details', {'class': 'family-group', 'data-harness': 'claude', 'open': ''})
            and dom_query(board).has('details', {'class': 'family-group', 'data-harness': 'codex'})
            and dom_query(board).has('details', {'class': 'family-group infra', 'data-harness': 'infra'})
        ),
    )
    check(
        'resources: policy line sits below the groups',
        (
            dom_query(board).has(None, {'data-harness': 'infra'})
            and dom_query(board).has(None, {'class': 'resource-policy'})
            and board.index('data-harness="infra"') < board.index('class="resource-policy"')
        ),
    )

def run_view_family_opens_the_drawer_with_the_family_name_the_tab_stays_resources(page):
    check = page.check
    dom_fam = page.fixture('dom_fam')
    fam_drawer = dom_fam.split('<div id="drawer"', 1)[1].split('id="confirm-layer"', 1)[0]
    check(
        'View family opens the drawer with the family name; the tab stays Resources',
        (
            len(dom_query(dom_fam).find_all('div', {'id': 'drawer', 'class': 'drawer'})) == 1
            and 'id="drawer-title-text">Codex · data-pipeline@feat/etl<' in fam_drawer
            and dom_query(dom_fam).has(None, {'class': 'tab-btn active', 'data-tab': 'system'})
            and dom_query(dom_fam).has(None, {'class': 'subtab-btn active', 'data-system-subtab': 'resources'})
        ),
    )

def run_family_drawer(page):
    check = page.check
    dom_fam = page.fixture('dom_fam')
    fam_drawer = dom_fam.split('<div id="drawer"', 1)[1].split('id="confirm-layer"', 1)[0]
    fam_probe = (re.search('<pre id="family-probe"[^>]*>(.*?)</pre>', dom_fam, re.S) or [None, ''])[1]
    check(
        'family drawer: the process table shows 12 rows and Show 8 more, then expands in place',
        (
            fam_probe == 'rows=12 more=Show 8 more'
            and len(dom_query(fam_drawer).find_all(None, {'class': 'family-proc-row'})) == 20
            and not dom_query(fam_drawer).has(None, {'data-action': 'show-more'})
        ),
        f"probe={fam_probe!r} rows={len(dom_query(fam_drawer).find_all(None, {'class': 'family-proc-row'}))}",
    )
    check(
        'family drawer: leftover marked, recent activity and findings scoped to the family',
        (
            'family-proc-row orphan' in fam_drawer
            and 'Bash → pytest -q' in fam_drawer
            and 'npm install' not in fam_drawer
            and 'Keychain file access' in fam_drawer
        ),
    )
    check(
        'family drawer: footer offers Terminate orphans and Terminate family on the root',
        (
            dom_query(fam_drawer).has(None, {'data-action': 'kill-family-orphans', 'data-key': '4412:1789470000000000000'})
            and 'Terminate orphans (1)' in fam_drawer
            and dom_query(fam_drawer).has(None, {'data-action': 'kill', 'data-pid': '4412'})
        ),
    )

def run_open_in_events_switches_to_events_scoped_to_the_family_pids(page):
    check = page.check
    dom_famev = page.fixture('dom_famev')
    ev_scoped = dom_famev.split('id="events-container"', 1)[1].split('</section>', 1)[0]
    ev_pids = set((int(x) for x in re.findall('<span class="pid" title="PID (\\d+)"', ev_scoped)))
    check(
        'Open in Events switches to Events scoped to the family pids',
        (
            dom_query(dom_famev).has(None, {'class': 'subtab-btn active', 'data-subtab': 'events'})
            and len(ev_pids) >= 2
            and ev_pids <= set(range(4412, 4432))
        ),
        f'pids={sorted(ev_pids)}',
    )

def run_events_tab_shows_the_newest_50_rows_and_a_show_more_button(page):
    check = page.check
    dom_evcap = page.fixture('dom_evcap')
    ev_cap = dom_evcap.split('id="events-container"', 1)[1].split('</section>', 1)[0]
    check(
        'Events tab shows the newest 50 rows and a Show more button',
        (
            len(dom_query(ev_cap).find_all(None, {'class': 'timeline-item'})) == 50
            and re.search('data-action="show-more" data-key="events"[^>]*>Show \\d+ more<', ev_cap) is not None
        ),
        f"rows={len(dom_query(ev_cap).find_all(None, {'class': 'timeline-item'}))}",
    )

def run_events_rows_name_trace_kinds(page):
    check = page.check
    dom_evtrace = page.fixture('dom_evtrace')
    ev_trace = dom_evtrace.split('id="events-container"', 1)[1].split('</section>', 1)[0]
    check(
        'Events rows name trace kinds: MODEL and TOOL with their session, never PID 0',
        (
            '>MODEL<' in ev_trace
            and '>TOOL<' in ev_trace
            and 'Bash · ok · 2.5s' in ev_trace
            and 'claude-sonnet-4-5 · 12.0k in / 340 out · $0.04' in ev_trace
            and 'api-service@main' in ev_trace
            and 'PID 0' not in ev_trace
        ),
        f"model={'>MODEL<' in ev_trace} tool={'>TOOL<' in ev_trace} pid0={'PID 0' in ev_trace}",
    )

def run_events(page):
    check = page.check
    dom_duptrace = page.fixture('dom_duptrace')
    dom_evorder = page.fixture('dom_evorder')
    ev_dup = dom_duptrace.split('id="events-container"', 1)[1].split('</section>', 1)[0]
    check(
        'Events: two tool calls at the same ts with different call ids render as two rows',
        (
            len(dom_query(ev_dup).find_all(None, {'class': 'timeline-item'})) >= 2
            and 'Read · ok' in ev_dup
            and 'Write · ok' in ev_dup
        ),
        f"rows={len(dom_query(ev_dup).find_all(None, {'class': 'timeline-item'}))}",
    )
    ev_order = dom_evorder.split('id="events-container"', 1)[1].split('</section>', 1)[0]
    order_rows = re.findall('<div class="timeline-item[^"]*">.*?</div>', ev_order, re.S)
    order_names = [m.group(1) for r in order_rows if (m := re.search('/(\\w+)\\.ts<', r))]
    old_row = next((r for r in order_rows if 'old.ts' in r), '')
    old_dated = re.search('<span class="t">[A-Za-z]{3} \\d{2} \\d{2}:\\d{2}</span>', old_row) is not None
    check(
        'Events: out-of-order rows sort newest first and the 4-month-old row shows a date, not a clock time',
        (
            order_names == ['new', 'mid', 'old']
            and old_dated
        ),
        f'order={order_names} old_dated={old_dated}',
    )

def run_terminate_policy_save_requires_explicit_confirmation(page):
    check = page.check
    dom_policy = page.fixture('dom_policy')
    check(
        'terminate policy save requires explicit confirmation',
        (
            dom_query(dom_policy).has(None, {'id': 'confirm-message'})
            and (
                'Terminate mode will automatically apply the enabled intervention ladder to entire agent sessions' in dom_query(dom_policy).text
                or dom_query(dom_policy).has(None, {'title': lambda value: 'Terminate mode will automatically apply the enabled intervention ladder to entire agent sessions' in (value or '')})
            )
            and 'id="confirm-title">Enable terminate mode<' in dom_policy
        ),
    )

def run_resource_approval_contains_the_whole_session(page):
    check = page.check
    dom = page.fixture('dom')
    resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'resource approval contains the whole session',
        dom_query(resource_view).has(None, {'data-action': 'resource-control', 'data-id': 'resource-1', 'data-decision': 'apply', 'data-intervention': 'pause'}),
    )

def run_resource_approval_can_keep_the_session_running(page):
    check = page.check
    dom = page.fixture('dom')
    resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'resource approval can keep the session running',
        dom_query(resource_view).has(None, {'data-action': 'resource-control', 'data-id': 'resource-1', 'data-decision': 'dismiss'}),
    )

def run_paused_resource_session_can_resume(page):
    check = page.check
    dom = page.fixture('dom')
    resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'paused resource session can resume',
        dom_query(resource_view).has(None, {'data-action': 'resource-control', 'data-session': '6033:1789484400000000000', 'data-decision': 'resume'}),
    )

def run_resource_intervention_failure_is_visible(page):
    check = page.check
    dom = page.fixture('dom')
    resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'resource intervention failure is visible',
        'Intervention failed: rollback failed: permission denied' in resource_view,
    )

def run_home_has_no_session_board(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'home has no session board',
        'id="session-board"' not in dom.split('id="tab-home"', 1)[1].split('id="tab-sessions"', 1)[0],
    )

def run_trends_lead_with_the_activity_chart(page):
    check = page.check
    dom = page.fixture('dom')
    overview = dom.split('id="home-trends"', 1)[1].split('id="tab-sessions"', 1)[0]
    check(
        'trends lead with the activity chart',
        dom_query(overview).has(None, {'id': 'activity-chart'}),
    )

def run_trends_have_the_findings_by_rule_chart(page):
    check = page.check
    dom = page.fixture('dom')
    overview = dom.split('id="home-trends"', 1)[1].split('id="tab-sessions"', 1)[0]
    check(
        'trends have the findings-by-rule chart',
        dom_query(overview).has(None, {'id': 'chart-flags'}),
    )

def run_trends_have_the_memory_by_family_chart(page):
    check = page.check
    dom = page.fixture('dom')
    resource_sub = dom_query(dom).find(None, {'id': 'sub-resources', 'class': 'system-subview'})
    system_tab = dom_query(dom).find(None, {'id': 'tab-system'})
    sessions_tab = dom_query(dom).find(None, {'id': 'tab-sessions'})
    overview = dom.split('id="home-trends"', 1)[1].split('id="tab-sessions"', 1)[0]
    system_resources = dom_query(dom).find(None, {'id': 'sub-resources', 'data-system-view': 'resources'})
    check('System Resources orders live usage, Memory by family and Pressure history', system_resources is not None and system_resources.has(None, {'id': 'resource-board'}) and system_resources.has(None, {'id': 'chart-memory'}) and system_resources.has(None, {'id': 'history-board'}) and (system_resources.html.index('id="resource-board"') < system_resources.html.index('id="chart-memory"') < system_resources.html.index('id="history-board"')) and (not dom_query(overview).has(None, {'id': 'chart-memory'})))

def run_trends_carry_no_list_panels(page):
    check = page.check
    dom = page.fixture('dom')
    overview = dom.split('id="home-trends"', 1)[1].split('id="tab-sessions"', 1)[0]
    check(
        'trends carry no list panels',
        (
            not dom_query(overview).has(None, {'id': 'session-strip'})
            and not dom_query(overview).has(None, {'id': 'events-container'})
            and not dom_query(overview).has(None, {'id': 'resource-board'})
        ),
    )

def run_the_egress_tab_carries_no_decision_badge(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'the Egress tab carries no decision badge: recurring egress is never queued',
        (
            not dom_query(dom).has(None, {'id': 'tab-badge-egress'})
            and not dom_query(dom).has(None, {'data-kind': 'recurring_egress'})
        ),
    )

def run_home_tab_badge_shows_needs_you_count(page):
    check = page.check
    dom = page.fixture('dom')
    needs_you = json.loads(html.unescape(pre(dom, 'fixture-posture')))['needs_you']
    check(
        'home tab badge shows needs-you count',
        f'id="tab-badge-home">{needs_you}<' in dom,
    )

def run_needs_you_shows_the_api_service_session_s_decisions_as_flat_rows_with_its_memory_cpu_and_process_count(page):
    check = page.check
    dom = page.fixture('dom')
    attention = dom.split('id="attention-center"', 1)[1].split('id="security-findings-grid"', 1)[0]
    decisions = attention.split('id="coverage-center"', 1)[0]
    check(
        "Needs you shows the api-service session's decisions as flat rows with its memory, CPU and process count",
        (
            (
                'attention-group' not in dom_query(dom).text
                and not dom_query(dom).has(None, {'title': lambda value: 'attention-group' in (value or '')})
            )
            and 'api-service' in decisions
            and '5.5 GB memory · 132.5% CPU · 2 processes' in decisions
        ),
    )

def run_a_pattern_never_reaches_needs_you_it_is_one_history_row_with_its_count(page):
    check = page.check
    dom_pattern = page.fixture('dom_pattern')
    pat_need = dom_pattern.split('id="attention-center"', 1)[-1].split('id="coverage-center"', 1)[0]
    pat_row = log_rows(dom_pattern).get('pattern:codex|keychain-access|/Users/dev/Library/Keychains/login.keychain-db', '')
    check(
        'a pattern never reaches Needs you; it is one history row with its count',
        (
            'data-pattern-key' not in pat_need
            and not dom_query(pat_need).has(None, {'data-kind': 'pattern'})
            and (
                'codex activity' not in dom_query(dom_pattern).text
                and not dom_query(dom_pattern).has(None, {'title': lambda value: 'codex activity' in (value or '')})
            )
            and '<span class="c-count">323×</span>' in pat_row
        ),
        f'row={pat_row[:200]!r}',
    )

def run_needs_you_unifies_guard_resource_incident_and_critical_finding_rows_highest_priority_first(page):
    check = page.check
    dom = page.fixture('dom')
    attention = dom.split('id="attention-center"', 1)[1].split('id="security-findings-grid"', 1)[0]
    decisions = attention.split('id="coverage-center"', 1)[0]
    need_kinds = re.findall('<li class="need [^"]*" data-kind="(\\w+)"', decisions)
    check(
        'Needs you unifies guard, resource, incident and critical-finding rows, highest priority first',
        need_kinds == ['guard', 'resource', 'incident', 'flag', 'flag', 'flag'],
        f'kinds={need_kinds}',
    )

def run_home_keeps_coverage_outside_the_decisions_count(page):
    check = page.check
    dom = page.fixture('dom')
    attention = dom.split('id="attention-center"', 1)[1].split('id="security-findings-grid"', 1)[0]
    decisions = attention.split('id="coverage-center"', 1)[0]
    coverage = attention.split('id="coverage-center"', 1)[1].split('id="home-spend"', 1)[0]
    check(
        'Home keeps coverage outside the decisions count',
        (
            'id="badge-coverage-count">2<' in coverage
            and 'File monitoring is off' in coverage
            and '2 connections bypassed inspection' in coverage
            and 'Uninspected egress' not in decisions
        ),
    )

def run_home_with_only_coverage_gaps_hides_needs_you_and_shows_the_gap(page):
    check = page.check
    dom_coverage = page.fixture('dom_coverage')
    check(
        'Home with only coverage gaps hides Needs you and shows the gap',
        (
            re.search('<section[^>]*id="attention-center"[^>]*\\bhidden', dom_coverage) is not None
            and 'No pending decisions' not in dom_coverage.split('id="attention-center"', 1)[-1].split('id="home-spend"', 1)[0]
            and 'id="posture-state">Monitoring needs attention<' in dom_coverage
            and 'id="tabs-posture-text">Monitoring gap<' in dom_coverage
            and 'id="coverage-center" hidden' not in dom_coverage
            and 'id="badge-coverage-count">2<' in dom_coverage
        ),
    )

def run_attention_resource_actions_target_the_full_session(page):
    check = page.check
    dom = page.fixture('dom')
    resource_attention = html.unescape(pre(dom, 'attention-resource-content'))
    check(
        'attention resource actions target the full session',
        dom_query(resource_attention).has(None, {'data-action': 'resource-control', 'data-id': 'resource-1', 'data-decision': 'apply'}),
    )

def run_same_agent_sessions_keep_independent_guard_evidence_and_closed_details(page):
    check = page.check
    dom_session_coverage = page.fixture('dom_session_coverage')
    check(
        'same-agent sessions keep independent guard evidence and closed details',
        (
            dom_query(dom_session_coverage).has(None, {'data-session-id': 'session-observed'})
            and dom_query(dom_session_coverage).has(None, {'data-session-id': 'session-silent'})
            and (
                '/work/observed · Guard: activity observed' in dom_query(dom_session_coverage).text
                or dom_query(dom_session_coverage).has(None, {'title': lambda value: '/work/observed · Guard: activity observed' in (value or '')})
            )
            and '/work/&lt;silent&gt; · Guard: not observed' in dom_session_coverage
            and re.search('<details[^>]*class="coverage-session"[^>]*\\bopen', dom_session_coverage) is None
        ),
    )

def run_an_invalidated_installed_hook_check_stays_separate_from_session_evidence(page):
    check = page.check
    dom_session_coverage = page.fixture('dom_session_coverage')
    check(
        'an invalidated installed-hook check stays separate from session evidence',
        (
            (
                'Installed hook checks' in dom_query(dom_session_coverage).text
                or dom_query(dom_session_coverage).has(None, {'title': lambda value: 'Installed hook checks' in (value or '')})
            )
            and (
                'claude · changed' in dom_query(dom_session_coverage).text
                or dom_query(dom_session_coverage).has(None, {'title': lambda value: 'claude · changed' in (value or '')})
            )
            and (
                'Configuration changed. Run the check again.' in dom_query(dom_session_coverage).text
                or dom_query(dom_session_coverage).has(None, {'title': lambda value: 'Configuration changed. Run the check again.' in (value or '')})
            )
        ),
    )

def run_attention_guard_actions_expose_bounded_choices(page):
    check = page.check
    dom = page.fixture('dom')
    guard_attention = html.unescape(pre(dom, 'attention-guard-content'))
    check(
        'attention guard actions expose bounded choices',
        (
            dom_query(guard_attention).has(None, {'data-action': 'guard-resolve', 'data-id': 'guard-1', 'data-verdict': 'allow', 'data-scope': 'once'})
            and dom_query(guard_attention).has(None, {'data-action': 'guard-resolve', 'data-id': 'guard-1', 'data-verdict': 'deny', 'data-scope': 'once'})
            and dom_query(guard_attention).has(None, {'data-scope': 'exact', 'data-expiry': '24h'})
            and not dom_query(guard_attention).has(None, {'data-scope': 'always'})
        ),
    )

def run_attention_keeps_scope_disclosure_compact(page):
    check = page.check
    dom = page.fixture('dom')
    guard_attention = html.unescape(pre(dom, 'attention-guard-content'))
    check(
        'attention keeps scope disclosure compact',
        'Future access requires a chosen limit' in guard_attention,
    )

def run_coverage_egress_opens_endpoint_evidence(page):
    check = page.check
    dom = page.fixture('dom')
    attention = dom.split('id="attention-center"', 1)[1].split('id="security-findings-grid"', 1)[0]
    coverage = attention.split('id="coverage-center"', 1)[1].split('id="home-spend"', 1)[0]
    check(
        'coverage egress opens endpoint evidence',
        dom_query(coverage).has(None, {'data-action': 'open-uninspected'}),
    )

def run_resolved_guard_request_leaves_the_attention_queue(page):
    check = page.check
    dom = page.fixture('dom')
    dom_guard = page.fixture('dom_guard')
    needs_you = json.loads(html.unescape(pre(dom, 'fixture-posture')))['needs_you']
    check(
        'resolved guard request leaves the attention queue',
        (
            f'id="tab-badge-home">{needs_you - 1}<' in dom_guard
            and not dom_query(dom_guard).has(None, {'data-action': 'guard-resolve', 'data-id': 'guard-1'})
        ),
    )

def run_resolved_incident_leaves_the_attention_count_before_reconciliation(page):
    check = page.check
    dom = page.fixture('dom')
    dom_resolve = page.fixture('dom_resolve')
    needs_you = json.loads(html.unescape(pre(dom, 'fixture-posture')))['needs_you']
    resolve_probe = (re.search('<pre id="resolve-probe"[^>]*>(.*?)</pre>', dom_resolve, re.S) or [None, ''])[1]
    check(
        'resolved incident leaves the attention count before reconciliation',
        resolve_probe == f'badge={needs_you - 1} tab={needs_you - 1} queued=false',
        f'probe={resolve_probe!r}',
    )

def run_an_expected_connection_leaves_egress_before_the_daemon_answers_the_banner_and_needs_you_count_never_held_it(page):
    check = page.check
    dom = page.fixture('dom')
    dom_expect = page.fixture('dom_expect')
    needs_you = json.loads(html.unescape(pre(dom, 'fixture-posture')))['needs_you']
    expect_before = (re.search('<pre id="expect-before"[^>]*>(.*?)</pre>', dom_expect, re.S) or [None, ''])[1]
    expect_probe = (re.search('<pre id="expect-probe"[^>]*>(.*?)</pre>', dom_expect, re.S) or [None, ''])[1]
    check(
        'an expected connection leaves Egress before the daemon answers; the banner and Needs you count never held it',
        (
            expect_before == f'choices=true listed=false needs={needs_you}'
            and expect_probe == f'choices=false listed=false needs={needs_you}'
        ),
        f'before={expect_before!r} probe={expect_probe!r}',
    )

def run_posture_flag_item_targets_its_recorded_evidence(page):
    check = page.check
    dom_tab = page.fixture('dom_tab')
    posture_list = dom_query(dom_tab).find(None, {'id': 'posture-items'})
    check(
        'posture flag item targets its recorded evidence',
        (
            posture_list is not None
            and dom_query(posture_list.html).has('a', {'data-action': 'open-flag', 'data-id': 'flag-1'})
        ),
    )

def run_tab_switch_reveals_the_target_panel(page):
    check = page.check
    dom_tab = page.fixture('dom_tab')
    check(
        'tab switch reveals the target panel',
        (
            dom_query(dom_tab).has(None, {'class': 'tab-btn active', 'data-tab': 'protection'})
            and dom_query(dom_tab).has(None, {'data-protection-view': 'traffic', 'aria-selected': 'true', 'class': 'active'})
            and 'hidden' not in dom_query(dom_tab).find(None, {'id': 'protection-traffic'}).attrs
            and 'id="tab-home" role="tabpanel" hidden' in dom_tab
        ),
    )

def run_egress_explains_scheduled_calls_as_observed_facts_and_labeled_advisor_inference(page):
    check = page.check
    dom_tab = page.fixture('dom_tab')
    recurring = dom_tab.split('id="recurring-egress-container"', 1)[-1].split('id="endpoints-panel"', 1)[0]
    check(
        'Egress explains scheduled calls as observed facts and labeled advisor inference',
        (
            'updates.example.com:443' in recurring
            and 'about every 30–31 min' in recurring
            and 'Advisor inference' in recurring
            and 'Possibly an update check' in recurring
        ),
    )

def run_egress_offers_broad_scope_only_with_complete_attribution(page):
    check = page.check
    dom_tab = page.fixture('dom_tab')
    recurring = dom_tab.split('id="recurring-egress-container"', 1)[-1].split('id="endpoints-panel"', 1)[0]
    check(
        'Egress offers broad scope only with complete attribution',
        (
            dom_query(recurring).has(None, {'data-episode-id': 'episode-routine', 'data-kind': 'scope'})
            and dom_query(recurring).has(None, {'data-episode-id': 'episode-ambiguous', 'data-kind': 'destination'})
            and not dom_query(recurring).has(None, {'data-episode-id': 'episode-ambiguous', 'data-kind': 'scope'})
        ),
    )

def run_egress_opens_linked_session_and_can_revoke_an_expected_episode(page):
    check = page.check
    dom_tab = page.fixture('dom_tab')
    recurring = dom_tab.split('id="recurring-egress-container"', 1)[-1].split('id="endpoints-panel"', 1)[0]
    check(
        'Egress opens linked session and can revoke an expected episode',
        (
            dom_query(recurring).has(None, {'data-action': 'filter-session', 'data-session': 'sess-claude-1'})
            and dom_query(recurring).has(None, {'data-action': 'revoke-expected-egress', 'data-id': 'expected-older'})
            and 'First ' in recurring
            and 'Last ' in recurring
        ),
    )

def run_resources_and_events_are_separate_sub_views(page):
    check = page.check
    dom = page.fixture('dom')
    resource_sub = dom_query(dom).find(None, {'id': 'sub-resources', 'class': 'system-subview'})
    system_tab = dom_query(dom).find(None, {'id': 'tab-system'})
    sessions_tab = dom_query(dom).find(None, {'id': 'tab-sessions'})

    check('resources and events are separate sub-views', resource_sub is not None and 'hidden' in system_tab.attrs and system_tab.has(None, {'id': 'sub-resources'}) and (not sessions_tab.has(None, {'id': 'sub-resources'})) and sessions_tab.has(None, {'id': 'sub-events', 'hidden': ''}) and system_tab.has(None, {'class': 'subtabs', 'role': 'tablist', 'aria-label': 'System views'}))

def run_pressure_history_sits_in_the_resources_sub_view(page):
    check = page.check
    dom = page.fixture('dom')
    resource_sub = dom_query(dom).find(None, {'id': 'sub-resources', 'class': 'system-subview'})
    system_tab = dom_query(dom).find(None, {'id': 'tab-system'})
    sessions_tab = dom_query(dom).find(None, {'id': 'tab-sessions'})

    check('pressure history sits in the Resources sub-view', resource_sub is not None and resource_sub.has(None, {'id': 'history-panel'}))

def run_resource_panel_lives_in_the_resources_sub_view(page):
    check = page.check
    dom = page.fixture('dom')
    resource_sub = dom_query(dom).find(None, {'id': 'sub-resources', 'class': 'system-subview'})
    system_tab = dom_query(dom).find(None, {'id': 'tab-system'})
    sessions_tab = dom_query(dom).find(None, {'id': 'tab-sessions'})

    check('resource panel lives in the resources sub-view', resource_sub is not None and resource_sub.has(None, {'id': 'resource-board'}) and (resource_sub.html.index('id="resource-board"') < resource_sub.html.index('id="history-panel"')))

def run_flight_recorder_lives_in_the_resources_sub_view(page):
    check = page.check
    dom = page.fixture('dom')
    resource_sub = dom_query(dom).find(None, {'id': 'sub-resources', 'class': 'system-subview'})
    system_tab = dom_query(dom).find(None, {'id': 'tab-system'})
    sessions_tab = dom_query(dom).find(None, {'id': 'tab-sessions'})
    history_panel = resource_sub.find(None, {'id': 'history-panel'}) if resource_sub else None
    check('flight recorder lives in the resources sub-view', history_panel is not None and history_panel.has(None, {'id': 'history-board'}))

def run_event_timeline_lives_in_the_events_sub_view(page):
    check = page.check
    dom = page.fixture('dom')
    resource_sub = dom_query(dom).find(None, {'id': 'sub-resources', 'class': 'system-subview'})
    system_tab = dom_query(dom).find(None, {'id': 'tab-system'})
    sessions_tab = dom_query(dom).find(None, {'id': 'tab-sessions'})

    check('event timeline lives in the events sub-view', sessions_tab.find(None, {'id': 'sub-events'}).has(None, {'id': 'events-container'}) and (not system_tab.has(None, {'id': 'events-container'})))

def run_saved_view_menu_is_present(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'saved-view menu is present',
        (
            dom_query(dom).has(None, {'id': 'btn-views'})
            and dom_query(dom).has(None, {'id': 'views-pop'})
        ),
    )

def run_a_saved_view_appears_in_the_list(page):
    check = page.check
    dom_view = page.fixture('dom_view')
    check(
        'a saved view appears in the list',
        dom_query(dom_view).has(None, {'data-action': 'apply-view', 'data-name': 'Prod leaks'}),
    )

def run_global_search_box_is_present(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'global search box is present',
        dom_query(dom).has(None, {'id': 'global-search'}),
    )

def run_export_actions_are_wired(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'export actions are wired',
        (
            dom_query(dom).has(None, {'data-action': 'export', 'data-what': 'flags'})
            and dom_query(dom).has(None, {'data-action': 'export', 'data-what': 'incidents'})
        ),
    )

def run_search_narrows_the_panel(page):
    check = page.check
    dom = page.fixture('dom')
    dom_view = page.fixture('dom_view')
    check(
        'search narrows the panel',
        len(dom_query(dom_view).find_all(None, {'class': 'timeline-item'})) <= len(dom_query(dom).find_all(None, {'class': 'timeline-item'})),
    )

def run_flag_card_carries_per_flag_dismiss(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'flag card carries per-flag dismiss',
        dom_query(dom).has(None, {'data-action': 'dismiss-flag', 'data-id': 'flag-1'}),
    )

def run_flag_card_carries_re_run_advisor(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'flag card carries re-run advisor',
        dom_query(dom).has(None, {'data-action': 'retriage', 'data-id': 'flag-1'}),
    )

def run_keychain_flag_shows_benign_context(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'keychain flag shows benign context',
        (
            'usually routine' in dom_query(dom).text
            or dom_query(dom).has(None, {'title': lambda value: 'usually routine' in (value or '')})
        ),
    )

def run_dismiss_removes_the_flag_s_row(page):
    check = page.check
    dom_dismiss = page.fixture('dom_dismiss')
    dismiss_rows = [k for k in log_rows(dom_dismiss) if k.startswith('flag:')]
    check(
        "dismiss removes the flag's row",
        (
            len(dismiss_rows) == 2
            and not dom_query(dom_dismiss).has(None, {'data-id': 'flag-3'})
        ),
        f'rows={dismiss_rows}',
    )

def run_re_triage_verdict_lands_and_replaces_the_chip(page):
    check = page.check
    dom_retriage = page.fixture('dom_retriage')
    check(
        're-triage verdict lands and replaces the chip',
        (
            (
                're-triage complete: routine vendor traffic' in dom_query(dom_retriage).text
                or dom_query(dom_retriage).has(None, {'title': lambda value: 're-triage complete: routine vendor traffic' in (value or '')})
            )
            and (
                'advisor: benign' in dom_query(dom_retriage).text
                or dom_query(dom_retriage).has(None, {'title': lambda value: 'advisor: benign' in (value or '')})
            )
        ),
    )

def run_fresh_identical_re_triage_verdict_clears_pending_and_reports_completion(page):
    check = page.check
    dom_retriage = page.fixture('dom_retriage')
    check(
        'fresh identical re-triage verdict clears pending and reports completion',
        (
            pre(dom_retriage, 'retriage-complete') == 'true'
            and (
                'POST /advisor/retriage' in dom_query(dom_retriage).text
                or dom_query(dom_retriage).has(None, {'title': lambda value: 'POST /advisor/retriage' in (value or '')})
            )
        ),
    )

def run_advisor_offline_renders_honest_disabled_state(page):
    check = page.check
    dom_advdown = page.fixture('dom_advdown')
    check(
        'advisor offline renders honest disabled state',
        (
            (
                'Advisor offline' in dom_query(dom_advdown).text
                or dom_query(dom_advdown).has(None, {'title': lambda value: 'Advisor offline' in (value or '')})
            )
            and not dom_query(dom_advdown).has(None, {'data-action': 'retriage', 'data-id': 'flag-1'})
        ),
    )

def run_timeline_rows_carry_agent_names_not_bare_pids(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'timeline rows carry agent names, not bare PIDs',
        (
            (
                'cursor · PID 6033' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: 'cursor · PID 6033' in (value or '')})
            )
            or (
                'claude · PID 5821' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: 'claude · PID 5821' in (value or '')})
            )
        ),
    )

def run_zero_inline_onclick_handlers_in_rendered_dom(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'zero inline onclick handlers in rendered DOM',
        not dom_query(dom).has(None, {'onclick': None}),
    )

def run_view_session_in_timeline_opens_the_session_in_the_sessions_tab(page):
    check = page.check
    dom_sesslink = page.fixture('dom_sesslink')
    link_rail = dom_sesslink.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
    check(
        'View session in timeline opens the session in the Sessions tab: card selected, trace rendered',
        (
            dom_query(dom_sesslink).has(None, {'class': 'tab-btn active', 'data-tab': 'sessions'})
            and re.search('<div class="session-card active selected">\\s*<button type="button" class="sc-main" data-action="select-session" data-id="sess-claude-1" aria-pressed="true"', link_rail) is not None
            and re.search('<h3[^>]*>api-service@main</h3>', dom_sesslink.split('id="session-detail"', 1)[1]) is not None
            and dom_query(dom_sesslink).has(None, {'class': 'wf-bar'})
        ),
    )

def run_timeline_filtered_to_2_session_events(page):
    check = page.check
    dom_session = page.fixture('dom_session')
    session_rows = len(dom_query(dom_session).find_all(None, {'class': 'timeline-item'}))
    check(
        'timeline filtered to 2 session events',
        session_rows == 2,
        f'rows={session_rows}',
    )

def run_burst(page):
    check = page.check
    dom_burst = page.fixture('dom_burst')
    dom_dismiss = page.fixture('dom_dismiss')
    dismiss_rows = [k for k in log_rows(dom_dismiss) if k.startswith('flag:')]
    counts_raw = pre(dom_burst, 'render-counts')
    try:
        counts = json.loads(counts_raw)
    except ValueError:
        counts = None
    check(
        'burst: hidden-tab panels never render (sessions, agents, firewall = 0)',
        (
            counts is not None
            and all((counts.get(k, 0) == 0 for k in ('sessions', 'agents', 'firewall')))
        ),
        f'counts={counts_raw[:200]}',
    )
    check(
        'burst: flags renders at most once per flag frame (1..3)',
        (
            counts is not None
            and 1 <= counts.get('flags', 0) <= 3
        ),
        f'counts={counts_raw[:200]}',
    )

def run_identical_title_sessions_fold_into_one_row_titled_with_the_spawning_agent(page):
    check = page.check
    dom_dup = page.fixture('dom_dup')
    dup_rail = dom_dup.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
    quill_key = 'group:codex|demo-app@main · quill'
    check(
        'identical-title sessions fold into one row titled with the spawning agent',
        (
            dup_rail.count(f'data-action="toggle-session-dup" data-key="{quill_key}"') == 1
            and '<span class="sc-label">demo-app@main · quill</span><span class="session-dup-count">×5</span>' in dup_rail
            and '<span class="sc-label">.openclaw · fennel</span><span class="session-dup-count">×3</span>' in dup_rail
        ),
    )

def run_an_expanded_folded_row_lists_its_five_sessions_newest_first_with_hh(page):
    check = page.check
    dom_dup = page.fixture('dom_dup')
    dup_rail = dom_dup.split('id="session-rail"', 1)[1].split('id="session-detail"', 1)[0]
    quill_key = 'group:codex|demo-app@main · quill'
    dup_row = dup_rail.split(f'data-key="{quill_key}"', 1)[1].split('toggle-session-dup', 1)[0]
    dup_ids = re.findall('data-action="select-session" data-id="(sess-dup-\\d)"', dup_row)
    dup_labels = re.findall('<span class="sc-label">(\\d\\d:\\d\\d)</span>', dup_row)
    check(
        'an expanded folded row lists its five sessions newest first with HH:MM start times',
        (
            dup_ids == [f'sess-dup-{i}' for i in range(1, 6)]
            and len(dup_labels) == 5
            and f'data-key="{quill_key}" aria-expanded="true"' in dup_rail
        ),
        f'ids={dup_ids} labels={dup_labels}',
    )

def run_a_selected_member_of_a_folded_row_keeps_its_selection_across_a_patch(page):
    check = page.check
    dom_dup = page.fixture('dom_dup')
    quill_key = 'group:codex|demo-app@main · quill'
    try:
        dup_probe = json.loads(pre(dom_dup, 'dup-probe') or 'null')
    except ValueError:
        dup_probe = None
    check(
        'a selected member of a folded row keeps its selection across a patch',
        dup_probe == {'key': quill_key, 'open': True, 'selected': ['sess-dup-3']},
        f'probe={dup_probe}',
    )

def run_resources_folds_identical_family_labels_into_one_row_with_summed_memory_cpu_and_processes(page):
    check = page.check
    dom_dupres = page.fixture('dom_dupres')
    dup_board = dom_dupres.split('id="resource-board"', 1)[1]
    check(
        'Resources folds identical family labels into one row with summed memory, CPU and processes',
        (
            re.search('data-action="toggle-family-dup" data-key="group:codex\\|Codex · fennel" aria-expanded="false"><strong>Codex · fennel</strong><span class="family-dup-count">×3</span>', dup_board) is not None
            and '<b>600 MB</b><small>memory</small>' in dup_board
            and '<b>6</b><small>processes</small>' in dup_board
        ),
    )

def run_a_status_change_patches_a_session_group_in_place(page):
    check = page.check
    dom_foldpatch = page.fixture('dom_foldpatch')
    try:
        fold_probe = json.loads(pre(dom_foldpatch, 'fold-probe') or 'null')
    except ValueError:
        fold_probe = None
    check(
        'a status change patches a session group in place: a focused row keeps identity and focus, the group stays open, the counts update',
        (
            isinstance(fold_probe, dict)
            and fold_probe.get('focus') is True
            and fold_probe.get('group') is True
            and fold_probe.get('before')
            and fold_probe.get('after')
            and fold_probe.get('before') != fold_probe.get('after')
        ),
        f'probe={fold_probe}',
    )

def run_a_live_and_an_ended_fold_with_one_title_expand_independently(page):
    check = page.check
    dom_foldpatch = page.fixture('dom_foldpatch')
    try:
        fold_probe = json.loads(pre(dom_foldpatch, 'fold-probe') or 'null')
    except ValueError:
        fold_probe = None
    check(
        'a live and an ended fold with one title expand independently',
        (
            isinstance(fold_probe, dict)
            and fold_probe.get('live') == 'false'
            and fold_probe.get('ended') == 'true'
        ),
        f'probe={fold_probe}',
    )

def run_a_metric_update_patches_a_resources_group_per_row(page):
    check = page.check
    dom_familypatch = page.fixture('dom_familypatch')
    try:
        family_probe = json.loads(pre(dom_familypatch, 'family-probe') or 'null')
    except ValueError:
        family_probe = None
    check(
        'a metric update patches a Resources group per row: a focused family control keeps identity and focus, the fold stays expanded',
        (
            isinstance(family_probe, dict)
            and family_probe.get('focus') is True
            and family_probe.get('group') is True
            and family_probe.get('fold') == 'true'
            and family_probe.get('before')
            and family_probe.get('after')
            and family_probe.get('before') != family_probe.get('after')
        ),
        f'probe={family_probe}',
    )

def run_burst_2(page):
    check = page.check
    dom_focus = page.fixture('dom_focus')
    dom_railburst = page.fixture('dom_railburst')
    infra_tag = re.search('<details class="session-group infra"[^>]*>', dom_railburst)
    infra_tag = infra_tag.group(0) if infra_tag else ''
    check(
        'burst: an opened rail <details> is the same node and still open',
        (
            dom_query(infra_tag).has(None, {'open': ''})
            and dom_query(infra_tag).has(None, {'data-probe': '1'})
        ),
        f'tag={infra_tag}',
    )
    flags_focus = dom_focus.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
    check(
        'burst: a focused history row head keeps identity and focus',
        (
            dom_query(flags_focus).has(None, {'data-probe': '1'})
            and pre(dom_focus, 'focus-probe') == 'kept'
        ),
        f"probe={pre(dom_focus, 'focus-probe')!r}",
    )

def run_burst_3(page):
    check = page.check
    dom_click = page.fixture('dom_click')
    flags_click = dom_click.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
    check(
        'burst: a click spanning renders lands (POST /flags/acknowledge, card gone)',
        (
            'POST /flags/acknowledge' in pre(dom_click, 'mock-requests')
            and not dom_query(flags_click).has(None, {'data-id': 'flag-3'})
        ),
        f"requests={pre(dom_click, 'mock-requests')!r}",
    )

def run_raw_card_mute_carries_the_flag_s_agent(page):
    check = page.check
    dom_rawmute = page.fixture('dom_rawmute')
    raw_reqs = pre(dom_rawmute, 'mock-requests')
    check(
        "raw card mute carries the flag's agent (no global mute)",
        'POST /mute body={"rule":"keychain-access","host":"*","agent":"codex"}' in raw_reqs,
        f'requests={raw_reqs!r}',
    )

def run_act_in_place(page):
    check = page.check
    dom_act = page.fixture('dom_act')
    dom_actfail = page.fixture('dom_actfail')
    act_row = dom_act.split('registry.npmjs.org · cursor', 1)[-1].split('</div>', 1)[0] if 'registry.npmjs.org · cursor' in dom_query(dom_act).text or dom_query(dom_act).has(None, {'title': lambda value: 'registry.npmjs.org · cursor' in (value or '')}) else ''
    check(
        'act in place: allowlist row on screen when the request leaves, with an inline note',
        (
            'POST /allowlist row=1' in pre(dom_act, 'mock-requests')
            and dom_query(act_row).has(None, {'class': 'card-note'})
        ),
        f"requests={pre(dom_act, 'mock-requests')!r} row={act_row[:160]!r}",
    )
    check(
        'act in place: a failed allow reverts the row and toasts danger',
        (
            'POST /allowlist row=1' in pre(dom_actfail, 'mock-requests')
            and (
                'registry.npmjs.org · cursor' not in dom_query(dom_actfail).text
                and not dom_query(dom_actfail).has(None, {'title': lambda value: 'registry.npmjs.org · cursor' in (value or '')})
            )
            and dom_query(dom_actfail).has(None, {'class': 'toast danger'})
            and dom_query(dom_actfail).has(None, {'data-action': 'allow-host', 'data-agent': 'cursor', 'data-host': 'registry.npmjs.org'})
        ),
        f"requests={pre(dom_actfail, 'mock-requests')!r}",
    )

def run_finding_row(page):
    check = page.check
    dom_explain = page.fixture('dom_explain')

    def visible(markup):
        return re.sub('<[^>]*>', ' ', markup)
    card = log_rows(dom_explain).get('flag:flag-2', '')
    head = (re.search('<button type="button" class="log-head".*?</button>', card, re.S) or [''])[0]
    outside = re.sub('<details.*?</details>', '', card, flags=re.S)
    check(
        'finding row: the head shows the title, never the rule id; no pid or IPv6 outside Evidence',
        (
            card != ''
            and 'Sensitive file read near an outside connection' in head
            and 'sensitive-read-then-connect' not in visible(head)
            and not re.search('\\bpid\\b', visible(outside), re.I)
            and '6033' not in visible(outside)
            and '2606:' not in visible(outside)
        ),
        f'card={card[:240]!r}',
    )

def run_finding_row_carries_no_inline_handlers_or_styles(page):
    check = page.check
    dom_explain = page.fixture('dom_explain')
    card = log_rows(dom_explain).get('flag:flag-2', '')
    check(
        'finding row carries no inline handlers or styles',
        (
            card != ''
            and not dom_query(card).has(None, {'onclick': None})
            and not dom_query(card).has(None, {'style': None})
        ),
    )

def run_finding_row_2(page):
    check = page.check
    dom_explain = page.fixture('dom_explain')
    card = log_rows(dom_explain).get('flag:flag-2', '')
    buttons = re.findall('<button class="btn ([a-z-]+) btn-sm" data-action="explain-act" data-flag-id="flag-2" data-action-id="([a-z-]+)"', card)
    menu = re.findall('<button class="act-menu-item( danger)?" data-action="explain-act" data-flag-id="flag-2" data-action-id="([a-z-]+)"', card)
    check(
        'finding row: who, what and verdict; the recommended action leads the bar, the rest sit under More',
        (
            '>cursor · web-app@main</span>' in card
            and '<p class="body-lead">Cursor read AWS credentials (~/.aws/credentials), then reached Cloudflare 3 s later.</p>' in card
            and '<p class="body-verdict">Likely benign (advisor 93 %): Cloudflare fronts the package registry this project installs from.</p>' in card
            and buttons == [('btn-primary', 'allow-host'), ('btn-ghost', 'dismiss')]
            and menu == [('', 'allow-path'), (' danger', 'kill')]
        ),
        f'buttons={buttons} menu={menu}',
    )
    details = (re.search('<details class="body-evidence">(.*?)</details></div>', card, re.S) or [None, ''])[1]
    check(
        'finding row: Evidence is closed by default and holds the chain, pid, full address and ISO timestamp',
        (
            details != ''
            and dom_query(details).has(None, {'class': 'chain'})
            and '2026-09-22T16:05:01Z' in details
            and '6033' in details
            and '[2606:4700::6810:84e5]:443' in details
            and '/Users/dev/.aws/credentials' in details
        ),
        f'details={details[:200]!r}',
    )

def run_finding_card(page):
    check = page.check
    dom_allowpathact = page.fixture('dom_allowpathact')
    dom_explainact = page.fixture('dom_explainact')
    dom_orgallow = page.fixture('dom_orgallow')
    act_reqs = pre(dom_explainact, 'mock-requests')
    flags_act = dom_explainact.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
    check(
        'finding card: the recommended action sends the served request; the card leaves with an inline note',
        (
            'POST /allowlist' in act_reqs
            and 'body={"agent":"cursor","host":"2606:4700::6810:84e5"}' in act_reqs
            and 'POST /flags/acknowledge' in act_reqs
            and not dom_query(flags_act).has(None, {'data-flag-id': 'flag-2'})
            and 'class="card-note">allowlisted<' in dom_explainact
        ),
        f'requests={act_reqs!r}',
    )
    allowpath_reqs = pre(dom_allowpathact, 'mock-requests')
    check(
        'finding card: the allow-path action (not the first/recommended button) sends its own served request',
        (
            'POST /guard/path-allow body={"agent":"cursor","rule_id":"cloud-creds","path":"/Users/dev/.aws/credentials"}' in allowpath_reqs
            and 'POST /allowlist' not in allowpath_reqs
        ),
        f'requests={allowpath_reqs!r}',
    )
    org_card = pre(dom_orgallow, 'org-allow-card')
    org_reqs = pre(dom_orgallow, 'mock-requests')
    check(
        'finding card: three Google addresses are one Allow Google choice that allows each host, then marks the flag reviewed',
        (
            org_card == 'bar=1 org=1 hosts=0'
            and org_reqs.count('POST /allowlist') == 3
            and 'body={"agent":"cursor","host":"2607:f8b0:4002:c08::54"}' in org_reqs
            and org_reqs.rstrip().endswith('POST /flags/acknowledge body={"flag_id":"flag-1"}')
        ),
        f'card={org_card!r} requests={org_reqs!r}',
    )

def run_routine(page):
    check = page.check
    dom = page.fixture('dom')
    dom_routine = page.fixture('dom_routine')
    needs_you = json.loads(html.unescape(pre(dom, 'fixture-posture')))['needs_you']
    routine_before = pre(dom_routine, 'routine-before')
    routine_after = pre(dom_routine, 'routine-after')
    check(
        'routine: gh across three agents is one history row, never a decision; Treat as routine sends the served ids and the row leaves before the answer',
        (
            routine_before == 'queued=false count=145× buttons=2'
            and routine_after == f'card=false needs={needs_you}'
            and 'POST /expected body={"flag_ids":["r1","r2"]}' in pre(dom_routine, 'mock-requests')
        ),
        f"before={routine_before!r} after={routine_after!r} requests={pre(dom_routine, 'mock-requests')!r}",
    )

def run_finding_card_2(page):
    check = page.check
    dom_explainfail = page.fixture('dom_explainfail')
    fail_reqs = pre(dom_explainfail, 'mock-requests')
    flags_fail = dom_explainfail.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
    check(
        'finding card: a failed allow puts the card back and toasts danger',
        (
            'POST /allowlist' in fail_reqs
            and 'POST /flags/acknowledge' not in fail_reqs
            and dom_query(flags_fail).has('div', {'class': 'row-body', 'data-flag-id': 'flag-2'})
            and dom_query(dom_explainfail).has(None, {'class': 'toast danger'})
        ),
        f'requests={fail_reqs!r}',
    )

def run_attention(page):
    check = page.check
    dom_explain = page.fixture('dom_explain')
    attn = dom_explain.split('id="attention-center"', 1)[-1].split('id="coverage-center"', 1)[0]
    flag2_row = log_rows(dom_explain).get('flag:flag-2', '')
    check(
        'attention: a benign-likely explained finding is not a decision; it is a history row with its verdict',
        (
            'flag-2' not in attn
            and 'Sensitive file read near an outside connection' in flag2_row
            and '<span class="c-verdict-text">Likely benign (advisor 93 %)</span>' in flag2_row
            and dom_query(flag2_row).has(None, {'data-action': 'explain-act', 'data-flag-id': 'flag-2', 'data-action-id': 'allow-host'})
        ),
        f'row={flag2_row[:200]!r}',
    )

def run_finding_row_3(page):
    check = page.check
    dom_detailsprobe = page.fixture('dom_detailsprobe')
    dom_explain = page.fixture('dom_explain')
    probe = pre(dom_detailsprobe, 'details-probe')
    check(
        'finding row: an open Evidence section survives a burst of re-renders',
        probe == 'kept',
        f'probe={probe!r}',
    )
    flag3 = log_rows(dom_explain).get('flag:flag-3', '')
    check(
        "finding row: a flag without explain opens to its evidence lines and the console's Dismiss and Kill",
        (
            dom_query(flag3).has(None, {'class': 'flag-evidence'})
            and dom_query(flag3).has(None, {'data-action': 'dismiss-flag', 'data-id': 'flag-3'})
            and dom_query(flag3).has(None, {'data-action': 'kill'})
        ),
        f'row={flag3[:200]!r}',
    )

def run_sticky_tabs(page):
    check = page.check
    dom = page.fixture('dom')
    dom_sticky = page.fixture('dom_sticky')
    needs_you = json.loads(html.unescape(pre(dom, 'fixture-posture')))['needs_you']
    sticky = pre(dom_sticky, 'sticky-probe')
    m = re.match('top=(-?\\d+) scroll=(\\d+) stuck=(\\w+) pill=(\\w+):(.*)$', sticky)
    check(
        'sticky tabs: after scrolling 5000 px on Attention the tablist sits at the top with the posture pill',
        (
            m is not None
            and 0 <= int(m.group(1)) < 60
            and int(m.group(2)) > 0
            and m.group(3) == 'true'
            and m.group(4) == 'visible'
            and m.group(5) == f'{needs_you} need you'
        ),
        f'probe={sticky!r}',
    )

def run_drawer_back(page):
    check = page.check
    dom_drawerback = page.fixture('dom_drawerback')
    back = pre(dom_drawerback, 'drawer-back-probe')
    m = re.match('chained: back=(.*) title=(.*) \\| back: title=(.*) rows=(\\d+) button=(\\w+) open=(\\w+)$', back)
    check(
        'drawer back: Evidence from the Uninspected drawer shows ‹ Uninspected egress; Back reopens the list',
        (
            m is not None
            and m.group(1) == '‹ Uninspected egress'
            and m.group(2) == 'Endpoint detail'
            and m.group(3) == 'Uninspected egress — last 24h'
            and int(m.group(4)) > 0
            and m.group(5) == 'absent'
            and m.group(6) == 'true'
        ),
        f'probe={back!r}',
    )

def run_scope_bar(page):
    check = page.check
    dom_scope = page.fixture('dom_scope')
    scope = pre(dom_scope, 'scope-probe')
    m = re.match('tab=(\\w+) bar=(\\w+):(.*) \\| scoped rows=(\\d+) \\| cleared bar=(\\w+):(.*) rows=(\\d+) chip=(\\w+)$', scope)
    check(
        'scope bar: View session shows the scope on Sessions; Clear hides it and Events shows every row',
        (
            m is not None
            and m.group(1) == 'sessions'
            and m.group(2) == 'visible'
            and m.group(3).startswith('Scoped to session ')
            and re.search(' · \\d+ events? · \\d+ flags?Back to sessionClear$', m.group(3))
            and m.group(5) == 'hidden'
            and m.group(6) == ''
            and int(m.group(7)) > int(m.group(4))
            and m.group(8) == 'hidden'
        ),
        f'probe={scope!r}',
    )

def run_attention_badge_and_tab_badge_equal_posture_needs_you_coverage_stays_separate(page):
    check = page.check
    dom = page.fixture('dom')
    needs_you = json.loads(html.unescape(pre(dom, 'fixture-posture')))['needs_you']
    attention = dom.split('id="attention-center"', 1)[1].split('id="security-findings-grid"', 1)[0]
    coverage = attention.split('id="coverage-center"', 1)[1].split('id="home-spend"', 1)[0]
    attention_badge = (re.search('id="badge-attention-count"[^>]*>(\\d+)<', dom) or [None, ''])[1]
    tab_badge = (re.search('id="tab-badge-home"[^>]*>(\\d+)<', dom) or [None, ''])[1]
    check(
        'attention badge and tab badge equal posture.needs_you; coverage stays separate',
        (
            attention_badge == str(needs_you)
            and tab_badge == str(needs_you)
            and '<strong>File monitoring is off</strong>' in coverage
            and dom_query(coverage).has(None, {'data-action': 'open-fda'})
            and not dom_query(attention).has(None, {'data-id': 'flag-3'})
            and dom_query(dom).has(None, {'data-row-key': 'flag:flag-3'})
        ),
        f'badge={attention_badge!r} tab={tab_badge!r} needs_you={needs_you}',
    )

def run_github_grouped_finding_exposes_approval_local_review_and_inspection(page):
    check = page.check
    dom_gh = page.fixture('dom_gh')
    gh_cards = dom_gh.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
    check(
        'GitHub grouped finding exposes approval, local review and inspection',
        all((f'data-action-id="{action}"' in gh_cards for action in ('expect', 'review-local', 'inspect-file'))),
    )

def run_github_approval_posts_the_served_exact_scope_and_reconciles_to_reviewed(page):
    check = page.check
    dom_ghapprove = page.fixture('dom_ghapprove')
    check(
        'GitHub approval posts the served exact scope and reconciles to reviewed',
        (
            'POST /expected body={"flag_id":"gh-flag","path":"/Users/dev/.config/gh/hosts.yml","host":"140.82.114.6"}' in pre(dom_ghapprove, 'mock-requests')
            and '<b class="pattern-open">0 open</b>' in dom_ghapprove
        ),
    )

def run_patterns(page):
    check = page.check
    dom_csp = page.fixture('dom_csp')
    dom_hiddenrender = page.fixture('dom_hiddenrender')
    dom_pattern = page.fixture('dom_pattern')
    dom_patternact = page.fixture('dom_patternact')
    dom_patternphone = page.fixture('dom_patternphone')
    dom_patternstream = page.fixture('dom_patternstream')
    csp_widths = (re.search('data-csp-widths="([^"]*)"', dom_csp) or [None, ''])[1]
    widths = {k: float(v) for k, v in (kv.split(':') for kv in csp_widths.split(',') if kv)}
    hrp = (re.search('<pre id="hidden-render-probe"[^>]*>(.*?)</pre>', dom_hiddenrender, re.S) or [None, ''])[1]
    hrp_stages = dict(re.findall('(boot|refresh|search|shown):((?:[a-z-]+=\\d+,?)+)', hrp))

    def hrp_zero(stage):
        counts = dict(re.findall('([a-z-]+)=(\\d+)', hrp_stages.get(stage, '')))
        return len(counts) == 4 and all((v == '0' for v in counts.values()))

    def hrp_shown():
        counts = dict(re.findall('([a-z-]+)=(\\d+)', hrp_stages.get('shown', '')))
        return len(counts) == 4 and all((int(v) >= 1 for v in counts.values()))
    pat_flags = dom_pattern.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
    pat_rows = log_rows(pat_flags)
    pat_cards = [(k, v) for k, v in pat_rows.items() if k.startswith('pattern:')]
    check(
        'patterns: History shows the storm as one row, its body with the count, summary, 24 bars and open count',
        (
            len(pat_cards) == 1
            and '323×' in pat_cards[0][1]
            and 'codex touched the login keychain 323 times' in pat_cards[0][1]
            and len(re.findall('<i class="h\\d"></i>', (re.search('<span class="pattern-bars" role="img"[^>]*>(.*?)</span>', pat_cards[0][1], re.S) or [None, ''])[1])) == 24
            and '<b class="pattern-open">323 open</b>' in pat_cards[0][1]
            and not dom_query(pat_flags).has(None, {'data-row-key': 'flag:flag-6'})
            and not dom_query(pat_flags).has(None, {'data-row-key': 'flag:flag-7'})
            and all((f'data-action="open-flag" data-id="{fid}"' in pat_cards[0][1] for fid in ('flag-6', 'flag-7')))
        ),
        f'cards={len(pat_cards)}',
    )
    pat_standalone = ''.join((v for k, v in pat_rows.items() if not k.startswith('pattern:')))
    check(
        'patterns: critical individual flags lead warnings without duplicating covered flags',
        (
            dom_query(pat_flags).has(None, {'data-pattern-key': starts_with('codex|keychain-access|')})
            and pat_flags.index('data-id="flag-1"') < pat_flags.index('data-pattern-key=') < pat_flags.index('data-id="flag-3"')
            and not any((f'data-id="{fid}"' in pat_standalone or f'data-flag-id="{fid}"' in pat_standalone for fid in ('flag-6', 'flag-7')))
            and '(PID 40844)' not in pat_flags
            and '(PID 51364)' not in pat_flags
            and dom_query(pat_flags).has(None, {'data-id': 'flag-3'})
        ),
    )
    pat_reqs = pre(dom_patternact, 'mock-requests')
    check(
        'patterns: dismiss-all posts the served flag_ids and the row shows 0 open',
        (
            'POST /flags/acknowledge body={"flag_ids":["flag-7","flag-6"]}' in pat_reqs
            and re.search('<div class="row-body" data-pattern-key="[^"]+">.*?<b class="pattern-open">0 open</b>', dom_patternact, re.S) is not None
            and '<b class="pattern-open">323 open</b>' not in dom_patternact
        ),
        f'requests={pat_reqs!r}',
    )
    check(
        "patterns: the page still fits a 375px phone, the pattern card's tab included",
        dom_query(dom_patternphone).has(None, {'data-hscroll': 'sessions:0,agents:0,resources:0,findings:0'}),
        (re.search('data-hscroll="[^"]*"', dom_patternphone) or [None])[0],
    )
    stream = pre(dom_patternstream, 'pattern-stream-probe')
    check(
        'patterns: a streamed flag the pattern covers folds into its one card after the debounced reconcile',
        stream == 'mid cards=1 covered=0 row=1 | end cards=1 covered=1 row=0',
        f'probe={stream!r}',
    )

def run_history(page):
    check = page.check
    dom_attnkeep = page.fixture('dom_attnkeep')
    keep = pre(dom_attnkeep, 'attn-probe')
    check(
        'history: an open pattern disclosure and a focused button survive a session RSS change; Needs you shows the new memory and never the pattern',
        (
            keep.startswith('open=true focus=true queued=false metrics=')
            and '700 MB memory' in keep
        ),
        f'probe={keep!r}',
    )

def run_a_61_flag_pattern_is_exactly_one_history_row_reading_61(page):
    check = page.check
    dom_csp = page.fixture('dom_csp')
    dom_hiddenrender = page.fixture('dom_hiddenrender')
    dom_pattern = page.fixture('dom_pattern')
    dom_patternbig = page.fixture('dom_patternbig')
    csp_widths = (re.search('data-csp-widths="([^"]*)"', dom_csp) or [None, ''])[1]
    widths = {k: float(v) for k, v in (kv.split(':') for kv in csp_widths.split(',') if kv)}
    hrp = (re.search('<pre id="hidden-render-probe"[^>]*>(.*?)</pre>', dom_hiddenrender, re.S) or [None, ''])[1]
    hrp_stages = dict(re.findall('(boot|refresh|search|shown):((?:[a-z-]+=\\d+,?)+)', hrp))

    def hrp_zero(stage):
        counts = dict(re.findall('([a-z-]+)=(\\d+)', hrp_stages.get(stage, '')))
        return len(counts) == 4 and all((v == '0' for v in counts.values()))

    def hrp_shown():
        counts = dict(re.findall('([a-z-]+)=(\\d+)', hrp_stages.get('shown', '')))
        return len(counts) == 4 and all((int(v) >= 1 for v in counts.values()))
    pat_flags = dom_pattern.split('id="flags-list"', 1)[-1].split('id="incidents-container"', 1)[0]
    pat_rows = log_rows(pat_flags)
    pat_cards = [(k, v) for k, v in pat_rows.items() if k.startswith('pattern:')]
    pat_standalone = ''.join((v for k, v in pat_rows.items() if not k.startswith('pattern:')))
    big_rows = log_rows(dom_patternbig)
    big_pattern = [k for k in big_rows if k.startswith('pattern:')]
    check(
        'a 61-flag pattern is exactly one history row reading 61×',
        (
            len(big_pattern) == 1
            and '<span class="c-count">61×</span>' in big_rows[big_pattern[0]]
            and not [k for k in big_rows if k.startswith('flag:kc-')]
        ),
        f'rows={list(big_rows)[:6]}',
    )

def run_bulk_mark_reviewed_on_two_selected_rows_asks_one_confirm_and_sends_one_acknowledge_batch(page):
    check = page.check
    dom_bulk = page.fixture('dom_bulk')
    bulk_reqs = pre(dom_bulk, 'mock-requests')
    check(
        'bulk Mark reviewed on two selected rows asks one confirm and sends one acknowledge batch',
        (
            pre(dom_bulk, 'bulk-probe') == 'confirms=1'
            and bulk_reqs.count('POST /flags/acknowledge') == 1
            and re.search('POST /flags/acknowledge body=\\{"flag_ids":\\["flag-[13]","flag-[13]"\\]\\}', bulk_reqs) is not None
        ),
        f"probe={pre(dom_bulk, 'bulk-probe')!r} requests={bulk_reqs!r}",
    )

def run_empty_posture(page):
    check = page.check
    dom_empty = page.fixture('dom_empty')
    empty_need = dom_empty.split('id="attention-center"', 1)[-1].split('id="home-spend"', 1)[0]
    check(
        'empty posture: Needs you, the Monitoring gap and the Home tab badge are all hidden',
        (
            re.search('<section[^>]*id="attention-center"[^>]*\\bhidden', dom_empty) is not None
            and re.search('id="coverage-center"[^>]*\\bhidden', dom_empty) is not None
            and re.search('id="tab-badge-home"[^>]*\\bhidden', dom_empty) is not None
            and 'No pending decisions' not in empty_need
            and not dom_query(empty_need).has(None, {'class': 'need '})
        ),
    )

def run_auth_recovery(page):
    check = page.check
    for label, query, size in [('memory', '?authrecover&authhistory', (1280, 800)), ('trace', '?authrecover&authtrace', (900, 768))]:
        recovery_dom = page.dom(query, window_size=size, served=True)
        receipt = re.search('data-auth-recovery="([^"]+)"', recovery_dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        check(
            f'console recovery ({label}): receipt produced',
            bool(state),
            str(state),
        )
        for name, result in state.items():
            check(
                f'console recovery ({label}): {name}',
                result is True,
                str(result),
            )
    first_connect = page.dom('?notokenrecover', served=True)
    check(
        'credential handoff connects an initially unauthenticated tab without reload',
        (
            'id="count-agents">3<' in first_connect
            and not dom_query(first_connect).has(None, {'class': 'is-ended'})
            and re.search('<section[^>]*id="session-ended"[^>]*\\bhidden\\b', first_connect) is not None
        ),
    )
    network_recovery = page.dom('?networkrecover', served=True)
    check(
        'connection failure retains cached data with a last-connected time; Retry now reconnects',
        (
            '<pre id="network-retained" hidden="">true</pre>' in network_recovery
            and '<pre id="network-recovered" hidden="">true</pre>' in network_recovery
        ),
    )
    permission_denial = page.dom('?permissiondeny', served=True)
    check(
        'permission denial retains console authentication and its live stream',
        '<pre id="permission-retained" hidden="">true</pre>' in permission_denial,
    )

CASES = (
    Case('resource_results', run_resource_results, ('dom_resource_results',)),
    Case('group_head_carries_mark_display_name_and_counts', run_group_head_carries_mark_display_name_and_counts, ('dom',)),
    Case('sub_session_nests_under_its_parent', run_sub_session_nests_under_its_parent, ('dom',)),
    Case('live_only_hides_a_harness_with_nothing_running', run_live_only_hides_a_harness_with_nothing_running, ('dom',)),
    Case('live_cards_carry_kill_ended_cards_do_not', run_live_cards_carry_kill_ended_cards_do_not, ('dom',)),
    Case('count_strip_shows_sessions_harnesses_and_coverage', run_count_strip_shows_sessions_harnesses_and_coverage, ('dom',)),
    Case('one_filter_pill_per_live_harness', run_one_filter_pill_per_live_harness, ('dom',)),
    Case('a_switched_off_pill_hides_its_group', run_a_switched_off_pill_hides_its_group, ('dom_pill',)),
    Case('empty_rail_says_all_quiet', run_empty_rail_says_all_quiet, ('dom_quiet',)),
    Case('filter_that_hides_everything_offers_to_clear_it', run_filter_that_hides_everything_offers_to_clear_it, ('dom_nomatch',)),
    Case('the_page_posture_banner_included_fits_a_375px_phone_on_sessions_agents_and_resources', run_the_page_posture_banner_included_fits_a_375px_phone_on_sessions_agents_and_resources, ('dom_phone',)),
    Case('phone_overflow_probe', run_phone_overflow_probe, ('dom_phone',)),
    Case('detail_head', run_detail_head, ('dom_rail',)),
    Case('detail_chrome_keeps_copy_report_reachable_and_the_copyable_path_in_expandable_details', run_detail_chrome_keeps_copy_report_reachable_and_the_copyable_path_in_expandable_details, ('dom_rail',)),
    Case('export_copies_the_markdown_session_report_and_toasts', run_export_copies_the_markdown_session_report_and_toasts, ('dom_export',)),
    Case('home_session_opens_its_current_controls_evidence_and_observed_coverage', run_home_session_opens_its_current_controls_evidence_and_observed_coverage, ('dom_overview',)),
    Case('home_session_opens_current_status_in_the_workbench_viewport', run_home_session_opens_current_status_in_the_workbench_viewport, ('dom_overview',)),
    Case('failed_overview_refresh_preserves_facts_with_disabled_controls_and_a_visible_stale_warning', run_failed_overview_refresh_preserves_facts_with_disabled_controls_and_a_visible_stale_warning, ('dom_overview_stale',)),
    Case('late_session_overview_cannot_overwrite_the_newly_selected_session', run_late_session_overview_cannot_overwrite_the_newly_selected_session, ('dom_overview_race',)),
    Case('new_findings_preserve_the_focused_guard_control', run_new_findings_preserve_the_focused_guard_control, ('dom_overview_focus',)),
    Case('late_response_from_previous_selection_cannot_replace_memory', run_late_response_from_previous_selection_cannot_replace_memory, ('dom_memory_race',)),
    Case('trace_refetches_after_an_event_arrives_while_memory_is_active', run_trace_refetches_after_an_event_arrives_while_memory_is_active, ('dom_trace_reactivation',)),
    Case('waterfall_carries_model_usage_row', run_waterfall_carries_model_usage_row, ('dom_rail',)),
    Case('waterfall_marks_tool_errors', run_waterfall_marks_tool_errors, ('dom_rail',)),
    Case('theme', run_theme, ('dom_themefirst',)),
    Case('under_the_daemon_csp_the_waterfall_bar_ranked_bar_and_memory_segment_keep_their_widths', run_under_the_daemon_csp_the_waterfall_bar_ranked_bar_and_memory_segment_keep_their_widths, ('dom_csp',)),
    Case('version_badge_comes_from_status', run_version_badge_comes_from_status, ('dom',)),
    Case('posture_banner_is_critical', run_posture_banner_is_critical, ('dom',)),
    Case('posture_headline_rendered', run_posture_headline_rendered, ('dom',)),
    Case('kpi_agents_count', run_kpi_agents_count, ('dom',)),
    Case('kpi_flags_are_unacted_last_24h', run_kpi_flags_are_unacted_last_24h, ('dom',)),
    Case('kpi_incidents_count', run_kpi_incidents_count, ('dom',)),
    Case('empty_spend_report', run_empty_spend_report, ('dom_nocosts',)),
    Case('console', run_console, ('dom_attentionremodel', 'dom_remodelusage')),
    Case('a_switched_off_pill_hides_the_harness_in_agents_too', run_a_switched_off_pill_hides_the_harness_in_agents_too, ('dom_pill',)),
    Case('claude_instance_pid', run_claude_instance_pid, ('dom',)),
    Case('nested_helper_pid', run_nested_helper_pid, ('dom',)),
    Case('leftover_cursor_status', run_leftover_cursor_status, ('dom',)),
    Case('terminate_not_labelled_kill', run_terminate_not_labelled_kill, ('dom',)),
    Case('firewall_enforcing_badge', run_firewall_enforcing_badge, ('dom',)),
    Case('egress_coverage_names_the_displayed_sample_without_implying_findings', run_egress_coverage_names_the_displayed_sample_without_implying_findings, ('dom',)),
    Case('blocking_rule_shows_demote_button', run_blocking_rule_shows_demote_button, ('dom',)),
    Case('demote_flips_the_rule_back_to_promote', run_demote_flips_the_rule_back_to_promote, ('dom_demote',)),
    Case('remove_drops_the_allowlist_row', run_remove_drops_the_allowlist_row, ('dom_allowrm',)),
    Case('drill_down_keeps_unknown_endpoints_actionable', run_drill_down_keeps_unknown_endpoints_actionable, ('dom_uninsp',)),
    Case('drill_down_collapses_cdn_cloud_carriers', run_drill_down_collapses_cdn_cloud_carriers, ('dom_uninsp',)),
    Case('drill_down_rolls_vendor_apis_up_per_agent_and_vendor', run_drill_down_rolls_vendor_apis_up_per_agent_and_vendor, ('dom_uninsp',)),
    Case('unknown_section_does_not_list_vendor_endpoints', run_unknown_section_does_not_list_vendor_endpoints, ('dom_uninsp',)),
    Case('unknown_section_keeps_cloud_hosts_named', run_unknown_section_keeps_cloud_hosts_named, ('dom_uninsp',)),
    Case('egress_rows_show_first_seen_and_session', run_egress_rows_show_first_seen_and_session, ('dom_uninsp',)),
    Case('egress_bulk_allow_groups_same_suffix_hosts', run_egress_bulk_allow_groups_same_suffix_hosts, ('dom_uninsp',)),
    Case('egress_explains_what_the_list_is_and_what_to_do', run_egress_explains_what_the_list_is_and_what_to_do, ('dom_uninsp',)),
    Case('egress_rows_carry_a_plain_allow_action', run_egress_rows_carry_a_plain_allow_action, ('dom_uninsp',)),
    Case('egress_rows_offer_on_demand_advisor_assessment', run_egress_rows_offer_on_demand_advisor_assessment, ('dom_uninsp',)),
    Case('egress_rows_with_a_verdict_show_the_advisor_chip', run_egress_rows_with_a_verdict_show_the_advisor_chip, ('dom_uninsp',)),
    Case('drawer_is_open_for_the_drill_down', run_drawer_is_open_for_the_drill_down, ('dom_toast',)),
    Case('toast_rendered_while_the_drawer_is_open', run_toast_rendered_while_the_drawer_is_open, ('dom_toast',)),
    Case('vendor_key_promote_banner', run_vendor_key_promote_banner, ('dom',)),
    Case('incident_row_reads_its_risk_and_workflow', run_incident_row_reads_its_risk_and_workflow, ('dom',)),
    Case('payload_incident_preserves_mixed_results_after_reported_resolution', run_payload_incident_preserves_mixed_results_after_reported_resolution, ('dom_payload',)),
    Case('payload_finding_names_the_local_forwarding_gate_and_registered_match', run_payload_finding_names_the_local_forwarding_gate_and_registered_match, ('dom_payload',)),
    Case('secret_sources_rendered', run_secret_sources_rendered, ('dom',)),
    Case('chain_rendered_with_3_nodes', run_chain_rendered_with_3_nodes, ('dom',)),
    Case('chain_node', run_chain_node, ('dom',)),
    Case('chain_verdict_node', run_chain_verdict_node, ('dom',)),
    Case('history_lists_every_flag_as_one_log_row_the_critical_ones_first', run_history_lists_every_flag_as_one_log_row_the_critical_ones_first, ('dom',)),
    Case('an_unexplained_flag_s_evidence_rows_render_as_text_not_object_object', run_an_unexplained_flag_s_evidence_rows_render_as_text_not_object_object, ('dom',)),
    Case('sparkline_has_points', run_sparkline_has_points, ('dom',)),
    Case('sparkline_rate_label', run_sparkline_rate_label, ('dom',)),
    Case('fresh_timeline_rows_after_sse_drip', run_fresh_timeline_rows_after_sse_drip, ('dom_events',)),
    Case('timeline_times_are_hh', run_timeline_times_are_hh, ('dom',)),
    Case('advisor_chip_rendered_with_assessment_class', run_advisor_chip_rendered_with_assessment_class, ('dom',)),
    Case('advisor_chip_rationale_in_tooltip', run_advisor_chip_rationale_in_tooltip, ('dom',)),
    Case('stale_process_marked', run_stale_process_marked, ('dom',)),
    Case('flag_card_kill_action', run_flag_card_kill_action, ('dom',)),
    Case('collector_down_fda_deep_link', run_collector_down_fda_deep_link, ('dom',)),
    Case('advisor_posture_line_separates_opinion_from_evidence_and_risk_off_home', run_advisor_posture_line_separates_opinion_from_evidence_and_risk_off_home, ('dom_tab',)),
    Case('incident_narrative_rendered_in_its_row_s_body', run_incident_narrative_rendered_in_its_row_s_body, ('dom', 'dom_csp')),
    Case('egress_suggestion_rendered', run_egress_suggestion_rendered, ('dom',)),
    Case('suggestion_advisor_chip', run_suggestion_advisor_chip, ('dom',)),
    Case('suggestion_allow_button_is_delegated', run_suggestion_allow_button_is_delegated, ('dom',)),
    Case('activity_chart_draws_event_bars', run_activity_chart_draws_event_bars, ('dom',)),
    Case('activity_chart_marks_the_flag_hour', run_activity_chart_marks_the_flag_hour, ('dom',)),
    Case('activity_chart_zero_fills_empty_hours', run_activity_chart_zero_fills_empty_hours, ('dom',)),
    Case('rule_level_mute_renders_as_all_hosts', run_rule_level_mute_renders_as_all_hosts, ('dom',)),
    Case('keychain_flag_carries_class_dismiss_action', run_keychain_flag_carries_class_dismiss_action, ('dom',)),
    Case('uninspected_warning_is_a_clickable_drill_down', run_uninspected_warning_is_a_clickable_drill_down, ('dom',)),
    Case('home', run_home, ('dom',)),
    Case('egress', run_egress, ('dom_posturemore',)),
    Case('and_n_more_lands_on_home_where_the_banner_lists_nothing', run_and_n_more_lands_on_home_where_the_banner_lists_nothing, ('dom_posturemore',)),
    Case('egress_2', run_egress_2, ('dom_fold',)),
    Case('processes_panel_fills_the_content_width_at_1440_px', run_processes_panel_fills_the_content_width_at_1440_px, ('dom_procwidth',)),
    Case('drill_down_drawer_title', run_drill_down_drawer_title, ('dom_uninsp',)),
    Case('drill_down_lists_endpoint_host', run_drill_down_lists_endpoint_host, ('dom_uninsp',)),
    Case('drill_down_allow_action_delegated', run_drill_down_allow_action_delegated, ('dom_uninsp',)),
    Case('drill_down_explains_the_blind_spot', run_drill_down_explains_the_blind_spot, ('dom_uninsp',)),
    Case('drill_down_vendor_disclosure_stays_open_across_an_allow_refill', run_drill_down_vendor_disclosure_stays_open_across_an_allow_refill, ('dom_keepopen',)),
    Case('drill_down_allow_refill_posted_and_dropped_the_row', run_drill_down_allow_refill_posted_and_dropped_the_row, ('dom_keepopen',)),
    Case('incident_accessed_files_path_is_a_file_link', run_incident_accessed_files_path_is_a_file_link, ('dom_file',)),
    Case('file_drawer_shows_the_masked_excerpt_never_an_unmasked_value', run_file_drawer_shows_the_masked_excerpt_never_an_unmasked_value, ('dom_file',)),
    Case('file_drawer_offers_reveal_in_finder_and_open_in_editor', run_file_drawer_offers_reveal_in_finder_and_open_in_editor, ('dom_file',)),
    Case('file_drawer_lists_findings_agent_access_and_the_session', run_file_drawer_lists_findings_agent_access_and_the_session, ('dom_file',)),
    Case('file_drawer_goes_back_to_the_incident_report', run_file_drawer_goes_back_to_the_incident_report, ('dom_file',)),
    Case('file_drawer_shows_the_advisor_plan_and_the_playbook', run_file_drawer_shows_the_advisor_plan_and_the_playbook, ('dom_file',)),
    Case('finding_cards_offer_what_to_do', run_finding_cards_offer_what_to_do, ('dom_explain',)),
    Case('finding_cards_offer_mark_as_routine_not_ok', run_finding_cards_offer_mark_as_routine_not_ok, ('dom_explain',)),
    Case('file_drawer_shows_the_operator_s_history_and_suggestion', run_file_drawer_shows_the_operator_s_history_and_suggestion, ('dom_file',)),
    Case('menubar_deep_link_file_opens_the_file_drawer', run_menubar_deep_link_file_opens_the_file_drawer, ('dom_filedeep',)),
    Case('endpoint_evidence_opens_a_detail_drawer', run_endpoint_evidence_opens_a_detail_drawer, ('dom_endpoint',)),
    Case('endpoint_detail_names_the_owner_not_a_bare_address', run_endpoint_detail_names_the_owner_not_a_bare_address, ('dom_endpoint',)),
    Case('endpoint_detail_shows_which_agent_and_session_reached_it', run_endpoint_detail_shows_which_agent_and_session_reached_it, ('dom_endpoint',)),
    Case('endpoint_detail_lists_recent_connections', run_endpoint_detail_lists_recent_connections, ('dom_endpoint',)),
    Case('notify_bell_present', run_notify_bell_present, ('dom',)),
    Case('notify_popover_renders_rules', run_notify_popover_renders_rules, ('dom_notify',)),
    Case('notify_override_pre_selected', run_notify_override_pre_selected, ('dom_notify',)),
    Case('notify_popover_lists_workspace_scopes', run_notify_popover_lists_workspace_scopes, ('dom_notify',)),
    Case('notify_popover_offers_adding_a_workspace_scope', run_notify_popover_offers_adding_a_workspace_scope, ('dom_notify',)),
    Case('notify_add_scope_input_survives_a_reconcile_that_changes_notifycfg', run_notify_add_scope_input_survives_a_reconcile_that_changes_notifycfg, ('dom_notifyfocus',)),
    Case('delayed_spend_refresh_retains_totals_rows_and_plan_headroom_with_a_quiet_status', run_delayed_spend_refresh_retains_totals_rows_and_plan_headroom_with_a_quiet_status, ('dom', 'dom_spendshape')),
    Case('first_load_malformed_spend_reports_retry_quietly_without_inventing_empty_results', run_first_load_malformed_spend_reports_retry_quietly_without_inventing_empty_results, ('dom', 'dom_spendshapefirst')),
    Case('valid_spend_recovery_clears_the_delayed_refresh_status', run_valid_spend_recovery_clears_the_delayed_refresh_status, ('dom_spendshaperecover',)),
    Case('malformed_containers_retain_prior_results_with_a_stale_warning', run_malformed_containers_retain_prior_results_with_a_stale_warning, ('dom', 'dom_slowshape', 'dom_slowshapefirst', 'dom_slowshaperecover')),
    Case('malformed_slow_reports_preserve_resource_rendering_and_healthy_live_telemetry', run_malformed_slow_reports_preserve_resource_rendering_and_healthy_live_telemetry, ('dom_slowshape',)),
    Case('resource_request_failure_preserves_data_with_a_persistent_stale_notice', run_resource_request_failure_preserves_data_with_a_persistent_stale_notice, ('dom', 'dom_health')),
    Case('first_load_audit_failure_is_explicitly_unavailable', run_first_load_audit_failure_is_explicitly_unavailable, ('dom', 'dom_health')),
    Case('unreadable_guard_response_shows_stale_decisions_despite_a_healthy_snapshot', run_unreadable_guard_response_shows_stale_decisions_despite_a_healthy_snapshot, ('dom_health',)),
    Case('successful_recovery_clears_stale_and_unavailable_notices', run_successful_recovery_clears_stale_and_unavailable_notices, ('dom', 'dom_healthrecover')),
    Case('failed_filtered_refresh_preserves_matching_rows_and_warns_stale', run_failed_filtered_refresh_preserves_matching_rows_and_warns_stale, ('dom', 'dom_historyevents', 'dom_historyeventschanged', 'dom_historyflags', 'dom_historyflagschanged')),
    Case('empty_filtered_findings_recover_successfully_and_clear_the_stale_warning', run_empty_filtered_findings_recover_successfully_and_clear_the_stale_warning, ('dom', 'dom_historyrecover')),
    Case('malformed_snapshot_and_guard_containers_retain_last_good_metrics_with_persistent_warnings', run_malformed_snapshot_and_guard_containers_retain_last_good_metrics_with_persistent_warnings, ('dom', 'dom_malformed')),
    Case('a_failed_snapshot_retains_critical_posture_with_a_visible_freshness_warning_and_retry', run_a_failed_snapshot_retains_critical_posture_with_a_visible_freshness_warning_and_retry, ('dom_malformed',)),
    Case('snapshot_failure_is_not_repeated_in_panels_while_the_independent_guard_failure_remains_visible', run_snapshot_failure_is_not_repeated_in_panels_while_the_independent_guard_failure_remains_visible, ('dom', 'dom_malformed')),
    Case('snapshot_recovery_clears_the_primary_freshness_warning_and_retry', run_snapshot_recovery_clears_the_primary_freshness_warning_and_retry, ('dom_malformed', 'dom_malformedrecover')),
    Case('valid_hot_responses_recover_from_malformed_containers', run_valid_hot_responses_recover_from_malformed_containers, ('dom', 'dom_malformedrecover')),
    Case('a_delayed_older_snapshot_cannot_replace_a_newer_manual_refresh', run_a_delayed_older_snapshot_cannot_replace_a_newer_manual_refresh, ('dom_refreshrace',)),
    Case('auth_expired_shows_the_ended_state_not_daemon_down', run_auth_expired_shows_the_ended_state_not_daemon_down, ('dom_authfail',)),
    Case('a_403_hides_the_posture_counts_and_panels_and_closes_the_stream', run_a_403_hides_the_posture_counts_and_panels_and_closes_the_stream, ('dom_authfail',)),
    Case('endpoint_403_ends_the_console_even_when_snapshot_succeeds', run_endpoint_403_ends_the_console_even_when_snapshot_succeeds, ('dom_authmixed', 'dom_spendauth')),
    Case('no_token_at_load', run_no_token_at_load, ('dom_notoken',)),
    Case('a_token_at_load', run_a_token_at_load, ('dom',)),
    Case('unreachable_shows_the_retry_banner', run_unreachable_shows_the_retry_banner, ('dom_netfail',)),
    Case('unreachable_sets_disconnected_chip', run_unreachable_sets_disconnected_chip, ('dom_netfail',)),
    Case('unavailable_first_telemetry_cannot_show_a_green_primary_status', run_unavailable_first_telemetry_cannot_show_a_green_primary_status, ('dom_netfail',)),
    Case('token_survives_reload_via_sessionstorage', run_token_survives_reload_via_sessionstorage, ('dom_tokenseed',)),
    Case('fleet_card_renders_the_local_node_object', run_fleet_card_renders_the_local_node_object, ('dom',)),
    Case('fleet_panel_visible_when_a_collector_is_configured', run_fleet_panel_visible_when_a_collector_is_configured, ('dom',)),
    Case('fleet_panel_hides_when_no_collector_is_configured', run_fleet_panel_hides_when_no_collector_is_configured, ('dom_nofleet',)),
    Case('panels_after_fleet_still_render', run_panels_after_fleet_still_render, ('dom',)),
    Case('tab_bar_renders_five_tabs_with_protection_grouping_and_agent_last', run_tab_bar_renders_five_tabs_with_protection_grouping_and_agent_last, ('dom',)),
    Case('the_attention_panel_lives_in_home_first', run_the_attention_panel_lives_in_home_first, ('dom',)),
    Case('home_tab_active_by_default', run_home_tab_active_by_default, ('dom',)),
    Case('non_active_panels_hidden', run_non_active_panels_hidden, ('dom',)),
    Case('home_panel_visible', run_home_panel_visible, ('dom',)),
    Case('home_opens_usage_by_default_and_keeps_findings_and_trends_closed', run_home_opens_usage_by_default_and_keeps_findings_and_trends_closed, ('dom',)),
    Case('hash_agents_opens_sessions_on_the_processes_sub_view', run_hash_agents_opens_sessions_on_the_processes_sub_view, ('dom_hashagents',)),
    Case('hash_opens_the_system_tab', run_hash_opens_the_system_tab, ('dom_hashsessionswt', 'dom_hashworktrees')),
    Case('hash_findings_opens_home', run_hash_findings_opens_home, ('dom_hashfindings',)),
    Case('trends_closed', run_trends_closed, ('dom_trends',)),
    Case('hidden_panels', run_hidden_panels, ('dom_csp', 'dom_hiddenrender')),
    Case('forget_deletes_the_expected_pattern_and_the_list_reloads_without_it', run_forget_deletes_the_expected_pattern_and_the_list_reloads_without_it, ('dom_forget',)),
    Case('resource_mission_control_is_present', run_resource_mission_control_is_present, ('dom',)),
    Case('whole_machine_headroom_is_visible', run_whole_machine_headroom_is_visible, ('dom',)),
    Case('headroom_hint_explains_the_score_is_the_tightest_limit', run_headroom_hint_explains_the_score_is_the_tightest_limit, ('dom',)),
    Case('headroom_hint_fits_its_panel_at_desktop_and_phone_widths', run_headroom_hint_fits_its_panel_at_desktop_and_phone_widths, ('dom_headroomphone', 'dom_headroomwide')),
    Case('live_resources_exclude_the_flight_recorder', run_live_resources_exclude_the_flight_recorder, ('dom',)),
    Case('whole_machine_cpu_swap_and_thermal_context_are_visible', run_whole_machine_cpu_swap_and_thermal_context_are_visible, ('dom',)),
    Case('high_impact_session_shows_cpu_and_memory', run_high_impact_session_shows_cpu_and_memory, ('dom',)),
    Case('resource_diagnosis_explains_the_pressure', run_resource_diagnosis_explains_the_pressure, ('dom',)),
    Case('resource_flight_recorder_preserves_exited_sessions', run_resource_flight_recorder_preserves_exited_sessions, ('dom',)),
    Case('resource_flight_recorder_remains_visible_with_no_live_sessions', run_resource_flight_recorder_remains_visible_with_no_live_sessions, ('dom_noresources',)),
    Case('resource_flight_recorder_identifies_the_dominant_process', run_resource_flight_recorder_identifies_the_dominant_process, ('dom',)),
    Case('resource_pressure_episode_explains_correlated_activity', run_resource_pressure_episode_explains_correlated_activity, ('dom',)),
    Case('pressure_episode_preserves_captured_machine_context', run_pressure_episode_preserves_captured_machine_context, ('dom',)),
    Case('resource_pressure_chart_includes_activity_markers', run_resource_pressure_chart_includes_activity_markers, ('dom',)),
    Case('historical_resource_evidence_stays_scoped_to_its_captured_lifetime', run_historical_resource_evidence_stays_scoped_to_its_captured_lifetime, ('dom',)),
    Case('resource_trend_svg_is_rendered', run_resource_trend_svg_is_rendered, ('dom',)),
    Case('resource_action_opens_the_family_in_place', run_resource_action_opens_the_family_in_place, ('dom',)),
    Case('resource_policy_mode_and_grace_are_visible', run_resource_policy_mode_and_grace_are_visible, ('dom',)),
    Case('resource_policy_source_is_visible_on_sessions', run_resource_policy_source_is_visible_on_sessions, ('dom',)),
    Case('resource_policy_editor_opens_with_the_active_document', run_resource_policy_editor_opens_with_the_active_document, ('dom_policy',)),
    Case('resource_intervention_ladder_is_visible', run_resource_intervention_ladder_is_visible, ('dom',)),
    Case('resources', run_resources, ('dom_fam',)),
    Case('view_family_opens_the_drawer_with_the_family_name_the_tab_stays_resources', run_view_family_opens_the_drawer_with_the_family_name_the_tab_stays_resources, ('dom_fam',)),
    Case('family_drawer', run_family_drawer, ('dom_fam',)),
    Case('open_in_events_switches_to_events_scoped_to_the_family_pids', run_open_in_events_switches_to_events_scoped_to_the_family_pids, ('dom_famev',)),
    Case('events_tab_shows_the_newest_50_rows_and_a_show_more_button', run_events_tab_shows_the_newest_50_rows_and_a_show_more_button, ('dom_evcap',)),
    Case('events_rows_name_trace_kinds', run_events_rows_name_trace_kinds, ('dom_evtrace',)),
    Case('events', run_events, ('dom_duptrace', 'dom_evorder')),
    Case('terminate_policy_save_requires_explicit_confirmation', run_terminate_policy_save_requires_explicit_confirmation, ('dom_policy',)),
    Case('resource_approval_contains_the_whole_session', run_resource_approval_contains_the_whole_session, ('dom',)),
    Case('resource_approval_can_keep_the_session_running', run_resource_approval_can_keep_the_session_running, ('dom',)),
    Case('paused_resource_session_can_resume', run_paused_resource_session_can_resume, ('dom',)),
    Case('resource_intervention_failure_is_visible', run_resource_intervention_failure_is_visible, ('dom',)),
    Case('home_has_no_session_board', run_home_has_no_session_board, ('dom',)),
    Case('trends_lead_with_the_activity_chart', run_trends_lead_with_the_activity_chart, ('dom',)),
    Case('trends_have_the_findings_by_rule_chart', run_trends_have_the_findings_by_rule_chart, ('dom',)),
    Case('trends_have_the_memory_by_family_chart', run_trends_have_the_memory_by_family_chart, ('dom',)),
    Case('trends_carry_no_list_panels', run_trends_carry_no_list_panels, ('dom',)),
    Case('the_egress_tab_carries_no_decision_badge', run_the_egress_tab_carries_no_decision_badge, ('dom',)),
    Case('home_tab_badge_shows_needs_you_count', run_home_tab_badge_shows_needs_you_count, ('dom',)),
    Case('needs_you_shows_the_api_service_session_s_decisions_as_flat_rows_with_its_memory_cpu_and_process_count', run_needs_you_shows_the_api_service_session_s_decisions_as_flat_rows_with_its_memory_cpu_and_process_count, ('dom',)),
    Case('a_pattern_never_reaches_needs_you_it_is_one_history_row_with_its_count', run_a_pattern_never_reaches_needs_you_it_is_one_history_row_with_its_count, ('dom_pattern',)),
    Case('needs_you_unifies_guard_resource_incident_and_critical_finding_rows_highest_priority_first', run_needs_you_unifies_guard_resource_incident_and_critical_finding_rows_highest_priority_first, ('dom',)),
    Case('home_keeps_coverage_outside_the_decisions_count', run_home_keeps_coverage_outside_the_decisions_count, ('dom',)),
    Case('home_with_only_coverage_gaps_hides_needs_you_and_shows_the_gap', run_home_with_only_coverage_gaps_hides_needs_you_and_shows_the_gap, ('dom_coverage',)),
    Case('attention_resource_actions_target_the_full_session', run_attention_resource_actions_target_the_full_session, ('dom',)),
    Case('same_agent_sessions_keep_independent_guard_evidence_and_closed_details', run_same_agent_sessions_keep_independent_guard_evidence_and_closed_details, ('dom_session_coverage',)),
    Case('an_invalidated_installed_hook_check_stays_separate_from_session_evidence', run_an_invalidated_installed_hook_check_stays_separate_from_session_evidence, ('dom_session_coverage',)),
    Case('attention_guard_actions_expose_bounded_choices', run_attention_guard_actions_expose_bounded_choices, ('dom',)),
    Case('attention_keeps_scope_disclosure_compact', run_attention_keeps_scope_disclosure_compact, ('dom',)),
    Case('coverage_egress_opens_endpoint_evidence', run_coverage_egress_opens_endpoint_evidence, ('dom',)),
    Case('resolved_guard_request_leaves_the_attention_queue', run_resolved_guard_request_leaves_the_attention_queue, ('dom', 'dom_guard')),
    Case('resolved_incident_leaves_the_attention_count_before_reconciliation', run_resolved_incident_leaves_the_attention_count_before_reconciliation, ('dom', 'dom_resolve')),
    Case('an_expected_connection_leaves_egress_before_the_daemon_answers_the_banner_and_needs_you_count_never_held_it', run_an_expected_connection_leaves_egress_before_the_daemon_answers_the_banner_and_needs_you_count_never_held_it, ('dom', 'dom_expect')),
    Case('posture_flag_item_targets_its_recorded_evidence', run_posture_flag_item_targets_its_recorded_evidence, ('dom_tab',)),
    Case('tab_switch_reveals_the_target_panel', run_tab_switch_reveals_the_target_panel, ('dom_tab',)),
    Case('egress_explains_scheduled_calls_as_observed_facts_and_labeled_advisor_inference', run_egress_explains_scheduled_calls_as_observed_facts_and_labeled_advisor_inference, ('dom_tab',)),
    Case('egress_offers_broad_scope_only_with_complete_attribution', run_egress_offers_broad_scope_only_with_complete_attribution, ('dom_tab',)),
    Case('egress_opens_linked_session_and_can_revoke_an_expected_episode', run_egress_opens_linked_session_and_can_revoke_an_expected_episode, ('dom_tab',)),
    Case('resources_and_events_are_separate_sub_views', run_resources_and_events_are_separate_sub_views, ('dom',)),
    Case('pressure_history_sits_in_the_resources_sub_view', run_pressure_history_sits_in_the_resources_sub_view, ('dom',)),
    Case('resource_panel_lives_in_the_resources_sub_view', run_resource_panel_lives_in_the_resources_sub_view, ('dom',)),
    Case('flight_recorder_lives_in_the_resources_sub_view', run_flight_recorder_lives_in_the_resources_sub_view, ('dom',)),
    Case('event_timeline_lives_in_the_events_sub_view', run_event_timeline_lives_in_the_events_sub_view, ('dom',)),
    Case('saved_view_menu_is_present', run_saved_view_menu_is_present, ('dom',)),
    Case('a_saved_view_appears_in_the_list', run_a_saved_view_appears_in_the_list, ('dom_view',)),
    Case('global_search_box_is_present', run_global_search_box_is_present, ('dom',)),
    Case('export_actions_are_wired', run_export_actions_are_wired, ('dom',)),
    Case('search_narrows_the_panel', run_search_narrows_the_panel, ('dom', 'dom_view')),
    Case('flag_card_carries_per_flag_dismiss', run_flag_card_carries_per_flag_dismiss, ('dom',)),
    Case('flag_card_carries_re_run_advisor', run_flag_card_carries_re_run_advisor, ('dom',)),
    Case('keychain_flag_shows_benign_context', run_keychain_flag_shows_benign_context, ('dom',)),
    Case('dismiss_removes_the_flag_s_row', run_dismiss_removes_the_flag_s_row, ('dom_dismiss',)),
    Case('re_triage_verdict_lands_and_replaces_the_chip', run_re_triage_verdict_lands_and_replaces_the_chip, ('dom_retriage',)),
    Case('fresh_identical_re_triage_verdict_clears_pending_and_reports_completion', run_fresh_identical_re_triage_verdict_clears_pending_and_reports_completion, ('dom_retriage',)),
    Case('advisor_offline_renders_honest_disabled_state', run_advisor_offline_renders_honest_disabled_state, ('dom_advdown',)),
    Case('timeline_rows_carry_agent_names_not_bare_pids', run_timeline_rows_carry_agent_names_not_bare_pids, ('dom',)),
    Case('zero_inline_onclick_handlers_in_rendered_dom', run_zero_inline_onclick_handlers_in_rendered_dom, ('dom',)),
    Case('view_session_in_timeline_opens_the_session_in_the_sessions_tab', run_view_session_in_timeline_opens_the_session_in_the_sessions_tab, ('dom_sesslink',)),
    Case('timeline_filtered_to_2_session_events', run_timeline_filtered_to_2_session_events, ('dom_session',)),
    Case('burst', run_burst, ('dom_burst', 'dom_dismiss')),
    Case('identical_title_sessions_fold_into_one_row_titled_with_the_spawning_agent', run_identical_title_sessions_fold_into_one_row_titled_with_the_spawning_agent, ('dom_dup',)),
    Case('an_expanded_folded_row_lists_its_five_sessions_newest_first_with_hh', run_an_expanded_folded_row_lists_its_five_sessions_newest_first_with_hh, ('dom_dup',)),
    Case('a_selected_member_of_a_folded_row_keeps_its_selection_across_a_patch', run_a_selected_member_of_a_folded_row_keeps_its_selection_across_a_patch, ('dom_dup',)),
    Case('resources_folds_identical_family_labels_into_one_row_with_summed_memory_cpu_and_processes', run_resources_folds_identical_family_labels_into_one_row_with_summed_memory_cpu_and_processes, ('dom_dupres',)),
    Case('a_status_change_patches_a_session_group_in_place', run_a_status_change_patches_a_session_group_in_place, ('dom_foldpatch',)),
    Case('a_live_and_an_ended_fold_with_one_title_expand_independently', run_a_live_and_an_ended_fold_with_one_title_expand_independently, ('dom_foldpatch',)),
    Case('a_metric_update_patches_a_resources_group_per_row', run_a_metric_update_patches_a_resources_group_per_row, ('dom_familypatch',)),
    Case('burst_2', run_burst_2, ('dom_focus', 'dom_railburst')),
    Case('burst_3', run_burst_3, ('dom_click',)),
    Case('raw_card_mute_carries_the_flag_s_agent', run_raw_card_mute_carries_the_flag_s_agent, ('dom_rawmute',)),
    Case('act_in_place', run_act_in_place, ('dom_act', 'dom_actfail')),
    Case('finding_row', run_finding_row, ('dom_explain',)),
    Case('finding_row_carries_no_inline_handlers_or_styles', run_finding_row_carries_no_inline_handlers_or_styles, ('dom_explain',)),
    Case('finding_row_2', run_finding_row_2, ('dom_explain',)),
    Case('finding_card', run_finding_card, ('dom_allowpathact', 'dom_explainact', 'dom_orgallow')),
    Case('routine', run_routine, ('dom', 'dom_routine')),
    Case('finding_card_2', run_finding_card_2, ('dom_explainfail',)),
    Case('attention', run_attention, ('dom_explain',)),
    Case('finding_row_3', run_finding_row_3, ('dom_detailsprobe', 'dom_explain')),
    Case('sticky_tabs', run_sticky_tabs, ('dom', 'dom_sticky')),
    Case('drawer_back', run_drawer_back, ('dom_drawerback',)),
    Case('scope_bar', run_scope_bar, ('dom_scope',)),
    Case('attention_badge_and_tab_badge_equal_posture_needs_you_coverage_stays_separate', run_attention_badge_and_tab_badge_equal_posture_needs_you_coverage_stays_separate, ('dom',)),
    Case('github_grouped_finding_exposes_approval_local_review_and_inspection', run_github_grouped_finding_exposes_approval_local_review_and_inspection, ('dom_gh',)),
    Case('github_approval_posts_the_served_exact_scope_and_reconciles_to_reviewed', run_github_approval_posts_the_served_exact_scope_and_reconciles_to_reviewed, ('dom_ghapprove',)),
    Case('patterns', run_patterns, ('dom_csp', 'dom_hiddenrender', 'dom_pattern', 'dom_patternact', 'dom_patternphone', 'dom_patternstream')),
    Case('history', run_history, ('dom_attnkeep',)),
    Case('a_61_flag_pattern_is_exactly_one_history_row_reading_61', run_a_61_flag_pattern_is_exactly_one_history_row_reading_61, ('dom_csp', 'dom_hiddenrender', 'dom_pattern', 'dom_patternbig')),
    Case('bulk_mark_reviewed_on_two_selected_rows_asks_one_confirm_and_sends_one_acknowledge_batch', run_bulk_mark_reviewed_on_two_selected_rows_asks_one_confirm_and_sends_one_acknowledge_batch, ('dom_bulk',)),
    Case('empty_posture', run_empty_posture, ('dom_empty',)),
    Case('auth_recovery', run_auth_recovery, ()),
)
