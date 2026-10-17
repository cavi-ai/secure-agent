"""Console policy cases."""
from case_support import html, json, re, HTMLParser, dom_query, starts_with, payload_cases, pre, log_rows, PolicyRowCounter
from case_types import Case

def run_allowlist_entries_render_with_remove(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'allowlist entries render with remove',
        (
            (
                'Allowed endpoints' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: 'Allowed endpoints' in (value or '')})
            )
            and (
                'artifacts.example.com' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: 'artifacts.example.com' in (value or '')})
            )
        ),
    )

def run_mute_action_on_advisor_benign_flag(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'mute action on advisor-benign flag',
        dom_query(dom).has(None, {'data-action': 'mute-flag', 'data-rule': 'sensitive-read-then-connect', 'data-host': 'logs.example.com'}),
    )

def run_mutes_list_rendered_with_unmute(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'mutes list rendered with unmute',
        dom_query(dom).has(None, {'data-action': 'unmute', 'data-rule': 'proxy-prompt-injection', 'data-host': 'blog.example.com'}),
    )

def run_policy_lists_guard_decisions_file_exceptions_and_muted_classes_from_their_endpoints(page):
    check = page.check
    dom_policylists = page.fixture('dom_policylists')
    policy_counter = PolicyRowCounter()
    policy_counter.feed(dom_policylists)

    def policy_rows(kind):
        return policy_counter.counts.get(kind, -1)
    check(
        'Policy lists guard decisions, file exceptions and muted classes from their endpoints',
        (
            dom_query(dom_policylists).has(None, {'class': 'tab-btn active', 'data-tab': 'protection'})
            and dom_query(dom_policylists).has(None, {'data-protection-view': 'rules', 'aria-selected': 'true', 'class': 'active'})
            and 'hidden' not in dom_query(dom_policylists).find(None, {'id': 'protection-rules'}).attrs
            and policy_rows('guard') == 2
            and policy_rows('path') == 1
            and policy_rows('mute') == 2
            and 'id="badge-guard-rules">2<' in dom_policylists
            and 'id="badge-path-allows">1<' in dom_policylists
            and '.env.example</code>' in dom_policylists
            and 'keychain-security-cli' in dom_policylists.split('data-policy="mute"', 1)[-1]
        ),
        f"guard={policy_rows('guard')} path={policy_rows('path')} mute={policy_rows('mute')}",
    )

def run_policy_empty_lists_say_what_fills_them(page):
    check = page.check
    dom_policyempty = page.fixture('dom_policyempty')
    check(
        'Policy empty lists say what fills them',
        (
            (
                'No guard decisions yet.' in dom_query(dom_policyempty).text
                or dom_query(dom_policyempty).has(None, {'title': lambda value: 'No guard decisions yet.' in (value or '')})
            )
            and (
                'No file exceptions yet.' in dom_query(dom_policyempty).text
                or dom_query(dom_policyempty).has(None, {'title': lambda value: 'No file exceptions yet.' in (value or '')})
            )
            and (
                'No muted flag classes.' in dom_query(dom_policyempty).text
                or dom_query(dom_policyempty).has(None, {'title': lambda value: 'No muted flag classes.' in (value or '')})
            )
            and (
                'No expected secret reads.' in dom_query(dom_policyempty).text
                or dom_query(dom_policyempty).has(None, {'title': lambda value: 'No expected secret reads.' in (value or '')})
            )
        ),
    )

def run_policy_lists_expected_secret_reads_with_a_forget_button(page):
    check = page.check
    dom_policylists = page.fixture('dom_policylists')
    policy_counter = PolicyRowCounter()
    policy_counter.feed(dom_policylists)

    def policy_rows(kind):
        return policy_counter.counts.get(kind, -1)
    check(
        'Policy lists expected secret reads with a Forget button',
        (
            policy_rows('expected') == 1
            and 'id="badge-expected">1<' in dom_policylists
            and '<b>gh</b> reads <code>/Users/dev/.config/gh/hosts.yml</code>, then reaches <b>GitHub</b>' in dom_policylists
            and dom_query(dom_policylists).has(None, {'data-action': 'forget-expected'})
        ),
        f"expected={policy_rows('expected')}",
    )

def run_scoped_expectation_submits_the_displayed_revision_and_explicit_expiry(page):
    check = page.check
    dom_scoped = page.fixture('dom_scoped')
    scoped_reqs = pre(dom_scoped, 'mock-requests')
    check(
        'scoped expectation submits the displayed revision and explicit expiry',
        (
            'POST /reviews/decision' in scoped_reqs
            and '"revision":3' in scoped_reqs
            and '"scope":{"kind":"exact","expiry":"24h"}' in scoped_reqs
        ),
    )

def run_scoped_permission_shows_the_exact_endpoint_and_executable_with_revocation(page):
    check = page.check
    dom_scoped = page.fixture('dom_scoped')
    check(
        'scoped permission shows the exact endpoint and executable with revocation',
        (
            (
                'api.example.com:443' in dom_query(dom_scoped).text
                or dom_query(dom_scoped).has(None, {'title': lambda value: 'api.example.com:443' in (value or '')})
            )
            and (
                '/usr/bin/cat' in dom_query(dom_scoped).text
                or dom_query(dom_scoped).has(None, {'title': lambda value: '/usr/bin/cat' in (value or '')})
            )
            and dom_query(dom_scoped).has(None, {'data-action': 'revoke-scope', 'data-id': 'scope-browser'})
        ),
    )

def run_scoped_permission_revoke_uses_its_id_and_updates_the_visible_state(page):
    check = page.check
    dom_scoped_revoke = page.fixture('dom_scoped_revoke')
    check(
        'scoped permission revoke uses its ID and updates the visible state',
        (
            'DELETE /decision-scopes?id=scope-browser' in pre(dom_scoped_revoke, 'mock-requests')
            and (
                'Revoked' in dom_query(dom_scoped_revoke).text
                or dom_query(dom_scoped_revoke).has(None, {'title': lambda value: 'Revoked' in (value or '')})
            )
            and not dom_query(dom_scoped_revoke).has(None, {'data-action': 'revoke-scope', 'data-id': 'scope-browser'})
        ),
    )

def run_protection_groups_notification_rules_and_audit_in_their_own_views_the_bell_opens_rules(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'Protection groups notification rules and audit in their own views; the bell opens Rules',
        (
            dom_query(dom).find(None, {'id': 'protection-rules'}).has(None, {'id': 'notify-rules-list'})
            and dom_query(dom).has(None, {'id': 'btn-notify', 'data-action': 'goto-protection', 'data-protection-view': 'rules'})
            and dom_query(dom).find(None, {'id': 'protection-audit'}).has(None, {'id': 'audit-panel'})
        ),
    )

def run_policy_editor_exposes_intervention_steps(page):
    check = page.check
    dom_policy = page.fixture('dom_policy')
    check(
        'policy editor exposes intervention steps',
        (
            'data-step-action="lower_priority" checked' in dom_policy
            and 'data-step-action="pause" checked' in dom_policy
        ),
    )

def run_policy_editor_adds_the_selected_session_workspace(page):
    check = page.check
    dom_policy = page.fixture('dom_policy')
    check(
        'policy editor adds the selected session workspace',
        dom_query(dom_policy).has(None, {'value': '/Users/dev/workspace/api-service'}),
    )

def run_policy_editor_exposes_automatic_containment_warning(page):
    check = page.check
    dom_policy = page.fixture('dom_policy')
    check(
        'policy editor exposes automatic containment warning',
        (
            'applies every enabled intervention automatically' in dom_query(dom_policy).text
            or dom_query(dom_policy).has(None, {'title': lambda value: 'applies every enabled intervention automatically' in (value or '')})
        ),
    )

def run_policy_lists_reversible_expected_connections(page):
    check = page.check
    dom_policylists = page.fixture('dom_policylists')
    check(
        'Policy lists reversible expected connections',
        (
            (
                'old.example.com:443' in dom_query(dom_policylists).text
                or dom_query(dom_policylists).has(None, {'title': lambda value: 'old.example.com:443' in (value or '')})
            )
            and dom_query(dom_policylists).has(None, {'data-action': 'revoke-expected-egress', 'data-id': 'expected-older'})
        ),
    )

def run_allow_removes_the_suggestion_from_the_list(page):
    check = page.check
    dom_allow = page.fixture('dom_allow')
    check(
        'allow removes the suggestion from the list',
        (
            'fw-suggestion' not in dom_query(dom_allow).text
            and not dom_query(dom_allow).has(None, {'title': lambda value: 'fw-suggestion' in (value or '')})
        ),
        'suggestion still rendered after Allow',
    )

def run_mutes_ledger(page):
    check = page.check
    dom_rawmute = page.fixture('dom_rawmute')
    check(
        'mutes ledger: a new scoped mute keeps the focused unmute button',
        pre(dom_rawmute, 'mute-focus-probe') == 'kept rows=3',
        f"probe={pre(dom_rawmute, 'mute-focus-probe')!r}",
    )

def run_policy_permissions(page):
    check = page.check
    for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
        for variant in ('confirmed', 'ambiguousrevoke', 'scopereadfail', 'unknownscope'):
            dom = page.dom('?scoperevoke&' + variant, window_size=size, served=True)
            receipt = re.search(r'data-global-permissions-probe="([^"]+)"', dom)
            state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
            names = ['loaded', 'fits'] + (['unknown'] if variant == 'unknownscope' else
                ['confirmation', 'cancelled', 'cancelFocus', 'once', 'noReplay'] +
                (['unconfirmed', 'refreshed'] if variant == 'ambiguousrevoke' else ['saved', *(['retained'] if variant == 'scopereadfail' else [])]))
            for name in names:
                check(f'global permissions ({label}, {variant}): {name}', state.get(name) is True, str(state))

def run_workspace_permissions(page):
    for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
        dom = page.dom('?workspacepermissions', window_size=size, served=True,
                       fixture={'script': 'cases_workspace_permissions.js'})
        receipt = re.search(r'data-workspace-permissions-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('entry','groups','limits','confirm','cancel','revoked','reading','unassigned','stale','retry','back','forward','empty','clear','fits','inspect'):
            page.check(f'workspace permissions ({label}): {name}', state.get(name) is True, str(state))

CASES = (
    Case('workspace_permissions', run_workspace_permissions, ()),
    Case('policy_permissions', run_policy_permissions, ()),
    Case('allowlist_entries_render_with_remove', run_allowlist_entries_render_with_remove, ('dom',)),
    Case('mute_action_on_advisor_benign_flag', run_mute_action_on_advisor_benign_flag, ('dom',)),
    Case('mutes_list_rendered_with_unmute', run_mutes_list_rendered_with_unmute, ('dom',)),
    Case('policy_lists_guard_decisions_file_exceptions_and_muted_classes_from_their_endpoints', run_policy_lists_guard_decisions_file_exceptions_and_muted_classes_from_their_endpoints, ('dom_policylists',)),
    Case('policy_empty_lists_say_what_fills_them', run_policy_empty_lists_say_what_fills_them, ('dom_policyempty',)),
    Case('policy_lists_expected_secret_reads_with_a_forget_button', run_policy_lists_expected_secret_reads_with_a_forget_button, ('dom_policylists',)),
    Case('scoped_expectation_submits_the_displayed_revision_and_explicit_expiry', run_scoped_expectation_submits_the_displayed_revision_and_explicit_expiry, ('dom_scoped',)),
    Case('scoped_permission_shows_the_exact_endpoint_and_executable_with_revocation', run_scoped_permission_shows_the_exact_endpoint_and_executable_with_revocation, ('dom_scoped',)),
    Case('scoped_permission_revoke_uses_its_id_and_updates_the_visible_state', run_scoped_permission_revoke_uses_its_id_and_updates_the_visible_state, ('dom_scoped_revoke',)),
    Case('protection_groups_notification_rules_and_audit_in_their_own_views_the_bell_opens_rules', run_protection_groups_notification_rules_and_audit_in_their_own_views_the_bell_opens_rules, ('dom',)),
    Case('policy_editor_exposes_intervention_steps', run_policy_editor_exposes_intervention_steps, ('dom_policy',)),
    Case('policy_editor_adds_the_selected_session_workspace', run_policy_editor_adds_the_selected_session_workspace, ('dom_policy',)),
    Case('policy_editor_exposes_automatic_containment_warning', run_policy_editor_exposes_automatic_containment_warning, ('dom_policy',)),
    Case('policy_lists_reversible_expected_connections', run_policy_lists_reversible_expected_connections, ('dom_policylists',)),
    Case('allow_removes_the_suggestion_from_the_list', run_allow_removes_the_suggestion_from_the_list, ('dom_allow',)),
    Case('mutes_ledger', run_mutes_ledger, ('dom_rawmute',)),
)
