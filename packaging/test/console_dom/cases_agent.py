"""Console agent cases."""
from case_support import html, json, re, HTMLParser, dom_query, starts_with, payload_cases, pre, log_rows, PolicyRowCounter
from case_types import Case

def run_agents_tab_renders_one_group_per_harness_newest_first(page):
    check = page.check
    dom = page.fixture('dom')
    agents_view = dom.split('id="agents-container"', 1)[1].split('id="fleet-col"', 1)[0]
    agent_groups = re.findall('<details class="agent-group" data-harness="([^"]+)"', agents_view)
    check(
        'agents tab renders one group per harness, newest first',
        agent_groups == ['codex', 'claude', 'cursor'],
        f'groups={agent_groups}',
    )

def run_agent_group_head(page):
    check = page.check
    dom = page.fixture('dom')
    agents_view = dom.split('id="agents-container"', 1)[1].split('id="fleet-col"', 1)[0]
    check(
        'agent group head: mark, name, instances, processes, RSS, CPU',
        (
            '#logo-codex' in agents_view
            and '<span class="harness-label">Claude Code</span>' in agents_view
            and '1 instance · 2 processes' in agents_view
            and '14.5% CPU' in agents_view
        ),
    )

def run_agents_infra_section_sits_last_and_is_not_counted(page):
    check = page.check
    dom = page.fixture('dom')
    agents_view = dom.split('id="agents-container"', 1)[1].split('id="fleet-col"', 1)[0]
    check(
        'agents infra section sits last and is not counted',
        (
            agents_view.index('class="agent-infra"') > agents_view.rindex('<details class="agent-group" ')
            and 'data-harness="ollama"' in agents_view.split('class="agent-infra"', 1)[1]
            and 'id="badge-agents-count">3<' in dom
        ),
    )

def run_agent_instances_lead_with_repo_branch_pid_secondary(page):
    check = page.check
    dom = page.fixture('dom')
    agents_view = dom.split('id="agents-container"', 1)[1].split('id="fleet-col"', 1)[0]
    check(
        'agent instances lead with repo@branch, pid secondary',
        (
            '<span class="agent-row-title">api-service@main</span>' in agents_view
            and '<span class="agent-pid">PID 5821</span>' in agents_view
        ),
    )

def run_agent_helpers_sit_behind_a_disclosure(page):
    check = page.check
    dom = page.fixture('dom')
    agents_view = dom.split('id="agents-container"', 1)[1].split('id="fleet-col"', 1)[0]
    check(
        'agent helpers sit behind a disclosure',
        'PID 5822' in agents_view.split('<details class="session-helpers agent-tree" data-pid="5821"', 1)[1].split('</details>', 1)[0],
    )

def run_agent_last_active_rendered(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'agent last-active rendered',
        (
            dom_query(dom).has(None, {'class': 'active'})
            and (
                ' ago' in dom_query(dom).text
                or dom_query(dom).has(None, {'title': lambda value: ' ago' in (value or '')})
            )
        ),
    )

def run_agent_and_non_agent_memory_are_separated(page):
    check = page.check
    dom = page.fixture('dom')
    resource_view = dom.split('id="resource-mission-control"', 1)[1].split('id="history-panel"', 1)[0]
    check(
        'agent and non-agent memory are separated',
        (
            'Agents 34.4%' in resource_view
            and 'Other 40.6%' in resource_view
            and dom_query(resource_view).has(None, {'class': 'resource-host-segment agent'})
        ),
    )

def run_agent_workspace(page):
    check = page.check
    dom_agentworkspace = page.fixture('dom_agentworkspace')
    dom_agentworkspace_mobile = page.fixture('dom_agentworkspace_mobile')
    for viewport, workspace_dom in [('desktop', dom_agentworkspace), ('mobile', dom_agentworkspace_mobile)]:
        receipt = re.search('data-agent-workspace="([^"]+)"', workspace_dom)
        checks = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        check(
            f'agent workspace ({viewport}): interaction receipt was produced',
            bool(checks),
        )
        for name, result in checks.items():
            check(
                f'agent workspace ({viewport}): {name}',
                result is True,
            )

def run_agent(page):
    check = page.check
    dom_agent = page.fixture('dom_agent')
    dom_agentchat = page.fixture('dom_agentchat')
    dom_agentdispatch = page.fixture('dom_agentdispatch')
    dom_agentlatency = page.fixture('dom_agentlatency')
    dom_agentlocal = page.fixture('dom_agentlocal')
    dom_agentoff = page.fixture('dom_agentoff')
    dom_agentreduced = page.fixture('dom_agentreduced')
    dom_agentreject = page.fixture('dom_agentreject')
    dom_agentthinking = page.fixture('dom_agentthinking')

    def agent_block(dom_text):
        return dom_text.split('id="tab-agent"', 1)[-1].split('id="drawer"', 1)[0]

    def agent_count(dom_text, cls):
        return agent_block(dom_text).count(f'class="{cls}')
    ag = agent_block(dom_agent)
    check(
        'agent: the tab opens with the conversation, plans, runs and the model state',
        (
            dom_query(dom_agent).has(None, {'class': 'tab-btn active', 'data-tab': 'agent'})
            and agent_count(dom_agent, 'agent-msg ') == 5
            and len(dom_query(ag).find_all(None, {'class': 'agent-plan', 'data-plan': None})) == 2
            and len(dom_query(ag).find_all(None, {'class': 'agent-run', 'data-run': None})) == 2
            and 'qwen3:latest on Ollama 0.15.1 · stays on this machine' in ag
        ),
    )
    check(
        'agent: message text, proposal tasks, plan titles and run output render escaped',
        (
            '<img src=x' not in ag
            and '&lt;img src=x onerror=alert(1)&gt;' in ag
        ),
    )
    check(
        'agent: local chat and optional harness handoff are separate; unavailable harnesses are marked for later',
        (
            'Local Ollama · no harness' in ag
            and dom_query(ag).has(None, {'id': 'agent-handoff-panel'})
            and 'id="agent-harness"' not in ag.split('id="agent-composer"', 1)[1].split('</form>', 1)[0]
            and '<option value="openclaw">OpenClaw (plan for later)</option>' in ag
            and '<option value="codex">Codex</option>' in ag
            and '<option value="pi">Pi runner (plan for later)</option>' in ag
            and ag.count('<option ') == 5
        ),
    )
    check(
        'agent: a plan whose harness cannot run says why and its dispatch buttons are disabled',
        (
            'agent-plan-reason">OpenClaw is not installed where the daemon can find it (openclaw)</div>' in ag
            and dom_query(ag).has(None, {'data-plan': '2', 'data-mode': 'headless', 'disabled': ''})
        ),
    )
    check(
        'agent: a proposal offers Save plan and dispatch; a saved one names its plan',
        (
            'data-action="agent-save-proposal" data-message="2">Save plan</button>' in ag
            and 'Saved as plan #2' in ag
        ),
    )
    check(
        'agent: a manual terminal dispatch offers its command to copy',
        dom_query(ag).has(None, {'data-action': 'agent-copy', 'data-text': "sh '/Users/dev/.config/secure-agent/sysagent/terminal-1-1.sh'"}),
    )
    check(
        'agent: harnesses show ready or the reason; skills are listed',
        (
            ag.count('badge badge-ok">ready</span>') == 2
            and dom_query(ag).has(None, {'data-action': 'agent-skill', 'data-skill': 'signing'})
        ),
    )
    ago = agent_block(dom_agentoff)
    check(
        'agent: off, the tab says how to turn it on and the composer is disabled',
        (
            'Secure Agent chat is off' in ago
            and 'system_agent:\n  enabled: true' in ago
            and dom_query(ago).has('textarea', {'id': 'agent-input'})
            and ago.split('<textarea id="agent-input"', 1)[1].split('>', 1)[0].count('disabled') == 1
        ),
    )
    for label, progress_dom, expected, animation in [('delivery', dom_agentlatency, 'Sending your message', 'spin'), ('Ollama wait', dom_agentthinking, 'Waiting for local Ollama', 'spin'), ('reduced motion', dom_agentreduced, 'Waiting for local Ollama', 'none')]:
        receipt = re.search('data-agent-feedback-state="([^"]+)"', progress_dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        check(
            f'agent: {label} is visible immediately, disables Send, and handles repeated Enter once',
            (
                expected in state.get('pending', '')
                and state.get('animation') == animation
                and state.get('sendDisabled')
                and pre(progress_dom, 'mock-requests').count('POST /agent/chat') == 1
            ),
            str(state),
        )
    receipt = re.search('data-agent-feedback-state="([^"]+)"', dom_agentreject)
    rejected = json.loads(html.unescape(receipt.group(1))) if receipt else {}
    check(
        'agent: failed send keeps the draft and renders a persistent error',
        (
            rejected.get('errorVisible')
            and 'Model unavailable' in rejected.get('error', '')
            and rejected.get('draft') == 'Keep my Git token in the keychain'
            and not rejected.get('sendDisabled')
        ),
        str(rejected),
    )
    agc = agent_block(dom_agentchat)
    check(
        'agent: a message sent from the composer gets a direct local command proposal',
        (
            'POST /agent/chat' in pre(dom_agentchat, 'mock-requests')
            and 'Keep my Git token in the keychain' in agc
            and 'git config --global credential.helper osxkeychain' in agc
            and dom_query(agc).has(None, {'data-action': 'agent-run-local'})
            and 'The local model is answering' not in agc
            and agent_count(dom_agentchat, 'agent-msg ') == 7
        ),
    )
    agl = agent_block(dom_agentlocal)
    check(
        'agent: confirmed local command runs once and its output stays expanded in chat',
        (
            'POST /agent/actions' in pre(dom_agentlocal, 'mock-requests')
            and 'Git credential helper configured.' in agl
            and not dom_query(agl).has(None, {'data-action': 'agent-run-local'})
            and len(dom_query(agl).find_all(None, {'class': 'agent-run', 'data-run': None})) == 3
            and 'agent-inline-output' in agl.split('class="agent-chat-foot"', 1)[0]
            and 'Completed · exit 0' in agl.split('class="agent-chat-foot"', 1)[0]
            and dom_query(agl).has('aside', {'class': 'agent-inspector', 'id': 'agent-side', 'aria-label': 'Agent tools', 'hidden': None})
        ),
    )
    agd = agent_block(dom_agentdispatch)
    reqs = pre(dom_agentdispatch, 'mock-requests')
    check(
        'agent: Run headless dispatches after the dialog; the run lands under Runs and finishes',
        (
            'POST /agent/dispatch' in reqs
            and 'Credentials now live in the keychain.' in agd
            and len(dom_query(agd).find_all(None, {'class': 'agent-run', 'data-run': None})) == 3
            and 'badge badge-ok">done</span>' in agd.split('id="agent-runs"', 1)[1]
        ),
    )
    check(
        'agent: Save plan on a proposal saves it and the reply names the plan',
        (
            'POST /agent/plans' in reqs
            and len(dom_query(agd).find_all(None, {'class': 'agent-plan', 'data-plan': None})) == 3
            and agd.count('Saved as plan #') == 2
            and not dom_query(agd).has(None, {'data-action': 'agent-save-proposal'})
        ),
    )

CASES = (
    Case('agents_tab_renders_one_group_per_harness_newest_first', run_agents_tab_renders_one_group_per_harness_newest_first, ('dom',)),
    Case('agent_group_head', run_agent_group_head, ('dom',)),
    Case('agents_infra_section_sits_last_and_is_not_counted', run_agents_infra_section_sits_last_and_is_not_counted, ('dom',)),
    Case('agent_instances_lead_with_repo_branch_pid_secondary', run_agent_instances_lead_with_repo_branch_pid_secondary, ('dom',)),
    Case('agent_helpers_sit_behind_a_disclosure', run_agent_helpers_sit_behind_a_disclosure, ('dom',)),
    Case('agent_last_active_rendered', run_agent_last_active_rendered, ('dom',)),
    Case('agent_and_non_agent_memory_are_separated', run_agent_and_non_agent_memory_are_separated, ('dom',)),
    Case('agent_workspace', run_agent_workspace, ('dom_agentworkspace', 'dom_agentworkspace_mobile')),
    Case('agent', run_agent, ('dom_agent', 'dom_agentchat', 'dom_agentdispatch', 'dom_agentlatency', 'dom_agentlocal', 'dom_agentoff', 'dom_agentreduced', 'dom_agentreject', 'dom_agentthinking')),
)
