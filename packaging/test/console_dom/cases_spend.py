"""Console spend cases."""
from case_support import html, json, re, HTMLParser, dom_query, starts_with, payload_cases, pre, log_rows, PolicyRowCounter
from case_types import Case

def run_spend_tile_shows_the_24h_total(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'spend tile shows the 24h total',
        'id="count-spend">$36.67<' in dom,
    )

def run_spend_tile_sub_line_counts_calls_and_unpriced_calls(page):
    check = page.check
    dom = page.fixture('dom')
    check(
        'spend tile sub-line counts calls and unpriced calls',
        'id="hint-spend">40 calls · 2 unpriced<' in dom,
    )

def run_spend_card_restores_a_saved_repo_view_over_24h(page):
    check = page.check
    dom_spendrepo = page.fixture('dom_spendrepo')

    def spend_card_of(d):
        card = dom_query(d).find(None, {'id': 'spend-card'})
        return card.inner_html if card else ''
    spend_key_re = '<span class="spend-key" title="[^"]*">([^<]+)</span>'
    spend_card = spend_card_of(dom_spendrepo)
    spend_keys = re.findall(spend_key_re, spend_card)
    check(
        'spend card restores a saved repo view over 24h',
        (
            spend_keys == ['api-service', 'web-console', 'infra-tools', 'scratch', '(no repo)', 'docs']
            and '<span class="spend-cost">$24.50</span>' in spend_card
            and '#logo-claude' in spend_card
        ),
        f'keys={spend_keys}',
    )

def run_spend_card_defaults_to_selectable_daily_usage_over_7d(page):
    check = page.check
    dom = page.fixture('dom')
    default_spend = dom_query(dom).find(None, {'id': 'spend-card'})
    check(
        'spend card defaults to selectable daily usage over 7d',
        (
            default_spend is not None
            and pre(dom, 'spend-default-view') == 'by=day since=7d'
            and len(default_spend.find_all('button', {'data-action': 'select-spend-day'})) == 7
            and any((q.startswith('since=7d&by=day&tz=') for q in html.unescape(pre(dom, 'mock-costs')).splitlines()))
        ),
    )

def run_spend(page):
    check = page.check
    dom_plans = page.fixture('dom_plans')
    dom_spend = page.fixture('dom_spend')
    dom_spendcache = page.fixture('dom_spendcache')
    dom_spendday = page.fixture('dom_spendday')
    dom_spendkeep = page.fixture('dom_spendkeep')
    dom_spendphone = page.fixture('dom_spendphone')
    dom_spendrepo = page.fixture('dom_spendrepo')
    dom_spendslow = page.fixture('dom_spendslow')

    def spend_card_of(d):
        card = dom_query(d).find(None, {'id': 'spend-card'})
        return card.inner_html if card else ''
    spend_key_re = '<span class="spend-key" title="[^"]*">([^<]+)</span>'
    spend_card = spend_card_of(dom_spendrepo)
    plans_card = spend_card_of(dom_plans)
    plan_node = dom_query(plans_card).find(None, {'class': 'spend-plans'})
    plan_row = dom_query(plans_card).find(None, {'class': 'spend-key'})
    check(
        'spend: a /costs/plans entry renders its plan line and a bar at used_percent above the rows; none when empty',
        (
            re.search('<div class="spend-plans"><div class="spend-plan">\\s*<span class="spend-plan-text">Codex Pro · codex · weekly 52% used · resets (Sun|Mon|Tue|Wed|Thu|Fri|Sat) \\d{1,2}:\\d{2} (AM|PM) · Observed <time datetime="[^"]+">[A-Z][a-z]{2} \\d{1,2}, \\d{4} \\d{1,2}:\\d{2} (AM|PM)</time></span><span class="hbar-track" title="weekly"><span class="hbar-fill" data-w="52.0"', plans_card) is not None
            and plan_node is not None
            and plan_row is not None
            and plan_node.start < plan_row.start
            and '<div class="spend-plans"></div>' in spend_card
        ),
        plans_card[:600],
    )
    check(
        'spend: the stat strip counts calls on plans before unpriced',
        'id="hint-spend">40 calls · 12 on plans · 2 unpriced<' in dom_plans,
    )
    spend_q = html.unescape(pre(dom_spend, 'mock-costs')).split('\n')
    tz_ok = all((re.search('&tz=-?\\d+&cached=1$', q) for q in spend_q if q != 'since=24h&by=repo&cached=1'))
    check(
        'spend: switching the dimension fetches by=provider and renders the provider rows',
        (
            any((q.startswith('since=24h&by=provider&tz=') for q in spend_q))
            and tz_ok
            and re.findall(spend_key_re, spend_card_of(dom_spend)) == ['anthropic', 'openai-codex', 'openai', '(unknown)']
            and 'provider not recorded' in spend_card_of(dom_spend)
        ),
        f'queries={spend_q}',
    )
    check(
        'spend: the tile keeps its 24h by-repo fetch and meaning',
        (
            'since=24h&by=repo&cached=1' in spend_q
            and 'id="count-spend">$36.67<' in dom_spend
        ),
        f'queries={spend_q}',
    )
    check(
        'spend: the chosen view survives a full re-render and is saved for the tab',
        (
            pre(dom_spend, 'spend-probe') == 'select=provider saved={"by":"provider","since":"24h"}'
            and spend_q[-1].startswith('since=24h&by=provider&tz=')
        ),
        f"probe={pre(dom_spend, 'spend-probe')!r} last={spend_q[-1]!r}",
    )
    day_card = spend_card_of(dom_spendday)
    highest_day = dom_query(day_card).find('button', {'data-action': 'select-spend-day', 'data-day': '2026-09-22'})
    day_labels = re.findall('<span class="spend-day-label">([^<]+)</span>', day_card)
    check(
        'spend: a saved by-day view renders one column per day, oldest first, the costliest at full height',
        (
            day_labels == ['Thu 17', 'Fri 18', 'Sat 19', 'Sun 20', 'Mon 21', 'Tue 22', 'Wed 23']
            and highest_day is not None
            and highest_day.has(None, {'data-h': '100.0'})
            and any((q.startswith('since=7d&by=day&tz=') for q in html.unescape(pre(dom_spendday, 'mock-costs')).split('\n')))
        ),
        f'labels={day_labels}',
    )
    keep = html.unescape(pre(dom_spendkeep, 'spend-keep-probe')).split('\n')
    keep_day = re.fullmatch('day same=(\\w+) left=(-?\\d+)->(-?\\d+) refetched=(\\w+)', keep[0])
    check(
        "spend: a slow refresh keeps the day column nodes and the day bars' scrollLeft",
        (
            bool(keep_day)
            and keep_day.group(1) == 'true'
            and int(keep_day.group(2)) > 0
            and keep_day.group(2) == keep_day.group(3)
            and keep_day.group(4) == 'true'
        ),
        f'probe={keep}',
    )
    check(
        'spend: a slow refresh keeps the list row nodes',
        (
            len(keep) > 1
            and keep[1] == 'list same=true refetched=true'
        ),
        f'probe={keep}',
    )
    check(
        'spend: the Overview tab with the day bars fits a 375px phone',
        dom_query(dom_spendphone).has(None, {'data-hscroll': 'sessions:0,agents:0,resources:0,overview:0'}),
        (re.search('data-hscroll="[^"]*"', dom_spendphone) or [None])[0],
    )
    cache_probe = html.unescape(pre(dom_spendcache, 'spend-cache-probe'))
    check(
        'spend: a report from the usage cache shows at once with the updating notice and its age',
        cache_probe == 'notice=Refreshing usage… · saved 3h ago hint=40 calls · 2 unpriced · updating…',
        f'probe={cache_probe!r}',
    )
    cache_q = html.unescape(pre(dom_spendcache, 'mock-costs')).split('\n')
    check(
        'spend: the card re-reads until the fresh report lands, then the notice goes',
        (
            len(cache_q) == 6
            and 'id="count-spend">$37.67<' in dom_spendcache
            and 'id="hint-spend">40 calls · 2 unpriced<' in dom_spendcache
            and dom_query(dom_spendcache).has(None, {'id': 'spend-cache', 'class': 'spend-cache', 'role': 'status', 'hidden': ''})
        ),
        f'queries={cache_q}',
    )
    slow_probe = html.unescape(pre(dom_spendslow, 'spend-slow-probe'))
    check(
        'spend: a report computed cold never holds the first render of the other panels',
        (
            slow_probe == 'agents=3 spend=Refreshing usage…'
            and 'id="count-spend">$36.67<' in dom_spendslow
        ),
        f'probe={slow_probe!r}',
    )

def run_spend_refresh(page):
    check = page.check
    cached = page.dom('?savedspendrepo&spendcachedemo', served=True)
    check(
        'spend: saved rows remain visible during a quiet cache refresh',
        'notice=Refreshing usage… · saved 3h ago' in html.unescape(pre(cached, 'spend-cache-probe')),
    )
    check(
        'spend: fresh data replaces cached data and clears the indicator',
        (
            'id="count-spend">$37.67<' in cached
            and dom_query(cached).has(None, {'id': 'spend-cache', 'class': 'spend-cache', 'role': 'status', 'hidden': ''})
        ),
    )
    delayed = page.dom('?savedspendrepo&spendshape', fixture=payload_cases.delayed_spend(), served=True)
    check(
        'spend: delayed refresh retains totals and rows without warning banners',
        (
            'Refresh delayed · showing saved usage' in delayed
            and 'id="count-spend">$36.67<' in delayed
            and 'api-service' in delayed
            and 'Spend detail: Stale' not in delayed
            and 'Spend plans: Stale' not in delayed
        ),
    )
    first = page.dom('?savedspendrepo&spendshape&firstload', fixture=payload_cases.delayed_spend(), served=True)
    check(
        'spend: unavailable first response retries without claiming empty computed usage',
        (
            'Usage is taking longer to load · retrying…' in first
            and 'Refreshing usage…' in first
            and 'No model calls' not in first
        ),
    )
    recovered = page.dom('?savedspendrepo&spendshape&recover', fixture=payload_cases.delayed_spend(), served=True)
    check(
        'spend: valid recovery clears the delayed state',
        (
            'Refresh delayed' in pre(recovered, 'spend-shape-before-recovery')
            and dom_query(recovered).has(None, {'id': 'spend-cache', 'class': 'spend-cache', 'role': 'status', 'hidden': ''})
            and 'id="count-spend">$36.67<' in recovered
        ),
    )
    cold = page.dom('?spendslowdemo', served=True)
    check(
        'spend: cold loading leaves sibling panels available',
        html.unescape(pre(cold, 'spend-slow-probe')) == 'agents=3 spend=Refreshing usage…',
    )

def run_quota_observation_time(page):
    fixture = payload_cases.spend_plans()
    seen_at = fixture['patches'][0]['value'][0]['seen_at']
    dom = page.dom('?plansdemo', served=True, fixture=fixture)
    row = dom_query(dom).find(None, {'class': 'spend-plan'})
    text = row.find(None, {'class': 'spend-plan-text'}) if row else None
    times = text.find_all('time') if text else []
    page.check('quota observation: one semantic time carries the actual seen_at',
               len(times) == 1 and times[0].attrs.get('datetime') == seen_at, row.inner_html if row else 'missing row')
    page.check('quota observation: absolute calendar date includes year and clock inside the existing label',
               bool(text and re.search(r' · Observed <time datetime="[^"]+">[A-Z][a-z]{2} \d{1,2}, \d{4} \d{1,2}:\d{2} (AM|PM)</time>', text.inner_html)),
               text.inner_html if text else 'missing label')
    page.check('quota observation: quota label and weekly usage bar remain intact',
               bool(text and text.inner_html.startswith('Codex Pro · codex · weekly 52% used · resets ')
                    and len(row.find_all(None, {'class': 'hbar-track'})) == 1
                    and row.find(None, {'class': 'hbar-fill', 'data-w': '52.0'})), row.inner_html if row else 'missing row')


CASES = (
    Case('quota_observation_time', run_quota_observation_time),
    Case('spend_tile_shows_the_24h_total', run_spend_tile_shows_the_24h_total, ('dom',)),
    Case('spend_tile_sub_line_counts_calls_and_unpriced_calls', run_spend_tile_sub_line_counts_calls_and_unpriced_calls, ('dom',)),
    Case('spend_card_restores_a_saved_repo_view_over_24h', run_spend_card_restores_a_saved_repo_view_over_24h, ('dom_spendrepo',)),
    Case('spend_card_defaults_to_selectable_daily_usage_over_7d', run_spend_card_defaults_to_selectable_daily_usage_over_7d, ('dom',)),
    Case('spend', run_spend, ('dom_plans', 'dom_spend', 'dom_spendcache', 'dom_spendday', 'dom_spendkeep', 'dom_spendphone', 'dom_spendrepo', 'dom_spendslow')),
    Case('spend_refresh', run_spend_refresh, ()),
)
