import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Exact overview tab markup for hostile served values: each value renders
// escaped once in text and attribute positions, and nested fragments render as markup.
process.env.TZ = 'UTC';
const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const sources = ['lib.js', 'tab-overview.js'].map(name => [name, readFileSync(new URL(name, web), 'utf8')]);
const NOW = Date.parse('2026-11-25T12:30:00Z');
const H = `<img src=x onerror=1>"'&amp;`;
const E = '&lt;img src=x onerror=1&gt;&quot;&#39;&amp;amp;';

// A fresh console context over stub elements; patchList records each item's html.
function load({ SA = {}, elements = {} } = {}) {
  const ctx = vm.createContext({ window: { SA }, document: { activeElement: null, getElementById: id => elements[id] || null } });
  for (const [name, source] of sources) vm.runInContext(source, ctx, { filename: name });
  vm.runInContext(`Date.now = () => ${NOW};`, ctx);
  const patched = [];
  ctx.patchList = (container, items, opts) => { patched.push(Array.from(items, opts.html)); };
  ctx.applyInlineMetrics = () => {};
  return { ctx, patched };
}
const el = () => ({ innerHTML: '', textContent: '', hidden: false, children: [] });
const htmlOf = items => Array.from(items, item => item.html);
const at = minute => `2026-11-25T12:${String(minute).padStart(2, '0')}:00Z`;
const GB = 1073741824;

const family = { key: H, name: H, workspace: H, rss_bytes: GB, cpu_percent: 12.5, process_count: 2, estimated_reclaim_bytes: GB / 2,
  diagnoses: [{ severity: H, summary: H, evidence: [H] }, { code: 'heavy-cpu' }],
  control: { state: H, policy_source: 'workspace', policy_scope: H }, samples: [{ at: at(0), rss_bytes: 10, cpu_percent: 1 }, { at: at(10), rss_bytes: 20, cpu_percent: 3 }] };
const episode = {
  severity: H, captured_at: at(20), diagnosis_codes: [H], activity_status: 'settling',
  host: { available_memory_bytes: GB, memory_pressure: H, thermal_state: H, headroom_score: 12 },
  session: { name: H, rss_bytes: 2 * GB, cpu_percent: 55.5, process_count: 13, diagnoses: [{ summary: H, evidence: [H, H] }],
    processes: [{ name: H, pid: 7, rss_bytes: GB, is_orphan: true }, { pid: 8, rss_bytes: 0 }],
    samples: [{ at: at(0), rss_bytes: 1, cpu_percent: 2 }, { at: at(10), rss_bytes: 3, cpu_percent: 1 }] },
  activities: Array.from({ length: 9 }, (_, i) => (i ? { at: at(i), kind: 'tool', pid: i } : { at: at(i), kind: H, process: H, summary: H })),
  correlations: [{ summary: H }],
};
const outcome = { kind: H, status: 'partial', verification: 'pending', error: H, limits: [H, H],
  before: { rss_bytes: 1024, cpu_percent: 5, host_capacity: H, host_available_bytes: 2048, host_cpu_percent: 7 }, after: [{ rss_bytes: null }] };

// renderSpend over a stub card: every innerHTML write, then every patchList call.
function spendCard(SA, by) {
  const writes = [];
  const inspector = { contains: () => false, set innerHTML(value) { writes.push(value); } };
  const body = { className: 'spend-body', childElementCount: 0, firstElementChild: null, set innerHTML(value) {
    writes.push(value);
    const day = value.startsWith('<div class="spend-bars"');
    this.childElementCount = day ? 2 : 1;
    this.firstElementChild = { className: day ? 'spend-bars' : 'spend-list', scrollLeft: 0, children: [], contains: () => false,
      setAttribute() {}, removeAttribute() {}, nextElementSibling: inspector };
  } };
  const card = { childElementCount: 2, firstElementChild: { className: 'spend-plans', nextElementSibling: body } };
  const { ctx, patched } = load({ SA, elements: { 'spend-card': card, 'spend-by': { value: by }, 'spend-day-guidance': { hidden: false } } });
  ctx.renderSpend();
  return [writes, patched];
}

// renderEvents: the container's innerHTML, then every patchList call.
function events(SA) {
  const container = el();
  const { ctx, patched } = load({ SA: { timelineSession: null, timelinePids: null, globalSearchTerm: () => '', isEventsFiltered: () => false,
    eventFreshness: { rendered() {}, isFresh: () => true }, agentNameFor: () => H, reducedMotion: false, ...SA }, elements: { 'events-container': container } });
  ctx.renderEvents();
  return [container.innerHTML, patched];
}

const cases = {
  'activity chart': () => {
    const chart = el();
    const { ctx } = load({ SA: { t: { rollup: [{ bucket: '2026-11-25T11', kind: 'event', count: 3 }, { bucket: '2026-11-25T11', kind: 'flag:x', count: 1 },
      { bucket: '2026-11-25T12', kind: 'event', count: 2 }] } }, elements: { 'activity-chart': chart, 'activity-window': { value: '3' } } });
    ctx.renderActivity();
    return chart.innerHTML;
  },
  'activity markers': () => load().ctx.resourceActivityMarkers([{ at: at(5), kind: H, summary: H }, { at: at(10) }], [{ at: at(0) }, { at: at(20) }], 220, 38),
  'machine strip': () => load().ctx.resourceHostContextHTML({ total_memory_bytes: 16 * GB, available_memory_bytes: 4 * GB, memory_pressure: H,
    agent_memory_percent: 25, non_agent_memory_bytes: 8 * GB, capacity: H, thermal_state: H, system_cpu_percent: 42.5, agent_cpu_percent: 30,
    non_agent_cpu_percent: 12.5, swap_total_bytes: 2 * GB, swap_used_bytes: GB, headroom_score: 37, headroom_limiter: 'swap' }),
  'machine strip unavailable': () => load().ctx.resourceHostContextHTML({ total_memory_bytes: GB, memory_pressure: 'unknown', system_cpu_percent: null }),
  'flight recorder': () => load().ctx.resourceFlightRecorderHTML({ episodes: [episode, {}] }),
  'flight recorder empty': () => {
    const board = el();
    const { ctx } = load({ SA: { t: { episodes: [] } }, elements: { 'history-board': board } });
    ctx.renderResourceHistory();
    return board.innerHTML;
  },
  'resource control': () => load().ctx.resourceControlHTML({ key: H, control: { pending_id: H, next_action: H, paused: true, last_error: H, result: outcome } }),
  'resource control defaults': () => [load().ctx.resourceControlHTML({ key: 'k', control: { pending_id: 'p1', last_error: H } }), load().ctx.resourceOutcomeHTML({})],
  'attention card': () => load().ctx.resourceAttentionCardHTML(family, []),
  'attention card defaults': () => load().ctx.resourceAttentionCardHTML({ key: 'k', control: { state: 'healthy', policy_source: 'workspace' }, diagnoses: [] }, []),
  'attention section': () => [load().ctx.resourceAttentionHTML([{ key: 'k', diagnoses: [] }], []), load().ctx.resourceAttentionHTML([], [])],
  'family rows': () => [load().ctx.resourceFamilyRowHTML(family, [], true, NOW), load().ctx.resourceFamilyRowHTML({ key: 'k' }, [], false, NOW)],
  'family dup': () => {
    const dup = { key: H, label: H, rss_bytes: GB, cpu_percent: 2, process_count: 1, families: [{ key: 'a' }, { key: 'b' }] };
    return [load().ctx.resourceFamilyDupHTML(dup, [], true, NOW), load().ctx.resourceFamilyDupHTML(dup, [], false, NOW)];
  },
  'family groups': () => [
    load().ctx.resourceFamilyGroupHTML({ key: H, families: 2, rss: 1024, cpu: 3, rows: [{ family: { key: 'a' }, children: [{ key: 'b' }] }] }, [], new Set(['b'])),
    load().ctx.resourceFamilyGroupHTML({ key: H, infra: true, rss: 0, cpu: 0, rows: [{ family: { key: 'c' }, children: [] }] }, [], new Set()),
  ],
  'family group rows': () => {
    const { ctx } = load();
    const infra = ctx.resourceFamilyGroupRows({ key: H, infra: true, rows: [{ family: { key: H, workspace: H }, children: [{ key: 'b', workspace: H }] }] }, [], new Set(), NOW, {});
    const folded = ctx.resourceFamilyGroupRows({ key: 'claude', rows: [{ family: { key: 'x1', name: 'claude', workspace: '/w/' + H }, children: [] },
      { family: { key: 'x2', name: 'claude', workspace: '/w/' + H }, children: [] }] }, [], new Set(), NOW, {});
    return [...htmlOf(infra), ...htmlOf(folded)];
  },
  'policy line': () => [load().ctx.resourcePolicyLineHTML({ mode: H, max_rss_bytes: GB, max_cpu_percent: 80, sustain_seconds: 30,
    interventions: [{ action: 'pause_session' }, { action: H }], workspace_overrides: [1], pending: [1, 2] }), load().ctx.resourcePolicyLineHTML({})],
  'mission control': () => {
    const render = resources => {
      const { ctx, patched } = load({ SA: { t: { resources, sessions: [] }, familyDupOpen: {}, clearResourceSelection() {} },
        elements: { 'resource-board': { children: [] }, 'resource-observed': el() } });
      ctx.renderResourceMissionControl();
      return patched;
    };
    return [render({ host: {}, control: { mode: H }, sessions: [{ key: H, name: 'claude', root_pid: 4, workspace: '/w/' + H, rss_bytes: 1024, cpu_percent: 1, process_count: 1 }],
      interventions: [{ kind: H, status: 'applied' }] }), render({})];
  },
  'family drawer': () => htmlOf(load().ctx.familyDrawerSections({ ...family, root_pid: 1,
    processes: [{ pid: 1, name: H, rss_bytes: 100, cpu_percent: 1, started_at: at(0) }, { pid: 2, ppid: 99, name: H, rss_bytes: 50 }] },
  { sessions: [], now: NOW, events: [{ pid: 1, kind: 8, ts: at(1), detail: H }, { pid: 2, kind: 5, ts: at(2), remote_host: H, remote_port: 443 }],
    flags: [{ pid: 1, severity: 3, title: H, ts: at(10) }, { pid: 2, severity: 1, rule: 'x' }] })),
  'family drawer defaults': () => htmlOf(load().ctx.familyDrawerSections({ key: 'k', workspace: '/', root_pid: 1,
    processes: Array.from({ length: 13 }, (_, i) => ({ pid: i + 2 })) }, { now: NOW })),
  'drawer foot': () => [load().ctx.familyDrawerFootHTML({ key: H, orphan_count: 2, root_pid: 5, root_started_at: H, control: {} }, H), load().ctx.familyDrawerFootHTML({ key: 'k' })],
  'findings chart': () => {
    const render = flagsView => {
      const chart = el();
      const { ctx } = load({ SA: { t: { flagsView } }, elements: { 'chart-flags': chart } });
      ctx.renderChartFlags();
      return chart.innerHTML;
    };
    return [render([]), render([{ rule: H, severity: 3 }, { rule: 'x', severity: 1 }])];
  },
  'memory chart empty': () => {
    const chart = el();
    const { ctx } = load({ SA: { t: {} }, elements: { 'chart-memory': chart } });
    ctx.renderChartMemory();
    return chart.innerHTML;
  },
  'spend card refreshing': () => spendCard({ t: { costsCard: null } }, 'repo'),
  'spend card empty': () => spendCard({ t: { costsCard: { rows: [] } } }, 'repo'),
  'spend card list': () => spendCard({ t: { costsCard: { by: 'repo', rows: [{ key: H, calls: 1, cost_usd: 1 }] } } }, 'repo'),
  'spend card days': () => spendCard({ t: { costsCard: { by: 'day', rows: [{ key: H, calls: 1, cost_usd: 1 }] }, spendDay: H } }, 'day'),
  'spend day detail': () => {
    const { ctx } = load();
    const card = { since: '2026-10-09T00:00:00Z', until: '2026-10-11T00:00:00Z' };
    const report = rows => ({ since: '2026-10-10T00:00:00.000Z', until: '2026-10-11T00:00:00.000Z', by: 'repo', total: { calls: 2 }, rows });
    const row = { key: '2026-10-10', calls: 2, cost_usd: 2, local_calls: 1 };
    return [ctx.spendDayDetailHTML(row, card, 0, report([{ key: H, calls: 2, cost_usd: 2, harness: H }]), {}),
      ctx.spendDayDetailHTML(row, card, 0, report([]), { error: H })];
  },
  'plan items': () => htmlOf(load().ctx.spendPlanItems([
    { harness: 'codex', plan_type: H, home: H, account_key: H, limit_id: H, seen_at: '2026-11-25T10:00:00Z', windows: [{ window_minutes: 300, used_percent: 80 }, { window_minutes: 10080, used_percent: 95 }] },
    { harness: 'codex', home: H, seen_at: H, windows: [] }])),
  'spend list': () => [htmlOf(load().ctx.spendListItems([{ key: H, calls: 1, cost_usd: 3, harness: H, unpriced_calls: 1, local_calls: 1 },
    { key: '(unknown)', calls: 2, cost_usd: 2 }, { key: 'z', calls: 1, cost_usd: 1 }], 2, { by: 'provider', dayDetail: true })),
  htmlOf(load().ctx.spendListItems([{ key: H, calls: 1, cost_usd: 0 }], 8, { by: 'repo' }))],
  'spend days': () => htmlOf(load().ctx.spendDayItems([{ key: H, calls: 1, cost_usd: 2, local_calls: 1 }, { key: '2026-10-10', calls: 0, cost_usd: 0 }], H)),
  'events rows': () => events({ t: { sessions: [], eventsView: [{ ts: '2026-01-02T03:04:05Z', pid: 7, kind: 9, detail: H },
    { ts: '2026-01-02T03:04:06Z', pid: 0, session_id: H, kind: 12, tool: H, tool_status: 'ok' }] } }),
  'events capped': () => events({ t: { sessions: [], eventsView: Array.from({ length: 51 }, (_, i) => ({ ts: '2026-01-02T03:04:05Z', pid: i + 1, kind: 9 })) } })[1][0].at(-1),
  'events empty': () => events({ t: { eventsView: [] } }),
  'events empty scope label': () => events({ t: { eventsView: [] }, timelinePids: [7], timelinePidLabel: H }),
};

const hostileChip = label => `<span class="harness-chip" title="${E}"><span class="harness-glyph" data-harness-color="hsl(264 62% 62%)" aria-hidden="true">&lt;</span>${label}</span>`;
const agentChip = label => `<span class="harness-chip" title="agent"><span class="harness-glyph" data-harness-color="hsl(61 62% 62%)" aria-hidden="true">?</span>${label}</span>`;
const viewFamily = key => `<button type="button" class="btn btn-ghost btn-sm" data-action="view-family" data-key="${key}">View family</button>`;
const emptySpark = '<svg class="resource-spark" viewBox="0 0 120 24" preserveAspectRatio="none" role="img" aria-label="Memory over the last hour"></svg>';
const quietRow = ({ cls = '', title = '', label = 'agent', key }) => `<div class="family-row${cls}">\n    <span class="family-name" title="${title}"><strong>${label}</strong></span>\n    <span class="resource-metric"><b>—</b><small>memory</small></span>\n    <span class="resource-metric"><b>—</b><small>CPU</small></span>\n    <span class="resource-metric"><b>0</b><small>processes</small></span>\n    ${emptySpark}\n    ${viewFamily(key)}\n  </div>`;
const dupHead = (open, cpu, memory) => `<div class="family-branch family-dup${open ? ' open' : ''}">\n    <div class="family-row">\n      <span class="family-name"><button type="button" class="family-dup-toggle" data-action="toggle-family-dup" data-key="${E}" aria-expanded="${open}"><strong>${E}</strong><span class="family-dup-count">×2</span><svg class="icon"><use href="#i-arrow"/></svg></button></span>\n      <span class="resource-metric"><b>${memory}</b><small>memory</small></span>\n      <span class="resource-metric"><b>${cpu}</b><small>CPU</small></span>\n      <span class="resource-metric"><b>1</b><small>process</small></span>\n    </div>`;
const policyDefault = mode => `<div class="resource-policy"><span><b>${mode}</b> machine policy · budgets disabled · 0 workspace overrides</span><span><span>0 approvals pending</span><button type="button" class="btn btn-ghost btn-sm" data-action="edit-resource-policy">Edit policy</button></span></div>`;
const hint = 'The score is the tightest limit, not free RAM. It is the lowest of memory still available, CPU still idle, swap still free, and thermal headroom. Under 15 is critical. Under 50 is constrained. 50 or more is ample. Critical pressure is separate: available memory under 10%, or swap at least 80% full.';
const stripHead = (capacity, text, score) => `<section class="machine-strip capacity-${capacity}" aria-label="Whole-machine resource pressure">\n    <div class="machine-tile machine-headroom">\n      <div class="machine-eyebrow-row"><span class="resource-eyebrow">Machine headroom</span><details class="headroom-hint"><summary aria-label="What machine headroom means">?</summary><p class="headroom-hint-box">${text}</p></details></div>\n      <b>${score} / 100</b><small>${capacity}</small>\n    </div>\n    <div class="machine-tile machine-memory"><span class="resource-eyebrow">Memory</span>`;
const marker = (kind, x, title) => `<g class="resource-activity-marker kind-${kind}"><line x1="${x}" x2="${x}" y1="2" y2="36"/><circle cx="${x}" cy="5" r="2.4"/><title>${title}</title></g>`;
const toolMarkers = [22, 44, 66, 88, 110, 132, 154, 176].map(x => marker('tool', `${x}.0`, 'Recorded activity')).join('');
const activityRows = [1, 2, 3, 4, 5, 6, 7, 8].map(i => `\n        <div class="resource-activity-row">\n          <time>12:0${i}:00</time>\n          <span class="resource-activity-kind kind-tool">TOOL</span>\n          <span><b>PID ${i}</b> · Recorded activity</span>\n        </div>`).join('');
const outcomeDefault = '<details class="resource-action-result"><summary>intervention · Application unknown · Verification unknown</summary><ul></ul></details>';
const orphanRows = Array.from({ length: 12 }, (_, i) => `<tr class="family-proc-row orphan">\n      <td>process <span class="agent-status orphan">leftover</span></td>\n      <td>${i + 2}</td><td>—</td><td>—</td><td>—</td>\n    </tr>`).join('');
const procTable = (count, rows, more) => `<section class="family-drawer-section">\n    <h4>Processes <small>${count}</small></h4>\n    <table class="family-drawer-procs"><thead><tr><th>Name</th><th>PID</th><th>Memory</th><th>CPU</th><th>Age</th></tr></thead><tbody>${rows}</tbody></table>\n    ${more}\n  </section>`;
const terminate = (pid, started, label) => `<button type="button" class="btn btn-danger btn-sm" data-action="kill" data-pid="${pid}" data-started="${started}" data-family="${label}"><svg class="icon"><use href="#i-power"/></svg><span>Terminate family</span></button>`;
const dayHead = (key, range, summary) => `<section class="spend-day-detail" aria-label="Selected day usage">\n    <div class="spend-day-detail-head"><h3>${key}</h3><button type="button" class="btn btn-ghost btn-sm" data-action="reset-spend-day">Clear selection</button></div>\n    <p class="spend-day-range">${range}</p>\n    <p class="spend-day-summary">${summary}</p>\n    `;
const spendRow = (focus, key, hintText, chip, calls, cost, unpriced) => `<div class="spend-row"${focus}>\n      <span class="spend-key" title="${key}">${key}</span>\n      ${hintText}\n      ${chip}\n      <span class="spend-calls">${calls}</span>\n      <span class="spend-cost">${cost}</span>\n      ${unpriced}\n    </div>`;
const dayButton = (key, pressed, label, h, cost, dayLabel) => `<button type="button" class="spend-day" data-action="select-spend-day" data-day="${key}" aria-pressed="${pressed}" aria-label="${label}" title="${label}">\n      <span class="spend-day-track"><span class="spend-day-bar" data-h="${h}"></span></span>\n      <span class="spend-day-cost">${cost}</span>\n      <span class="spend-day-label">${dayLabel}</span>\n    </button>`;
const timelineRow = (fresh, cls, label, title, who, detail) => `\n      <div class="timeline-item ${fresh}">\n        <span class="t">Jan 02 03:04</span>\n        <span class="event-kind ${cls}">${label}</span>\n        <span class="pid" title="${title}">${who}</span>\n        <span class="dtl">${detail}</span>\n      </div>\n    `;
const eventsEmpty = text => `<div class="empty"><svg class="icon"><use href="#i-activity"/></svg><span>${text}</span></div>`;

const expected = {
  'activity chart': '<rect x="0.0" y="94" width="399.0" height="2" class="act-zero"/><rect x="400.0" y="34.5" width="399.0" height="61.5" rx="1.5" class="act-ev"><title>11:00 — 3 events, 1 flags</title></rect><rect x="400.0" y="14.0" width="399.0" height="20.5" rx="1.5" class="act-fl"/><rect x="800.0" y="55.0" width="399.0" height="41.0" rx="1.5" class="act-ev"><title>12:00 — 2 events</title></rect>',
  'activity markers': marker('imgsrcxonerror1amp', '55.0', E) + marker('activity', '110.0', 'Recorded activity'),
  'machine strip': stripHead(E, hint + ' Right now the score is swap still free. A full swap file can make this critical while plenty of RAM is still available.', 37)
    + `<div class="resource-host-bar" role="img" aria-label="Memory: 25.0 percent agents, 50.0 percent other, 25.0 percent available">\n        <span class="resource-host-segment agent" data-w="25.0"></span>\n        <span class="resource-host-segment other" data-w="50.0"></span>\n        <span class="resource-host-segment available" data-w="25.0"></span>\n      </div>\n      <div class="resource-host-legend"><span><i class="agent"></i>Agents 25.0%</span><span><i class="other"></i>Other 50.0%</span><span><i class="available"></i>4.0 GB available of 16.0 GB</span></div></div>\n    <div class="machine-tile"><span class="resource-eyebrow">CPU</span><b>42.5% total</b><small>30.0% agents · 12.5% other</small></div>\n    <div class="machine-tile"><span class="resource-eyebrow">Swap</span><b>1.0 GB / 2.0 GB</b></div>\n    <div class="machine-chips"><span class="machine-chip">${E} pressure</span><span class="machine-chip">${E} thermal</span></div>\n  </section>`,
  'machine strip unavailable': stripHead('unknown', hint, 0)
    + '<b>Unavailable</b></div>\n    <div class="machine-tile"><span class="resource-eyebrow">CPU</span><b>Unavailable</b></div>\n    <div class="machine-tile"><span class="resource-eyebrow">Swap</span><b>Not configured</b></div>\n    <div class="machine-chips"><span class="machine-chip">Unknown pressure</span><span class="machine-chip">Unknown thermal</span></div>\n  </section>',
  'flight recorder': `<section class="resource-flight-recorder">\n    <div class="resource-flight-head"><div><span class="resource-eyebrow">Local history</span><h3>Pressure flight recorder</h3></div><span>2 recent episodes</span></div>\n    <p class="resource-flight-intro">When a session crosses a diagnostic threshold, secure-agent keeps a bounded ten-minute prelude and the highest-impact processes for post-mortem review.</p>\n    <div class="resource-episode-list">`
    + `<details class="resource-episode severity-${E}">\n        <summary><span><b>${E}</b><small>${E}</small></span><span class="resource-episode-metrics"><b>2.0 GB</b><b>55.5%</b><time>10m ago</time></span></summary>\n        <div class="resource-episode-body">\n          <div class="resource-episode-host"><span class="resource-eyebrow">Host at capture</span><strong>1.0 GB available</strong><span>${E} pressure · ${E} thermal · headroom 12 / 100</span></div>\n          <div><span class="resource-eyebrow">What drove it</span><div class="resource-episode-processes"><div class="resource-episode-process"><span><b>${E}</b> · PID 7 · leftover</span><span>1.0 GB · 50%</span></div><div class="resource-episode-process"><span><b>process</b> · PID 8</span><span>— · 0%</span></div><small>11 lower-impact processes omitted</small></div></div>\n          <div><span class="resource-eyebrow">Evidence</span><ul><li>${E}</li><li>${E}</li></ul><svg class="resource-episode-spark" viewBox="0 0 220 38" preserveAspectRatio="none" role="img" aria-label="Resource trend and nearby activity before capture"><polyline class="resource-spark-memory" points="0.0,38.0 220.0,0.0"/><polyline class="resource-spark-cpu" points="0.0,0.0 220.0,38.0"/>${marker('imgsrcxonerror1amp', '2.0', E)}${toolMarkers}</svg></div>\n          <div class="resource-episode-context">\n            <div class="resource-context-head"><span class="resource-eyebrow">What happened nearby</span><span class="resource-correlation-badge">Observed correlation</span></div>\n            <strong>${E}</strong><p>Timing evidence can narrow an investigation, but does not prove which action caused the resource change.</p>\n            <div class="resource-activity-list">${activityRows}</div>\n            <div class="resource-context-actions"><small>1 earlier activities omitted from this view</small><small>Activity context is still settling</small></div>\n          </div>\n        </div>\n      </details>`
    + '<details class="resource-episode severity-warning">\n        <summary><span><b>Unknown</b><small>Resource pressure</small></span><span class="resource-episode-metrics"><b>—</b><b>—</b><time>recorded</time></span></summary>\n        <div class="resource-episode-body">\n          \n          <div><span class="resource-eyebrow">What drove it</span><div class="resource-episode-processes"><span>No process breakdown recorded</span></div></div>\n          <div><span class="resource-eyebrow">Evidence</span><p>No additional evidence recorded.</p><svg class="resource-episode-spark" viewBox="0 0 220 38" preserveAspectRatio="none" role="img" aria-label="Resource trend and nearby activity before capture"></svg></div>\n          <div class="resource-episode-context">\n            <div class="resource-context-head"><span class="resource-eyebrow">What happened nearby</span></div>\n            <p>No matching activity was recorded during this pressure window.</p>\n            <div class="resource-activity-list"><span>No bounded activity references were available.</span></div>\n            <div class="resource-context-actions"><span></span><small>Scoped to this captured process lifetime</small></div>\n          </div>\n        </div>\n      </details></div>\n  </section>',
  'flight recorder empty': '<section class="resource-flight-recorder">\n    <div class="resource-flight-head"><div><span class="resource-eyebrow">Local history</span><h3>Pressure flight recorder</h3></div><span>No pressure captured yet</span></div>\n    <p class="resource-flight-intro">When a session crosses a diagnostic threshold, secure-agent keeps a bounded ten-minute prelude and the highest-impact processes for post-mortem review.</p>\n    <div class="resource-episode-list"><div class="resource-detail-empty">The recorder is armed. Episodes appear here when a session becomes heavy, grows rapidly, or leaves resource-holding processes behind.</div></div>\n  </section>',
  'resource control': `<span class="resource-approval">\n      <button type="button" class="btn btn-danger btn-sm" data-action="resource-control" data-id="${E}" data-decision="apply" data-intervention="${E}">Apply ${E}</button>\n      <button type="button" class="btn btn-ghost btn-sm" data-action="resource-control" data-id="${E}" data-decision="dismiss">Keep running</button>\n    </span><button type="button" class="btn btn-primary btn-sm" data-action="resource-control" data-session="${E}" data-decision="resume">Resume session</button><details class="resource-control-error"><summary>The last action did not complete; the session is still paused.</summary><p>${E}</p></details><details class="resource-action-result"><summary>${E} · Partially applied · Observing up to 3 samples / 15 seconds</summary><p>${E}</p><ul><li>Before · Memory 1 KB · CPU 5% · Host ${E} · Available 2 KB · Host CPU 7%</li><li>After 1 · Family memory unavailable</li><li>${E}</li><li>${E}</li></ul></details>`,
  'resource control defaults': [`<span class="resource-approval">\n      <button type="button" class="btn btn-danger btn-sm" data-action="resource-control" data-id="p1" data-decision="apply" data-intervention="">Apply intervention</button>\n      <button type="button" class="btn btn-ghost btn-sm" data-action="resource-control" data-id="p1" data-decision="dismiss">Keep running</button>\n    </span><details class="resource-control-error"><summary>The last action did not complete.</summary><p>${E}</p></details>`, outcomeDefault],
  'attention card': `<article class="resource-session-card needs-attention-card pressure-${E}" data-key="${E}">\n    <div class="family-name">${hostileChip('')}<strong>${E} · ${E}</strong></div>\n    <div class="family-metrics"><b>1.0 GB</b> memory · <b>12.5%</b> CPU · 2 processes</div>\n    <p class="resource-diagnosis">${E} <small>+1 more</small></p>\n    <div class="resource-session-foot">\n      <span class="resource-reclaim">up to 512 MB reclaimable</span>\n      <span class="resource-control-state">${E}</span><span class="resource-policy-source">workspace policy · ${E}</span>\n      ${viewFamily(E)}\n    </div>\n  </article>`,
  'attention card defaults': `<article class="resource-session-card needs-attention-card pressure-warning" data-key="k">\n    <div class="family-name">${agentChip('')}<strong>agent</strong></div>\n    <div class="family-metrics"><b>—</b> memory · <b>—</b> CPU · 0 processes</div>\n    <p class="resource-diagnosis">Resource pressure detected</p>\n    <div class="resource-session-foot">\n      \n      <span class="resource-policy-source">workspace policy · </span>\n      ${viewFamily('k')}\n    </div>\n  </article>`,
  'attention section': [`<section class="needs-attention" aria-label="Families that need attention">\n    <h3 class="family-section-head">Needs attention<span>1</span></h3>\n    <div class="needs-attention-cards"><article class="resource-session-card needs-attention-card pressure-warning" data-key="k">\n    <div class="family-name">${agentChip('')}<strong>agent</strong></div>\n    <div class="family-metrics"><b>—</b> memory · <b>—</b> CPU · 0 processes</div>\n    <p class="resource-diagnosis">Resource pressure detected</p>\n    <div class="resource-session-foot">\n      \n      \n      ${viewFamily('k')}\n    </div>\n  </article></div>\n  </section>`,
    '<section class="needs-attention" aria-label="Families that need attention">\n    <h3 class="family-section-head">Needs attention</h3>\n    <div class="needs-attention-empty">Every family is within its thresholds.</div>\n  </section>'],
  'family rows': [`<div class="family-row nested pressure-${E}">\n    <span class="family-name" title="${E}"><strong>${E} · ${E}</strong></span>\n    <span class="resource-metric"><b>1.0 GB</b><small>memory</small></span>\n    <span class="resource-metric"><b>12.5%</b><small>CPU</small></span>\n    <span class="resource-metric"><b>2</b><small>processes</small></span>\n    <svg class="resource-spark" viewBox="0 0 120 24" preserveAspectRatio="none" role="img" aria-label="Memory over the last hour"><polyline class="resource-spark-memory" points="0.0,24.0 120.0,0.0"/></svg>\n    ${viewFamily(E)}\n  </div>`,
    quietRow({ key: 'k' })],
  'family dup': [dupHead(true, '2%', '1.0 GB') + `<div class="family-children">${quietRow({ cls: ' nested', key: 'a' })}${quietRow({ cls: ' nested', key: 'b' })}</div>\n  </div>`,
    dupHead(false, '2%', '1.0 GB') + '\n  </div>'],
  'family groups': [`<details class="family-group" data-harness="${E}" open>\n    <summary class="family-group-head">${hostileChip(`<span class="harness-label">${E}</span>`)}<span class="family-group-counts">2 families · 1 KB · 3% CPU</span></summary>\n    <div class="family-group-body"></div>\n  </details>`,
    `<details class="family-group infra" data-harness="${E}">\n    <summary class="family-group-head"><span class="family-group-title">Infrastructure</span><span class="family-group-counts">1 tracked · — · 0% CPU</span></summary>\n    <div class="family-group-body"></div>\n  </details>`],
  'family group rows': [`<div class="family-branch">${quietRow({ title: E, label: `agent · ${E}`, key: E })}<div class="family-children">${quietRow({ cls: ' nested', title: E, label: `agent · ${E}`, key: 'b' })}</div></div>`,
    `<div class="family-branch family-dup">\n    <div class="family-row">\n      <span class="family-name"><button type="button" class="family-dup-toggle" data-action="toggle-family-dup" data-key="group:claude|Claude Code · ${E}" aria-expanded="false"><strong>Claude Code · ${E}</strong><span class="family-dup-count">×2</span><svg class="icon"><use href="#i-arrow"/></svg></button></span>\n      <span class="resource-metric"><b>—</b><small>memory</small></span>\n      <span class="resource-metric"><b>0%</b><small>CPU</small></span>\n      <span class="resource-metric"><b>0</b><small>processes</small></span>\n    </div>\n  </div>`],
  'policy line': [`<div class="resource-policy"><span><b>${E}</b> machine policy · 1.0 GB memory · 80% CPU · 30s grace · pause session → ${E} · 1 workspace override</span><span><span>2 approvals pending</span><button type="button" class="btn btn-ghost btn-sm" data-action="edit-resource-policy">Edit policy</button></span></div>`,
    policyDefault('observe')],
  'mission control': [[[
    '<section class="needs-attention" aria-label="Families that need attention">\n    <h3 class="family-section-head">Needs attention</h3>\n    <div class="needs-attention-empty">Every family is within its thresholds.</div>\n  </section>',
    '<h3 class="family-section-head">Families by harness<span>1 family</span></h3>',
    '<details class="family-group" data-harness="claude">\n    <summary class="family-group-head"><span class="harness-chip" title="Claude Code"><span class="harness-tile hk-claude" aria-hidden="true"><svg class="harness-logo" aria-hidden="true"><use href="#logo-claude"/></svg></span><span class="harness-label">Claude Code</span></span><span class="family-group-counts">1 family · 1 KB · 1% CPU</span></summary>\n    <div class="family-group-body"></div>\n  </details>',
    policyDefault(E),
    `<section aria-label="Recent intervention results"><h3 class="family-section-head">Recent intervention results</h3><details class="resource-action-result"><summary>${E} · Applied · Verification unknown</summary><ul></ul></details></section>`,
  ]], [[
    '<div class="empty"><svg class="icon"><use href="#i-activity"/></svg><span>No attributed agent resource use right now</span></div>',
    policyDefault('observe'),
  ]]],
  'family drawer': [
    `<div class="family-drawer-head">${hostileChip(`<span class="harness-label">${E}</span>`)}<button type="button" class="sd-path" data-action="copy-path" data-path="${E}" title="${E} — click to copy">${E}</button></div>`,
    `<section class="family-drawer-section">\n    <h4>Memory and CPU <small>last 60 min</small></h4>\n    <div class="family-drawer-now"><span><b>1.0 GB</b> memory</span><span><b>12.5%</b> CPU</span><span><b>512 MB</b> reclaimable</span></div>\n    <svg class="family-drawer-spark" viewBox="0 0 480 56" preserveAspectRatio="none" role="img" aria-label="Memory and CPU over the last hour"><polyline class="resource-spark-memory" points="0.0,56.0 480.0,0.0"/><polyline class="resource-spark-cpu" points="0.0,56.0 480.0,0.0"/></svg>\n    <p class="resource-diagnosis">${E}</p><p class="resource-diagnosis">High CPU use</p>\n    <ul class="family-drawer-evidence"><li>${E}</li></ul>\n  </section>`,
    procTable(2, `<tr class="family-proc-row">\n      <td>${E}</td>\n      <td>1</td><td>100 B</td><td>1%</td><td>30m</td>\n    </tr><tr class="family-proc-row orphan">\n      <td>${E} <span class="agent-status orphan">leftover</span></td>\n      <td>2</td><td>50 B</td><td>—</td><td>—</td>\n    </tr>`, ''),
    `<section class="family-drawer-section">\n    <h4>Recent activity <small>2</small></h4>\n    <div class="family-drawer-events"><div class="family-event"><time>12:01:00</time><span class="event-kind">TOOL USE</span><span><b>${E}</b> ${E}</span></div><div class="family-event"><time>12:02:00</time><span class="event-kind">NET CONN</span><span><b>${E}</b> ${E}:443</span></div></div>\n    <button type="button" class="link-btn" data-action="family-events" data-key="${E}">Open in Events</button>\n  </section>`,
    `<section class="family-drawer-section">\n    <h4>Findings <small>2</small></h4>\n    <div class="family-finding"><span class="sev s3">●</span><span>${E}</span><time>20m ago</time></div><div class="family-finding"><span class="sev s1">●</span><span>x</span></div><button type="button" class="link-btn" data-action="goto-tab" data-tab="home" data-group="findings">Open Findings</button>\n  </section>`,
  ],
  'family drawer defaults': [
    `<div class="family-drawer-head">${agentChip('<span class="harness-label">agent</span>')}</div>`,
    '<section class="family-drawer-section">\n    <h4>Memory and CPU <small>last 60 min</small></h4>\n    <div class="family-drawer-now"><span><b>—</b> memory</span><span><b>—</b> CPU</span></div>\n    <svg class="family-drawer-spark" viewBox="0 0 480 56" preserveAspectRatio="none" role="img" aria-label="Memory and CPU over the last hour"></svg>\n    <p class="resource-diagnosis quiet">Within current thresholds</p>\n    \n  </section>',
    procTable(13, orphanRows, '<button type="button" class="btn btn-ghost btn-sm show-more" data-action="show-more" data-key="family-procs:k">Show 1 more</button>'),
    '<section class="family-drawer-section">\n    <h4>Recent activity <small>0</small></h4>\n    <p class="family-drawer-empty">No events from these processes in the loaded window.</p>\n    <button type="button" class="link-btn" data-action="family-events" data-key="k">Open in Events</button>\n  </section>',
    '<section class="family-drawer-section">\n    <h4>Findings <small>0</small></h4>\n    <p class="family-drawer-empty">No open findings for these processes.</p>\n  </section>',
  ],
  'drawer foot': [`<button type="button" class="btn btn-danger btn-sm" data-action="kill-family-orphans" data-key="${E}"><svg class="icon"><use href="#i-power"/></svg><span>Terminate orphans (2)</span></button>` + terminate(5, E, E), terminate(0, '', '')],
  'findings chart': ['<div class="empty"><svg class="icon"><use href="#i-alert"/></svg><span>No findings in the window</span></div>',
    `<div class="hbar-row">\n      <span class="hbar-label" title="${E}">${E}</span>\n      <span class="hbar-track"><span class="hbar-fill crit" data-w="100.0"></span></span>\n      <span class="hbar-val">1</span>\n      <span class="hbar-sub">1 critical</span>\n    </div><div class="hbar-row">\n      <span class="hbar-label" title="x">x</span>\n      <span class="hbar-track"><span class="hbar-fill warn" data-w="100.0"></span></span>\n      <span class="hbar-val">1</span>\n      \n    </div>`],
  'memory chart empty': '<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>No attributed sessions yet</span></div>',
  'spend card refreshing': [['<div class="empty"><span>Refreshing usage…</span></div>'], [[]]],
  'spend card empty': [['<div class="empty"><svg class="icon"><use href="#i-activity"/></svg><span>No model calls in this window.</span></div>'], [[]]],
  'spend card list': [['<div class="spend-list"></div>'], [[], [spendRow('', E, '', '', '1 call', '$1.00', '')]]],
  'spend card days': [['<div class="spend-bars" role="group" aria-label="Daily usage dates" aria-describedby="spend-day-guidance"></div><div class="spend-day-inspector"></div>',
    dayHead(E, 'Time range unavailable', '<strong>$1.00</strong> · 1 call') + '<p class="spend-day-status" role="status">Day breakdown unavailable: chart time range is missing.</p>\n  </section>'],
  [[], [dayButton(E, true, `${E} · $1.00 · 1 call`, '100.0', '$1.00', E)]]],
  'spend day detail': [
    dayHead('2026-10-10', 'Day grouped at UTC+00:00', '<strong>$2.00</strong> · 2 calls · 1 local') + '<h4>By repository</h4><div class="spend-list">'
      + spendRow(` data-spend-repo="${E}" tabindex="-1" role="group" aria-label="${E} · $2.00 · 2 calls"`, E, '', hostileChip(''), '2 calls', '$2.00', '') + '</div>\n  </section>',
    dayHead('2026-10-10', 'Day grouped at UTC+00:00', '<strong>$2.00</strong> · 2 calls · 1 local')
      + `<p class="spend-day-status" role="status">Day breakdown unavailable: ${E}</p><h4>By repository</h4><div class="spend-list"><p>No model calls recorded for this day.</p></div>\n  </section>`,
  ],
  'plan items': [
    `<div class="spend-plan">\n      <span class="spend-plan-text">Codex ${E} · ${E} · 5-hour 80% used · weekly 95% used · Observed <time datetime="2026-11-25T10:00:00.000Z">Nov 25, 2026 10:00 AM</time></span><span class="hbar-track" title="5-hour"><span class="hbar-fill warn" data-w="80.0"></span></span><span class="hbar-track" title="weekly"><span class="hbar-fill crit" data-w="95.0"></span></span>\n    </div>`,
    `<details class="spend-plan-history"><summary>Unverified quota observation · ${E}</summary><div class="spend-plan spend-plan-unverified">\n      <span class="spend-plan-text">Codex · ${E} · Account unverified — may overlap a shared account · Observation time unavailable</span>\n    </div></details>`,
  ],
  'spend list': [[
    spendRow(` data-spend-repo="${E}" tabindex="-1" role="group" aria-label="${E} · $3.00 · 1 call · 1 unpriced · 1 local"`, E, '', hostileChip(''), '1 call', '$3.00', '<span class="spend-hint">1 unpriced</span>'),
    spendRow(' data-spend-repo="(unknown)" tabindex="-1" role="group" aria-label="(unknown) · $2.00 · 2 calls"', '(unknown)', '<span class="spend-hint">provider not recorded</span>', '', '2 calls', '$2.00', ''),
    '<button type="button" class="btn btn-ghost btn-sm show-more" data-action="show-more" data-key="spend">Show 1 more</button>',
  ], [spendRow('', E, '', '', '1 call', '$0.00', '')]],
  'spend days': [dayButton('2026-10-10', false, '2026-10-10 · $0.00 · 0 calls', '0.0', '$0', 'Sat 10'),
    dayButton(E, true, `${E} · $2.00 · 1 call · 1 local`, '100.0', '$2.00', E)],
  'events rows': ['', [[timelineRow('fresh', 'tool', 'TOOL', `session ${E}`, 'session &lt;img src', `${E} · ok`),
    timelineRow('fresh-sev', 'proxy', 'PROXY HIT', 'PID 7', `${E} · PID 7`, E)]]],
  'events capped': '<div class="list-more"><button type="button" class="btn btn-ghost btn-sm show-more" data-action="show-more" data-key="events">Show 1 more</button></div>',
  'events empty': [eventsEmpty('No system events logged'), []],
  'events empty scope label': [eventsEmpty(`No events for ${E} in the loaded window`), []],
};

for (const [name, render] of Object.entries(cases)) {
  test(`overview markup: ${name}`, () => {
    assert.deepEqual(render(), expected[name]);
  });
}
