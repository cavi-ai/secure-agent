import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Exact tab-egress.js markup for hostile served values: each value renders
// escaped once in text and attribute positions, and nested fragments render as markup.
const H = `<img src=x onerror=1>"'&amp;`;
const E = '&lt;img src=x onerror=1&gt;&quot;&#39;&amp;amp;';
const NOW = Date.parse('2026-01-01T02:00:00Z');

const assets = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const ctx = { window: {}, document: {} };
vm.createContext(ctx);
for (const f of ['lib.js', 'tab-egress.js']) vm.runInContext(readFileSync(new URL(f, assets), 'utf8'), ctx, { filename: f });
vm.runInContext(`Date.now = () => ${NOW};`, ctx);

// A container for lib.js patchList and innerHTML writes: it keeps the markup
// of every node patchList inserts, or the string an innerHTML assignment wrote.
function container() {
  const child = markup => ({ nodeType: 1, markup });
  return {
    childNodes: [], written: '',
    ownerDocument: { createElement: () => ({ querySelectorAll: () => [], set innerHTML(markup) { this.firstElementChild = markup ? child(markup) : null; } }) },
    get firstChild() { return this.childNodes[0] || null; },
    set innerHTML(markup) { this.childNodes = []; this.written = markup; },
    insertBefore(node) { this.childNodes.push(node); },
    querySelector: () => null, querySelectorAll: () => [], contains: () => false,
  };
}
const written = el => (el.childNodes.length ? el.childNodes.map(n => n.markup) : el.written);

// Runs a renderer against window.SA.t and returns what it wrote into ids[0].
function render(fn, t, ids, sa = {}) {
  const els = Object.fromEntries(ids.map(id => [id, container()]));
  ctx.document = { activeElement: null, getElementById: id => els[id] || null };
  ctx.window = { SA: { t, reducedMotion: true, ...sa } };
  ctx[fn]();
  return written(els[ids[0]]);
}

function drawer(rows, status = {}) {
  const body = container();
  ctx.window = { SA: { t: { status, uninspected: rows } } };
  ctx.fillUninspected(body);
  return written(body);
}

const firewall = ['firewall-container', 'badge-firewall-mode'];
const seen = { first_seen: '2026-01-01T00:00:00Z', last_seen: '2026-01-01T01:30:00Z' };
const vendorInput = { agent: H, host: H, count: 2, first_seen: seen.first_seen, identity: { class: 'vendor', org: H } };
const uninspected = [
  { agent: H, host: `a.${H}.x`, count: 5, ...seen, session_id: H, assessment: H, rationale: H, identity: { org: H, name: H } },
  { agent: H, host: `b.${H}.x`, count: 1 },
  vendorInput,
  { agent: 'claude', host: '104.16.0.1', count: 3, infra: H },
  { agent: H, host: H, count: 1, agent_kind: 'infra' },
];
const scope = { agent: H, exe_path: H, harness: H, workspace: H };
const episodes = [
  { id: H, candidate: true, advisor_inference: { possible_purpose: H, confidence: H }, observed: { id: H, host: H, port: 443, protocol: H, count: 5,
    recurring: true, intervals: [1800000000000, 3600000000000], first_seen: H, last_seen: H, session_ids: [H, 'session-2'], scope_complete: true, scope } },
  { id: 'e2', expected: true, expected_rule_id: H, observed: { recurring: true } },
  { id: 'e3', candidate: true, observed: { host: H, recurring: true, scope_complete: false, scope: { agent: H } } },
];
const rules = [
  { id: H, kind: 'scope', agent: H, exe_path: H, harness: 'claude', workspace: H, rationale: H },
  { id: 'r2', kind: 'destination', host: H, port: 443, protocol: H, agent: H, harness: H },
  { id: 'r3' },
];

const cases = {
  'firewall empty': () => render('renderFirewall', { status: {} }, firewall),
  'firewall rules, suggestions and allowlist': () => render('renderFirewall', {
    status: { advisor_enabled: true, firewall_stats: {
      [H]: { mode: 'block', would_block: 2, blocked: 1, legit: 0 },
      quiet: { would_block: 0, blocked: 0, legit: 0 },
      'vendor-key': { type: 'vendor-key', mode: 'monitor', would_block: 0, blocked: 0, legit: 4 } } },
    suggestions: [{ agent: H, host: H, count: 4, assessment: H, rationale: H, identity: { org: H } }, { agent: H, host: H, count: 1 }],
    allowlist: [{ agent: H, host: H }],
  }, firewall),
  'firewall rule rows': () => [ctx.fwRuleHTML(H, { would_block: 2, blocked: 1, legit: 3 }, true), ctx.fwRuleHTML(H, { mode: 'block' }, false)],
  'endpoints': () => render('renderEndpoints', { status: { advisor_enabled: true }, uninspected }, ['endpoints-container']),
  'endpoints empty': () => render('renderEndpoints', { status: {} }, ['endpoints-container']),
  'uninspected drawer': () => drawer(uninspected),
  'uninspected drawer with only vendor rows': () => drawer([vendorInput], { advisor_enabled: true }),
  'uninspected drawer empty': () => drawer([]),
  'recurring episodes': () => render('renderEgressEpisodes', { egressEpisodes: episodes, expectedEgress: [] },
    ['recurring-egress-container', 'badge-recurring-egress'], { protectionContext: { phase: 'traffic', episodeId: H } }),
  'expected rules': () => render('renderExpectedEgressRules', { expectedEgress: rules, egressEpisodes: [] },
    ['expected-egress-container', 'badge-expected-egress'], { protectionContext: { phase: 'rules', ruleId: H, status: 'ready' } }),
  'expected rule rows': () => [ctx.expectedEgressRuleHTML(rules[0], true), ctx.expectedEgressRuleHTML(rules[1])],
  'sources': () => render('renderSources', { sources: [{ source: H, origin: 'user' }, { source: H, origin: 'config' }] }, ['sources-list', 'badge-sources-count']),
  'sources empty': () => render('renderSources', { sources: [] }, ['sources-list', 'badge-sources-count']),
};

// Served counters that the unconverted templates interpolated without escaping.
const counters = {
  'suggestion count': () => render('renderFirewall', { status: { uninspected_egress: 1 }, suggestions: [{ agent: 'a', host: 'h', count: H }] }, firewall),
  'rule counters': () => ctx.fwRuleHTML('r', { would_block: H, blocked: H, legit: H }, false),
  'endpoint count': () => ctx.egressRowHTML({ agent: 'a', host: 'h', count: H }, false),
  'vendor rollup count': () => ctx.vendorRollupHTML({ agent: 'a', org: 'o', count: H, first_seen: '', rows: [{ agent: 'a', host: 'h', count: 1 }] }, false),
  'carrier hits': () => ctx.carriersHTML([{ agent: 'a', host: 'h', count: H, infra: 'o' }]),
};

const label = text => ` <span class="fw-metric dim">${text}</span>`;
const chip = `<span class="advisor-chip adv-${E}" title="${E}">advisor: ${E}</span>`;
const suggestion = (host, agent, count, extra = '', advice = '') => `<div class="fw-rule fw-suggestion">\n        <div class="fw-rule-main">\n          <span class="fw-rule-id">${host}</span>${extra}\n          <div class="fw-metrics">\n            <span class="fw-metric dim">${agent} · seen <b>${count}×</b> uninspected</span>\n            ${advice}\n          </div>\n        </div>\n        <button class="btn btn-ghost btn-sm" data-action="allow-host" data-agent="${agent}" data-host="${host}"><svg class="icon"><use href="#i-shield"/></svg><span>Allow for ${agent}</span></button>\n      </div>`;
const promote = id => `<button class="btn btn-primary btn-sm" data-action="promote" data-rule="${id}"><svg class="icon"><use href="#i-arrow"/></svg><span>Promote to block</span></button>`;
const demote = id => `<span class="mode-chip block">blocking</span><button class="btn btn-ghost btn-sm" data-action="demote" data-rule="${id}" title="Back to monitor-only — blocking is reversible"><svg class="icon"><use href="#i-arrow"/></svg><span>Demote to monitor</span></button>`;
const rule = (id, [wouldBlock, blocked, legit], action, flash = '') => `\n      <div class="fw-rule${flash}">\n        <div class="fw-rule-main">\n          <span class="fw-rule-id">${id}</span>\n          <div class="fw-metrics">\n            <span class="fw-metric"><b>${wouldBlock}</b> would-block</span>\n            <span class="fw-metric"><b>${blocked}</b> blocked</span>\n            <span class="fw-metric dim"><b>${legit}</b> legit</span>\n          </div>\n        </div>\n        ${action}\n      </div>`;
const vendorPromote = '<div class="fw-promote-vendor">\n    <div class="fw-rule-main">\n      <span class="fw-rule-id">Catch secrets</span>\n      <div class="fw-metrics"><span class="fw-metric">1 vendor-key rule still in monitor — they report leaks but do not stop them</span></div>\n    </div>\n    <button class="btn btn-primary btn-sm" data-action="promote-vendor-keys"><svg class="icon"><use href="#i-arrow"/></svg><span>Promote vendor keys to block</span></button>\n  </div>';

const hostA = `a.${E}.x`;
const hostB = `b.${E}.x`;
const ask = host => `<button class="btn btn-ghost btn-sm" data-action="assess-host" data-agent="${E}" data-host="${host}"><svg class="icon"><use href="#i-agent"/></svg><span>Ask the advisor</span></button>`;
const OFF = '<span class="fw-metric dim">advisor off</span>';
const row = (host, extra, facts, advisor, agent = E) => `<div class="fw-rule egress-row">\n    <div class="fw-rule-main">\n      <span class="fw-rule-id">${host}</span>${extra}\n      <div class="fw-metrics"><span class="fw-metric dim">${facts}</span></div>\n      ${advisor}\n    </div>\n    <div class="egress-actions">\n      <button class="btn btn-primary btn-sm" data-action="allow-host" data-agent="${agent}" data-host="${host}" title="Mark this endpoint expected for ${agent}; it leaves this list"><svg class="icon"><use href="#i-shield"/></svg><span>Allow</span></button>\n      <button class="btn btn-ghost btn-sm" data-action="endpoint-detail" data-host="${host}" data-agent="${agent}" title="Identify this endpoint and see every connection to it"><svg class="icon"><use href="#i-activity"/></svg><span>Evidence</span></button>\n    </div>\n  </div>`;
const rowA = row(hostA, label(`${E} · ${E}`), '<b>5×</b> in 24h · last 30m ago · first seen 2h ago · session &lt;img src', `${chip}<div class="egress-advice">${E}</div>`);
const rowB = advisor => row(hostB, '', '<b>1×</b> in 24h', advisor);
const vendorRow = advisor => row(E, label(E), '<b>2×</b> in 24h · first seen 2h ago', advisor);
const appRow = advisor => row(E, '', '<b>1×</b> in 24h', advisor);
const rollup = (inner, { agent = E, org = E, host = E, facts = '1 endpoint · <b>2×</b> in 24h · first seen 2h ago' } = {}) => `<div class="fw-rule egress-row">\n    <div class="fw-rule-main">\n      <span class="fw-rule-id">${agent} → ${org}</span>\n      <div class="fw-metrics"><span class="fw-metric dim">${facts}</span></div>\n    </div>\n    <div class="egress-actions">\n      <button class="btn btn-primary btn-sm" data-action="bulk-allow" data-agent="${agent}" data-hosts="${host}" title="Mark these ${org} endpoints expected for ${agent}; they leave this list"><svg class="icon"><use href="#i-shield"/></svg><span>Allow all for ${agent}</span></button>\n      <button class="btn btn-ghost btn-sm" data-action="endpoint-detail" data-host="${host}" data-agent="${agent}" title="Identify the busiest endpoint and see every connection to it"><svg class="icon"><use href="#i-activity"/></svg><span>Evidence</span></button>\n    </div>\n  </div>\n  <details class="infra-group" data-key="vendor:${agent}|${org}"><summary>1 ${org} endpoint for ${agent}</summary>${inner}</details>`;
const carriers = (org, facts) => `<details class="infra-group" data-key="carriers"><summary>Known cloud/CDN infrastructure (1 endpoint) — these are the agents' own API carriers (Anthropic, OpenAI, GitHub, AWS…); nothing to decide, shown for completeness</summary><div class="mute-row"><span class="mute-pair">${org}</span><span class="fw-metric dim">${facts}</span></div></details>`;
const apps = advisor => `<details class="infra-group" data-key="infra-apps"><summary>Infrastructure apps (1 endpoint from ${E}) — IDEs, the Claude app and model servers are not agents and are not counted in the egress warning</summary>${appRow(advisor)}</details>`;
const agentHead = `<span class="egress-agent-name">${E}</span><span class="fw-metric dim">2 uninspected endpoints</span>`;
const bulk = `<div class="bulk-allow"><button class="btn btn-ghost btn-sm" data-action="bulk-allow" data-agent="${E}" data-hosts="${hostA},${hostB}"><svg class="icon"><use href="#i-shield"/></svg><span>Allow all 2 ${E}.x hosts</span></button></div>`;
const vendorHead = '<span class="egress-agent-name">Vendor APIs</span><span class="fw-metric dim">the agent\'s own model or tooling vendor, reached without the proxy — decide: Allow it, or Route the agent through the proxy</span>';
const globeEmpty = '<div class="empty"><svg class="icon"><use href="#i-globe"/></svg><span>No uninspected endpoints in the last 24h — the blind spot is closed</span></div>';
const explanation = advice => `<div class="uninspected-expl">\n    <b>What this is:</b> these agents connected directly to the internet, bypassing the inspection proxy — usually an app with pinned TLS certs or tooling that ignores the proxy environment.\n    <br><b>What to do:</b> for each endpoint, <b>Allow</b> it if it's expected for that agent (future connections stop asking), or <b>Route</b> the agent through the proxy to inspect it instead. ${advice}\n  </div>`;
const vendorGroup = advisor => `<div class="egress-agent-group">\n      <div class="egress-agent-head">${vendorHead}</div>\n      ${rollup(vendorRow(advisor))}\n    </div>`;
const notAssessed = '<div class="egress-inference"><span>Possible purpose</span><p>Not assessed yet. Connection timing alone does not establish intent.</p></div>';
const note = '\n    <p class="egress-security-note">Expectations quiet informational repeats. Security checks and the connection record continue.</p>\n  </article>';
const button = attrs => `<button type="button" class="btn btn-ghost btn-sm" ${attrs}`;

const expected = {
  'firewall empty': '<div class="empty"><svg class="icon"><use href="#i-shield"/></svg><span>No egress inspected yet — traffic is scanned as your agents run</span></div>',
  'firewall rules, suggestions and allowlist': [
    vendorPromote,
    suggestion(E, E, 4, label(E), chip),
    suggestion(E, E, 1),
    rule(E, [2, 1, 0], demote(E)).trim(),
    rule('vendor-key', [0, 0, 4], promote('vendor-key')).trim(),
    '<details class="fw-fold" data-key="rules-quiet"><summary></summary><div class="fw-fold-rows"></div></details>',
    `<div class="mute-list"><div class="mute-head">Allowed endpoints</div>\n      <div class="mute-row">\n        <span class="mute-pair">${E} · ${E}</span>\n        <button class="source-remove" title="Remove — the endpoint goes back to uninspected" data-action="allowlist-remove" data-agent="${E}" data-host="${E}"><svg class="icon"><use href="#i-close"/></svg></button>\n      </div></div>`,
  ],
  'firewall rule rows': [rule(E, [2, 1, 3], promote(E), ' fw-flash'), rule(E, [0, 0, 0], demote(E))],
  'endpoints': [
    `<div class="egress-agent-lead"><div class="egress-agent-head">${agentHead}</div>${bulk}</div>`,
    rowA,
    rowB(ask(hostB)),
    `<div class="egress-agent-lead"><div class="egress-agent-head">${vendorHead}</div></div>`,
    `<div class="egress-vendor">${rollup(vendorRow(ask(E)))}</div>`,
    carriers(E, '1 endpoint · 3× in 24h'),
    apps(ask(E)),
  ],
  'endpoints empty': globeEmpty,
  'uninspected drawer': explanation('<b>Advisor is off</b> — enable it in Settings for automatic endpoint guidance.')
    + `<div class="egress-agent-group">\n      <div class="egress-agent-head">${agentHead}</div>\n      ${bulk}\n      ${rowA}${rowB(OFF)}\n    </div>`
    + vendorGroup(OFF) + carriers(E, '1 endpoint · 3× in 24h') + apps(OFF),
  'uninspected drawer with only vendor rows': explanation('Not sure? <b>Ask the advisor</b> for a plain-English read.')
    + '<div class="empty"><svg class="icon"><use href="#i-globe"/></svg><span>No unknown endpoints — everything unrouted is a known vendor API, a cloud/CDN carrier or an infrastructure app (below)</span></div>'
    + vendorGroup(ask(E)),
  'uninspected drawer empty': globeEmpty,
  'recurring episodes': [
    '<div class="protection-context" tabindex="-1" role="status"><p>Returned to the original activity.</p></div>',
    `<article class="egress-episode is-context-target" data-egress-episode-id="${E}" tabindex="-1">\n    <div class="egress-episode-head"><strong>${E}:443 · ${E}</strong><span class="badge">review</span></div>\n    <div class="egress-observed"><span>Observed</span><p>5 calls · about every 30–60 min · ${E} · ${E} · ${E} · ${E}</p><p>First ${E} · Last ${E}</p></div>\n    <div class="egress-inference"><span>Advisor inference · ${E}</span><p>${E}</p></div>\n    <div class="egress-episode-actions">${button(`data-action="filter-session" data-session="${E}">Session &lt;img src</button>`)}${button('data-action="filter-session" data-session="session-2">Session session-</button>')}</div>\n    <div class="egress-episode-choices">\n      <span>Exact: ${E}:443 · ${E}</span>\n      ${button(`data-action="expect-egress" data-episode-id="${E}" data-kind="destination">Expect this destination</button>`)}\n      <span>All destinations for ${E} · ${E} · ${E} · ${E}</span>${button(`data-action="expect-egress" data-episode-id="${E}" data-kind="scope">Expect all destinations for this activity scope</button>`)}\n    </div>${note}`,
    `<article class="egress-episode" data-egress-episode-id="e2" tabindex="-1">\n    <div class="egress-episode-head"><strong>unknown destination · protocol unknown</strong><span class="badge badge-ok">expected</span></div>\n    <div class="egress-observed"><span>Observed</span><p>0 calls · interval unknown · activity scope unavailable</p></div>\n    ${notAssessed}\n    <div class="egress-episode-actions">${button(`data-action="view-egress-expectation" data-id="${E}" data-episode-id="e2">View expectation</button>`)}${button(`data-action="revoke-expected-egress" data-id="${E}">Revoke expectation</button>`)}${button('data-action="assess-egress-episode" data-id="e2">Ask advisor why</button>')}</div>\n    ${note}`,
    `<article class="egress-episode" data-egress-episode-id="e3" tabindex="-1">\n    <div class="egress-episode-head"><strong>${E} · protocol unknown</strong><span class="badge">review</span></div>\n    <div class="egress-observed"><span>Observed</span><p>0 calls · interval unknown · ${E}</p></div>\n    ${notAssessed}\n    <div class="egress-episode-actions">${button('data-action="assess-egress-episode" data-id="e3">Ask advisor why</button>')}</div>\n    <div class="egress-episode-choices">\n      <span>Exact: ${E} · protocol unknown</span>\n      ${button('data-action="expect-egress" data-episode-id="e3" data-kind="destination">Expect this destination</button>')}\n      <span>All-destinations choice unavailable: activity scope is incomplete.</span>\n    </div>${note}`,
  ],
  'expected rules': [
    `<div class="protection-context" tabindex="-1" role="status"><p>Saved expectation for this activity. Its scope and rationale are shown below.</p>${button('data-action="back-egress-context">Back to traffic</button>')}</div>`,
    `<section class="policy-harness-group"><div class="policy-harness-title"><span class="harness-chip" title="${E}"><span class="harness-glyph" data-harness-color="hsl(264 62% 62%)" aria-hidden="true">&lt;</span><span class="harness-label">${E}</span></span></div><div class="policy-list" data-expected-harness="${E}"></div></section>`,
    '<section class="policy-harness-group"><div class="policy-harness-title">All harnesses</div><div class="policy-list" data-expected-harness="all"></div></section>',
    '<section class="policy-harness-group"><div class="policy-harness-title"><span class="harness-chip" title="Claude Code"><span class="harness-tile hk-claude" aria-hidden="true"><svg class="harness-logo" aria-hidden="true"><use href="#logo-claude"/></svg></span><span class="harness-label">Claude Code</span></span></div><div class="policy-list" data-expected-harness="claude"></div></section>',
  ],
  'expected rule rows': [
    `<div class="expected-egress-row is-context-target" data-expected-egress-rule="${E}" tabindex="-1" role="group" aria-label="Saved expectation" aria-current="true"><span><strong>All destinations · ${E} · ${E} · claude · ${E}</strong><span>${E}</span></span>\n    ${button(`data-action="revoke-expected-egress" data-id="${E}">Revoke</button>`)}</div>`,
    `<div class="expected-egress-row" data-expected-egress-rule="r2" tabindex="-1" role="group" aria-label="Saved expectation"><span><strong>${E}:443 · ${E} · ${E}</strong><span>Marked expected by the operator</span></span>\n    ${button('data-action="revoke-expected-egress" data-id="r2">Revoke</button>')}</div>`,
  ],
  'sources': `\n      <div class="source-item">\n        <svg class="icon source-ico"><use href="#i-key"/></svg>\n        <span class="source-path">${E}</span>\n        <span class="origin-chip user">USER</span>\n        <button class="source-remove" title="Stop watching" data-action="remove-source" data-source="${E}"><svg class="icon"><use href="#i-close"/></svg></button>\n      </div>\n    `
    + `\n      <div class="source-item">\n        <svg class="icon source-ico"><use href="#i-key"/></svg>\n        <span class="source-path">${E}</span>\n        \n        <span class="origin-chip config">CONFIG</span>\n      </div>\n    `,
  'sources empty': '<div class="empty"><svg class="icon"><use href="#i-key"/></svg><span>No secret files watched yet — add the credential files whose keys must never leave</span></div>',
};

const escapedCounters = {
  'suggestion count': [suggestion('h', 'a', E)],
  'rule counters': rule('r', [E, E, E], promote('r')),
  'endpoint count': row('h', '', `<b>${E}×</b> in 24h`, OFF, 'a'),
  'vendor rollup count': rollup(row('h', '', '<b>1×</b> in 24h', OFF, 'a'), { agent: 'a', org: 'o', host: 'h', facts: `1 endpoint · <b>${E}×</b> in 24h` }),
  'carrier hits': carriers('o', `1 endpoint · 0${E}× in 24h`),
};

for (const [name, run] of Object.entries(cases)) {
  test(`egress markup: ${name}`, () => assert.deepEqual(run(), expected[name]));
}

for (const [name, run] of Object.entries(counters)) {
  test(`egress markup escapes the served ${name}`, () => assert.deepEqual(run(), escapedCounters[name]));
}
