// tab-egress.js unit tests — evaluated on top of lib.js in a fresh VM
// context, the way the browser loads the classic scripts.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const webDist = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../daemon/internal/api/web_dist'
);
const ctx = {};
vm.runInNewContext(readFileSync(path.join(webDist, 'lib.js'), 'utf8'), ctx, { filename: 'lib.js' });
vm.runInContext(readFileSync(path.join(webDist, 'tab-egress.js'), 'utf8'), ctx, { filename: 'tab-egress.js' });
const { groupUninspected, identityLabel } = ctx;

test('recurring egress card separates observed cadence from advisor inference', () => {
  const html = ctx.egressEpisodeHTML({ id: 'episode-1', candidate: true, observed: {
    id: 'episode-1', host: 'api.example.com', port: 443, protocol: 'tcp', count: 5,
    first_seen: '2026-09-25T10:00:00Z', last_seen: '2026-09-25T12:00:00Z',
    intervals: [1800000000000, 1830000000000, 1770000000000, 1800000000000],
    session_ids: ['session-123456'], scope_complete: true,
    scope: { agent: 'claude', exe_path: '/Applications/Claude', harness: 'claude', workspace: '/work/repo' }
  }, advisor_inference: { possible_purpose: 'Periodic update check', confidence: 'medium' } });
  assert.match(html, /Observed/);
  assert.match(html, /about every 30–31 min/);
  assert.match(html, /Advisor inference/);
  assert.match(html, /Periodic update check/);
  assert.match(html, /data-action="filter-session" data-session="session-123456"/);
  assert.match(html, /First 2026-09-25T10:00:00Z/);
  assert.match(html, /Last 2026-09-25T12:00:00Z/);
  assert.match(html, /data-kind="destination"/);
  assert.match(html, /data-kind="scope"/);
  assert.match(html, /Security checks and the connection record continue/);
});

test('ambiguous scope has an exact choice only; expected activity has no approval choices', () => {
  const observed = { id: 'e', host: '203.0.113.1', port: 443, protocol: 'tcp', count: 5,
    intervals: [1800000000000], scope_complete: false, scope: { agent: 'codex' } };
  const candidate = ctx.egressEpisodeHTML({ id: 'e', candidate: true, observed });
  assert.match(candidate, /data-kind="destination"/);
  assert.doesNotMatch(candidate, /data-kind="scope"/);
  assert.match(candidate, /activity scope is incomplete/);
  const expected = ctx.egressEpisodeHTML({ id: 'e', expected: true, expected_rule_id: 'rule-1', candidate: false, observed });
  assert.doesNotMatch(expected, /data-action="expect-egress"/);
  assert.match(expected, /data-action="revoke-expected-egress" data-id="rule-1"/);
});

test('episode host and advisor text are escaped in the card', () => {
  const html = ctx.egressEpisodeHTML({ id: 'e', candidate: true, observed: {
    id: 'e', host: '<img src=x onerror=1>', port: 443, protocol: 'tcp', count: 5,
    intervals: [1800000000000], scope_complete: false, scope: { agent: 'claude' }
  }, advisor_inference: { possible_purpose: '<script>alert(1)</script>' } });
  assert.doesNotMatch(html, /<img|<script>/);
  assert.match(html, /&lt;img/);
  assert.match(html, /&lt;script&gt;/);
});

test('episode scope escapes once and remains readable', () => {
  const html = ctx.egressEpisodeHTML({ id: 'e', observed: {
    host: 'api.example.com', count: 5, scope: { agent: 'claude', workspace: '/work/R&D <client>' }
  } });
  assert.match(html, /\/work\/R&amp;D &lt;client&gt;/);
  assert.doesNotMatch(html, /&amp;amp;|&amp;lt;/);
});

test('expected-egress rule names the entire scope and escapes it; revoke targets rule ID', () => {
  const html = ctx.expectedEgressRuleHTML({ id: 'rule-1', kind: 'scope', agent: 'claude',
    exe_path: '/Applications/Claude', harness: 'claude', workspace: '<script>work</script>', rationale: 'Routine task' });
  assert.match(html, /All destinations/);
  assert.match(html, /\/Applications\/Claude/);
  assert.match(html, /&lt;script&gt;work/);
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /data-action="revoke-expected-egress" data-id="rule-1"/);
});

const rows = [
  { agent: 'openclaw', host: '2607:6bc0::10', count: 94, first_seen: '2026-09-23T12:00:00Z', identity: { kind: 'ipv6', org: 'Anthropic', class: 'vendor' } },
  { agent: 'openclaw', host: '160.79.104.10', count: 25, first_seen: '2026-09-23T11:00:00Z', identity: { kind: 'ipv4', org: 'Anthropic', class: 'vendor' } },
  { agent: 'claude', host: '160.79.104.10', count: 4, identity: { kind: 'ipv4', org: 'Anthropic', class: 'vendor' } },
  { agent: 'cursor', host: '2606:4700::1', count: 56, infra: 'Cloudflare', identity: { kind: 'ipv6', org: 'Cloudflare', class: 'cloud' } },
  { agent: 'claude', host: '34.120.1.1', count: 7, identity: { kind: 'ipv4', org: 'Google Cloud', class: 'cloud' } },
  { agent: 'claude', host: 'api.statsig.com', count: 6, identity: { kind: 'hostname', name: 'api.statsig.com', org: 'Statsig', class: 'telemetry' } },
  { agent: 'claude', host: 'telemetry.example.com', count: 5, identity: { kind: 'hostname', name: 'telemetry.example.com' } },
  { agent: 'claude', host: '203.0.113.7', count: 2 },
  { agent: 'cursor-ide', host: '52.21.130.202', count: 1, agent_kind: 'infra', identity: { kind: 'ipv4', org: 'AWS', class: 'cloud' } },
];

test('groupUninspected splits carriers, infra apps, vendors and unknowns', () => {
  const { unknown, vendors, carriers, apps } = groupUninspected(rows);
  assert.deepEqual(Array.from(carriers, e => e.host), ['2606:4700::1']);
  assert.deepEqual(Array.from(apps, e => e.host), ['52.21.130.202']);
  assert.deepEqual(Array.from(unknown, e => e.host), ['34.120.1.1', 'api.statsig.com', 'telemetry.example.com', '203.0.113.7']);
  assert.deepEqual(Array.from(vendors, g => `${g.agent}|${g.org}`), ['openclaw|Anthropic', 'claude|Anthropic']);
});

test('only vendor-class rows without infra roll up; cloud and telemetry stay unknown', () => {
  const { vendors } = groupUninspected(rows);
  for (const g of vendors) {
    assert.equal(g.org, 'Anthropic');
    for (const e of g.rows) {
      assert.equal(e.infra, undefined);
      assert.equal(e.identity.class, 'vendor');
    }
  }
});

test('identityLabel names the org, marks telemetry, adds a differing reverse name', () => {
  assert.equal(identityLabel(rows[4]), 'Google Cloud');
  assert.equal(identityLabel(rows[5]), 'Statsig · telemetry');
  assert.equal(identityLabel({ host: '34.1.2.3', identity: { org: 'Azure', class: 'cloud', name: 'vm.example.net' } }), 'Azure · vm.example.net');
  assert.equal(identityLabel({ host: '203.0.113.7' }), '');
});

test('vendor rollup sums counts per (agent, org), busiest first, earliest first_seen', () => {
  const { vendors } = groupUninspected(rows);
  const oc = vendors[0];
  assert.equal(oc.count, 119);
  assert.equal(oc.rows.length, 2);
  assert.equal(oc.rows[0].host, '2607:6bc0::10');
  assert.equal(oc.first_seen, '2026-09-23T11:00:00Z');
  assert.equal(vendors[1].count, 4);
});

test('groupUninspected tolerates no rows', () => {
  const g = groupUninspected(undefined);
  assert.equal(g.unknown.length + g.vendors.length + g.carriers.length + g.apps.length, 0);
});

test('Egress warning counts pending egress decisions, never raw coverage observations', () => {
  const badge = {};
  const container = { querySelector: () => null };
  ctx.document = { getElementById: id => id === 'firewall-container' ? container : badge };
  ctx.patchList = () => {};
  let count;
  ctx.window = { SA: {
    t: { status: { uninspected_egress: 11 }, posture: {
      needs_you: 0, items: [], coverage_items: [{ kind: 'uninspected_egress' }]
    } },
    setTabBadge: (id, n) => { assert.equal(id, 'egress'); count = n; },
    prevFwStats: null, reducedMotion: true,
  } };
  ctx.renderFirewall();
  assert.equal(count, 0, 'coverage alone must not paint a warning');
  ctx.window.SA.t.posture.items = [{ kind: 'recurring_egress' }, { kind: 'guard_pending' }];
  ctx.renderFirewall();
  assert.equal(count, 1, 'an actual egress decision must remain discoverable');
});

test('infrastructure-only endpoint list presents coverage without implying findings', () => {
  const container = { querySelectorAll: () => [] };
  const title = {}, summary = {};
  ctx.document = { getElementById: id => ({
    'endpoints-container': container, 'endpoints-title': title, 'endpoints-summary': summary,
  })[id] };
  ctx.window = { SA: { t: { status: {}, uninspected: Array.from({ length: 200 }, (_, i) => ({
    agent: 'claude', host: `104.16.0.${i}`, count: 1, infra: 'Cloudflare',
  })) } } };
  let rendered;
  ctx.patchList = (_container, parts) => { rendered = parts; };
  ctx.renderEndpoints();
  assert.equal(title.textContent, 'Connection coverage · last 24 h');
  assert.match(summary.textContent, /200 endpoints shown · 200 known infrastructure/);
  assert.match(summary.textContent, /not a security finding/);
  assert.equal(rendered.length, 1);
  assert.equal(rendered[0].key, 'carriers', 'infrastructure evidence stays available');
});

test('foldRules: rules with any hit stay listed, all-zero rules fold', () => {
  const stats = {
    'b-key': { would_block: 0, blocked: 0, legit: 3 },
    'a-key': { would_block: 2, blocked: 0, legit: 0 },
    'z-key': { would_block: 0, blocked: 0, legit: 0 },
    'c-key': { would_block: 0, blocked: 0, legit: 0, mode: 'block' },
  };
  assert.deepEqual(JSON.parse(JSON.stringify(ctx.foldRules(stats))), { hit: ['a-key', 'b-key'], quiet: ['c-key', 'z-key'] });
  assert.deepEqual(JSON.parse(JSON.stringify(ctx.foldRules(undefined))), { hit: [], quiet: [] });
});

test('uninspectedParts: one keyed part per endpoint, vendor rollups, carriers', () => {
  const parts = ctx.uninspectedParts(rows, true);
  const keys = parts.map(p => p.key);
  assert.equal(new Set(keys).size, keys.length);
  assert.ok(keys.includes('vendor:openclaw|Anthropic'));
  assert.ok(keys.includes('ep:claude|34.120.1.1'));
  assert.ok(keys.includes('carriers'));
  assert.ok(!keys.includes('ep:cursor-ide|52.21.130.202'), 'an infra app is not an agent row');
  const apps = parts.find(p => p.key === 'infra-apps');
  assert.equal(apps.count, 1);
  assert.match(apps.html, /^<details class="infra-group" data-key="infra-apps">/);
  assert.match(apps.html, /from cursor-ide\)/);
  for (const p of parts) {
    const html = p.html.trim();
    assert.ok(html.startsWith('<div') || html.startsWith('<details'), p.key);
  }
  const vendor = parts.find(p => p.key === 'vendor:openclaw|Anthropic').html;
  assert.match(vendor, /^<div class="egress-vendor">/);
  assert.match(vendor, /data-action="bulk-allow" data-agent="openclaw"/);
  assert.ok(keys.indexOf('agent:claude') < keys.indexOf('ep:claude|34.120.1.1'));
});
