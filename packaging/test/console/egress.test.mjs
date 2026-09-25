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

const rows = [
  { agent: 'openclaw', host: '2607:6bc0::10', count: 94, first_seen: '2026-09-23T12:00:00Z', identity: { kind: 'ipv6', org: 'Anthropic', class: 'vendor' } },
  { agent: 'openclaw', host: '160.79.104.10', count: 25, first_seen: '2026-09-23T11:00:00Z', identity: { kind: 'ipv4', org: 'Anthropic', class: 'vendor' } },
  { agent: 'claude', host: '160.79.104.10', count: 4, identity: { kind: 'ipv4', org: 'Anthropic', class: 'vendor' } },
  { agent: 'cursor', host: '2606:4700::1', count: 56, infra: 'Cloudflare', identity: { kind: 'ipv6', org: 'Cloudflare', class: 'cloud' } },
  { agent: 'claude', host: '34.120.1.1', count: 7, identity: { kind: 'ipv4', org: 'Google Cloud', class: 'cloud' } },
  { agent: 'claude', host: 'api.statsig.com', count: 6, identity: { kind: 'hostname', name: 'api.statsig.com', org: 'Statsig', class: 'telemetry' } },
  { agent: 'claude', host: 'telemetry.example.com', count: 5, identity: { kind: 'hostname', name: 'telemetry.example.com' } },
  { agent: 'claude', host: '203.0.113.7', count: 2 },
];

test('groupUninspected splits carriers, vendors and unknowns', () => {
  const { unknown, vendors, carriers } = groupUninspected(rows);
  assert.deepEqual(Array.from(carriers, e => e.host), ['2606:4700::1']);
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
  assert.equal(g.unknown.length + g.vendors.length + g.carriers.length, 0);
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
  for (const p of parts) {
    const html = p.html.trim();
    assert.ok(html.startsWith('<div') || html.startsWith('<details'), p.key);
  }
  const vendor = parts.find(p => p.key === 'vendor:openclaw|Anthropic').html;
  assert.match(vendor, /^<div class="egress-vendor">/);
  assert.match(vendor, /data-action="bulk-allow" data-agent="openclaw"/);
  assert.ok(keys.indexOf('agent:claude') < keys.indexOf('ep:claude|34.120.1.1'));
});
