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
const { groupUninspected } = ctx;

const rows = [
  { agent: 'openclaw', host: '2607:6bc0::10', count: 94, first_seen: '2026-09-23T12:00:00Z', identity: { kind: 'ipv6', org: 'Anthropic' } },
  { agent: 'openclaw', host: '160.79.104.10', count: 25, first_seen: '2026-09-23T11:00:00Z', identity: { kind: 'ipv4', org: 'Anthropic' } },
  { agent: 'claude', host: '160.79.104.10', count: 4, identity: { kind: 'ipv4', org: 'Anthropic' } },
  { agent: 'cursor', host: '2606:4700::1', count: 56, infra: 'Cloudflare', identity: { kind: 'ipv6', org: 'Cloudflare' } },
  { agent: 'claude', host: 'telemetry.example.com', count: 5, identity: { kind: 'hostname', name: 'telemetry.example.com' } },
  { agent: 'claude', host: '203.0.113.7', count: 2 },
];

test('groupUninspected splits carriers, vendors and unknowns', () => {
  const { unknown, vendors, carriers } = groupUninspected(rows);
  assert.deepEqual(Array.from(carriers, e => e.host), ['2606:4700::1']);
  assert.deepEqual(Array.from(unknown, e => e.host), ['telemetry.example.com', '203.0.113.7']);
  assert.deepEqual(Array.from(vendors, g => `${g.agent}|${g.org}`), ['openclaw|Anthropic', 'claude|Anthropic']);
});

test('a row with infra never lands in vendors', () => {
  const { vendors } = groupUninspected(rows);
  for (const g of vendors) for (const e of g.rows) assert.equal(e.infra, undefined);
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
