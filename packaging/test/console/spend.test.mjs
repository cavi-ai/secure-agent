// Console Spend card tests — zero dependencies. Evaluates lib.js and
// tab-overview.js in one fresh VM context, as the browser loads them.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const webDist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../daemon/internal/api/web_dist');
const ctx = { window: {} };
vm.createContext(ctx);
for (const f of ['lib.js', 'tab-overview.js']) {
  vm.runInContext(readFileSync(path.join(webDist, f), 'utf8'), ctx, { filename: f });
}
const { spendListHTML, spendDayBarsHTML } = ctx;

const keysOf = html => [...html.matchAll(/<span class="spend-key" title="[^"]*">([^<]+)<\/span>/g)].map(m => m[1]);

test('spendListHTML: top 8 by cost, the rest behind Show more', () => {
  const rows = Array.from({ length: 11 }, (_, i) => ({ key: `repo-${i}`, calls: i + 1, cost_usd: i }));
  const html = spendListHTML(rows, 8, { by: 'repo' });
  assert.deepEqual(keysOf(html), ['repo-10', 'repo-9', 'repo-8', 'repo-7', 'repo-6', 'repo-5', 'repo-4', 'repo-3']);
  assert.match(html, /data-action="show-more" data-key="spend">Show 3 more</);
  assert.match(html, /<span class="spend-calls">11 calls<\/span>\s*<span class="spend-cost">\$10\.00<\/span>/);
  const open = spendListHTML(rows, 8, { by: 'repo', expanded: new Set(['spend']) });
  assert.equal(keysOf(open).length, 11);
  assert.doesNotMatch(open, /show-more/);
  const few = spendListHTML(rows.slice(0, 3), 8, { by: 'repo' });
  assert.equal(keysOf(few).length, 3);
  assert.doesNotMatch(few, /show-more/);
});

test('spendListHTML: harness chip when present; "(unknown)" provider says it was not recorded', () => {
  const rows = [
    { key: 'anthropic', harness: 'claude', calls: 5, cost_usd: 4 },
    { key: '(unknown)', calls: 1, cost_usd: 0 },
  ];
  const html = spendListHTML(rows, 8, { by: 'provider' });
  assert.match(html, /#logo-claude/);
  assert.equal((html.match(/provider not recorded/g) || []).length, 1);
  assert.match(html, /\(unknown\)<\/span>\s*<span class="spend-hint">provider not recorded/);
  assert.doesNotMatch(spendListHTML(rows, 8, { by: 'model' }), /provider not recorded/);
});

test('spendDayBarsHTML: one column per row in key order, the costliest at full height', () => {
  const rows = [
    { key: '2026-09-21', calls: 10, cost_usd: 335.84 },
    { key: '2026-09-22', calls: 20, cost_usd: 676.54 },
    { key: '2026-09-23', calls: 1, cost_usd: 0 },
  ];
  const html = spendDayBarsHTML(rows);
  assert.equal((html.match(/class="spend-day"/g) || []).length, 3);
  assert.deepEqual([...html.matchAll(/<span class="spend-day-label">([^<]+)</g)].map(m => m[1]), ['Mon 21', 'Tue 22', 'Wed 23']);
  assert.deepEqual([...html.matchAll(/data-h="([^"]+)"/g)].map(m => m[1]), ['49.6', '100.0', '0.0']);
  assert.match(html, /title="2026-09-22 · \$676\.54 · 20 calls"/);
  assert.deepEqual([...html.matchAll(/<span class="spend-day-cost">([^<]+)</g)].map(m => m[1]), ['$336', '$677', '$0']);
  assert.doesNotMatch(html, /<canvas/);
});
