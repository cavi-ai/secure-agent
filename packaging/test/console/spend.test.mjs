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
const { spendListItems, spendDayItems, spendHintText, planWindowLabel, planLineText, spendPlanItems } = ctx;
const joined = items => items.map(i => i.html).join('');

const keysOf = html => [...html.matchAll(/<span class="spend-key" title="[^"]*">([^<]+)<\/span>/g)].map(m => m[1]);

test('spendListItems: top 8 by cost keyed <by>:<row key>, the rest behind Show more', () => {
  const rows = Array.from({ length: 11 }, (_, i) => ({ key: `repo-${i}`, calls: i + 1, cost_usd: i }));
  const items = spendListItems(rows, 8, { by: 'repo' });
  assert.deepEqual(Array.from(items, i => i.key), ['repo:repo-10', 'repo:repo-9', 'repo:repo-8', 'repo:repo-7', 'repo:repo-6', 'repo:repo-5', 'repo:repo-4', 'repo:repo-3', 'more:spend']);
  const html = joined(items);
  assert.deepEqual(keysOf(html), ['repo-10', 'repo-9', 'repo-8', 'repo-7', 'repo-6', 'repo-5', 'repo-4', 'repo-3']);
  assert.match(html, /data-action="show-more" data-key="spend">Show 3 more</);
  assert.match(html, /<span class="spend-calls">11 calls<\/span>\s*<span class="spend-cost">\$10\.00<\/span>/);
  const open = joined(spendListItems(rows, 8, { by: 'repo', expanded: new Set(['spend']) }));
  assert.equal(keysOf(open).length, 11);
  assert.doesNotMatch(open, /show-more/);
  const few = joined(spendListItems(rows.slice(0, 3), 8, { by: 'repo' }));
  assert.equal(keysOf(few).length, 3);
  assert.doesNotMatch(few, /show-more/);
});

test('spendListItems: harness chip when present; "(unknown)" provider says it was not recorded', () => {
  const rows = [
    { key: 'anthropic', harness: 'claude', calls: 5, cost_usd: 4 },
    { key: '(unknown)', calls: 1, cost_usd: 0 },
  ];
  const html = joined(spendListItems(rows, 8, { by: 'provider' }));
  assert.match(html, /#logo-claude/);
  assert.equal((html.match(/provider not recorded/g) || []).length, 1);
  assert.match(html, /\(unknown\)<\/span>\s*<span class="spend-hint">provider not recorded/);
  assert.doesNotMatch(joined(spendListItems(rows, 8, { by: 'model' })), /provider not recorded/);
});

test('spendDayItems: one column per row in ascending key order keyed day:<key>, the costliest at full height', () => {
  const rows = [
    { key: '2026-09-23', calls: 1, cost_usd: 0 },
    { key: '2026-09-21', calls: 10, cost_usd: 335.84 },
    { key: '2026-09-22', calls: 20, cost_usd: 676.54 },
  ];
  const items = spendDayItems(rows);
  assert.deepEqual(Array.from(items, i => i.key), ['day:2026-09-21', 'day:2026-09-22', 'day:2026-09-23']);
  assert.deepEqual(rows.map(r => r.key), ['2026-09-23', '2026-09-21', '2026-09-22']);
  const html = joined(items);
  assert.equal((html.match(/class="spend-day"/g) || []).length, 3);
  assert.deepEqual([...html.matchAll(/<span class="spend-day-label">([^<]+)</g)].map(m => m[1]), ['Mon 21', 'Tue 22', 'Wed 23']);
  assert.deepEqual([...html.matchAll(/data-h="([^"]+)"/g)].map(m => m[1]), ['49.6', '100.0', '0.0']);
  assert.match(html, /title="2026-09-22 · \$676\.54 · 20 calls"/);
  assert.deepEqual([...html.matchAll(/<span class="spend-day-cost">([^<]+)</g)].map(m => m[1]), ['$336', '$677', '$0']);
  assert.doesNotMatch(html, /<canvas/);
});

test('planWindowLabel: 10080 min is weekly, 300 is 5-hour, else hours', () => {
  assert.equal(planWindowLabel(10080), 'weekly');
  assert.equal(planWindowLabel(300), '5-hour');
  assert.equal(planWindowLabel(1440), '24h');
  assert.equal(planWindowLabel(90), '1.5h');
});

test('spendHintText: calls, then plan and unpriced only when non-zero', () => {
  assert.equal(spendHintText({ calls: 39631, plan_calls: 19447, unpriced_calls: 2 }), '39631 calls · 19447 on plans · 2 unpriced');
  assert.equal(spendHintText({ calls: 640, plan_calls: 640, unpriced_calls: 0 }), '640 calls · 640 on plans');
  assert.equal(spendHintText({ calls: 40, plan_calls: 0, unpriced_calls: 2 }), '40 calls · 2 unpriced');
  assert.equal(spendHintText({ calls: 1 }), '1 call');
  assert.equal(spendHintText({ calls: 0, plan_calls: 3 }), '');
  assert.equal(spendHintText(undefined), '');
});

// A local Friday 3:10 PM, so the expected clock holds in any TZ.
const friday = new Date(2026, 8, 25, 15, 10).toISOString();
const proPlan = { harness: 'codex', home: 'codex', plan_type: 'pro', limit_id: 'codex',
  windows: [{ window_minutes: 10080, used_percent: 52, resets_at: friday }], unlimited: false, seen_at: friday };

test('planLineText: plan, home, window, percent and the local reset time', () => {
  assert.equal(planLineText(proPlan), 'Codex Pro · codex · weekly 52% used · resets Fri 3:10 PM');
  const two = { ...proPlan, home: 'scout (openclaw)', windows: [proPlan.windows[0], { window_minutes: 300, used_percent: 7.5, resets_at: 'bad' }] };
  assert.equal(planLineText(two), 'Codex Pro · scout (openclaw) · weekly 52% used · resets Fri 3:10 PM · 5-hour 8% used');
});

test('spendPlanItems: one item per plan keyed plan:<home>, a bar per window at used_percent; none for an empty list', () => {
  const items = spendPlanItems([proPlan, { ...proPlan, home: 'scout (openclaw)', windows: [{ window_minutes: 300, used_percent: 95, resets_at: friday }] }]);
  assert.deepEqual(Array.from(items, i => i.key), ['plan:codex', 'plan:scout (openclaw)']);
  assert.match(items[0].html, /<span class="spend-plan-text">Codex Pro · codex · weekly 52% used · resets Fri 3:10 PM<\/span>/);
  assert.match(items[0].html, /class="hbar-fill" data-w="52\.0"/);
  assert.match(items[1].html, /class="hbar-fill crit" data-w="95\.0"/);
  assert.equal(spendPlanItems([]).length, 0);
  assert.equal(spendPlanItems(undefined).length, 0);
});

test('spendListItems: a row whose calls are all on plans reads "plan", not $0.00', () => {
  const rows = [
    { key: 'anthropic', calls: 5, cost_usd: 4, plan_calls: 0 },
    { key: 'chatgpt', calls: 19447, cost_usd: 0, plan_calls: 19447 },
    { key: 'openai', calls: 3, cost_usd: 0, plan_calls: 1 },
  ];
  const html = joined(spendListItems(rows, 8, { by: 'provider' }));
  assert.match(html, /chatgpt<\/span>[\s\S]*?<span class="spend-calls">19447 calls<\/span>\s*<span class="spend-cost">plan<\/span>/);
  assert.match(html, /openai<\/span>[\s\S]*?<span class="spend-cost">\$0\.00<\/span>/);
  assert.equal((html.match(/spend-cost">plan</g) || []).length, 1);
});
