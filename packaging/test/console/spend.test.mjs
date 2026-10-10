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
const { spendListItems, spendDayItems, spendHintText, spendCacheText, spendUpdating, planWindowLabel, planLineText, spendPlanItems,
  spendDayWindow, spendDayDetailHTML, spendDayRangeText, spendRowCost } = ctx;
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

test('day selection uses native keyboard buttons, persistent aria state, and escaped labels', () => {
  const rows = [{key:'2026-09-21',calls:2,cost_usd:4}, {key:'2026-09-22',calls:1,cost_usd:0,unpriced_calls:1}];
  const html = joined(spendDayItems(rows,'2026-09-22'));
  assert.match(html, /<button type="button" class="spend-day" data-action="select-spend-day" data-day="2026-09-21" aria-pressed="false"/);
  assert.match(html, /data-day="2026-09-22" aria-pressed="true"/);
  assert.match(html, /aria-label="2026-09-22 · unpriced · 1 call · 1 unpriced"/);
  assert.equal((html.match(/<\/button>/g) || []).length, 2);
  assert.match(joined(spendDayItems([{key:'"><script>',calls:1,cost_usd:1}])), /data-day="&quot;&gt;&lt;script&gt;"/);
  assert.doesNotMatch(joined(spendDayItems([{key:'"><script>',calls:1,cost_usd:1}])), /<script>/);
});

test('day interval clamps partial first/last buckets to the displayed report window', () => {
  const report = {since:'2026-09-21T12:15:00Z',until:'2026-09-23T18:30:00Z'};
  assert.deepEqual(JSON.parse(JSON.stringify(spendDayWindow('2026-09-21',report,-240))),
    {since:'2026-09-21T12:15:00.000Z',until:'2026-09-22T04:00:00.000Z',tz:-240,partial:true});
  assert.deepEqual(JSON.parse(JSON.stringify(spendDayWindow('2026-09-22',report,-240))),
    {since:'2026-09-22T04:00:00.000Z',until:'2026-09-23T04:00:00.000Z',tz:-240,partial:false});
  assert.deepEqual(JSON.parse(JSON.stringify(spendDayWindow('2026-09-23',report,-240))),
    {since:'2026-09-23T04:00:00.000Z',until:'2026-09-23T18:30:00.000Z',tz:-240,partial:true});
  assert.equal(spendDayWindow('2026-09-24',report,-240),null);
});

test('day buckets keep the captured fixed UTC offset across both DST transitions', () => {
  const broad = {since:'2026-01-01T00:00:00Z',until:'2027-01-01T00:00:00Z'};
  for (const day of ['2026-03-08','2026-11-01']) {
    for (const tz of [-300,-240,330,840]) {
      const range = spendDayWindow(day,broad,tz);
      const start = Date.parse(range.since), end = Date.parse(range.until);
      assert.equal(end-start,86400000);
      // This is also the server's datetime(ts, '+N minutes') day key.
      assert.equal(new Date(start+tz*60000).toISOString().slice(0,10),day);
      assert.equal(new Date(end-1000+tz*60000).toISOString().slice(0,10),day);
      assert.notEqual(new Date(end+tz*60000).toISOString().slice(0,10),day);
    }
  }
});

test('invalid day, timezone, and report windows cannot make a breakdown request', () => {
  const report = {since:'2026-01-01T00:00:00Z',until:'2027-01-01T00:00:00Z'};
  for (const day of ['bad','2026-02-30','2026-13-01','2026-00-01']) assert.equal(spendDayWindow(day,report,0),null);
  for (const tz of [undefined,null,841,-841,NaN,1.5]) assert.equal(spendDayWindow('2026-09-22',report,tz),null);
  assert.equal(spendDayWindow('2026-09-22',{...report,since:'bad'},0),null);
  assert.equal(spendDayWindow('2026-09-22',{since:report.until,until:report.since},0),null);
});

test('day range copy shows readable chart-offset hours and exclusive midnight as 24:00', () => {
  const card = {since:'2026-09-21T12:15:00Z',until:'2026-09-23T18:30:00Z'};
  assert.equal(spendDayRangeText('2026-09-21',spendDayWindow('2026-09-21',card,-240)),
    'Partial day · 08:15–24:00 · UTC−04:00');
  assert.equal(spendDayRangeText('2026-09-22',spendDayWindow('2026-09-22',card,-240)),
    'Day grouped at UTC−04:00');
  assert.equal(spendDayRangeText('2026-09-23',spendDayWindow('2026-09-23',card,-240)),
    'Partial day · 00:00–14:30 · UTC−04:00');
  assert.equal(spendDayRangeText('2026-09-23',spendDayWindow('2026-09-23',{...card,until:'2026-09-23T13:00:15Z'},330)),
    'Partial day · 00:00–18:30:15 · UTC+05:30');
});

test('selected detail distinguishes unavailable, loading, delayed, saved and zero usage', () => {
  const row = {key:'2026-09-22',calls:0,cost_usd:0};
  const card = {since:'2026-09-22T12:00:00Z',until:'2026-09-23T04:00:00Z'};
  const range = spendDayWindow(row.key,card,-240);
  const report = {...range,by:'repo',total:row,rows:[],refreshing:false};
  const render = (rep,state={}) => spendDayDetailHTML(row,card,-240,rep,state);
  const html = render(report);
  assert.match(html, /Partial day · 08:00–24:00 · UTC−04:00/);
  assert.doesNotMatch(html, /2026-09-22T|fixed offset/);
  assert.match(html, /data-action="reset-spend-day">Clear selection/);
  assert.match(html, /\$0\.00<\/strong> · 0 calls/);
  assert.match(html, /No model calls recorded for this day/);
  assert.doesNotMatch(html, /unavailable/);
  assert.match(render(null,{loading:true}), /Loading day breakdown/);
  assert.match(render(null), /Day breakdown unavailable/);
  assert.match(render(null,{delayed:true}), /unavailable · refresh delayed/);
  assert.match(render(report,{delayed:true}), /showing saved breakdown/);
  assert.match(render({...report,refreshing:true}), /Loading day breakdown/);
  assert.match(render({...report,refreshing:true,generated_at:card.since}), /Refreshing usage/);
  assert.match(render(null,{error:'<img src=x onerror=alert(1)>'}), /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(render(null,{error:'<img src=x onerror=alert(1)>'}), /<img/);
});

test('selected detail drops a breakdown from another window and escapes repository evidence', () => {
  const row = {key:'2026-09-22',calls:2,cost_usd:5};
  const card = {since:'2026-09-21T04:00:00Z',until:'2026-09-24T04:00:00Z'};
  const report = {...spendDayWindow(row.key,card,-240),by:'repo',total:row,
    rows:[{key:'<script>repo</script>',calls:2,cost_usd:5}]};
  assert.match(spendDayDetailHTML(row,card,-240,report), /&lt;script&gt;repo&lt;\/script&gt;/);
  assert.doesNotMatch(spendDayDetailHTML(row,card,-240,{...report,until:card.until}), /repo&lt;/);
  assert.match(spendDayDetailHTML(row,card,-240,{...report,until:card.until}), /Day breakdown unavailable/);
});

test('plan, unpriced and local usage never masquerade as a fully priced zero', () => {
  assert.equal(spendRowCost({calls:2,plan_calls:2,cost_usd:0}),'plan');
  assert.equal(spendRowCost({calls:2,unpriced_calls:2,cost_usd:0}),'unpriced');
  assert.equal(spendRowCost({calls:2,local_calls:2,cost_usd:0}),'local');
  const mixed = joined(spendDayItems([{key:'2026-09-22',calls:5,plan_calls:2,unpriced_calls:1,local_calls:1,cost_usd:1.2}]));
  assert.match(mixed, /5 calls · 2 on plans · 1 unpriced · 1 local/);
  assert.match(mixed, /spend-day-cost">\$1\.20/);
  assert.match(joined(spendListItems([{key:'repo',calls:3,unpriced_calls:1,cost_usd:5}],8,{by:'repo'})), /1 unpriced/);
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

test('spendCacheText: quiet refresh notice retains the oldest saved report age', () => {
  const now = Date.parse('2026-09-25T12:00:00Z');
  const at = ms => new Date(now - ms).toISOString();
  assert.equal(spendCacheText([{ refreshing: false, generated_at: at(9 * 3600000) }, null], now), '');
  assert.equal(spendCacheText([], now), '');
  assert.equal(spendCacheText(undefined, now), '');
  assert.equal(spendCacheText([{ refreshing: true, generated_at: at(30000) }], now), 'Refreshing usage… · saved 30s ago');
  assert.equal(spendUpdating({ refreshing: true, generated_at: at(30000) }, now), true);
  assert.equal(spendUpdating({ refreshing: true, generated_at: at(60000) }, now), true);
  assert.equal(spendUpdating(null, now), false);
  assert.equal(spendCacheText([{ refreshing: true, generated_at: at(3 * 3600000) }, { refreshing: true, generated_at: at(5 * 60000) }], now),
    'Refreshing usage… · saved 3h ago');
  assert.equal(spendCacheText([{ refreshing: false, generated_at: at(9 * 3600000) }, { refreshing: true, generated_at: at(5 * 60000) }], now),
    'Refreshing usage… · saved 5m ago');
  assert.equal(spendCacheText([{ refreshing: true }], now), 'Refreshing usage…');
});

test('shared account row has one quota and stable account/limit identity', () => {
  const plan = { harness:'codex', plan_type:'pro', home:'shared account', account_key:'opaque', limit_id:'codex',
    homes:['codex','agent'], windows:[{window_minutes:10080,used_percent:47}] };
  assert.equal(spendPlanItems([plan])[0].key,'plan:opaque:codex');
  assert.match(planLineText(plan),/Codex Pro · shared by 2 homes · weekly 47% used/);
  assert.equal((joined(spendPlanItems([plan])).match(/hbar-track/g)||[]).length,1);
});

// A local Friday 3:10 PM, so the expected clock holds in any TZ.
const friday = new Date(2026, 8, 25, 15, 10).toISOString();
const proPlan = { harness: 'codex', home: 'codex', plan_type: 'pro', limit_id: 'codex',
  windows: [{ window_minutes: 10080, used_percent: 52, resets_at: friday }], unlimited: false, seen_at: friday };

test('planLineText: plan, home, window, percent and the local reset time', () => {
  assert.equal(planLineText(proPlan), 'Codex Pro · codex · weekly 52% used · resets Fri 3:10 PM');
  const two = { ...proPlan, home: 'birch (openclaw)', windows: [proPlan.windows[0], { window_minutes: 300, used_percent: 7.5, resets_at: 'bad' }] };
  assert.equal(planLineText(two), 'Codex Pro · birch (openclaw) · weekly 52% used · resets Fri 3:10 PM · 5-hour 8% used');
});

test('spendPlanItems: one item per plan keyed plan:<home>, a bar per window at used_percent; none for an empty list', () => {
  const items = spendPlanItems([proPlan, { ...proPlan, home: 'birch (openclaw)', windows: [{ window_minutes: 300, used_percent: 95, resets_at: friday }] }]);
  assert.deepEqual(Array.from(items, i => i.key), ['plan:codex', 'plan:birch (openclaw)']);
  assert.match(items[0].html, /<span class="spend-plan-text">Codex Pro · codex · weekly 52% used · resets Fri 3:10 PM<\/span>/);
  assert.match(items[0].html, /class="hbar-fill" data-w="52\.0"/);
  assert.match(items[1].html, /class="hbar-fill crit" data-w="95\.0"/);
  assert.equal(spendPlanItems([]).length, 0);
  assert.equal(spendPlanItems(undefined).length, 0);
});

test('spendPlanItems: two same-label plans key apart by home_path', () => {
  const items = spendPlanItems([
    { ...proPlan, home_path: '/Users/a/.codex' },
    { ...proPlan, home_path: '/Users/b/.codex' },
  ]);
  assert.deepEqual(Array.from(items, i => i.key), ['plan:/Users/a/.codex', 'plan:/Users/b/.codex']);
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
