import { controller } from './controllers.mjs';
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
  assert.equal(planLineText(proPlan), 'Codex Pro · codex · Account unverified — may overlap a shared account · weekly 52% used · resets Fri 3:10 PM · observed ' + new Date(friday).toLocaleString(undefined, {month:'short',day:'numeric',hour:'numeric',minute:'2-digit'}));
  const two = { ...proPlan, home: 'birch (openclaw)', windows: [proPlan.windows[0], { window_minutes: 300, used_percent: 7.5, resets_at: 'bad' }] };
  assert.equal(planLineText(two), 'Codex Pro · birch (openclaw) · Account unverified — may overlap a shared account · weekly 52% used · resets Fri 3:10 PM · 5-hour 8% used · observed ' + new Date(friday).toLocaleString(undefined, {month:'short',day:'numeric',hour:'numeric',minute:'2-digit'}));
});

test('spendPlanItems: one item per plan keyed plan:<home>, a bar per window at used_percent; none for an empty list', () => {
  const items = spendPlanItems([proPlan, { ...proPlan, home: 'birch (openclaw)', windows: [{ window_minutes: 300, used_percent: 95, resets_at: friday }] }]);
  assert.deepEqual(Array.from(items, i => i.key), ['plan:codex', 'plan:birch (openclaw)']);
  assert.match(items[0].html, /<span class="spend-plan-text">Codex Pro · codex · Account unverified — may overlap a shared account · weekly 52% used · resets Fri 3:10 PM · observed [^<]+<\/span>/);
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


function inspectorFixture() {
  const document = {activeElement:null};
  const focusCalls = [];
  const node = (dataset) => ({dataset, closest() { return this; }, focus(options) {
    document.activeElement = this; focusCalls.push({node:this,options});
  }});
  const reset = node({action:"reset-spend-day"});
  const bar = node({action:"select-spend-day",day:"2026-10-10"});
  const inspector = {
    nodes:[], replacement:[],
    contains(item) { return this.nodes.includes(item); },
    querySelectorAll(selector) { return this.nodes.filter(item => selector === "[data-spend-repo]" ? item.dataset.spendRepo !== undefined : !!item.dataset.action); },
    querySelector(selector) { return selector.includes("reset-spend-day") ? this.nodes.find(item => item.dataset.action === "reset-spend-day") : null; },
    set innerHTML(value) { this.nodes = this.replacement; }
  };
  document.querySelector = () => bar;
  return {document,node,inspector,reset,bar,focusCalls};
}

test("selected-day repository rows have escaped stable identities and named usage without Tab stops", () => {
  const rows = [{key:"repo\"<x>",calls:3,cost_usd:2,plan_calls:1,unpriced_calls:1,local_calls:1}];
  const html = joined(spendListItems(rows,8,{by:"repo",dayDetail:true}));
  assert.match(html,/data-spend-repo="repo&quot;&lt;x&gt;"/);
  assert.match(html,/tabindex="-1" role="group" aria-label="repo&quot;&lt;x&gt; · \$2\.00 · 3 calls · 1 on plans · 1 unpriced · 1 local"/);
  assert.doesNotMatch(joined(spendListItems(rows,8,{by:"repo"})),/data-spend-repo|tabindex|role="group"/);
  const card={since:'2026-10-09T00:00:00Z',until:'2026-10-11T00:00:00Z'};
  const day={key:'2026-10-10',calls:3,cost_usd:2};
  const report={...spendDayWindow(day.key,card,0),by:'repo',total:day,rows};
  assert.match(spendDayDetailHTML(day,card,0,report),/data-spend-repo="repo&quot;&lt;x&gt;" tabindex="-1"/);
});

test("breakdown refresh preserves focused repository identity across replacement and reordering", () => {
  const f = inspectorFixture(); ctx.document=f.document;
  const old=f.node({spendRepo:"repo-9"});
  const replacement=f.node({spendRepo:"repo-9"});
  f.inspector.nodes=[f.reset,old]; f.inspector.replacement=[f.node({spendRepo:"repo-2"}),replacement,f.reset];
  f.document.activeElement=old;
  ctx.patchSpendDayInspector(f.inspector,"updated");
  assert.equal(f.document.activeElement,replacement);
  assert.equal(f.focusCalls.length,1);
  assert.equal(f.focusCalls[0].options.preventScroll,true);
  ctx.patchSpendDayInspector(f.inspector,"updated");
  assert.equal(f.focusCalls.length,1,"unchanged markup does not refocus");
});

test("disappeared focused repository falls back to Clear selection; outside focus remains untouched", () => {
  const f = inspectorFixture(); ctx.document=f.document;
  const old=f.node({spendRepo:"removed"});
  f.inspector.nodes=[f.reset,old]; f.inspector.replacement=[f.reset]; f.document.activeElement=old;
  ctx.patchSpendDayInspector(f.inspector,"removed");
  assert.equal(f.document.activeElement,f.reset);
  const outside=f.node({action:"refresh"}); f.document.activeElement=outside;
  ctx.patchSpendDayInspector(f.inspector,"background");
  assert.equal(f.document.activeElement,outside);
  assert.equal(f.focusCalls.length,1);
  f.document.activeElement=f.reset; f.inspector.replacement=[];
  ctx.patchSpendDayInspector(f.inspector,"");
  assert.equal(f.document.activeElement,f.bar);
});

test("focused expansion captures first newly revealed repository before rerender reorders rows", () => {
  const f=inspectorFixture();
  const rows=Array.from({length:11},(_,i)=>({key:`repo-${i+1}`,calls:1,cost_usd:11-i}));
  f.inspector.nodes=[...rows.slice(0,8).map(row=>f.node({spendRepo:row.key})),f.reset];
  const control=f.node({action:"show-more",key:"spend"});
  control.closest=selector=>selector === ".spend-day-inspector" ? f.inspector : null;
  const expandedLists=new Set(); let rendered=0;
  const c={document:f.document,telemetryData:{spendDayReport:{rows}},expandedLists,topCostRows:ctx.topCostRows,
    renderNow(keys) { assert.equal(Array.from(keys).join(),"spend"); rendered++;
      f.inspector.nodes=[...rows.slice().reverse().map(row=>f.node({spendRepo:row.key})),f.reset];
    }};
  vm.createContext(c);
  const source=readFileSync(path.join(webDist,"app.js"),"utf8");
  Object.assign(c, controller('spend-controller.js', 'createSpendController', c));
  assert.equal(c.expandSpendDayRepositories(control),true);
  assert.equal(f.document.activeElement.dataset.spendRepo,"repo-9");
  assert.equal(expandedLists.has("spend"),true);
  assert.equal(rendered,1);
  assert.equal(f.focusCalls.length,1);
  assert.equal(f.focusCalls[0].options,undefined,"explicit activation permits native focused-row visibility");
  control.closest=()=>null;
  assert.equal(c.expandSpendDayRepositories(control),false);
  assert.equal(rendered,1,"shared Show more consumers use their existing path");
  assert.match(source,/if \(d\.key === .spend. && expandSpendDayRepositories\(el\)\) break;/);
});

test('Clear selection restores its selected chart bar without changing the chart report or expansion', () => {
  const f=inspectorFixture();
  const chart={by:'day',since:'2026-10-09T00:00:00Z',until:'2026-10-11T00:00:00Z'};
  const telemetryData={spendDay:'2026-10-10',spendDayReport:{rows:[]},spendDayRefresh:{loading:true},costsCard:chart};
  const expandedLists=new Set(['spend']);
  const c={telemetryData,expandedLists,spendDayGen:1,document:{querySelectorAll:()=>[f.bar]},renderNow:()=>{}};
  vm.createContext(c);
  const source=readFileSync(path.join(webDist,'app.js'),'utf8');
  Object.assign(c, controller('spend-controller.js', 'createSpendController', c));
  c.resetSpendDay(true);
  assert.equal(telemetryData.spendDay,'');
  assert.equal(telemetryData.spendDayReport,null);
  assert.equal(c.spendDayGen,2);
  assert.equal(f.document.activeElement,f.bar);
  assert.equal(f.focusCalls[0].options.preventScroll,true);
  assert.equal(telemetryData.costsCard,chart);
  assert.equal(expandedLists.has('spend'),true);
});

function dayKeyboardFixture(count = 4) {
  const source = readFileSync(path.join(webDist,'app.js'),'utf8');
  const focusCalls = [];
  const bars = {buttons:[],querySelectorAll:()=>bars.buttons};
  const button = (day, options = {}) => ({dataset:{action:'select-spend-day',day},disabled:false,
    matches() { return this.fieldsetDisabled || this.disabled; },
    closest(selector) { return selector === '.spend-bars' ? bars : this; },
    focus(...args) { focusCalls.push({button:this,args}); }, ...options});
  bars.buttons = Array.from({length:count}, (_,i)=>button(`day-${i}`));
  let listener;
  const forbidden = () => assert.fail('day-key focus must not activate, load, render, or schedule work');
  const c = {sessionEnded:false,document:{getElementById:id=>{
    assert.equal(id,'spend-card'); return {addEventListener:(type,handler)=>{assert.equal(type,'keydown');listener=handler;}};
  }},selectSpendDay:forbidden,loadSpendDay:forbidden,apiFetch:forbidden,renderNow:forbidden,setTimeout:forbidden};
  vm.createContext(c);
  vm.runInContext(source.slice(source.indexOf('  function handleSpendDayKeydown('),source.indexOf('  function renderStatus(')),c);
  const key = (current, value, options = {}) => {
    const event = {target:current,key:value,prevented:0,preventDefault(){this.prevented++;},...options};
    listener(event); return event;
  };
  return {c,bars,button,focusCalls,key};
}

test('daily chart arrows move to adjacent enabled DOM buttons, Home/End reach bounds, without activation', () => {
  const f=dayKeyboardFixture(), [first,second,third,last]=f.bars.buttons;
  for (const [from,key,to] of [[first,'ArrowRight',second],[third,'ArrowLeft',second],[third,'Home',first],[second,'End',last]]) {
    assert.equal(f.key(from,key).prevented,1);
    assert.equal(f.focusCalls.at(-1).button,to);
    assert.equal(f.focusCalls.at(-1).args.length,0,'native focus may reveal the destination in the scrollable chart');
  }
  const count=f.focusCalls.length;
  assert.equal(f.key(first,'ArrowLeft').prevented,1);
  assert.equal(f.key(last,'ArrowRight').prevented,1);
  assert.equal(f.focusCalls.length,count,'bounds clamp without redundant focus');
  assert.equal(first.dataset.day,'day-0');
});

test('day-key navigation resolves live enabled buttons in its originating chart', () => {
  const f=dayKeyboardFixture(), [first,second,third,last]=f.bars.buttons;
  second.disabled=true; third.fieldsetDisabled=true;
  assert.equal(f.key(first,'ArrowRight').prevented,1);
  assert.equal(f.focusCalls.at(-1).button,last);
  f.bars.buttons=[last,first];
  assert.equal(f.key(last,'ArrowRight').prevented,1);
  assert.equal(f.focusCalls.at(-1).button,first,'refresh DOM order is used immediately');
  const foreign=f.button('other'); foreign.closest=selector=>selector === '.spend-bars' ? {} : foreign;
  // Nested or other chart buttons never become neighbors of this chart.
  f.bars.buttons=[first,foreign,last];
  assert.equal(f.key(first,'ArrowRight').prevented,1);
  assert.equal(f.focusCalls.at(-1).button,last);
  const count=f.focusCalls.length;
  assert.equal(f.key(second,'ArrowRight').prevented,0);
  assert.equal(f.focusCalls.length,count,'removed/disabled source is ignored');
});

test('day-key navigation leaves activation, Tab, modified/composing/prevented events and unrelated controls untouched', () => {
  const f=dayKeyboardFixture(), first=f.bars.buttons[0];
  for (const key of ['Enter',' ','Tab','Escape','ArrowUp','ArrowDown']) assert.equal(f.key(first,key).prevented,0);
  for (const field of ['altKey','ctrlKey','metaKey','shiftKey','isComposing','defaultPrevented'])
    assert.equal(f.key(first,'ArrowRight',{[field]:true}).prevented,0);
  assert.equal(f.key({closest:()=>null},'Home').prevented,0);
  assert.equal(f.key({},'End').prevented,0);
  assert.equal(f.key(null,'Home').prevented,0);
  first.disabled=true;
  assert.equal(f.key(first,'ArrowRight').prevented,0);
  first.disabled=false; f.c.sessionEnded=true;
  assert.equal(f.key(first,'ArrowRight').prevented,0);
  assert.equal(f.focusCalls.length,0);
});

test('empty and single-day charts are safe and never leave their bounds', () => {
  const f=dayKeyboardFixture(1), only=f.bars.buttons[0];
  for (const key of ['ArrowLeft','ArrowRight','Home','End']) assert.equal(f.key(only,key).prevented,1);
  assert.equal(f.focusCalls.length,0);
  f.bars.buttons=[];
  assert.equal(f.key(only,'Home').prevented,0);
  assert.equal(f.focusCalls.length,0);
});

function guidanceFixture() {
  const guidance={hidden:true,textContent:'Select a day to see usage by repository. Use ←/→ or Home/End to move between dates.'}, grouping={value:'day'};
  const inspector={contains:()=>false,set innerHTML(value){this.markup=value;}};
  const body={firstElementChild:null,childElementCount:0,markup:'',set innerHTML(value){
    this.markup=value;
    const opening=value.match(/^<div class="(spend-bars|spend-list)"([^>]*)>/);
    if (!opening) { this.firstElementChild=null; this.childElementCount=1; return; }
    const attributes=new Map(Array.from(opening[2].matchAll(/([\w-]+)="([^"]*)"/g),match=>[match[1],match[2]]));
    this.firstElementChild={className:opening[1],scrollLeft:0,children:[],nextElementSibling:inspector,
      contains:()=>false,setAttribute:(name,value)=>attributes.set(name,value),removeAttribute:name=>attributes.delete(name),attributes};
    this.childElementCount=opening[1] === 'spend-bars' ? 2 : 1;
  }};
  const plans={className:'spend-plans',nextElementSibling:body};
  const cardElement={firstElementChild:plans,childElementCount:2};
  const card={by:'day',since:'2026-10-09T00:00:00Z',until:'2026-10-11T00:00:00Z',total:{calls:2,cost_usd:2},rows:[{key:'2026-10-10',calls:2,cost_usd:2}]};
  const SA={t:{costsCard:card,costsCardTZ:0},expanded:new Set()};
  const context={window:{SA},document:{activeElement:null,getElementById:id=>({
    'spend-card':cardElement,'spend-by':grouping,'spend-day-guidance':guidance
  }[id])}};
  vm.createContext(context);
  for (const file of ['lib.js','tab-overview.js']) vm.runInContext(readFileSync(path.join(webDist,file),'utf8'),context);
  context.patchList=()=>{};
  return {context,SA,guidance,grouping,body,card,render:()=>context.renderSpend()};
}

test('day guidance stays visible across initial loading, empty, selected loading, selection, clear and refresh', () => {
  const f=guidanceFixture();
  f.SA.t.costsCard=null; f.render(); assert.equal(f.guidance.hidden,false);
  f.SA.t.costsCard={...f.card,rows:[]}; f.render(); assert.equal(f.guidance.hidden,false);
  f.SA.t.costsCard=f.card; f.render();
  const chart=f.body.firstElementChild; chart.scrollLeft=37;
  assert.equal(chart.attributes.get('role'),'group');
  assert.equal(chart.attributes.get('aria-label'),'Daily usage dates');
  assert.equal(chart.attributes.get('aria-describedby'),'spend-day-guidance');
  f.SA.t.spendDay='2026-10-10'; f.SA.t.spendDayRefresh={loading:true}; f.render();
  assert.equal(f.guidance.hidden,false);
  f.SA.t.spendDayReport={...spendDayWindow('2026-10-10',f.card,0),by:'repo',total:f.card.total,rows:[]};
  f.SA.t.spendDayRefresh={}; f.render(); assert.equal(f.guidance.hidden,false);
  f.SA.t.spendDay=''; f.render(); assert.equal(f.guidance.hidden,false);
  f.SA.t.costsCard={...f.card,refreshing:true,generated_at:f.card.since}; f.render();
  assert.equal(f.guidance.hidden,false);
  assert.equal(f.body.firstElementChild,chart,'caption changes do not replace the chart');
  assert.equal(chart.scrollLeft,37);
  assert.equal(f.guidance.textContent,'Select a day to see usage by repository. Use ←/→ or Home/End to move between dates.');
});

test('guidance visibility follows the current grouping control, including stale report grouping', () => {
  const f=guidanceFixture();
  for (const by of ['repo','provider','model']) {
    f.SA.t.costsCard=f.card; f.render(); const chart=f.body.firstElementChild;
    f.grouping.value=by; f.render();
    assert.equal(f.guidance.hidden,true);
    assert.equal(chart.attributes.has('aria-describedby'),false,'hidden guidance cannot describe a stale day chart');
    assert.equal(f.body.firstElementChild,chart);
    f.SA.t.costsCard=null; f.render(); assert.equal(f.guidance.hidden,true);
    f.SA.t.costsCard=f.card;
  }
  f.grouping.value='day'; f.SA.t.costsCard={...f.card,by:'repo'}; f.render();
  assert.equal(f.guidance.hidden,false,'stale non-day report does not hide current day instructions');
  assert.equal(f.body.firstElementChild.attributes.has('aria-describedby'),false);
});

test('guidance is one static muted caption outside the replaced spend-card markup', () => {
  const html=readFileSync(path.join(webDist,'index.html'),'utf8');
  assert.equal((html.match(/id="spend-day-guidance"/g)||[]).length,1);
  assert.match(html,/<p id="spend-day-guidance" class="spend-day-guidance" hidden>Select a day to see usage by repository\. Use ←\/→ or Home\/End to move between dates\.<\/p>\s*<div id="spend-card"/);
  const caption=html.match(/<p id="spend-day-guidance"[^>]*>/)[0];
  assert.doesNotMatch(caption,/tabindex|role=|aria-live|data-action/);
});

test('saved grouping initializes guidance before boot and grouping changes update it without a render', () => {
  const source=readFileSync(path.join(webDist,'app.js'),'utf8');
  for (const by of ['day','repo']) {
    const f=guidanceFixture(), since={value:''};
    f.guidance.hidden=by !== 'repo'; // Start with the opposite visibility.
    Object.assign(f.context,{spendView:{by,since:'7d'},SPEND_BY:['day','repo','provider','model'],SPEND_SINCE:['24h','7d','30d'],
      SPEND_VIEW_KEY:'sa.spend-view',sessionStorage:{setItem(){}},telemetryData:f.SA.t,spendPolls:0,
      resetSpendDay(){},reportHealth:{reset(){}},renderReportHealth(){},renderNow(){},loadSpend(){}});
    f.context.document.getElementById=id=>({'spend-by':f.grouping,'spend-since':since,'spend-day-guidance':f.guidance}[id]);
    vm.runInContext(source.slice(source.indexOf('  const spendBySel ='),source.indexOf('  spendBySel?.addEventListener')),f.context);
    assert.equal(f.grouping.value,by);
    assert.equal(f.guidance.hidden,by !== 'day','guidance is initialized while rendering is unavailable before boot');
    f.grouping.value=by === 'day' ? 'repo' : 'day';
    f.context.spendBySel=f.grouping; f.context.spendSinceSel=since;
    controller('spend-controller.js', 'createSpendController', f.context).onSpendView();
    assert.equal(f.guidance.hidden,f.grouping.value !== 'day','preboot grouping change updates the same caption');
  }
});


test('unidentified historical Codex quota is explicitly unverified and observed', () => {
  const unknown = {...proPlan, home:'deb (openclaw)'};
  assert.match(planLineText(unknown), /Account unverified/);
  assert.match(planLineText(unknown), /observed/);
  assert.match(spendPlanItems([unknown])[0].html, /spend-plan-unverified/);
  assert.match(spendPlanItems([unknown])[0].html, /<details class="spend-plan-history"><summary>Unverified quota observation/);
  assert.doesNotMatch(spendPlanItems([unknown])[0].html, /<details[^>]* open/);
  const known = {...proPlan, account_key:'account'};
  assert.doesNotMatch(planLineText(known), /Account unverified/);
  assert.match(planLineText(known), /observed/);
  assert.equal(spendPlanItems([unknown,known])[0].key, 'plan:account:codex');
});
