import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const app = readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)),
  '../../../daemon/internal/api/web_dist/app.js'), 'utf8');
const start = app.indexOf('  window.explainAct = async function(');
const end = app.indexOf('  // A pattern card\'s served action', start);
assert.ok(start >= 0 && end > start, 'finding action handler is present');
const actionHandler = app.slice(start, end);

for (const success of [true, false]) {
 test(`incident dismissal ${success ? 'clears the queue and keeps history' : 'restores the queue on a failed write'}`, async () => {
  const begin = app.indexOf('  window.setIncidentStatus = async function(');
  const finish = app.indexOf('  // Worktree actions.', begin);
  const original = {incidents:[{id:'inc'}], posture:{items:[{kind:'incident',id:'inc'}]}};
  const ctx = {window:{}, telemetryData:structuredClone(original), drawerMode:null,
   mapAttentionItems:fn=>{ctx.telemetryData.posture.items=ctx.telemetryData.posture.items.map(fn).filter(Boolean);},
   stage:(_keys,_dirty,fn)=>{fn();return ()=>{ctx.telemetryData=structuredClone(original);};},
   apiFetch:async()=>({ok:success,json:async()=>({workflow:{status:'acknowledged'}}),text:async()=>'write unavailable'}),
   showToast:()=>{},cardNote:()=>{},cssq:x=>x,fetchTelemetry:()=>{}};
  vm.runInNewContext(app.slice(begin,finish),ctx);
  await ctx.window.setIncidentStatus('inc','acknowledged');
  assert.equal(ctx.telemetryData.posture.items.length,success?0:1);
  assert.equal(ctx.telemetryData.incidents.length,1);
  assert.equal(ctx.telemetryData.incidents[0].workflow?.status,success?'acknowledged':undefined);
 });
}

test('incident drawer loads current workflow and retains raw Markdown for copying', async () => {
 const begin=app.indexOf('  window.openIncidentReport = async function(');
 const finish=app.indexOf('  // Endpoint detail:',begin);
 const ctx={window:{},drawer:{},drawerSeq:1,btnDrawerCopy:{},drawerBody:{},openDrawer:()=>{},
  apiFetch:async url=>({ok:true,text:async()=>'# Original report',json:async()=>({workflow:{status:'acknowledged'}})}),
  incidentReportHTML:(id,wf,text)=>[id,wf.status,text].join('|'),loadPlanSlot:()=>{}};
 vm.runInNewContext(app.slice(begin,finish),ctx);
 await ctx.window.openIncidentReport('inc');
 assert.equal(ctx.currentRawMarkdown,'# Original report');
 assert.equal(ctx.drawerBody.innerHTML,'inc|acknowledged|# Original report');
});

test('group approval sends the selected served endpoint without a stale flag lookup', async () => {
  const begin = app.indexOf('  window.patternAct = async function(');
  const finish = app.indexOf('  window.unmuteFlag = async function(', begin);
  const requests = [];
  const body = { flag_id: 'older', path: '/home/.config/gh/hosts.yml', host: '140.82.114.6' };
  const ctx = { window: { saConfirm: async () => true },
    telemetryData: { patterns: [{ key: 'group', actions: [{id: 'expect', method: 'POST', path: '/expected', body, consequence: 'This endpoint only'}] }] },
    apiFetch: async (url, req) => { requests.push([url, JSON.parse(req.body)]); return {ok: true}; },
    showToast: () => {}, fetchTelemetry: () => {}, loadPolicy: () => {},
  };
  vm.runInNewContext(app.slice(begin, finish), ctx);
  await ctx.window.patternAct('group', 'expect', body.host);
  assert.deepEqual(requests, [['/expected', body]]);
  ctx.window.saConfirm = async () => false;
  await ctx.window.patternAct('group', 'expect', body.host);
  assert.equal(requests.length, 1);
});

test('opening an older finding makes its served actions immediately clickable', async () => {
  const begin = app.indexOf('  window.openFlagDetail = async function(');
  const finish = app.indexOf('  async function openConsoleContext(', begin);
  assert.ok(begin >= 0 && finish > begin, 'flag drawer handler is present');
  const cache = new Map();
  const flag = { id: 'older-flag', title: 'File access', rule: 'sensitive-read', agent: 'codex',
    ts: '2026-09-29T12:00:00Z', evidence: [], explain: { actions: [] } };
  const ctx = {
    window: {}, drawer: {}, drawerMode: '', drawerFlag: '', drawerSeq: 1,
    btnDrawerCopy: {}, drawerBody: {}, drawerTitle: {}, planFlagCache: cache,
    telemetryData: { status: {} },
    openDrawer: () => {}, apiFetch: async () => ({ ok: true, json: async () => flag }),
    escapeHTML: x => String(x), explainLines: () => null, ruleTitle: () => 'File access',
    explainActionsHTML: () => '', loadPlanSlot: () => {},
  };
  vm.runInNewContext(app.slice(begin, finish), ctx, { filename: 'app.js:openFlagDetail' });
  await ctx.window.openFlagDetail(flag.id);
  assert.equal(cache.get(flag.id), flag);
  assert.match(ctx.drawerBody.innerHTML, /File access/);
});

for (const [id, route, body] of [
  ['allow-host', '/allowlist', { agent: 'codex', host: '203.0.113.24' }],
  ['allow-path', '/guard/path-allow', { agent: 'codex', rule_id: 'env-files', path: '/workspace/.env' }],
]) {
  test(`${id} from a loaded flag drawer saves the decision and clears the queue`, async () => {
    const requests = [];
    const toasts = [];
    let dropped = 0;
    let closed = 0;
    const flag = { id: 'flag-1', agent: 'codex', explain: { actions: [{ id, method: 'POST', path: route, body }] } };
    const ctx = {
      window: {}, telemetryData: { flags: [], flagsView: [] }, planFlagCache: new Map([[flag.id, flag]]),
      drawerMode: 'flag', drawerFlag: flag.id,
      stageDropFlag: () => { dropped++; return () => { dropped--; }; },
      stageAllow: () => () => {},
      apiFetch: async (url, options) => {
        requests.push({ url, body: JSON.parse(options.body) });
        return { ok: true };
      },
      showToast: (message, type) => toasts.push({ message, type }),
      fetchTelemetry: () => {}, closeDrawer: () => { closed++; }, cardNote: () => {},
    };
    vm.runInNewContext(actionHandler, ctx, { filename: 'app.js:explainAct' });
    await ctx.window.explainAct(flag.id, id, body.host);
    assert.deepEqual(requests.map(r => r.url), [route, '/flags/acknowledge']);
    assert.deepEqual(requests[0].body, body);
    assert.equal(requests[1].body.flag_id, flag.id);
    assert.equal(dropped, 1);
    assert.equal(closed, 1);
    assert.equal(toasts.at(-1).type, 'success');
  });
}

test('failed file exception keeps the finding in the queue', async () => {
  let dropped = 0;
  const flag = { id: 'flag-2', explain: { actions: [{ id: 'allow-path', method: 'POST', path: '/guard/path-allow', body: { agent: 'codex', rule_id: 'env-files', path: '/workspace/.env' } }] } };
  const ctx = {
    window: {}, telemetryData: { flags: [flag] }, planFlagCache: new Map(),
    stageDropFlag: () => { dropped++; return () => { dropped--; }; },
    apiFetch: async () => ({ ok: false, text: async () => 'persist failed' }),
    showToast: () => {}, fetchTelemetry: () => {},
  };
  vm.runInNewContext(actionHandler, ctx, { filename: 'app.js:explainAct' });
  await ctx.window.explainAct(flag.id, 'allow-path');
  assert.equal(dropped, 0);
});

test('selected finding enters local review without dismissal or shell execution', async () => {
 const calls=[];const flag={id:'selected',explain:{actions:[{id:'review-local',body:{flag_ids:['selected']}}]}};
 const ctx={window:{analyzeAgentActivity:async ids=>calls.push(Array.from(ids))},telemetryData:{flags:[flag]},planFlagCache:new Map(),showToast:()=>{}};
 vm.runInNewContext(actionHandler,ctx);
 await ctx.window.explainAct('selected','review-local');
 assert.deepEqual(calls,[['selected']]);assert.equal(ctx.telemetryData.flags.length,1);
});
test('file exception confirmation does not optimistically dismiss mixed evidence', async () => {
 const requests=[];const flag={id:'mixed',explain:{actions:[{id:'expect-file',path:'/expected',method:'POST',consequence:'Exact file only',body:{flag_id:'mixed',scope:'file'}}]}};
 const ctx={window:{saConfirm:async()=>true},telemetryData:{flags:[flag]},planFlagCache:new Map(),showToast:()=>{},loadPolicy:()=>{},fetchTelemetry:()=>{},apiFetch:async(route,opts)=>{requests.push([route,JSON.parse(opts.body)]);return {ok:true,json:async()=>({})}}};
 vm.runInNewContext(actionHandler,ctx);await ctx.window.explainAct('mixed','expect-file');
 assert.equal(requests.length,1);assert.deepEqual(requests[0],['/expected',{flag_id:'mixed',scope:'file'}]);assert.equal(ctx.telemetryData.flags.length,1);
});
