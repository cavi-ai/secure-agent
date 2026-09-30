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

test('opening an older finding makes its served actions immediately clickable', async () => {
  const begin = app.indexOf('  window.openFlagDetail = async function(');
  const finish = app.indexOf('  // Deep link from the menubar', begin);
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
