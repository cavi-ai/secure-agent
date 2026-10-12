import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import { loadDrawer } from './drawer-harness.mjs';

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../daemon/internal/api/web_dist');
const app = readFileSync(path.join(web, 'app.js'), 'utf8');
const stagedWriteSource = readFileSync(path.join(web, 'staged-write.js'), 'utf8');

for (const success of [true, false]) {
 test(`incident dismissal ${success ? 'clears the queue and keeps history' : 'restores the queue on a failed write'}`, async () => {
  const begin = app.indexOf('  window.setIncidentStatus = async function(');
  const finish = app.indexOf('  // Discuss:', begin);
  const original = {incidents:[{id:'inc'}], posture:{items:[{kind:'incident',id:'inc'}]}};
  const ctx = {window:{}, telemetryData:structuredClone(original), detailDrawer:{isIncidentOpen:()=>false},
   mapAttentionItems:fn=>{const p=ctx.telemetryData.posture;ctx.telemetryData.posture={...p,items:p.items.map(fn).filter(Boolean)};},
   apiFetch:async()=>({ok:success,json:async()=>({workflow:{status:'acknowledged'}}),text:async()=>'write unavailable'}),
   showToast:()=>{},cardNote:()=>{},cssq:x=>x,fetchTelemetry:()=>{}};
  vm.createContext(ctx);
  vm.runInContext(stagedWriteSource,ctx);
  ctx.stagedWrite=ctx.createStagedWrite({telemetry:()=>ctx.telemetryData,render:()=>{},
   beginAttentionWrite:()=>Object.assign(()=>true,{isCurrent:()=>true}),request:(...args)=>ctx.apiFetch(...args)});
  vm.runInContext(app.slice(begin,finish),ctx);
  await ctx.window.setIncidentStatus('inc','acknowledged');
  assert.equal(ctx.telemetryData.posture.items.length,success?0:1);
  assert.equal(ctx.telemetryData.incidents.length,1);
  assert.equal(ctx.telemetryData.incidents[0].workflow?.status,success?'acknowledged':undefined);
 });
}

test('incident drawer loads current workflow and retains raw Markdown for copying', async () => {
 const h=loadDrawer({deps:{respond:async()=>({ok:true,status:200,text:async()=>'# Original report',json:async()=>({workflow:{status:'acknowledged'}})})}});
 h.ctx.incidentReportHTML=(id,wf,text)=>[id,wf.status,text].join('|');
 await h.api.openIncidentReport('inc');
 let copied=null;
 h.ctx.navigator.clipboard={writeText:async text=>{copied=text;}};
 await h.dom.copyButton.fire('click');
 assert.equal(copied,'# Original report');
 assert.equal(h.dom.body.innerHTML,'inc|acknowledged|# Original report');
});

test('opening an older finding makes its served actions immediately clickable', async () => {
  const flag = { id: 'older-flag', title: 'File access', rule: 'sensitive-read', agent: 'codex',
    ts: '2026-09-29T12:00:00Z', evidence: [], explain: { actions: [] } };
  const h = loadDrawer({ deps: { respond: async () => ({ ok: true, status: 200, json: async () => flag }) } });
  await h.api.openFlagDetail(flag.id);
  assert.equal(h.calls.cachedFlags[0], flag);
  assert.match(h.dom.body.innerHTML, /File access/);
});
