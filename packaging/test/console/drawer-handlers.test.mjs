import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

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
