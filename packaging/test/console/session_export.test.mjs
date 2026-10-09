import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const app = readFileSync(new URL('../../../daemon/internal/api/web_dist/app.js', import.meta.url), 'utf8');
const start = app.indexOf('  window.copySessionReport = function(id)');
const end = app.indexOf('  window.selectSession =',start);

async function copy(response, failClipboard = false) {
  const copied = [], toasts = [], requests = [];
  const ctx = { window:{}, navigator:{clipboard:{writeText:async text => { if(failClipboard) throw new Error('denied'); copied.push(text); }}},
    apiFetch:async url => { requests.push(url); return response; }, showToast:(...args)=>toasts.push(args) };
  assert.ok(start >= 0 && end > start);
  vm.runInNewContext(app.slice(start,end),ctx);
  ctx.window.copySessionReport('session/id');
  // Await the clipboard and toast promise chains, without wall-clock waits.
  for (let i=0;i<12;i++) await Promise.resolve();
  return {copied,toasts,requests};
}

test('copying a partial report keeps evidence notes and warns the operator',async()=>{
  const result = await copy({ok:true,headers:{get:()=> 'partial'},text:async()=> '# Report\nActivity totals unavailable'});
  assert.deepEqual(result.requests,['/sessions/session%2Fid/report?format=md']);
  assert.deepEqual(result.copied,['# Report\nActivity totals unavailable']);
  assert.match(result.toasts[0][0],/Partial session report copied/);
  assert.equal(result.toasts[0][1],'warning');
});

test('an unavailable report or rejected clipboard never claims a successful export',async()=>{
  for (const [response,failClipboard] of [[{ok:false,status:503,text:async()=> 'session report unavailable'},false],[{ok:true,text:async()=> '# Report'},true]]) {
    const result=await copy(response,failClipboard);
    assert.equal(result.copied.length,0);
    assert.match(result.toasts[0][0],/Export failed:/);
    assert.equal(result.toasts[0][1],'danger');
  }
});
