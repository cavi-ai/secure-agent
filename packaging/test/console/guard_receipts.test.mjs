import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const c = {Date}; vm.createContext(c);
for (const file of ['lib.js', 'decision-permissions.js']) vm.runInContext(readFileSync(new URL(file, web), 'utf8'), c);
const at = '2026-10-15T12:00:00Z';
const request = {id:'prompt',verdict:'allow',scope:'exact'};
const receipt = {...request,rule_id:'credentials',session_id:'owned',at,scope_ids:['permission']};

test('guard receipts bind the exact answer and reject malformed or unrelated responses', () => {
 assert.equal(c.validGuardReceipt(receipt,request),true);
 for(const change of [{id:'other'},{scope:'once'},{verdict:'deny'},{at:'invalid'},{scope_ids:['']},{scope_ids:'permission'}])
  assert.equal(c.validGuardReceipt({...receipt,...change},request),false,JSON.stringify(change));
});

test('guard history permissions use saved IDs only, and legacy records have no guessed link', () => {
 const r = c.guardPermissionReceipt(receipt,'owned');
 assert.equal(r.kind,'guard'); assert.deepEqual(Array.from(r.ids),['permission']);
 assert.equal(c.guardPermissionReceipt({...receipt,scope_ids:undefined},'owned'),null);
 assert.equal(c.guardPermissionReceipt(receipt,'other'),null);
 const html = c.sessionPermissionsHTML(r,{});
 assert.match(html,/Guard decision/); assert.doesNotMatch(html,/revision undefined/);
});

test('immediate guard result distinguishes submission, unavailable confirmation, and saved history', () => {
 const html = c.guardResultHTML({request,receipt});
 for(const text of ['Answer submitted','does not prove','View permissions']) assert.ok(html.includes(text),text);
 assert.ok(!html.includes('access completed'));
 const unknown = c.guardResultHTML({request,unconfirmed:true});
 assert.match(unknown,/Answer not confirmed/); assert.match(unknown,/Check session results/);
 assert.doesNotMatch(unknown,/data-action="guard-result-permissions"/);
});

function controller() {
 const calls=[], views=[], permissions=[], sessions=[];
 let gen=1, stopped=false;
 const t=c.createGuardDecisionController({request:(url,options)=>new Promise((resolve,reject)=>calls.push({url,body:JSON.parse(options.body),resolve,reject})),confirm:async()=>true,
  context:()=>({id:'prompt',session_id:'owned',available_scopes:[{kind:'once'},{kind:'exact',expiry:'24h'}]}),generation:()=>gen,ended:()=>stopped,paint:r=>views.push(r),announce:()=>{},refetch:()=>{},openPermissions:r=>permissions.push(r),openResults:id=>sessions.push(id)});
 return {t,calls,views,permissions,sessions,auth(){gen++;},stop(){stopped=true;},answer(payload){calls.at(-1).resolve({ok:true,json:async()=>payload});}};
}

test('duplicate clicks submit once and permissions use the confirmed receipt only',async()=>{
 const h=controller(); const pending=h.t.resolve('prompt','allow','once');
 await h.t.resolve('prompt','allow','once'); assert.equal(h.calls.length,1);
 h.answer({resolved:true,receipt:{...receipt,scope:'once',scope_ids:undefined}});await pending;
 assert.equal(h.views.at(-1).unconfirmed,undefined);h.t.permissions();assert.equal(h.permissions.length,0);
 h.t.history();assert.deepEqual(h.sessions,['owned']);
 const grant=h.t.resolve('prompt','allow','exact','24h');await new Promise(r=>setImmediate(r));
 h.answer({resolved:true,receipt});await grant;h.t.permissions();
 assert.deepEqual(Array.from(h.permissions[0].ids),['permission']);
});

test('lost, expired, mismatched, and legacy responses never invent a permission or replay writes',async()=>{
 for(const mode of ['lost','expired','mismatch','legacy']){
  const h=controller();const pending=h.t.resolve('prompt','allow','once');
  if(mode==='lost')h.calls[0].reject(new Error('lost response'));
  else h.answer(mode==='expired'?{resolved:false}:mode==='legacy'?{resolved:true}:{resolved:true,receipt});
  await pending;assert.equal(h.calls.length,1);h.t.permissions();assert.equal(h.permissions.length,0);
  assert.equal(!!h.views.at(-1).unconfirmed,mode==='lost' || mode==='mismatch');
  assert.equal(!!h.views.at(-1).expired,mode==='expired');
 }
});

test('late responses and cleared results cannot cross console authentication',async()=>{
 const h=controller();const pending=h.t.resolve('prompt','allow','once');
 h.auth();h.t.clear();h.answer({resolved:true,receipt:{...receipt,scope:'once',scope_ids:undefined}});await pending;
 assert.equal(h.views.at(-1),null);h.t.permissions();h.t.history();assert.equal(h.permissions.length+h.sessions.length,0);
});

test('a displayed guard receipt cannot open records after credentials change',async()=>{
 const h=controller();const pending=h.t.resolve('prompt','allow','exact','24h');await new Promise(r=>setImmediate(r));
 h.answer({resolved:true,receipt});await pending;h.auth();h.t.permissions();h.t.history();
 assert.equal(h.permissions.length+h.sessions.length,0);
});
