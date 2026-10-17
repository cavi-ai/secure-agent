import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const c = {Date}; vm.createContext(c);
for (const file of ['lib.js','decision-permissions.js','tab-findings.js']) vm.runInContext(readFileSync(new URL(file,web),'utf8'),c);
const p = {id:'request',session_id:'session',agent:'claude',tool:'Read',path:'/workspace/app/.env',rule_id:'env-files',workspace:'/workspace/app',reader_exe:'/bin/claude',available_scopes:[{kind:'once'},{kind:'exact',expiry:'24h'}]};

test('collapsed request exposes operation, full identity, resource and matched rule before consent',()=>{
 const v=c.needView({...p,kind:'guard',rule:p.rule_id,group:{agent:p.agent,workspace:p.workspace}},{ });
 const html=c.needRowHTML(v,false,0);
 for(const text of [p.path,p.workspace,p.reader_exe,p.rule_id,p.tool]) {
  assert.ok(html.indexOf(text)>=0 && html.indexOf(text)<html.indexOf('class="need-actions"'),text);
 }
 assert.match(html,/data-action="guard-inspect" data-id="request"/);
 assert.doesNotMatch(html,/secrets inside|safe to allow/);
});

function harness() {
 let context=p;
 const writes=[], inspections=[], confirmations=[], views=[];
 let confirm=async text=>{confirmations.push(text);return true;};
 const t=c.createGuardDecisionController({context:()=>context,request:async(url,options)=>{writes.push(JSON.parse(options.body));return {ok:true,json:async()=>({resolved:false})};},confirm:text=>confirm(text),generation:()=>1,ended:()=>false,paint:r=>views.push(r),announce:()=>{},refetch:()=>{},openInspection:id=>inspections.push(id)});
 return {t,writes,inspections,confirmations,views,setContext:v=>context=v,setConfirm:f=>confirm=f};
}
test('inspection uses only the pending request session and never submits an answer',()=>{
 const h=harness();h.t.inspect('request');assert.deepEqual(h.inspections,['session']);assert.equal(h.writes.length,0);
 h.setContext(undefined);h.t.inspect('request');assert.equal(h.inspections.length,1);
 h.setContext({...p,session_id:''});h.t.inspect('request');assert.equal(h.inspections.length,1);
});
test('future consent names the resource, operation, workspace, executable and lifetime',async()=>{
 const h=harness();await h.t.resolve('request','allow','exact','24h');
 for(const fact of [p.path,p.tool,p.workspace,p.reader_exe,'24 hours']) assert.ok(h.confirmations[0].includes(fact),fact);
 assert.equal(h.views.at(-1).expired,true);
 assert.match(c.guardResultHTML(h.views.at(-1)),/Request no longer pending/);
});
test('cancelled confirmation, removed request and unsupported scope never submit',async()=>{
 const h=harness();h.setConfirm(async()=>false);await h.t.resolve('request','allow','exact','24h');assert.equal(h.writes.length,0);
 h.setConfirm(async()=>{h.setContext(undefined);return true;});await h.t.resolve('request','allow','exact','24h');assert.equal(h.writes.length,0);
 h.setContext(p);await h.t.resolve('request','allow','exact','7d');assert.equal(h.writes.length,0);
});
