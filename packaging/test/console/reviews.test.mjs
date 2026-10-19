import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import {loadDrawer} from './drawer-harness.mjs';

const lib=readFileSync(new URL('../../../daemon/internal/api/web_dist/lib.js',import.meta.url),'utf8');
const app=readFileSync(new URL('../../../daemon/internal/api/web_dist/app.js',import.meta.url),'utf8');
const permissions=readFileSync(new URL('../../../daemon/internal/api/web_dist/decision-permissions.js',import.meta.url),'utf8');
const findings=readFileSync(new URL('../../../daemon/internal/api/web_dist/tab-findings.js',import.meta.url),'utf8');
const record={id:'context',revision:2,review_state:'unreviewed',reviewed_revision:1,count:8,evidence_available:true,
 context:{rule:'sensitive-read-then-connect',session_id:'session',resources:['<credentials>'],destinations:['203.0.113.5:443']},
 evidence_flag_id:'stronger',evidence_flag_available:true,source_ids:['source'],incident_ids:[],assessment:{risk:'critical',residual_risk:'model-exposure',control:'unknown',review_state:'unreviewed',reason:'Model-visible read'}};

test('review card preserves risk, context, receipts and explicit revision',()=>{
 const ctx={};vm.createContext(ctx);vm.runInContext(lib,ctx);
 ctx.record=record;
 const html=vm.runInContext('reviewHTML(record, {action:"acknowledge", conflict:true})',ctx);
 assert.match(html,/critical/i);assert.match(html,/8 occurrences/);assert.match(html,/&lt;credentials&gt;/);
 assert.match(html,/data-revision="2"/);assert.match(html,/Evidence changed/);assert.match(html,/reviewed revision 1/i);
 assert.match(html,/data-id="stronger">View supporting evidence/);
 assert.match(html,/data-action="open-flag" data-id="stronger"/);
 assert.match(html,/Revoke under Protection → Rules &amp; permissions\./);
 assert.equal(((app+permissions).match(/Revoke under Protection → Rules & permissions\./g)||[]).length,2);
 assert.doesNotMatch(app+lib,/Revoke in Policies/);
 const expired=vm.runInContext('reviewHTML({...record,evidence_available:false})',ctx);
 assert.match(expired,/Source evidence has expired/);assert.doesNotMatch(expired,/data-action="review-decision"/);
});

test('stale review decision retains choice, refreshes facts and never retries',async()=>{
 const start=app.indexOf('  window.reviewAct = async function(');
 const end=app.indexOf('  // Review pagination',start);
 assert.ok(start>=0&&end>start,'review handler exists');
 const calls=[],drafts=new Map();let refreshed=0;
 const ctx={window:{},handoffGeneration:0,sessionEnded:false,reviewResultSeq:0,reviewResult:null,attentionItems:()=>[],telemetryData:{reviews:{reviews:[record]}},beginAttentionWrite:()=>()=>{},reviewDrafts:drafts,apiFetch:async(url,opts)=>{calls.push([url,JSON.parse(opts.body)]);return{ok:false,status:409}},showToast:()=>{},fetchTelemetry:async()=>{refreshed++},markDirty:()=>{}};
 vm.runInNewContext(lib,ctx);
 vm.runInNewContext(app.slice(start,end),ctx);
 await ctx.window.reviewAct('context',1,'acknowledge');
 assert.equal(calls.length,1);assert.deepEqual(calls[0],['/reviews/decision',{id:'context',revision:1,action:'acknowledge'}]);
 assert.equal(refreshed,1);assert.equal(drafts.get('context').action,'acknowledge');assert.equal(drafts.get('context').conflict,true);
});

const receipt={id:record.id,revision:record.revision,action:'acknowledge',at:'2026-10-11T12:00:00Z'};
function reviewController(overrides={}) {
 const ctx={window:{saAnnounce:()=>{}},handoffGeneration:0,sessionEnded:false,reviewResultSeq:0,reviewResult:null,
  attentionItems:()=>[{kind:'review',id:record.id,review:record}],telemetryData:{reviews:{reviews:[record]}},
  beginAttentionWrite:()=>()=>{},reviewDrafts:new Map(),markDirty:()=>{},showToast:()=>{},fetchTelemetry:async()=>{},
  apiFetch:async()=>({ok:true,status:200,json:async()=>receipt}),...overrides};
 vm.createContext(ctx);vm.runInContext(lib,ctx);
 const start=app.indexOf('  window.reviewAct = async function('),end=app.indexOf('  // Review pagination',start);
 vm.runInContext(app.slice(start,end),ctx);
 return ctx;
}

test('unsafe or malformed review revisions never issue a decision request',async()=>{
 const rounded=JSON.parse('{"revision":9007199254740993}').revision;
 for(const revision of [rounded, Number.MAX_SAFE_INTEGER+1, 0, -1, 1.5, '2', null, undefined, NaN, Infinity]) {
  let writes=0;
  const ctx=reviewController({apiFetch:async()=>{writes++;return{ok:true,json:async()=>({...receipt,revision})}}});
  await ctx.window.reviewAct(record.id,revision,'acknowledge');
  assert.equal(writes,0,`revision ${revision} must not be submitted`);
  assert.equal(ctx.reviewDrafts.size,0);
  assert.equal(ctx.reviewResult,null);
 }
});

test('review requests accept supported decisions and safe boundary revisions',async()=>{
 for(const revision of [1,Number.MAX_SAFE_INTEGER]) {
  for(const [action,scope] of [['acknowledge'],['close_reported'],['expect',{kind:'once'}],
   ['expect',{kind:'session'}],['expect',{kind:'exact',expiry:'24h'}],['expect',{kind:'exact',expiry:'7d'}]]) {
   const calls=[];
   const ctx=reviewController({apiFetch:async(url,options)=>{
    calls.push(JSON.parse(options.body));return{ok:true,json:async()=>({...receipt,revision,action})};
   }});
   ctx.window.saConfirm=async()=>true;
   await ctx.window.reviewAct(record.id,revision,action,scope);
   assert.deepEqual(calls,[{id:record.id,revision,action,...(scope?{scope}:{})}]);
   assert.equal(ctx.reviewResult.receipt.revision,revision);
  }
 }
});

test('unsupported decisions and permission scopes never prompt or write',async()=>{
 for(const [action,scope] of [['future'],['expect'],['expect',{kind:'future'}],
  ['expect',{kind:'exact',expiry:'forever'}],['expect',{kind:'once',expiry:'24h'}],
  ['expect',{kind:'session',expiry:'7d'}],['acknowledge',{kind:'once'}]]) {
  let writes=0,confirms=0;
  const ctx=reviewController({apiFetch:async()=>{writes++}});
  ctx.window.saConfirm=async()=>{confirms++;return true};
  await ctx.window.reviewAct(record.id,2,action,scope);
  assert.equal(writes,0);assert.equal(confirms,0);assert.equal(ctx.reviewDrafts.size,0);
 }
});

test('review cards and attention actions withhold unsafe revisions and unknown scopes',()=>{
 const ctx={SA:{reviewDrafts:new Map()}};
 vm.createContext(ctx);vm.runInContext(lib,ctx);vm.runInContext(findings,ctx);
 for(const revision of [JSON.parse('9007199254740993'),0,1.5,'2']) {
  const r={...record,revision};
  assert.doesNotMatch(ctx.reviewHTML(r),/data-action="review-decision"/);
  assert.equal(ctx.reviewPermissionItems(r).length,0);
  const view=ctx.needView({kind:'review',id:r.id,review:r},ctx);
  assert.equal(view.items.length,0);
 }
 const r={...record,available_scopes:[{kind:'once'},{kind:'future'},{kind:'exact',expiry:'forever'},{kind:'exact',expiry:'7d'}]};
 const choices=ctx.reviewPermissionItems(r);
 assert.deepEqual(Array.from(choices,item=>item.label),['Expected once','Expected for 7 days']);
});

test('confirmed review retains its original evidence when the queue clears',async()=>{
 const original=structuredClone(record);
 const ctx=reviewController({attentionItems:()=>[{kind:'review',id:original.id,review:original}],fetchTelemetry:async()=>{
  original.revision=3;original.assessment.risk='low';original.context.resources=['new target'];
 }});
 await ctx.window.reviewAct(record.id,record.revision,'acknowledge');
 assert.deepEqual({...ctx.reviewResult.receipt},receipt);
 assert.equal(ctx.reviewResult.review.revision,2);assert.equal(ctx.reviewResult.review.assessment.risk,'critical');
 assert.equal(ctx.reviewResult.review.context.resources[0],'<credentials>');
 const html=ctx.reviewResultHTML(ctx.reviewResult,true);
 assert.match(html,/Review recorded/);assert.match(html,/Evidence before this decision/);assert.match(html,/revision 2/);
 assert.match(html,/&lt;credentials&gt;/);assert.match(html,/203\.0\.113\.5:443/);
 assert.doesNotMatch(html,/data-action="review-decision"/);
});

test('unmatched or unreadable receipts never confirm a review or replay the write',async()=>{
 for(const value of [null,{...receipt,id:'other'},{...receipt,revision:3},{...receipt,action:'expect'},{...receipt,at:'invalid'},{...receipt,scope_ids:['']},new Error('unreadable')]) {
  let writes=0;const messages=[];
  const ctx=reviewController({showToast:msg=>messages.push(msg),apiFetch:async()=>{
   writes++;return{ok:true,status:200,json:async()=>{if(value instanceof Error)throw value;return value}};
  }});
  await ctx.window.reviewAct(record.id,record.revision,'acknowledge');
  assert.equal(writes,1);assert.equal(ctx.reviewResult,null);assert.match(messages.join(' '),/not confirmed/i);
  assert.equal(ctx.reviewDrafts.has(record.id),true);
 }
});

test('late review receipts cannot cross an authentication boundary',async()=>{
 for(const change of [ctx=>{ctx.handoffGeneration++},ctx=>{ctx.sessionEnded=true}]) {
  let respond;let refreshed=0;
  const ctx=reviewController({apiFetch:()=>new Promise(resolve=>{respond=resolve}),fetchTelemetry:async()=>{refreshed++}});
  const pending=ctx.window.reviewAct(record.id,2,'acknowledge');change(ctx);
  respond({ok:true,status:200,json:async()=>receipt});await pending;
  assert.equal(ctx.reviewResult,null);assert.equal(refreshed,0);
 }
});

test('an older response cannot replace the result of the latest decision',async()=>{
 const replies=[];
 const ctx=reviewController({apiFetch:()=>new Promise(resolve=>replies.push(resolve))});
 const older=ctx.window.reviewAct(record.id,2,'acknowledge');
 const newer=ctx.window.reviewAct('second',4,'close_reported');
 replies[1]({ok:true,status:200,json:async()=>({...receipt,id:'second',revision:4,action:'close_reported'})});await newer;
 replies[0]({ok:true,status:200,json:async()=>receipt});await older;
 assert.equal(ctx.reviewResult.receipt.id,'second');assert.equal(ctx.reviewResult.receipt.action,'close_reported');
});

test('receipt labels preserve closure uncertainty and actual permission scope IDs',()=>{
 const ctx={};vm.createContext(ctx);vm.runInContext(lib,ctx);
 const closure=ctx.reviewResultHTML({receipt:{...receipt,action:'close_reported'},review:record},true);
 assert.match(closure,/Closure reported/);assert.match(closure,/not been verified/);
 const scoped=ctx.reviewResultHTML({receipt:{...receipt,action:'expect',scope_ids:['scope-one']},review:record},true);
 assert.match(scoped,/Scoped permission recorded/);assert.match(scoped,/scope-one/);assert.match(scoped,/firewall and payload checks/i);
 assert.match(scoped,/data-action="open-review-result-permissions"/);
 assert.doesNotMatch(ctx.reviewResultHTML({receipt:{...receipt,action:'expect',scope_ids:['scope-one']},review:record}),/data-action="open-review-result-permissions"/);
 const once=ctx.reviewResultHTML({receipt:{...receipt,action:'expect'},review:record},true);
 assert.match(once,/Expected once/);assert.match(once,/No future permission/);
 assert.doesNotMatch(once+closure,/data-action="open-review-result-permissions"/);
 assert.doesNotMatch(scoped,/data-action="review-decision"/);
});

test('a credential change during permission confirmation prevents the write',async()=>{
 let writes=0;const ctx=reviewController({apiFetch:async()=>{writes++}});
 ctx.window.saConfirm=async()=>{ctx.handoffGeneration++;return true};
 await ctx.window.reviewAct(record.id,2,'expect',{kind:'exact',expiry:'24h'});
 assert.equal(writes,0);assert.equal(ctx.reviewResult,null);
});

test('dismissing the result clears feedback without issuing another decision',async()=>{
 let writes=0;const ctx=reviewController({apiFetch:async()=>{writes++;return{ok:true,json:async()=>receipt}}});
 await ctx.window.reviewAct(record.id,2,'acknowledge');
 ctx.window.dismissReviewResult();
 assert.equal(ctx.reviewResult,null);assert.equal(writes,1);
});

test('evidence navigation returns to its original receipt and cannot cross authentication',()=>{
 const first={receipt,review:record};
 const ctx=reviewController({reviewResult:first});
 const h=loadDrawer({deps:{collaborators:{auth:{ended:()=>ctx.sessionEnded,generation:()=>ctx.handoffGeneration}}}});
 ctx.detailDrawer=h.api;
 ctx.window.openReviewResult();
 const back=h.api.back();
 assert.equal(back.label,'Review result');
 ctx.reviewResult={receipt:{...receipt,id:'new-review',revision:4},review:{...record,context:{resources:['new target']}}};
 back.reopen();
 assert.match(h.dom.body.innerHTML,/&lt;credentials&gt;/);assert.match(h.dom.body.innerHTML,/revision 2/);
 assert.doesNotMatch(h.dom.body.innerHTML,/new target|revision 4/);
 ctx.handoffGeneration++;
 back.reopen();
 assert.equal(h.calls.closedDocks,2);
});

function home(records, flags = []) {
 const nodes=new Map(['flags-list','badge-flags-count'].map(id=>[id,{children:[],querySelectorAll:()=>[],textContent:''}]));
 const sa={t:{status:{},flags,flagsView:flags,patterns:[],routine:[],incidents:[],reviews:{reviews:records}},
  seenAgents:new Set(),seenRules:new Set(),syncSelect:()=>{},globalSearchTerm:()=>'',isFlagsFiltered:()=>false,
  sessionScopeOn:()=>false,paintSessionChip:()=>{},expanded:new Set(),historySelected:new Set(),reviewDrafts:new Map()};
 const ctx={window:{SA:sa},document:{getElementById:id=>nodes.get(id)}};
 vm.createContext(ctx);vm.runInContext(lib,ctx);vm.runInContext(findings,ctx);
 let rows=[];ctx.patchLog=(_node,items)=>{rows=items;return items};
 return {ctx,sa,rows:()=>rows};
}

test('Home review row keeps revision-bound actions and its evidence detail',()=>{
 const {ctx,sa}=home([record]);
 const view=ctx.needView({kind:'review',id:record.id,review:record,group:{agent:'codex'}},ctx.homeContext(sa));
 const html=ctx.needRowHTML(view,true,Date.now());
 assert.match(html,/data-action="review-decision" data-id="context" data-revision="2" data-decision="acknowledge"/);
 assert.match(html,/data-action="select-attention" data-need-kind="review" data-need-id="context"/);assert.match(html,/Model-visible read/);
 const start=app.indexOf('  function selectAttention('),end=app.indexOf('  function attentionSignature',start);
 let inspector; Object.assign(ctx,{attentionItems:()=>[{kind:'review',id:record.id,review:record,group:{agent:'codex'}}],
  drawerBody:{querySelectorAll:()=>[]},attentionGeneration:0,attentionSignature:()=> 'fixture',detailDrawer:{setMode(){},setCopyVisible(){},open:options=>{inspector=options}},renderAttention:()=>{}});
 vm.runInContext(app.slice(start,end),ctx);ctx.selectAttention('review:context');
 assert.match(inspector.body,/View supporting evidence/);assert.match(inspector.body,/Model-visible read/);
 assert.match(inspector.foot,/data-revision="2"/);assert.equal(inspector.attentionOrigin.key,'review:context');
 assert.equal((html.match(/>Mark reviewed</g)||[]).length,1);
});

test('history represents a durable review once and preserves risk and revision on selection',()=>{
 const {ctx,sa,rows}=home([record],[{id:'source',review_id:record.id,agent:'codex',rule:record.context.rule,severity:3}]);
 ctx.renderFlags();
 assert.equal(rows().length,1);assert.equal(rows()[0].kind,'review');
 assert.equal(rows()[0].risk.critical,true);assert.deepEqual({...rows()[0].review},{id:'context',revision:2});
 assert.equal(ctx.selectableHistoryRows().get('review:context'),rows()[0]);
 const detail=rows()[0].body();assert.match(detail,/reviewed revision 1/i);assert.match(detail,/data-revision="2"/);
});

test('expired review evidence preserves history but disables bulk decisions',()=>{
 const {ctx,sa,rows}=home([{...record,evidence_available:false,evidence_flag_available:false}]);
 ctx.renderFlags();
 assert.equal(rows()[0].reviewed,false);assert.equal(rows()[0].risk.critical,true);
 assert.equal(ctx.selectableHistoryRows().size,0);
 assert.match(ctx.logRowHTML(rows()[0],false,Date.now()),/class="log-check"[^>]* disabled/);
 assert.match(rows()[0].body(),/Source evidence has expired/);
});

test('bulk review uses the selected evidence revision and retains a stale choice without retrying',async()=>{
 const start=app.indexOf('  window.historyBulkReview = async function('),end=app.indexOf('  // pid → agent',start);
 assert.ok(start>=0&&end>start);
 const calls=[],drafts=new Map(),selected=new Set(['review:context']);let refreshed=0;
 const ctx={window:{SA:{historyRows:new Map([['review:context',{review:{id:'context',revision:1},flagIds:[]}]])},saConfirm:async()=>true},
  historySelected:selected,reviewDrafts:drafts,telemetryData:{},reviewedAfterOptimistic:()=>({}),syncHistoryChecks:()=>{},markDirty:()=>{},
  showToast:()=>{},fetchTelemetry:async()=>{refreshed++},
  apiFetch:async(url,opts)=>{calls.push([url,JSON.parse(opts.body)]);return{ok:false,status:409,text:async()=> 'stale'}}};
 vm.createContext(ctx);vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/staged-write.js',import.meta.url),'utf8'),ctx);
 ctx.stagedWrite=ctx.createStagedWrite({telemetry:()=>ctx.telemetryData,render:()=>{},beginAttentionWrite:()=>null,request:ctx.apiFetch});
 vm.runInContext(app.slice(start,end),ctx);await ctx.window.historyBulkReview();
 assert.deepEqual(calls,[['/reviews/decision',{id:'context',revision:1,action:'acknowledge'}]]);
 assert.equal(refreshed,1);assert.equal(drafts.get('context').conflict,true);assert.equal(selected.size,1);
});
