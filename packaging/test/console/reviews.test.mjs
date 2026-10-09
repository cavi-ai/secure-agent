import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const lib=readFileSync(new URL('../../../daemon/internal/api/web_dist/lib.js',import.meta.url),'utf8');
const app=readFileSync(new URL('../../../daemon/internal/api/web_dist/app.js',import.meta.url),'utf8');
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
 const expired=vm.runInContext('reviewHTML({...record,evidence_available:false})',ctx);
 assert.match(expired,/Source evidence has expired/);assert.doesNotMatch(expired,/data-action="review-decision"/);
});

test('stale review decision retains choice, refreshes facts and never retries',async()=>{
 const start=app.indexOf('  window.reviewAct = async function(');
 const end=app.indexOf('  // Review pagination',start);
 assert.ok(start>=0&&end>start,'review handler exists');
 const calls=[],drafts=new Map();let refreshed=0;
 const ctx={window:{},reviewDrafts:drafts,apiFetch:async(url,opts)=>{calls.push([url,JSON.parse(opts.body)]);return{ok:false,status:409}},showToast:()=>{},fetchTelemetry:async()=>{refreshed++},markDirty:()=>{}};
 vm.runInNewContext(app.slice(start,end),ctx);
 await ctx.window.reviewAct('context',1,'acknowledge');
 assert.equal(calls.length,1);assert.deepEqual(calls[0],['/reviews/decision',{id:'context',revision:1,action:'acknowledge'}]);
 assert.equal(refreshed,1);assert.equal(drafts.get('context').action,'acknowledge');assert.equal(drafts.get('context').conflict,true);
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
 assert.match(html,/View supporting evidence/);assert.match(html,/Model-visible read/);
 assert.equal((html.match(/>Mark reviewed</g)||[]).length,1);
});

test('history represents a durable review once and preserves risk and revision on selection',()=>{
 const {ctx,sa,rows}=home([record],[{id:'source',review_id:record.id,agent:'codex',rule:record.context.rule,severity:3}]);
 ctx.renderFlags();
 assert.equal(rows().length,1);assert.equal(rows()[0].kind,'review');
 assert.equal(rows()[0].risk.critical,true);assert.deepEqual({...rows()[0].review},{id:'context',revision:2});
 assert.equal(sa.historyRows.get('review:context'),rows()[0]);
 const detail=rows()[0].body();assert.match(detail,/reviewed revision 1/i);assert.match(detail,/data-revision="2"/);
});

test('expired review evidence preserves history but disables bulk decisions',()=>{
 const {ctx,sa,rows}=home([{...record,evidence_available:false,evidence_flag_available:false}]);
 ctx.renderFlags();
 assert.equal(rows()[0].reviewed,false);assert.equal(rows()[0].risk.critical,true);
 assert.equal(sa.historyRows.size,0);
 assert.match(ctx.logRowHTML(rows()[0],false,Date.now()),/class="log-check"[^>]* disabled/);
 assert.match(rows()[0].body(),/Source evidence has expired/);
});

test('bulk review uses the selected evidence revision and retains a stale choice without retrying',async()=>{
 const start=app.indexOf('  window.historyBulkReview = async function('),end=app.indexOf('  // pid → agent',start);
 assert.ok(start>=0&&end>start);
 const calls=[],drafts=new Map(),selected=new Set(['review:context']);let refreshed=0;
 const ctx={window:{SA:{historyRows:new Map([['review:context',{review:{id:'context',revision:1},flagIds:[]}]])},saConfirm:async()=>true},
  historySelected:selected,reviewDrafts:drafts,telemetryData:{},stage:()=>()=>{},syncHistoryChecks:()=>{},markDirty:()=>{},
  showToast:()=>{},fetchTelemetry:async()=>{refreshed++},
  apiFetch:async(url,opts)=>{calls.push([url,JSON.parse(opts.body)]);return{ok:false,status:409,text:async()=> 'stale'}}};
 vm.runInNewContext(app.slice(start,end),ctx);await ctx.window.historyBulkReview();
 assert.deepEqual(calls,[['/reviews/decision',{id:'context',revision:1,action:'acknowledge'}]]);
 assert.equal(refreshed,1);assert.equal(drafts.get('context').conflict,true);assert.equal(selected.size,1);
});
