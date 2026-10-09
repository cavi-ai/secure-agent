import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const lib=readFileSync(new URL('../../../daemon/internal/api/web_dist/lib.js',import.meta.url),'utf8');
const app=readFileSync(new URL('../../../daemon/internal/api/web_dist/app.js',import.meta.url),'utf8');
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
