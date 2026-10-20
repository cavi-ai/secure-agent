import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const ctx={Date,window:{SA:{}}};vm.createContext(ctx);
for(const file of ['lib.js','tab-findings.js']) vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/'+file,import.meta.url),'utf8'),ctx);
const posture=()=>({needs_you:2,coverage_count:2,items:[{kind:'guard_pending',id:'g'},{kind:'hook',id:'h'}],groups:[{items:[{kind:'guard',id:'g',title:'Access request',session_id:'s'},{kind:'hook',id:'h',title:'Hook error'}]}],attention_summary:{version:1,buckets:[{kind:'decisions',count:1,coverage_count:0,first:{kind:'guard',id:'g',title:'Access request',session_id:'s'}},{kind:'security',count:0,coverage_count:0},{kind:'monitoring',count:1,coverage_count:2,first:{kind:'hook',id:'h',title:'Hook error'}}]}});
test('daemon categories preserve queued counts and expose separate monitoring gaps',()=>{
  assert.equal(typeof ctx.attentionSummaryHTML,'function');
  const html=ctx.attentionSummaryHTML(posture(),false);
  for(const text of ['Waiting for your decision','Security review','Monitoring problems','1 queued','3 current problems','data-need-kind="guard"','data-need-id="g"']) assert.ok(html.includes(text),text);
  assert.ok(!ctx.attentionSummaryHTML(posture(),true).includes('data-action="select-attention"'));
  assert.match(ctx.attentionSummaryHTML(posture(),true),/Last known/);
});
test('malformed, unknown-version and optimistic summaries do not invent category counts',()=>{
  assert.equal(typeof ctx.validAttentionSummary,'function');
  assert.equal(ctx.validAttentionSummary(posture()),true);
  const p=posture();p.attention_summary.buckets[0].count=7;
  assert.equal(ctx.validAttentionSummary(p),false);
  assert.equal(ctx.validAttentionSummary({...posture(),attention_summary:{version:2,buckets:[]}}),false);
  const wrong=posture();wrong.attention_summary.buckets[0].first.id='foreign';
  assert.equal(ctx.validAttentionSummary(wrong),false);
  const optimistic=ctx.mapPostureAttention(posture(),it=>it.kind==='guard'?null:it);
  assert.equal(optimistic.needs_you,1);
  assert.equal(ctx.validAttentionSummary(optimistic),false);
  assert.match(ctx.attentionSummaryHTML(optimistic,false),/unavailable/);
});

test('a current quiet overview is hidden and active monitoring has a truthful total',()=>{
  const panel={hidden:false};
  const root={innerHTML:'',contains:()=>false,closest:()=>panel};
  ctx.document={getElementById:()=>root};
  const p={state:'all-clear',needs_you:0,coverage_count:0,items:[],groups:[],attention_summary:{version:1,buckets:
    ['decisions','security','monitoring'].map(kind=>({kind,count:0,coverage_count:0}))}};
  const data={t:{posture:p},postureHealth:{lastSnapshotAt:Date.now()}};
  ctx.renderAttentionSummary(data);
  assert.equal(panel.hidden,true);
  p.state='attention';p.coverage_count=1;p.attention_summary.buckets[2].coverage_count=1;
  ctx.renderAttentionSummary(data);
  assert.equal(panel.hidden,false);
  assert.match(root.innerHTML,/1 current problem/);
});
