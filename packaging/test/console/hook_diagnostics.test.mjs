import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const ctx={Date,window:{SA:{}}};vm.createContext(ctx);
for(const file of ['lib.js','session-workbench.js']) vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/'+file,import.meta.url),'utf8'),ctx);
const scope={session:'session-1',harness:'codex',event:'PreToolUse',event_scope:'exact',handler:'handler-1',config:'revision-1',script:'/private/guard.py',after:'2026-10-15T09:59:00Z',problem:'Repeated execution errors',explanation:'Three errors observed.',guidance:'Restore the handler dependency.'};
const page=()=>({session_id:scope.session,filter:{harness:scope.harness,event:scope.event,event_scope:'exact',handler_id:scope.handler,config_id:scope.config,script:scope.script},since:'2026-10-15T09:30:00Z',until:'2026-10-15T10:00:00Z',truncated:false,rows:[{id:'run-1',ts:'2026-10-15T09:59:00Z',status:'error',duration_ms:0,evidence:{handler_id:scope.handler,config_id:scope.config,duration_known:true,chars_known:false,reason_code:'timeout'}}]});
const host=()=>({report:{type:'hook_forwarder',version:2,harness:'hermes',forwarder_id:'host-1',sequence:2,ts:'2026-10-15T10:00:00Z',state:'error',pending:3,delivery_failures:4,dropped:1,health:{source_state:'connected',delivery_error:'recorder-failed',report_error:false}},received_at:'2026-10-15T10:00:01Z',freshness:'recent',assessment:{state:'needs-action',title:'Hook delivery needs attention',issues:[{stage:'delivery',code:'recorder-failed',next_action:'Restore recorder storage.'}],evidence_gap:true,limits:['Host observations only.']}});
const status=row=>({hook_ingestion:{available:true,since:'2026-10-15T09:30:00Z',rejected:0,harnesses:[],forwarders:[row],forwarders_truncated:true}});

test('diagnostic summaries use scoped normalized fields across all supported runtimes',()=>{
  assert.equal(typeof ctx.hookDiagnosticSummary,'function');
  for(const harness of ['claude','codex','openclaw','hermes','opencode']) {
    const p=page();p.filter.harness=harness;p.rows[0].output='PRIVATE_OUTPUT';p.command='PRIVATE_COMMAND';
    const text=ctx.hookDiagnosticSummary('evidence',{...scope,harness},p);
    for(const value of [harness,'session-1','handler-1','revision-1','run-1','timeout','0ms','Returned characters: unknown','protection coverage','Equal timestamps']) assert.ok(text.includes(value),value);
    for(const value of ['/private/guard.py','PRIVATE_OUTPUT','PRIVATE_COMMAND']) assert.ok(!text.includes(value));
    assert.equal(ctx.hookDiagnosticSummary('evidence',{...scope,session:'foreign'},p),null);
  }
});

test('repair summaries preserve original guidance and newer configuration boundaries',()=>{
  const p=page();p.filter.verify_after=scope.after;
  p.verification={state:'configuration-changed',title:'Configuration changed',detail:'A newer revision completed.',config_id:'revision-2',observed_at:'2026-10-15T09:59:01Z',run_ids:['new-run'],truncated:false,limits:['This does not establish lasting repair.']};
  const text=ctx.hookDiagnosticSummary('repair',scope,p);
  for(const value of ['Original failure','Repeated execution errors','Restore the handler dependency.','revision-1','revision-2','configuration-changed','new-run','lasting repair','Original-configuration']) assert.ok(text.includes(value),value);
  assert.equal(ctx.hookDiagnosticSummary('repair',scope,{...p,verification:{...p.verification,state:'repaired'}}),null);
});

test('delivery summaries keep fresh errors, stale state, cumulative counts and gaps distinct',()=>{
  const row=host(), text=ctx.hookDiagnosticSummary('delivery',{id:'host-1'},status(row));
  for(const value of ['host-1','Session: not supplied','Restore recorder storage.','4','cumulative','1','dropped','Other forwarding instances may be omitted','Host observations only.']) assert.ok(text.includes(value),value);
  const stale={...row,freshness:'stale',assessment:{...row.assessment,state:'unknown',issues:[]}};
  assert.ok(ctx.hookDiagnosticSummary('delivery',{id:'host-1'},status(stale)).includes('current state unknown'));
  assert.equal(ctx.hookDiagnosticSummary('delivery',{id:'different'},status(row)),null);
  assert.equal(ctx.hookDiagnosticSummary('delivery',{id:'host-1'},{hook_ingestion:{...status(row).hook_ingestion,available:false}}),null);
});

test('summary previews escape markup and identify bounded or empty samples',()=>{
  const p=page();p.truncated=true;p.rows=Array.from({length:21},(_,i)=>({...p.rows[0],id:'run-'+i}));
  const text=ctx.hookDiagnosticSummary('evidence',scope,p);
  assert.ok(text.includes('20 of 21'));
  assert.ok(text.includes('latest 100'));
  assert.ok(!text.includes('Run: run-20\n'));
  assert.ok(ctx.hookDiagnosticSummary('evidence',scope,{...page(),rows:[]}).includes('No matching retained completions'));
  const html=ctx.hookDiagnosticPreviewHTML('</textarea><img src=x>');
  assert.ok(!html.includes('<img'));
  assert.ok(html.includes('&lt;/textarea&gt;'));
  assert.match(html,/readonly/);
});
