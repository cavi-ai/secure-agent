import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const ctx = { Date, window: { SA: {} } };
vm.createContext(ctx);
for (const file of ['lib.js', 'tab-findings.js', 'session-layout.js', 'session-workbench.js']) vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/' + file, import.meta.url), 'utf8'), ctx);
const row = () => ({ report: { type:'hook_forwarder',version:2,harness:'hermes',forwarder_id:'host-1',sequence:1,ts:'2026-10-14T10:00:00Z',state:'error',pending:3,delivery_failures:2,dropped:1,
  health:{source_state:'connected',delivery_error:'recorder-failed',report_error:false} }, received_at:'2026-10-14T10:00:01Z',freshness:'recent',
  assessment:{state:'needs-action',title:'Hook delivery needs attention',issues:[{stage:'delivery',code:'recorder-failed',next_action:'Restore recorder output storage.'}],evidence_gap:true,limits:['Host observations only']} });

test('delivery Attention opens host diagnostics without borrowing a session', () => {
  const r=row();
  const v=ctx.needView({kind:'hook_delivery',id:'hook-delivery:host-1',title:'Hermes hook delivery needs attention',hook_delivery:r},{});
  assert.equal(v.word,'hook delivery');
  assert.equal(v.items.length,1);
  assert.match(v.items[0].attrs,/data-action="hook-delivery-inspect"/);
  assert.ok(!v.items[0].attrs.includes('data-session'));
  assert.match(v.body(),/Restore recorder output storage/);
});

test('canonical delivery diagnoses are validated and rendered consistently', () => {
  const r=row();
  assert.equal(ctx.validHookForwarder(r),true);
  assert.equal(ctx.validHookForwarder({...r, report:undefined}),false);
  assert.equal(ctx.validHookForwarder({...r, report:null}),false);
  assert.equal(ctx.validHookForwarder({...r, report:undefined, freshness:'stale', assessment:{...r.assessment,state:'unknown'}}),false);
  assert.match(ctx.hookForwardersHTML([r],false),/Restore recorder output storage/);
  assert.equal(ctx.validHookForwarder({...r,assessment:{...r.assessment,state:'no-active-error'}}),false);
  assert.equal(ctx.validHookForwarder({...r,assessment:{...r.assessment,evidence_gap:false}}),false);
});

test('hook groups and repair findings link to their exact evidence scope', () => {
  const group={harness:'hermes',event:'pre_tool_call',script:'guard.py',handler_id:'h',config_id:'c',runs:3,errors:3,blocks:0,chars:0,total_ms:0,last_at:'2026-10-14T10:00:00Z'};
  const html=ctx.sessionHooksHTML([group],{},null,{},null,'s');
  for (const text of ['data-action="hook-evidence"','data-session="s"','data-handler="h"','data-config="c"','data-script="guard.py"']) assert.ok(html.includes(text),text);
});

test('setup guidance covers only supported sources without inventing installation', () => {
  assert.equal(typeof ctx.hookSetupHTML,'function');
  for (const harness of ['claude','codex','openclaw','hermes','opencode']) {
    const html=ctx.hookSetupHTML(harness,null);
    assert.match(html,/real completion/i);
    assert.match(html,/protection coverage/i);
    assert.ok(!html.includes('data-action="install'));
  }
  assert.ok(!ctx.hookSetupHTML('unknown',null).includes('NewCodex'));
});

test('recorded evidence preserves unknown measurements and rejects foreign scope', () => {
  assert.equal(typeof ctx.validHookEvidence,'function');
  const scope={session:'s',harness:'hermes',event:'pre_tool_call',handler:'h',config:'c',script:'guard.py'};
  const page={session_id:'s',filter:{harness:'hermes',event:'pre_tool_call',handler_id:'h',config_id:'c',script:'guard.py'},since:'2026-10-14T09:30:00Z',until:'2026-10-14T10:00:00Z',truncated:true,
    rows:[{id:'one',ts:'2026-10-14T09:59:00Z',status:'error',duration_ms:0,evidence:{handler_id:'h',config_id:'c',reason_code:'timeout',duration_known:true,chars_known:false}}]};
  assert.equal(ctx.validHookEvidence(page,scope),true);
  const html=ctx.hookEvidenceHTML(page);
  for (const text of ['timeout','0ms','unknown','limited','one']) assert.ok(html.includes(text),text);
  assert.equal(ctx.validHookEvidence({...page,session_id:'other'},scope),false);
  assert.equal(ctx.validHookEvidence({...page,filter:{...page.filter,config_id:'other'}},scope),false);
  assert.equal(ctx.validHookEvidence({...page,rows:[{...page.rows[0],status:'protected'}]},scope),false);
  assert.equal(ctx.validHookEvidence({...page,rows:[{...page.rows[0],duration_ms:undefined}]},scope),false);
});


test('repair checks retain the original failure and exact identity', () => {
  assert.equal(typeof ctx.hookRepairScope,'function');
  const f={kind:'execution-errors',harness:'codex',event:'PreToolUse',handler_id:'h',config_id:'c',script:'guard.py',last_at:'2026-10-14T09:59:00Z',title:'Hook repeatedly failed',detail:'Three execution errors.',next_action:'Restore dependency.'};
  const scope=ctx.hookRepairScope(f,'s');
  assert.equal(scope.after,f.last_at);
  assert.equal(scope.handler,'h');
  assert.equal(scope.config,'c');
  assert.equal(scope.event_scope,'exact');
  assert.equal(ctx.hookRepairScope({...f,handler_id:''},'s'),null);
  const html=ctx.hookFindingBodyHTML(f,'s');
  assert.match(html,/Check repair/);
  assert.match(html,/data-action="hook-repair-check"/);
  const pending=ctx.hookRepairHTML(scope,null,'Verification unavailable. Check again.');
  for(const text of [f.title,f.detail,f.next_action,'Original failure','Verification unavailable']) assert.ok(pending.includes(text),text);
});

test('repair responses must match the original failure and keep their limits visible', () => {
  assert.equal(typeof ctx.validHookRepair,'function');
  const scope={session:'s',harness:'codex',event:'PreToolUse',event_scope:'exact',handler:'h',config:'c',script:'guard.py',after:'2026-10-14T09:59:00Z',problem:'Original problem'};
  const page={session_id:'s',filter:{harness:'codex',event:'PreToolUse',event_scope:'exact',handler_id:'h',config_id:'c',script:'guard.py',verify_after:scope.after},since:'2026-10-14T09:30:00Z',until:'2026-10-14T10:00:00Z',truncated:false,rows:[],
    verification:{state:'successful-completion',title:'Successful completion observed',detail:'A newer completion succeeded.',observed_at:'2026-10-14T09:59:01Z',run_ids:['new-run'],config_id:'c',truncated:false,limits:['This does not establish protection coverage.']}};
  assert.equal(ctx.validHookRepair(page,scope),true);
  assert.equal(ctx.validHookRepair({...page,filter:{...page.filter,verify_after:'2026-10-14T09:58:00Z'}},scope),false);
  assert.equal(ctx.validHookRepair({...page,verification:{...page.verification,state:'repaired'}},scope),false);
  assert.equal(ctx.validHookRepair({...page,verification:{...page.verification,observed_at:scope.after}},scope),false);
  const nanoScope={...scope,after:'2026-10-14T09:59:00.000000001Z'};
  assert.equal(ctx.validHookRepair({...page,filter:{...page.filter,verify_after:nanoScope.after},verification:{...page.verification,observed_at:'2026-10-14T09:59:00.000000002Z'}},nanoScope),true);
  assert.equal(ctx.validHookRepair({...page,verification:{...page.verification,observed_at:'2026-10-14T05:59:01-04:00'}},scope),true);
  const html=ctx.hookRepairHTML(scope,page);
  for(const text of ['Original problem','Successful completion observed','new-run','protection coverage']) assert.ok(html.includes(text),text);
});
