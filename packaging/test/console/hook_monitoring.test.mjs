import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const ctx={window:{SA:{}}};
vm.createContext(ctx);
for(const file of ['lib.js','session-layout.js', 'session-workbench.js']) vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/'+file,import.meta.url),'utf8'),ctx);
const now=Date.parse('2026-10-15T14:00:00Z');
const health={lastSnapshotAt:now,error:''};
const ingestion=()=>({available:true,since:'2026-10-15T13:00:00Z',rejected:0,harnesses:[{harness:'codex',accepted:3,last_received_at:'2026-10-15T13:59:00Z'}],forwarders:[]});
const host=(id,state='connected',freshness='recent',dropped=0)=>({report:{type:'hook_forwarder',version:1,harness:'codex',forwarder_id:id,sequence:1,ts:'2026-10-15T13:59:59Z',state,pending:0,delivery_failures:2,dropped},received_at:'2026-10-15T14:00:00Z',freshness});

test('overview includes only observed supported runtimes and preserves session identity',()=>{
  assert.equal(typeof ctx.hookMonitoringModel,'function');
  const m=ctx.hookMonitoringModel(ingestion(),[{id:'s',harness:'claude',status:'active'},{id:'s',harness:'claude',status:'active'},{id:'foreign',harness:'cursor'}],health,now);
  assert.deepEqual(Array.from(m.rows,r=>r.harness).sort(),['claude','codex']);
  const claude=m.rows.find(r=>r.harness==='claude');
  assert.equal(claude.sessions.length,1);
  assert.equal(claude.receipt,null);
  assert.equal(m.rows.find(r=>r.harness==='codex').receipt.accepted,3);
});

test('new connected hosts cannot hide another host error, stale report or dropped evidence',()=>{
  const h=ingestion();h.forwarders=[host('error','error'),host('old','error','stale',1),host('good')];
  const m=ctx.hookMonitoringModel(h,[],health,now);
  const row=m.rows[0];
  assert.equal(row.errors,1);assert.equal(row.unknown,1);assert.equal(row.gaps,1);assert.equal(row.reports.length,3);
  const html=ctx.hookMonitoringHTML(m);
  for(const text of ['1 host with active errors','1 host with unknown current state','Evidence gap','data-id="error"','data-id="old"','data-id="good"']) assert.ok(html.includes(text),text);
  assert.doesNotMatch(html,/protected|healthy/i);
});

test('failed or old snapshots keep receipts visibly last known and report states unknown',()=>{
  const h=ingestion();h.forwarders=[host('error','error')];
  for(const state of [{...health,error:'offline'},{lastSnapshotAt:now-120001},{lastSnapshotAt:0}]) {
    const m=ctx.hookMonitoringModel(h,[],state,now);
    assert.equal(m.stale,true);
    assert.equal(m.rows[0].errors,0);assert.equal(m.rows[0].unknown,1);
    assert.match(ctx.hookMonitoringHTML(m),/Last loaded|last known/i);
  }
});

test('daemon restart replaces counters and host instances without inventing disconnection',()=>{
  const before=ingestion();before.forwarders=[host('old')];
  const after={...ingestion(),since:'2026-10-15T13:59:59Z',harnesses:[],forwarders:[]};
  const sessions=[{id:'s',harness:'codex',repo:'work',status:'active'}];
  assert.equal(ctx.hookMonitoringModel(before,sessions,health,now).rows[0].receipt.accepted,3);
  const html=ctx.hookMonitoringHTML(ctx.hookMonitoringModel(after,sessions,health,now));
  assert.match(html,/No completion received in this daemon run/);
  assert.match(html,/Forwarding state unknown/);
  assert.doesNotMatch(html,/data-id="old"|3 accepted|disconnected/i);
  assert.match(html,/data-action="hook-session-open" data-session="s"/);
});

test('malformed or unavailable ingestion cannot become current runtime diagnostics',()=>{
  const sessions=[{id:'s',harness:'hermes',repo:'<unsafe>',status:'active'}];
  for(const h of [null,{...ingestion(),harnesses:[{harness:'codex',accepted:-1,last_received_at:'bad'}]}]) {
    const m=ctx.hookMonitoringModel(h,sessions,health,now);
    assert.equal(m.available,false);
    assert.deepEqual(Array.from(m.rows,r=>r.harness),['hermes']);
    const html=ctx.hookMonitoringHTML(m);
    assert.match(html,/Ingestion diagnostics unavailable/);
    assert.ok(!html.includes('<unsafe>'));
  }
});

test('rejections remain unattributed and omitted host reports remain visible',()=>{
  const h={...ingestion(),rejected:2,last_rejected_at:'2026-10-15T13:59:00Z',forwarders_truncated:true};
  const html=ctx.hookMonitoringHTML(ctx.hookMonitoringModel(h,[],health,now));
  assert.match(html,/2 rejected shared records/);assert.match(html,/cannot be attributed to a runtime/i);
  assert.match(html,/Other forwarding instances may be omitted/);
});
