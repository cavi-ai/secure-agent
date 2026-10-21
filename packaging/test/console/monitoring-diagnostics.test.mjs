import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const displayed = '2026-10-20T20:15:00Z';
function setup(respond) {
  const requests = [], state = { generation: 1, ended: false, seq: 0, refreshed: 0 };
  const drawer = { seq: () => state.seq, setMode() {}, open(options) { state.seq++; state.view = options; } };
  const status = { bus_drops: 22, bus_drop_at: displayed, bus_dropping: true,
    es_service: { bytes_lost: 30937721, lost_at: displayed, losing: true, state: 'running', lag_seconds: 12 }, storage_health: { failures: 0 } };
  const doctor = { generated_at: displayed, loss_review:{pending:true}, checks: [{id:'bus', title:'Event bus', state:'fail', detail:'Queue full', fix:'Review ingestion'}] };
  const ctx = vm.createContext({ Date, window: {} });
  for (const file of ['lib.js', 'monitoring-diagnostics.js']) vm.runInContext(readFileSync(new URL(file, web), 'utf8'), ctx);
  const api = ctx.createMonitoringDiagnostics({
    request: async (url, options) => {
      requests.push([url, options]);
      if (respond) return respond(url, options, {status, doctor});
      if (options?.method === 'POST') doctor.loss_review = {pending:false,seen_at:displayed};
      return { ok:true, json:async () => url === '/doctor' ? doctor : url === '/status' ? status : {seen_at:displayed} };
    }, drawer, generation: () => state.generation, ended: () => state.ended,
    refresh: async () => { state.refreshed++; },
  });
  return { api, state, requests, status, doctor };
}

test('review confirmation remains separate from active delivery pressure and newer losses', async () => {
  const {api,state,status,doctor} = setup();
  await api.open();
  await api.acknowledge();
  assert.equal(status.bus_dropping,true);
  assert.equal(status.es_service.losing,true);
  assert.match(state.view.body,/Reviewed through/);
  assert.match(state.view.body,/Queue full/);
  assert.doesNotMatch(state.view.foot,/monitoring-loss-seen/);
  await api.open();
  assert.doesNotMatch(state.view.foot,/monitoring-loss-seen/);
  doctor.loss_review.pending = true;
  await api.open();
  assert.match(state.view.foot,/monitoring-loss-seen/);
});

test('diagnostics shows retained loss, last loss time, delivery lag, and real checks', async () => {
  const { api, state } = setup();
  await api.open();
  assert.match(state.view.body, /22/);
  assert.match(state.view.body, /30\.9 MB/);
  assert.match(state.view.body, /Last loss/);
  assert.match(state.view.body, /12 s/);
  assert.match(state.view.body, /Queue full/);
  assert.match(state.view.foot, /data-action="monitoring-loss-seen"/);
});

test('historical losses can be reviewed after current delivery has recovered', async () => {
  const {api,state,status} = setup();
  status.bus_dropping = false; status.es_service.losing = false;
  await api.open();
  assert.match(state.view.foot,/monitoring-loss-seen/);
  await api.acknowledge();
  assert.match(state.view.body,/Reviewed through/);
  assert.doesNotMatch(state.view.foot,/monitoring-loss-seen/);
});

test('acknowledgement sends displayed cutoff and retains history after refreshing', async () => {
  const { api, state, requests, status } = setup();
  await api.open();
  await api.acknowledge();
  const post = requests.find(([,options]) => options?.method === 'POST');
  assert.equal(post[0], '/doctor/seen');
  assert.equal(JSON.parse(post[1].body).seen_at, displayed);
  assert.equal(state.refreshed, 1);
  status.bus_dropping = false; status.es_service.losing = false;
  await api.open();
  assert.match(state.view.body, /30\.9 MB/);
  assert.match(state.view.body, /history remains incomplete/i);
  assert.doesNotMatch(state.view.foot, /monitoring-loss-seen/);
});

test('failed or malformed acknowledgement remains visible and can be retried', async () => {
  let posts = 0;
  const {api,state} = setup((url, options, {status,doctor}) => {
    if (options?.method === 'POST') { posts++; return {ok:true,json:async()=>({})}; }
    return {ok:true,json:async()=>url === '/doctor' ? doctor : status};
  });
  await api.open();
  await api.acknowledge();
  assert.match(state.view.body, /could not be confirmed/i);
  assert.match(state.view.foot, /monitoring-loss-seen/);
  await api.acknowledge();
  assert.equal(posts, 2);
});

test('a closed or superseded inspector cannot acknowledge an old report', async () => {
  const {api,state,requests} = setup();
  await api.open();
  state.seq++;
  await api.acknowledge();
  assert.equal(requests.filter(([,options])=>options?.method === 'POST').length,0);
  await api.open(); state.generation++;
  await api.acknowledge();
  assert.equal(requests.filter(([,options])=>options?.method === 'POST').length,0);
});
