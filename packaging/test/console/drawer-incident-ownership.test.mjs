import test from 'node:test';
import assert from 'node:assert/strict';
import { loadDrawer } from './drawer-harness.mjs';

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}
const report = id => ({ok:true,status:200,text:async()=>`# Report ${id}`,
  json:async()=>({incident:{id},workflow:{status:'open'}})});

test('incident copy belongs only to the successfully loaded current report', async () => {
  const pending = deferred();
  const h = loadDrawer({deps:{respond:async url => url.includes('id=B') ? pending.promise : report('A')}});
  const copied = [];
  h.ctx.navigator.clipboard = {writeText:async text => copied.push(text)};
  await h.api.openIncidentReport('A');
  assert.equal(h.dom.copyButton.hidden, false);
  const next = h.api.openIncidentReport('B');
  assert.equal(h.dom.copyButton.hidden, true);
  await h.dom.copyButton.fire('click');
  assert.deepEqual(copied, []);
  pending.resolve(report('B'));
  await next;
  assert.equal(h.dom.copyButton.hidden, false);
  await h.dom.copyButton.fire('click');
  assert.deepEqual(copied, ['# Report B']);
});

test('failed incident loads cannot copy the previous report', async () => {
  for (const failure of [404, 503, 'offline']) {
    const h = loadDrawer({deps:{respond:async url => {
      if (!url.includes('id=B')) return report('A');
      if (failure === 'offline') throw new Error('offline');
      return {ok:false,status:failure};
    }}});
    const copied = [];
    h.ctx.navigator.clipboard = {writeText:async text => copied.push(text)};
    await h.api.openIncidentReport('A');
    await h.api.openIncidentReport('B');
    assert.equal(h.dom.copyButton.hidden, true, String(failure));
    await h.dom.copyButton.fire('click');
    assert.deepEqual(copied, [], String(failure));
  }
});

test('closing or replacing an incident clears its copy action', async () => {
  const h = loadDrawer({deps:{respond:async()=>report('A')}});
  const copied = [];
  h.ctx.navigator.clipboard = {writeText:async text => copied.push(text)};
  await h.api.openIncidentReport('A');
  h.api.close();
  assert.equal(h.dom.copyButton.hidden, true);
  await h.dom.copyButton.fire('click');
  await h.api.openIncidentReport('A');
  h.api.open({title:'Different evidence',body:'Current evidence'});
  assert.equal(h.dom.copyButton.hidden, true);
  await h.dom.copyButton.fire('click');
  assert.deepEqual(copied, []);
});

test('a copy finishing after another drawer opens does not announce success there', async () => {
  const pending = deferred();
  const h = loadDrawer({deps:{respond:async()=>report('A')}});
  h.ctx.navigator.clipboard = {writeText:()=>pending.promise};
  await h.api.openIncidentReport('A');
  const copy = h.dom.copyButton.fire('click');
  h.api.open({title:'Different evidence',body:'Current evidence'});
  pending.resolve();
  await copy;
  assert.deepEqual(h.toasts, []);
});
