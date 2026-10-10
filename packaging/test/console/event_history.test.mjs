import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const c = vm.createContext({});
vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/event-history.js', import.meta.url), 'utf8'), c);
vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/lib.js', import.meta.url), 'utf8'), c);
const page = (id, next = '') => ({ session_id: 'ended', rows: [{ id, event: { kind: 0, ts: '2026-10-10T00:00:00Z', session_id: 'ended' } }], has_earlier: !!next, next_cursor: next });

test('Earlier and Newer commit only successful navigation and retain a frozen time filter', () => {
  const state = c.createEventHistoryPage('fixed-since');
  c.acceptEventHistoryPage(state, page('9007199254740993', 'older-one'));
  assert.equal(c.requestEventHistoryPage(state, 'earlier'), true);
  assert.equal(c.requestEventHistoryPage(state, 'earlier'), false);
  assert.equal(state.cursor, '');
  c.failEventHistoryPage(state);
  assert.equal(state.cursor, ''); assert.equal(state.next, 'older-one');
  assert.match(state.error, /current page is retained/);
  assert.equal(c.requestEventHistoryPage(state, 'earlier'), true);
  c.acceptEventHistoryPage(state, page('9007199254740992', 'older-two'));
  assert.equal(state.cursor, 'older-one'); assert.equal(state.since, 'fixed-since');
  c.requestEventHistoryPage(state, 'earlier'); c.acceptEventHistoryPage(state, page('1'));
  assert.equal(c.requestEventHistoryPage(state, 'earlier'), false);
  c.requestEventHistoryPage(state, 'newer'); c.acceptEventHistoryPage(state, page('9007199254740992', 'older-two'));
  assert.equal(state.cursor, 'older-one');
  c.requestEventHistoryPage(state, 'latest'); c.acceptEventHistoryPage(state, page('9007199254740994', 'new-first'));
  assert.equal(state.cursor, ''); assert.equal(state.trail.length, 0);
});

test('legacy arrays remain readable without claiming paging support', () => {
  const state = c.createEventHistoryPage();
  const rows = [{ session_id: 'ended' }];
  assert.equal(c.acceptEventHistoryPage(state, rows), rows);
  assert.equal(state.paged, false); assert.equal(state.next, '');
  assert.equal(c.requestEventHistoryPage(state, 'earlier'), false);
});

test('paged evidence requires exact session, durable string IDs, valid bounds, and unique rows', () => {
  assert.equal(c.validEventHistoryPage(page('9007199254740993', 'cursor'), 'ended'), true);
  for (const invalid of [
    { ...page('1'), session_id: 'other' }, { ...page('1'), rows: [null] },
    { ...page('1'), rows: [page('1').rows[0], page('1').rows[0]] },
    { ...page('1'), rows: [{ id: 1, event: { session_id: 'ended' } }] },
    { ...page('1'), rows: [{ id: '0', event: { session_id: 'ended' } }] },
    { ...page('1'), rows: [{ id: '1', event: { session_id: 'other' } }] },
    { ...page('1'), has_earlier: true }, { ...page('1', 'cursor'), rows: [] },
    { ...page('1'), next_cursor: 'unexpected' },
  ]) assert.equal(c.validEventHistoryPage(invalid, 'ended'), false);
});

test('return snapshots keep cursor history without sharing pending or mutable navigation', () => {
  const state = c.createEventHistoryPage(); state.cursor = 'a'; state.trail = ['']; state.loading = true;
  const saved = c.copyEventHistoryPage(state); saved.trail.push('b');
  assert.equal(state.trail.length, 1); assert.equal(saved.loading, false); assert.equal(saved.pending, null);
});

test('identical event metadata retains distinct identities across recorded rows', () => {
  const event = { kind: 0, ts: '2026-10-10T00:00:00Z', session_id: 'ended', path: '/same' };
  assert.notEqual(c.eventKey({ ...event, record_id: '9007199254740993' }), c.eventKey({ ...event, record_id: '9007199254740992' }));
});
