import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

import { controller } from './controllers.mjs';
function history() {
  const c = { URLSearchParams, Date, window: {}, timelineSession: null,
    filters: { events: { kind: 'all', since: 'all' }, flags: { agent: 'all', rule: 'all', minsev: 'all', since: 'all' } },
    historyScopes: { events: null, flags: null },
    telemetryData: { events: [{ session_id: 'other' }], eventsView: [{ session_id: 'other' }], flags: [] },
    reportHealth: { reset() {} }, failedEndpoints: new Set(), homeGroupOpen: () => false,
    renderReportHealth() {}, markDirty() {},
  };
  vm.createContext(c);
  vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/event-history.js', import.meta.url), 'utf8'), c);
  Object.assign(c, controller('history-controller.js', 'createHistoryController', c));
  c.eventHistoryPage = c.createEventHistoryPage();
  return c;
}

test('a session alone requests its retained Events history with an encoded exact identity', () => {
  const c = history(); c.timelineSession = 'ended/session?synthetic';
  assert.equal(c.isEventsFiltered(), true);
  const query = new URL(c.eventsQuery(), 'http://localhost').searchParams;
  assert.equal(query.get('session_id'), c.timelineSession);
  assert.equal(query.get('limit'), '200');
  assert.equal(query.get('page'), '1');
  assert.equal(query.has('kind'), false);
});

test('earlier requests keep the original time boundary and reset with a changed filter', () => {
  const c = history(); c.timelineSession = 'ended'; c.filters.events.since = '24h'; c.syncHistoryViews();
  const first = new URL(c.eventsQuery(), 'http://localhost').searchParams;
  vm.runInContext("eventHistoryPage.cursor='older';eventHistoryPage.trail=[''];", c);
  const earlier = new URL(c.eventsQuery(), 'http://localhost').searchParams;
  assert.equal(earlier.get('since'), first.get('since'));
  assert.equal(earlier.get('before'), 'older');
  c.filters.events.kind = '0'; c.syncHistoryViews();
  assert.equal(new URL(c.eventsQuery(), 'http://localhost').searchParams.has('before'), false);
});

test('changing sessions clears prior evidence; refreshing the same scope retains last-known rows', () => {
  const c = history(); c.timelineSession = 'a'; c.syncHistoryViews();
  assert.equal(c.telemetryData.eventsView, null);
  c.telemetryData.eventsView = [{ session_id: 'a' }];
  c.telemetryData.events = [{ session_id: 'global-update' }];
  c.syncHistoryViews();
  assert.equal(c.telemetryData.eventsView[0].session_id, 'a');
  c.timelineSession = 'b'; c.syncHistoryViews();
  assert.equal(c.telemetryData.eventsView, null);
  c.timelineSession = null; c.syncHistoryViews();
  assert.equal(c.telemetryData.eventsView[0].session_id, 'global-update');
});

test('kind zero and time filtering are combined with the session rather than applied to a global window', () => {
  const c = history(); c.timelineSession = 'ended'; c.filters.events = { kind: '0', since: '24h' };
  const query = new URL(c.eventsQuery(), 'http://localhost').searchParams;
  assert.equal(query.get('session_id'), 'ended');
  assert.equal(query.get('kind'), '0');
  assert.ok(query.get('since'));
});
