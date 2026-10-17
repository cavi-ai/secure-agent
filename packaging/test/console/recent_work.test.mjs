import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const c = { Date, window: { SA: {} } };
vm.createContext(c);
for (const file of ['lib.js', 'session-layout.js', 'session-workbench.js']) vm.runInContext(readFileSync(new URL(file, web), 'utf8'), c);
const session = (id, status, at) => ({ id, status, harness: 'claude', repo: 'project', last_seen_at: at });

test('recent work orders by recorded activity, uses durable IDs and bounds the loaded list', () => {
  const sessions = Array.from({ length: 8 }, (_, i) => session('session-' + i, i % 2 ? 'ended' : 'active', `2026-10-16T12:0${i}:00Z`));
  const html = c.sessionDailyHTML(sessions, null);
  assert.ok(html.indexOf('data-session="session-7"') < html.indexOf('data-session="session-6"'));
  assert.doesNotMatch(html, /data-session="session-0"|data-session="session-1"/);
  assert.match(html, /8 loaded sessions/);
  assert.match(html, /Last observed/);
  assert.match(html, /<time datetime="2026-10-16T12:07:00Z"/);
  assert.doesNotMatch(html, /Completed|Succeeded|Safe|needs review/i);
});

test('ended-only history remains discoverable and searchable without any running process', () => {
  const ended = { ...session('ended-id', 'ended', '2026-10-16T12:00:00Z'), branch: 'release' };
  const html = c.sessionDailyHTML([ended], null, 'release');
  assert.match(html, /data-action="recent-session-results" data-session="ended-id"/);
  assert.match(html, /ended/);
  assert.doesNotMatch(html, /No live/);
  assert.match(c.sessionDailyHTML([ended], null, 'absent'), /No sessions match/);
  assert.match(c.sessionDailyHTML([session('unknown-time', 'idle', 'invalid')], null), /Activity time unavailable/);
});

test('recent work keeps deterministic ties, does not mutate history and escapes labels', () => {
  const sessions = [session('b', 'ended', ''), { ...session('a', 'idle', ''), repo: '<img>' }];
  const original = JSON.stringify(sessions);
  const html = c.sessionDailyHTML(sessions, null);
  assert.ok(html.indexOf('data-session="a"') < html.indexOf('data-session="b"'));
  assert.equal(JSON.stringify(sessions), original);
  assert.doesNotMatch(html, /<img>/);
  assert.match(html, /&lt;img&gt;/);
});
