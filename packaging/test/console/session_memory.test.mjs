import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../daemon/internal/api/web_dist');
const context = { Date };
vm.createContext(context);
for (const file of ['lib.js', 'tab-sessions.js']) {
  vm.runInContext(readFileSync(path.join(web, file), 'utf8'), context, { filename: file });
}

test('memory page preserves oldest-first order and names five sources', () => {
  const rows = [
    { id: 'activity:1', at: '2026-09-26T10:00:00Z', kind: 'activity', title: 'Activity' },
    { id: 'flag:1', at: '2026-09-26T10:01:00Z', kind: 'flag', title: 'Finding', severity: 'high' },
    { id: 'incident:1', at: '2026-09-26T10:02:00Z', kind: 'incident', title: 'Incident', status: 'resolved' },
    { id: 'guard:1', at: '2026-09-26T10:03:00Z', kind: 'guard', title: 'Decision' },
    { id: 'resource:1', at: '2026-09-26T10:04:00Z', kind: 'resource', title: 'Pressure' },
  ];
  const html = context.sessionMemoryHTML({ rows, has_earlier: true, next_cursor: 'opaque' }, {});
  assert.ok(html.indexOf('Activity') < html.indexOf('Pressure'));
  for (const source of ['Activity', 'Flag', 'Incident', 'Guard', 'Resource']) {
    assert.match(html, new RegExp(`class="sm-source[^"]*">${source}<`));
  }
  assert.match(html, /data-action="memory-earlier"/);
  assert.match(html, />resolved</);
  assert.match(html, />high</);
});

test('memory page escapes every server string including identifiers and cursor', () => {
  const payload = '<img src=x onerror=alert(1)>';
  const at = '2026-09-26T10:00:00Z" data-injected="yes';
  const html = context.sessionMemoryHTML({ rows: [{ id: payload, at, kind: payload, title: payload, detail: payload, severity: payload, status: payload }], has_earlier: true, next_cursor: payload }, {});
  assert.ok(!html.includes(payload), html);
  assert.ok(!html.includes('<img'), html);
  assert.ok(html.includes('&lt;img'), html);
  assert.ok(!html.includes('datetime="2026-09-26T10:00:00Z" data-injected="yes"'), html);
  assert.ok(html.includes('datetime="2026-09-26T10:00:00Z&quot; data-injected=&quot;yes"'), html);
});

test('memory page has explicit empty, loading and error states', () => {
  assert.match(context.sessionMemoryHTML({ rows: [] }, {}), /No retained memory/);
  assert.match(context.sessionMemoryHTML({ rows: [] }, { loading: true }), /Loading memory/);
  assert.match(context.sessionMemoryHTML({ rows: [] }, { error: 'not available' }), /Memory unavailable/);
  assert.match(context.sessionMemoryHTML({ rows: [] }, { error: 'not available' }), /data-action="memory-retry"/);
  assert.match(context.sessionMemoryHTML({ rows: [{ id: 'a', at: '2026-09-26T10:00:00Z', kind: 'activity', title: 'A' }], has_earlier: true, next_cursor: 'x' }, { loadingEarlier: true }), /Loading earlier/);
});
