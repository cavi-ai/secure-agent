// Console lib.js unit tests — zero dependencies. Runs under Node's built-in
// test runner (node --test packaging/test/console/), evaluating lib.js in a
// fresh VM context exactly the way the browser sees it (a classic script:
// top-level functions become globals).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const libPath = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../daemon/internal/api/web_dist/lib.js'
);
const ctx = {};
vm.runInNewContext(readFileSync(libPath, 'utf8'), ctx, { filename: 'lib.js' });
const {
  escapeHTML, fmtTime, eventKey,
  advanceBuckets, bucketIndexFor, sparkPoints,
  parseMarkdownToHTML, buildEvidenceChain,
  sessionShort, filterEventsBySession, rollupSeries,
  familyTitle, fmtRSS, fmtAge, isFamilyRoot, childrenOf, groupAgents, familyShouldExpand,
} = ctx;

// ---------- escapeHTML ----------

test('escapeHTML escapes the HTML-significant set', () => {
  assert.equal(escapeHTML('<a href="x">&</a>'), '&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;');
});
test('escapeHTML tolerates null/undefined/numbers', () => {
  assert.equal(escapeHTML(null), '');
  assert.equal(escapeHTML(undefined), '');
  assert.equal(escapeHTML(0), '0');
});

// ---------- fmtTime ----------

test('fmtTime is zero-padded HH:MM:SS', () => {
  const d = new Date(2026, 8, 8, 16, 4, 7);
  assert.equal(fmtTime(d), '16:04:07');
  const midnight = new Date(2026, 8, 8, 0, 0, 5);
  assert.equal(fmtTime(midnight), '00:00:05');
});

// ---------- eventKey ----------

test('eventKey prefers detail, then path, then remote_host', () => {
  const base = { ts: 't', pid: 1, kind: 9 };
  assert.equal(eventKey({ ...base, detail: 'd', path: 'p', remote_host: 'h' }), 't|1|9|d');
  assert.equal(eventKey({ ...base, path: 'p', remote_host: 'h' }), 't|1|9|p');
  assert.equal(eventKey({ ...base, remote_host: 'h' }), 't|1|9|h');
  assert.equal(eventKey({ ...base }), 't|1|9|');
});

// ---------- sparkline helpers ----------

test('advanceBuckets shifts in fresh zero buckets and caps at length', () => {
  const b = [1, 2, 3, 4];
  advanceBuckets(b, 2);
  assert.deepEqual(b, [3, 4, 0, 0]);
  advanceBuckets(b, 99);
  assert.deepEqual(b, [0, 0, 0, 0]);
});

test('bucketIndexFor maps recency and clamps age', () => {
  const now = 60_000;
  assert.equal(bucketIndexFor(now, 0, 60), 59);            // no ts → newest
  assert.equal(bucketIndexFor(now, now, 60), 59);          // now → newest
  assert.equal(bucketIndexFor(now, now - 30_000, 60), 29); // 30s ago → middle
  assert.equal(bucketIndexFor(now, 1, 60), 0);             // ancient → oldest clamp
});

test('sparkPoints: quiet line stays flat, values scale', () => {
  const flat = sparkPoints([0, 0, 0], 120, 26, 24, 2);
  assert.deepEqual(flat.split(' '), ['0.0,26.0', '60.0,26.0', '120.0,26.0']);
  const pts = sparkPoints([0, 4, 2], 120, 26, 24, 2).split(' ');
  assert.equal(pts[1], '60.0,2.0');   // max value reaches baseY - span
  assert.equal(pts[2], '120.0,14.0'); // half of max → half the span
});

// ---------- parseMarkdownToHTML ----------

test('markdown: headers, bold, inline code, code block', () => {
  const html = parseMarkdownToHTML('# Title\n\n**bold** and `code`\n\n```\nblock\n```');
  assert.match(html, /<h1>Title<\/h1>/);
  assert.match(html, /<strong>bold<\/strong>/);
  assert.match(html, /<code class="md-inline-code">code<\/code>/);
  assert.match(html, /<pre class="md-codeblock"><code>\nblock\n<\/code><\/pre>/);
});

test('markdown escapes HTML before formatting (no injection)', () => {
  const html = parseMarkdownToHTML('<script>alert(1)</script>');
  assert.ok(!html.includes('<script>'));
  assert.ok(html.includes('&lt;script&gt;'));
});

test('markdown: empty input', () => {
  assert.equal(parseMarkdownToHTML(''), '');
  assert.equal(parseMarkdownToHTML(null), '');
});

// ---------- buildEvidenceChain ----------

test('chain: sensitive-read-then-connect parses to read → egress → verdict', () => {
  const nodes = buildEvidenceChain({
    rule: 'sensitive-read-then-connect', severity: 3,
    evidence: [
      'cursor (pid 6033) read ~/.aws/credentials at 2026-09-07T16:04:57Z',
      'then connected to logs.example.com:443 at 2026-09-07T16:05:01Z',
    ],
  });
  assert.equal(nodes.length, 3);
  assert.deepEqual(
    [nodes[0].cls, nodes[1].cls, nodes[2].cls],
    ['cn-read', 'cn-egress', 'cn-verdict-bad']
  );
  assert.equal(nodes[0].label, '~/.aws/credentials');
  assert.equal(nodes[1].label, 'logs.example.com:443');
  assert.match(nodes[0].sub, /^sensitive read · \d{2}:\d{2}:\d{2}$/);
});

test('chain: proxy violation parses to inspection → destination → verdict', () => {
  const nodes = buildEvidenceChain({
    rule: 'proxy-secret-leak', severity: 3,
    evidence: ["Local proxy detected security violation 'proxy-secret-leak: anthropic-key' while connecting to logs.example.com:443"],
  });
  assert.equal(nodes.length, 3);
  assert.equal(nodes[0].label, 'proxy-secret-leak: anthropic-key');
  assert.equal(nodes[0].sub, 'payload inspection');
  assert.equal(nodes[1].label, 'logs.example.com:443');
});

test('chain: keychain access / CLI / TCC formats', () => {
  const kc = buildEvidenceChain({
    rule: 'keychain-access', severity: 2,
    evidence: ['claude (pid 12) accessed keychain file /Users/x/Library/Keychains/login.keychain-db at 2026-09-07T16:00:00Z'],
  });
  assert.equal(kc.length, 2);
  assert.match(kc[0].sub, /^keychain access · /);
  assert.equal(kc[1].cls, 'cn-verdict-warn'); // severity 2 → warn verdict
  assert.equal(kc[1].label, 'Flag raised');

  const cli = buildEvidenceChain({
    rule: 'keychain-security-cli', severity: 3,
    evidence: ['cursor (pid 9) executed /usr/bin/security at 2026-09-07T16:00:00Z'],
  });
  assert.equal(cli[0].icon, 'i-power');

  const tcc = buildEvidenceChain({
    rule: 'tcc-tamper', severity: 3,
    evidence: ["codex (pid 7) modified TCC service 'kTCCServiceScreenCapture' at 2026-09-07T16:00:00Z"],
  });
  assert.equal(tcc[0].label, 'TCC: kTCCServiceScreenCapture');
});

test('chain: unknown evidence degrades to a raw node, never dropped', () => {
  const nodes = buildEvidenceChain({
    rule: 'future-rule', severity: 2,
    evidence: ['some totally new evidence format the parser does not know'],
  });
  assert.equal(nodes.length, 2);
  assert.equal(nodes[0].label, 'some totally new evidence format the parser does not know');
  assert.equal(nodes[0].cls, '');
});

test('chain: empty evidence yields no nodes (no dangling verdict)', () => {
  // Note: the returned array is from the VM realm — compare structurally.
  assert.equal(buildEvidenceChain({ rule: 'x', severity: 3, evidence: [] }).length, 0);
});

// ---------- session helpers ----------

test('sessionShort: first 8 chars, null-safe', () => {
  assert.equal(sessionShort('7f3a9c21-4b2e-4a1d-9c55-2e8f0d1a3b77'), '7f3a9c21');
  assert.equal(sessionShort('abc'), 'abc');
  assert.equal(sessionShort(null), '');
  assert.equal(sessionShort(12345678), '12345678');
});

test('filterEventsBySession: keeps only the session, null clears the filter', () => {
  const events = [
    { ts: '1', session_id: 'aaa' },
    { ts: '2', session_id: 'bbb' },
    { ts: '3', session_id: 'aaa' },
    { ts: '4' }, // no session at all
  ];
  assert.deepEqual(filterEventsBySession(events, 'aaa').map(e => e.ts), ['1', '3']);
  assert.equal(filterEventsBySession(events, null).length, 4);
  assert.equal(filterEventsBySession(null, 'aaa').length, 0); // VM-realm array: compare structurally
});

// ---------- rollupSeries ----------

test('rollupSeries: zero-fills the window and separates flags from events', () => {
  const now = Date.parse('2026-09-08T16:37:00Z');
  const b = (isoHour) => isoHour;
  const s = rollupSeries([
    { bucket: b('2026-09-08T16'), kind: 'event:tool', count: 5 },
    { bucket: b('2026-09-08T16'), kind: 'flag:s3', count: 1 },
    { bucket: b('2026-09-08T15'), kind: 'event:conn', count: 2 },
    { bucket: b('2026-08-01T00'), kind: 'event:tool', count: 99 }, // outside window
  ], 24, now);
  assert.equal(s.events.length, 24);
  assert.equal(s.events[23], 5);  // current hour
  assert.equal(s.flags[23], 1);
  assert.equal(s.events[22], 2);
  assert.equal(s.events[0], 0);   // zero-filled, not dropped
  assert.equal(s.events.reduce((a, c) => a + c, 0), 7); // out-of-window excluded
  // Labels are local wall-clock (UI shows local time) — derive the expectation
  // the same way instead of hardcoding a UTC assumption.
  const wantLabel = String(new Date(Date.parse('2026-09-08T16:00:00Z')).getHours()).padStart(2, '0') + ':00';
  assert.equal(s.labels[23], wantLabel);
});

test('rollupSeries: 7d window labels switch to day form', () => {
  const s = rollupSeries([], 168, Date.parse('2026-09-08T16:00:00Z'));
  assert.equal(s.labels.length, 168);
  assert.match(s.labels[167], /^\d{1,2}\/\d{1,2}$/);
});

test('groupAgents: families, roots, earliest, rss, orphans', () => {
  const families = groupAgents([
    { pid: 1, name: 'claude', root_pid: 1, started_at: '2026-09-09T14:00:00Z', rss_bytes: 100 },
    { pid: 2, name: 'claude', root_pid: 1, ppid: 1, started_at: '2026-09-09T14:01:00Z', rss_bytes: 50 },
    { pid: 3, name: 'cursor', root_pid: 3, started_at: '2026-09-09T15:00:00Z', rss_bytes: 10, is_orphan: true },
  ]);
  assert.equal(families.length, 2);
  assert.equal(families[0].name, 'claude');
  assert.equal(families[0].roots.length, 1);
  assert.equal(families[0].roots[0].pid, 1);
  assert.equal(childrenOf(families[0].roots[0], families[0].members).length, 1);
  assert.equal(families[0].earliest, '2026-09-09T14:00:00Z');
  assert.equal(families[0].rss, 150);
  assert.equal(families[1].orphanCount, 1);
});

test('familyShouldExpand: one family, few instances, orphans, user override', () => {
  const claude = { name: 'claude', roots: [1, 2], orphanCount: 0 };
  assert.equal(familyShouldExpand(claude, 1, 10, {}), true);
  assert.equal(familyShouldExpand(claude, 2, 2, {}), true);
  assert.equal(familyShouldExpand(claude, 2, 8, {}), false);
  assert.equal(familyShouldExpand({ name: 'x', orphanCount: 1 }, 2, 8, {}), true);
  assert.equal(familyShouldExpand(claude, 2, 8, { claude: true }), true);
  assert.equal(familyShouldExpand(claude, 1, 1, { claude: false }), false);
});

test('fmtRSS and fmtAge', () => {
  assert.equal(fmtRSS(0), '');
  assert.equal(fmtRSS(2048), '2 KB');
  assert.equal(fmtAge('2026-09-09T16:00:00Z', Date.parse('2026-09-09T16:02:00Z')), '2m');
});
