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
const webDist = path.dirname(libPath);
const indexHTML = readFileSync(path.join(webDist, 'index.html'), 'utf8');
const styleCSS = readFileSync(path.join(webDist, 'style.css'), 'utf8');
const ctx = {};
vm.runInNewContext(readFileSync(libPath, 'utf8'), ctx, { filename: 'lib.js' });
const {
  escapeHTML, fmtTime, eventKey,
  advanceBuckets, bucketIndexFor, sparkPoints,
  parseMarkdownToHTML, buildEvidenceChain,
  sessionShort, filterEventsBySession, rollupSeries, flagHost,
  familyTitle, fmtRSS, fmtAge, isFamilyRoot, childrenOf, groupAgents, familyShouldExpand,
  cwdLabel, sessionRows, filterEventsByPids, sessionBoardHTML,
  fmtCPU, resourceImpact, resourceSparkPoints, resourceDiagnosisText,
  monitorVendorKeyIDs, inspectionVisible, vendorKeyPromoteHTML,
  scopedBySession, unactedLast24h, filterSessionRows, sseNeedsSnapshot,
  sessionStripRows, sessionNeedsYou, sessionStripHTML,
  harnessMeta, harnessChipHTML, advisorAdviceHTML,
  groupSessionSections, endpointIdentityLine, endpointDetailHTML,
  sessionLabelDurable, sessionRowsDurable,
} = ctx;

// ---------- unified attention center ----------
// The grouping itself is computed daemon-side (daemon/internal/api/attention.go,
// covered by attention_test.go); the console renders posture.groups as served.

// ---------- resource mission control ----------

test('fmtCPU formats present values and preserves unavailable values', () => {
  assert.equal(fmtCPU(undefined), '');
  assert.equal(fmtCPU(null), '');
  assert.equal(fmtCPU(Number.NaN), '');
  assert.equal(fmtCPU(0), '0%');
  assert.equal(fmtCPU(0.5), '0.5%');
  assert.equal(fmtCPU(132.5), '132.5%');
  assert.equal(fmtCPU(75), '75%');
});

test('resourceImpact ranks the dominant CPU or memory pressure', () => {
  const sessions = [
    { key: 'memory', rss_bytes: 3 * 1024 ** 3, cpu_percent: 20 },
    { key: 'cpu', rss_bytes: 1024 ** 3, cpu_percent: 140 },
    { key: 'quiet', rss_bytes: 0, cpu_percent: 0 },
  ].sort((a, b) => resourceImpact(b) - resourceImpact(a));
  assert.deepEqual(sessions.map(s => s.key), ['cpu', 'memory', 'quiet']);
  assert.equal(resourceImpact(null), 0);
});

test('resourceSparkPoints normalizes trends and omits unavailable series', () => {
  assert.equal(resourceSparkPoints([], 'rss_bytes', 120, 24), '');
  assert.equal(resourceSparkPoints([{ rss_bytes: null }], 'rss_bytes', 120, 24), '');
  assert.equal(
    resourceSparkPoints([{ rss_bytes: 100 }, { rss_bytes: 200 }, { rss_bytes: 300 }], 'rss_bytes', 120, 24),
    '0.0,24.0 60.0,12.0 120.0,0.0'
  );
  assert.equal(
    resourceSparkPoints([{ cpu_percent: 50 }, { cpu_percent: 50 }], 'cpu_percent', 120, 24),
    '0.0,12.0 120.0,12.0'
  );
});

test('resourceDiagnosisText provides fallback copy and escapes server text', () => {
  assert.equal(resourceDiagnosisText({ code: 'heavy-memory' }), 'Heavy memory use');
  assert.equal(
    resourceDiagnosisText({ summary: '<img src=x onerror="boom">' }),
    '&lt;img src=x onerror=&quot;boom&quot;&gt;'
  );
});

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

test('chain: sensitive-read-then-connect renders structured read → egress → verdict', () => {
  const nodes = buildEvidenceChain({
    rule: 'sensitive-read-then-connect', severity: 3,
    evidence: [
      { kind: 'read', label: '~/.aws/credentials', sub: 'sensitive read', ts: '2026-09-07T16:04:57Z' },
      { kind: 'connect', label: 'logs.example.com:443', sub: 'egress', ts: '2026-09-07T16:05:01Z' },
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

test('chain: proxy violation renders inspection → destination → verdict', () => {
  const nodes = buildEvidenceChain({
    rule: 'proxy-secret-leak', severity: 3,
    evidence: [
      { kind: 'violation', label: 'proxy-secret-leak: anthropic-key', sub: 'payload inspection' },
      { kind: 'connect', label: 'logs.example.com:443', sub: 'destination' },
    ],
  });
  assert.equal(nodes.length, 3);
  assert.equal(nodes[0].label, 'proxy-secret-leak: anthropic-key');
  assert.equal(nodes[0].sub, 'payload inspection');
  assert.equal(nodes[1].label, 'logs.example.com:443');
});

test('chain: keychain access / CLI / TCC structured items', () => {
  const kc = buildEvidenceChain({
    rule: 'keychain-access', severity: 2,
    evidence: [{ kind: 'keychain', label: '/Users/x/Library/Keychains/login.keychain-db', sub: 'keychain access', ts: '2026-09-07T16:00:00Z' }],
  });
  assert.equal(kc.length, 2);
  assert.match(kc[0].sub, /^keychain access · /);
  assert.equal(kc[1].cls, 'cn-verdict-warn'); // severity 2 → warn verdict
  assert.equal(kc[1].label, 'Flag raised');

  const cli = buildEvidenceChain({
    rule: 'keychain-security-cli', severity: 3,
    evidence: [{ kind: 'exec', label: '/usr/bin/security', sub: 'keychain CLI', ts: '2026-09-07T16:00:00Z' }],
  });
  assert.equal(cli[0].icon, 'i-power');

  const tcc = buildEvidenceChain({
    rule: 'tcc-tamper', severity: 3,
    evidence: [{ kind: 'tcc', label: 'kTCCServiceScreenCapture', sub: 'privacy tamper', ts: '2026-09-07T16:00:00Z' }],
  });
  assert.equal(tcc[0].label, 'kTCCServiceScreenCapture');
});

test('chain: legacy string rows and unknown kinds degrade to raw nodes, never dropped', () => {
  const legacy = buildEvidenceChain({
    rule: 'future-rule', severity: 2,
    evidence: [{ kind: 'text', text: 'some totally new evidence format', label: 'some totally new evidence format' }],
  });
  assert.equal(legacy.length, 2);
  assert.equal(legacy[0].label, 'some totally new evidence format');
  assert.equal(legacy[0].cls, '');
  // Pre-structured wire rows may still be bare strings.
  const bare = buildEvidenceChain({ rule: 'x', severity: 2, evidence: ['raw old row'] });
  assert.equal(bare[0].label, 'raw old row');
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

test('cwdLabel: last path component, empty when missing', () => {
  assert.equal(cwdLabel('/Users/dev/workspace/api-service'), 'api-service');
  assert.equal(cwdLabel('/Users/dev/projects/web-app/'), 'web-app');
  assert.equal(cwdLabel(''), '');
  assert.equal(cwdLabel(undefined), '');
});

test('sessionRows: one row per root, cwd label, family rss, helpers excluded', () => {
  const rows = sessionRows([
    { pid: 5821, name: 'claude', cwd: '/Users/dev/workspace/api-service', root_pid: 5821, last_seen_at: '2026-09-11T12:00:00Z', rss_bytes: 100 },
    { pid: 5822, name: 'claude', root_pid: 5821, ppid: 5821, last_seen_at: '2026-09-11T11:00:00Z', rss_bytes: 50 },
    { pid: 6033, name: 'cursor', cwd: '/Users/dev/projects/web-app', root_pid: 6033, last_seen_at: '2026-09-11T11:00:00Z', rss_bytes: 10 },
  ]);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].root.pid, 5821);
  assert.equal(rows[0].label, 'api-service');
  assert.equal(rows[0].rss, 150);
  assert.equal(rows[0].pids.map(Number).join(','), '5821,5822');
  assert.equal(rows[0].children.length, 1);
  assert.equal(rows[1].label, 'web-app');
  assert.equal(rows[1].root.pid, 6033);
});

test('sessionRows: missing cwd falls back to harness name', () => {
  const rows = sessionRows([{ pid: 1, name: 'codex', root_pid: 1 }]);
  assert.equal(rows[0].label, 'Codex');
});

test('sessionRows: daemon trees are used as-is (no regroup)', () => {
  const trees = [{
    root: { pid: 10, name: 'claude', cwd: '/tmp/proj', root_pid: 10 },
    children: [{ pid: 11, name: 'claude', root_pid: 10 }],
    rss_bytes: 150,
    last_seen_at: '2026-09-15T12:00:00Z',
  }];
  const rows = sessionRows([{ pid: 99, name: 'should-ignore', root_pid: 99 }], trees);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].root.pid, 10);
  assert.equal(rows[0].label, 'proj');
  assert.equal(rows[0].rss, 150);
  assert.equal(rows[0].pids.map(Number).join(','), '10,11');
});

test('sessionBoardHTML labels the project folder', () => {
  const html = sessionBoardHTML([{
    root: { pid: 10, name: 'claude', cwd: '/tmp/proj', started_at: '' },
    children: [],
    label: 'proj',
    rss: 0,
    lastSeen: '',
    pids: [10],
  }], Date.now(), {});
  assert.match(html, /session-label">proj</);
  assert.match(html, /data-action="kill"/);
});

test('filterEventsByPids: empty pids is a no-op; otherwise pid set', () => {
  const events = [{ pid: 1, ts: 'a' }, { pid: 2, ts: 'b' }, { pid: 3, ts: 'c' }];
  assert.equal(filterEventsByPids(events, []).length, 3);
  assert.deepEqual(filterEventsByPids(events, [1, 3]).map(e => e.pid), [1, 3]);
});

// ---------- flagHost ----------

test('flagHost: extracts egress host from evidence, empty for hostless rules', () => {
  assert.equal(flagHost({ evidence: ['cursor (pid 1) read ~/.aws/credentials at 2026-09-08T10:00:00Z', 'then connected to logs.example.com:443 at 2026-09-08T10:00:04Z'] }), 'logs.example.com');
  assert.equal(flagHost({ evidence: ["Local proxy detected security violation 'x' while connecting to api.example.com:443"] }), 'api.example.com');
  assert.equal(flagHost({ evidence: ['claude (pid 1) accessed keychain file /x at 2026-09-08T10:00:00Z'] }), '');
  assert.equal(flagHost({ evidence: [] }), '');
  assert.equal(flagHost({}), '');
});

test('monitorVendorKeyIDs: monitor vendor-key only, sorted', () => {
  const stats = {
    'openai-key': { type: 'vendor-key', mode: 'monitor' },
    'anthropic-key': { type: 'vendor-key', mode: 'block' },
    'aws-key': { type: 'cloud-key', mode: 'monitor' },
    'stripe-key': { type: 'vendor-key', mode: 'monitor' },
  };
  assert.equal(monitorVendorKeyIDs(stats).join(','), 'openai-key,stripe-key');
  assert.equal(monitorVendorKeyIDs({}).join(','), '');
  assert.equal(monitorVendorKeyIDs(null).join(','), '');
});

test('inspectionVisible: fleet/advisor/audit stay hidden until configured', () => {
  const off = inspectionVisible({}, []);
  assert.equal(off.fleet, false);
  assert.equal(off.advisor, false);
  assert.equal(off.audit, false);
  const on = inspectionVisible({ fleet_configured: true, advisor_enabled: true }, [{}]);
  assert.equal(on.fleet, true);
  assert.equal(on.advisor, true);
  assert.equal(on.audit, true);
  const auditOnly = inspectionVisible({ fleet_configured: false, advisor_enabled: false }, [{}]);
  assert.equal(auditOnly.fleet, false);
  assert.equal(auditOnly.advisor, false);
  assert.equal(auditOnly.audit, true);
});

test('vendorKeyPromoteHTML: banner names the count and posts type=vendor-key', () => {
  const html = vendorKeyPromoteHTML(['anthropic-key', 'openai-key']);
  assert.match(html, /2 vendor-key rules/);
  assert.match(html, /data-action="promote-vendor-keys"/);
  assert.equal(vendorKeyPromoteHTML([]), '');
});

test('scopedBySession: session_id wins; else pid set; else identity', () => {
  const items = [
    { id: 'a', pid: 1, session_id: 'sess-a' },
    { id: 'b', pid: 2, session_id: 'sess-b' },
    { id: 'c', pid: 3 },
  ];
  assert.equal(scopedBySession(items, 'sess-a', null).map(x => x.id).join(','), 'a');
  assert.equal(scopedBySession(items, '', [2, 3]).map(x => x.id).join(','), 'b,c');
  assert.equal(scopedBySession(items, '', []).length, 3);
});

test('unactedLast24h: sev>=2, not ack, within 24h', () => {
  const now = Date.parse('2026-09-15T18:00:00Z');
  const flags = [
    { id: 'fresh', severity: 3, ts: '2026-09-15T17:00:00Z' },
    { id: 'old', severity: 3, ts: '2026-09-13T18:00:00Z' },
    { id: 'ack', severity: 3, ts: '2026-09-15T17:00:00Z', acknowledged: true },
    { id: 'info', severity: 1, ts: '2026-09-15T17:00:00Z' },
  ];
  assert.equal(unactedLast24h(flags, now).map(f => f.id).join(','), 'fresh');
  assert.equal(unactedLast24h([], now).length, 0);
});

test('filterSessionRows: cwd/label/name substring, empty query is identity', () => {
  const rows = [
    { label: 'api-service', root: { name: 'claude', cwd: '/Users/dev/workspace/api-service' } },
    { label: 'web-app', root: { name: 'cursor', cwd: '/Users/dev/projects/web-app' } },
  ];
  assert.equal(filterSessionRows(rows, '').length, 2);
  assert.equal(filterSessionRows(rows, 'API').map(r => r.label).join(','), 'api-service');
  assert.equal(filterSessionRows(rows, 'cursor').map(r => r.label).join(','), 'web-app');
  assert.equal(filterSessionRows(rows, 'projects/web').map(r => r.label).join(','), 'web-app');
  assert.equal(filterSessionRows(rows, 'nope').length, 0);
});

test('sseNeedsSnapshot: exec/guard/proxy-hit refetch; file/conn are spark-only', () => {
  assert.equal(sseNeedsSnapshot('exec'), true);
  assert.equal(sseNeedsSnapshot('guard-prompt'), true);
  assert.equal(sseNeedsSnapshot('guard-resolved'), true);
  assert.equal(sseNeedsSnapshot('proxy-hit'), true);
  assert.equal(sseNeedsSnapshot('file-open'), false);
  assert.equal(sseNeedsSnapshot('file-write'), false);
  assert.equal(sseNeedsSnapshot('conn-open'), false);
  assert.equal(sseNeedsSnapshot('transcript-hit'), false);
  assert.equal(sseNeedsSnapshot('plugin-action'), false);
});

test('sessionStripRows: first n, empty is empty', () => {
  const rows = [
    { label: 'a', pids: [1] },
    { label: 'b', pids: [2] },
    { label: 'c', pids: [3] },
    { label: 'd', pids: [4] },
  ];
  assert.equal(sessionStripRows(rows, 3).map(r => r.label).join(','), 'a,b,c');
  assert.equal(sessionStripRows(rows).map(r => r.label).join(','), 'a,b,c');
  assert.equal(sessionStripRows([], 3).length, 0);
});

test('sessionNeedsYou: unacked flags on the row pids', () => {
  const row = { pids: [5821, 5822] };
  const flags = [
    { pid: 5821, acknowledged: false },
    { pid: 5822, acknowledged: true },
    { pid: 6033, acknowledged: false },
  ];
  assert.equal(sessionNeedsYou(row, flags), 1);
  assert.equal(sessionNeedsYou(row, []), 0);
});

test('sessionStripHTML: labels, RSS, needs-you, opens Sessions tab', () => {
  const now = Date.parse('2026-09-15T18:00:00Z');
  const html = sessionStripHTML(
    [{ label: 'api-service', pids: [5821], rss: 160000000, lastSeen: '2026-09-15T17:59:00Z' }],
    5,
    now,
    [{ pid: 5821 }]
  );
  assert.match(html, /api-service/);
  assert.match(html, /session-strip-row/);
  assert.match(html, /data-action="goto-tab"/);
  assert.match(html, /data-tab="sessions"/);
  assert.match(html, /session-strip-need/);
  assert.match(html, /View all 5/);
  assert.equal(sessionStripHTML([], 0, now, []), '');
});

// ---------- per-harness identity ----------

// Relative luminance / contrast ratio (WCAG 2.x) for '#rrggbb' and
// 'hsl(h s% l%)' colors, so the white-on-tile marks are checked, not assumed.
function toRGB(color) {
  const hex = /^#([0-9a-f]{6})$/i.exec(color);
  if (hex) return [0, 2, 4].map(i => parseInt(hex[1].slice(i, i + 2), 16) / 255);
  const m = /^hsl\((\d+(?:\.\d+)?) (\d+(?:\.\d+)?)% (\d+(?:\.\d+)?)%\)$/.exec(color);
  assert.ok(m, `unparseable color ${color}`);
  const [h, s, l] = [Number(m[1]), Number(m[2]) / 100, Number(m[3]) / 100];
  const f = n => {
    const k = (n + h / 30) % 12;
    return l - s * Math.min(l, 1 - l) * Math.max(-1, Math.min(k - 3, 9 - k, 1));
  };
  return [f(0), f(8), f(4)];
}
function luminance(color) {
  const [r, g, b] = toRGB(color).map(c => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function contrast(a, b) {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}

const LIVE_HARNESSES = {
  claude: 'Claude Code', codex: 'Codex', cursor: 'Cursor', 'cursor-ide': 'Cursor',
  opencode: 'opencode', agy: 'Antigravity', openclaw: 'OpenClaw', ollama: 'Ollama', 'lm-studio': 'LM Studio',
};
const KNOWN_HARNESSES = [...Object.keys(LIVE_HARNESSES), 'gemini', 'windsurf', 'aider', 'codeium', 'copilot'];
// No mark for these in the sprite's sources (simple-icons, the menubar glyphs,
// or the source license is not CC0); they render a text glyph on the tint.
const UNMARKED = new Set(['openclaw', 'aider', 'codeium', 'copilot']);

test('harnessMeta resolves every live harness key to its display name and a sprite mark', () => {
  for (const [key, label] of Object.entries(LIVE_HARNESSES)) {
    const m = harnessMeta(key);
    assert.equal(m.known, true, key);
    assert.equal(m.key, key);
    assert.equal(m.label, label);
    if (UNMARKED.has(key)) {
      assert.equal(m.logo, '', key);
      assert.ok(m.glyph, `${key} needs a text glyph`);
      continue;
    }
    assert.match(m.logo, /^logo-/, key);
    assert.ok(indexHTML.includes(`<symbol id="${m.logo}"`), `#${m.logo} for ${key} is not in index.html`);
  }
});

test('harnessMeta maps variants onto one harness and flags infra', () => {
  assert.equal(harnessMeta('antigravity').key, 'agy');
  assert.equal(harnessMeta('agy').logo, 'logo-gemini');
  assert.equal(harnessMeta('gemini').logo, 'logo-gemini');
  assert.equal(harnessMeta('Claude-Code').key, 'claude');
  assert.equal(harnessMeta('lmstudio').key, 'lm-studio');
  // cursor-ide is Cursor's IDE: same mark and name, but infra.
  assert.equal(harnessMeta('cursor-ide').logo, harnessMeta('cursor').logo);
  assert.equal(harnessMeta('cursor-ide').infra, true);
  assert.equal(harnessMeta('cursor').infra, false);
  for (const k of ['ollama', 'lm-studio']) assert.equal(harnessMeta(k).infra, true, k);
  for (const k of ['claude', 'codex', 'opencode', 'agy', 'openclaw']) assert.equal(harnessMeta(k).infra, false, k);
});

test('harnessMeta falls back to a stable hue and initial for unknown harnesses', () => {
  const a = harnessMeta('mystery-agent');
  const b = harnessMeta('mystery-agent');
  assert.equal(a.known, false);
  assert.equal(a.logo, '');
  assert.equal(a.glyph, 'M');
  assert.match(a.color, /^hsl\(\d+ 62% 62%\)$/);
  assert.equal(a.color, b.color); // deterministic, not random
  assert.notEqual(harnessMeta('other-agent').color, a.color);
});

test('white marks keep at least 3:1 contrast on every brand tile', () => {
  for (const key of KNOWN_HARNESSES) {
    const m = harnessMeta(key);
    if (!m.logo) continue;
    const bg = m.tile === 'light' ? 'hsl(0 0% 94%)' : m.color;
    const fg = m.tile === 'light' ? '#000000' : '#ffffff';
    assert.ok(contrast(fg, bg) >= 3, `${key}: ${contrast(fg, bg).toFixed(2)}:1 on ${bg}`);
  }
});

test('style.css tile colors match harnessMeta for every known harness', () => {
  for (const key of KNOWN_HARNESSES) {
    const m = harnessMeta(key);
    const rule = new RegExp(`\\.hk-${key}\\b[^{]*\\{ --harness-color: ([^;]+); \\}`);
    const hit = rule.exec(styleCSS);
    assert.ok(hit, `no .hk-${key} rule in style.css`);
    assert.equal(hit[1], m.color, key);
  }
  assert.ok(styleCSS.includes('.harness-tile.light {'), 'light tile rule missing');
});

test('harnessChipHTML renders the sprite mark by class and escapes the name', () => {
  const claude = harnessChipHTML('claude');
  assert.match(claude, /<svg class="harness-logo" aria-hidden="true"><use href="#logo-claude"\/><\/svg>/);
  assert.match(claude, /class="harness-tile hk-claude"/);
  assert.ok(!claude.includes('style='), 'known marks must not rely on inline styles');
  assert.ok(!claude.includes('harness-label'), 'label only when asked');
  assert.match(harnessChipHTML('cursor'), /class="harness-tile hk-cursor light"/);
  assert.match(harnessChipHTML('claude', { label: true }), /<span class="harness-label">Claude Code<\/span>/);
  assert.match(harnessChipHTML('openclaw'), /class="harness-glyph hk-openclaw"[^>]*>O</);
  const unknown = harnessChipHTML('mystery-agent');
  assert.match(unknown, /--harness-color:hsl/);
  assert.match(unknown, /class="harness-glyph"/);
  // A malicious harness name must not break out of the title attribute.
  const evil = harnessChipHTML('"><script>alert(1)</script>', { label: true });
  assert.ok(!evil.includes('<script>'));
});

// ---------- advisor guard advice ----------

test('advisorAdviceHTML maps assessment to a recommendation and escapes text', () => {
  const allow = advisorAdviceHTML({ assessment: 'benign', confidence: 0.9, rationale: 'routine' });
  assert.match(allow, /advisor-advice allow/);
  assert.match(allow, /suggests allow/);
  assert.match(allow, /90% conf/);
  const deny = advisorAdviceHTML({ assessment: 'malicious', confidence: 0.8, rationale: 'exfil' });
  assert.match(deny, /advisor-advice deny/);
  const look = advisorAdviceHTML({ assessment: 'suspicious', confidence: 0.5, rationale: 'unclear' });
  assert.match(look, /advisor-advice look/);
  assert.match(look, /you look first/);
  // No advice / no rationale renders nothing.
  assert.equal(advisorAdviceHTML(null), '');
  assert.equal(advisorAdviceHTML({ assessment: 'benign' }), '');
  // Rationale is escaped (model output is untrusted).
  const evil = advisorAdviceHTML({ assessment: 'benign', rationale: '<script>x</script>' });
  assert.ok(!evil.includes('<script>'));
});

// ---------- session board organization ----------

test('groupSessionSections separates live from ended and collapses history', () => {
  const rows = [
    { id: 'a', status: 'active', lastSeen: '2026-01-01T10:00:00Z' },
    { id: 'b', status: 'ended', lastSeen: '2026-01-01T09:00:00Z' },
    { id: 'c', status: 'idle', lastSeen: '2026-01-01T08:00:00Z' },
    { id: 'd', status: 'ended', lastSeen: '2026-01-01T07:00:00Z' },
    { id: 'e', status: 'active', lastSeen: '2026-01-01T11:00:00Z' },
  ];
  const s = groupSessionSections(rows);
  assert.equal(s.map(x => x.key).join(','), 'active,idle,ended');
  assert.equal(s[0].rows.map(r => r.id).join(','), 'e,a'); // newest active first
  assert.equal(s[1].rows.map(r => r.id).join(','), 'c');
  assert.equal(s[2].collapsed, true);
  assert.equal(s[2].rows.length, 2);
  // No ended sessions → no empty section.
  assert.equal(groupSessionSections([{ id: 'x', status: 'active' }]).map(x => x.key).join(','), 'active');
});

// ---------- endpoint identity ----------

test('endpointIdentityLine explains an address in plain language', () => {
  assert.match(endpointIdentityLine({ kind: 'ipv6', org: 'Google Cloud' }), /Google Cloud address/);
  assert.match(endpointIdentityLine({ kind: 'ipv6', org: 'Anthropic', name: 'x.anthropic.com' }), /Anthropic address/);
  assert.match(endpointIdentityLine({ kind: 'ipv4', name: 'ec2-1-2-3-4.compute-1.amazonaws.com' }), /Resolves to/);
  assert.match(endpointIdentityLine({ kind: 'ipv6' }), /No owner identified/);
  assert.match(endpointIdentityLine({ kind: 'hostname', org: 'npm registry', name: 'registry.npmjs.org' }), /npm registry/);
});

test('endpointDetailHTML renders identity, agents, sessions and escapes', () => {
  const html = endpointDetailHTML({
    host: '2600:1901:0:9e23::',
    identity: { kind: 'ipv6', org: 'Google Cloud' },
    agents: ['claude', 'codex'],
    count: 4, last_seen: '2026-01-01T10:00:00Z', first_seen: '2026-01-01T09:00:00Z',
    sessions: [{ id: 'abcdefgh1234', harness: 'claude', repo: 'secure-agent', branch: 'main' }],
    events: [{ ts: '2026-01-01T10:00:00Z', remote_port: 443, session_id: 'abcdefgh1234' }],
    allowed: [],
  }, 'claude');
  assert.match(html, /Google Cloud address/);
  assert.match(html, /Allow for claude/);
  assert.match(html, /Allow for codex/);
  assert.match(html, /secure-agent@main/);
  assert.match(html, /:443/);
  // Untrusted host string must be escaped.
  const evil = endpointDetailHTML({ host: '<script>x</script>', identity: {}, agents: [], sessions: [], events: [] }, '');
  assert.ok(!evil.includes('<script>'));
});

// ---------- session labels ----------

test('sessionLabelDurable falls back to the live tree cwd, not the session id', () => {
  // repo wins.
  assert.equal(sessionLabelDurable({ harness: 'claude', repo: 'secure-agent', branch: 'main' }), 'claude · secure-agent@main');
  // workspace next.
  assert.equal(sessionLabelDurable({ harness: 'codex', workspace: '/work/api' }), 'codex · api');
  // Unhelpful workspace "/" → use the joined process tree's cwd.
  assert.equal(sessionLabelDurable({ harness: 'claude', workspace: '/', id: 'proc-132' }, '/work/myrepo'), 'claude · myrepo');
  // Nothing usable → short id, never a bare "/".
  assert.equal(sessionLabelDurable({ harness: 'claude', workspace: '/', id: 'proc-132' }), 'claude · proc-132');
});

test('sessionRowsDurable passes the live tree cwd into the label', () => {
  const sessions = [{ id: 'proc-1', harness: 'claude', workspace: '/', status: 'active', root_pid: 10 }];
  const trees = [{ root: { pid: 10, name: 'claude', cwd: '/Volumes/work/alpha' }, children: [], rss_bytes: 100 }];
  const rows = sessionRowsDurable(sessions, trees);
  assert.equal(rows[0].label, 'claude · alpha');
});
