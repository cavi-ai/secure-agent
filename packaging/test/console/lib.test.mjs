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
// tab-overview.js declares functions only, so its renderers evaluate in the
// same context on top of lib.js.
vm.runInContext(readFileSync(path.join(webDist, 'tab-overview.js'), 'utf8'), ctx, { filename: 'tab-overview.js' });
// tab-agents.js declares functions only too (the Processes rows).
vm.runInContext(readFileSync(path.join(webDist, 'tab-agents.js'), 'utf8'), ctx, { filename: 'tab-agents.js' });
const {
  escapeHTML, fmtTime, eventKey, eventTime, eventsNewestFirst, eventRow, eventWho,
  advanceBuckets, bucketIndexFor, sparkPoints,
  parseMarkdownToHTML, buildEvidenceChain,
  sessionShort, filterEventsBySession, rollupSeries, flagHost,
  familyTitle, fmtRSS, fmtAge, isFamilyRoot, childrenOf,
  groupAgentsByHarness, agentGroupTotals, applyAgentFilters,
  cwdLabel, sessionRows, filterEventsByPids, sessionBoardHTML,
  fmtCPU, resourceImpact, resourceSparkPoints, resourceDiagnosisText,
  monitorVendorKeyIDs, inspectionVisible, vendorKeyPromoteHTML,
  scopedBySession, unactedLast24h, filterSessionRows, sseNeedsSnapshot,
  sessionStripRows, sessionNeedsYou, sessionStripHTML,
  harnessMeta, harnessChipHTML, advisorAdviceHTML,
  endpointIdentityLine, endpointDetailHTML,
  sessionTitle, groupSessionsByHarness, applySessionFilters, familySize,
  sessionGroupCounts, sessionCountStrip, harnessPillsHTML, middleTruncate,
  hbarsHTML, sessionWaterfallHTML, applyInlineMetrics, resourceHostContextHTML,
  fmtUSD, topCostRows,
  familyLabel, cappedList, resourceNeedsAttention, resourceFamilyGroups,
  memoryRowsByFamily, renderChartMemory,
  mapPostureAttention,
  originAgent, fmtHHMM, collapseSessionFamilies, collapseFamilyRows,
} = ctx;

// ---------- spend ----------

test('fmtUSD: two decimals, thousands separators, sub-cent floor', () => {
  assert.equal(fmtUSD(0), '$0.00');
  assert.equal(fmtUSD(0.004), '<$0.01');
  assert.equal(fmtUSD(36.674), '$36.67');
  assert.equal(fmtUSD(1234.5), '$1,234.50');
  assert.equal(fmtUSD(undefined), '$0.00');
});

test('topCostRows sorts by cost desc, then calls, slices, and tolerates missing data', () => {
  const report = { rows: [
    { key: 'b', cost_usd: 0.1, calls: 1 },
    { key: 'c', cost_usd: 0, calls: 9 },
    { key: 'a', cost_usd: 5, calls: 2 },
    { key: 'd', cost_usd: 0, calls: 3 },
  ] };
  assert.deepEqual([...topCostRows(report, 3)].map(r => r.key), ['a', 'b', 'c']);
  assert.deepEqual(report.rows.map(r => r.key), ['b', 'c', 'a', 'd'], 'input not mutated');
  assert.deepEqual([...topCostRows(undefined, 5)], []);
  assert.deepEqual([...topCostRows({}, 5)], []);
  assert.deepEqual([...topCostRows({ rows: null }, 5)], []);
});

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

test('eventKey: tool_call rows key by session + call id, so same-ts calls differ', () => {
  const a = { ts: 't', pid: 0, kind: 12, session_id: 's1', call_id: 'c1' };
  const b = { ts: 't', pid: 0, kind: 12, session_id: 's1', call_id: 'c2' };
  assert.equal(eventKey(a), '12|s1|c1');
  assert.notEqual(eventKey(a), eventKey(b));
});

test('eventKey: model_call rows key by session, ts, model and tokens, so same-ts calls with different tokens differ', () => {
  const a = { ts: 't', pid: 0, kind: 14, session_id: 's1', model: 'claude-sonnet-4-5', tokens_in: 100, tokens_out: 10 };
  const b = { ts: 't', pid: 0, kind: 14, session_id: 's1', model: 'claude-sonnet-4-5', tokens_in: 200, tokens_out: 10 };
  assert.equal(eventKey(a), '14|s1|t|claude-sonnet-4-5|100|10');
  assert.notEqual(eventKey(a), eventKey(b));
});

test('eventKey: a file_open key is unchanged', () => {
  assert.equal(eventKey({ ts: 't', pid: 1, kind: 0, path: 'p' }), 't|1|0|p');
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

test('groupAgentsByHarness: harness groups by recency, instances with helpers, infra apart', () => {
  const at = (min) => new Date(Date.UTC(2026, 0, 1, 12, 0) - min * 60000).toISOString();
  const groups = groupAgentsByHarness([
    { pid: 1, name: 'claude', root_pid: 1, last_seen_at: at(9), rss_bytes: 100, cpu_percent: 10, repo: 'api', branch: 'main' },
    { pid: 2, name: 'claude', root_pid: 1, ppid: 1, last_seen_at: at(1), rss_bytes: 50, cpu_percent: 5 },
    { pid: 5, name: 'claude-code', root_pid: 5, last_seen_at: at(3), rss_bytes: 7, workspace: '/w/web' },
    { pid: 3, name: 'cursor', root_pid: 3, last_seen_at: at(60), rss_bytes: 10, is_orphan: true },
    { pid: 4, name: 'codex', root_pid: 4, last_seen_at: at(2), rss_bytes: 20 },
    { pid: 6, name: 'ollama', root_pid: 6, last_seen_at: at(0), rss_bytes: 900 },
    { pid: 7, name: 'modelsrv', kind: 'infra', root_pid: 7, last_seen_at: at(0), rss_bytes: 30 },
  ]);
  // Newest activity first; infra flagged, whatever its position.
  assert.equal(groups.map(g => g.key).join(','), 'modelsrv,ollama,claude,codex,cursor');
  assert.equal(groups.filter(g => g.infra).map(g => g.key).join(','), 'modelsrv,ollama');
  const claude = groups.find(g => g.key === 'claude');
  assert.equal(claude.label, 'Claude Code');
  // claude and claude-code are one harness; instances newest first.
  assert.equal(claude.instances.map(i => i.root.pid).join(','), '5,1');
  assert.equal(claude.instances[1].children.map(c => c.pid).join(','), '2');
  const t = agentGroupTotals(claude);
  assert.equal(t.instances, 2);
  assert.equal(t.processes, 3);
  assert.equal(t.rss, 157);
  assert.equal(t.cpu, 15);
  assert.equal(t.lastSeen, at(1));
  const cursor = agentGroupTotals(groups.find(g => g.key === 'cursor'));
  assert.equal(cursor.orphans, 1);
  // No process reported CPU: no figure, rather than a misleading 0%.
  assert.equal(cursor.cpu, null);
  assert.equal(fmtCPU(cursor.cpu), '');
});

test('applyAgentFilters: shared pills and text; infra untouched', () => {
  const groups = groupAgentsByHarness([
    { pid: 1, name: 'claude', root_pid: 1, repo: 'api', branch: 'main' },
    { pid: 2, name: 'claude', root_pid: 1, ppid: 1, cwd: '/w/api/special' },
    { pid: 3, name: 'claude', root_pid: 3, workspace: '/w/docs' },
    { pid: 4, name: 'codex', root_pid: 4, cwd: '/w/etl' },
    { pid: 6, name: 'ollama', root_pid: 6 },
  ]);
  const keys = (gs) => gs.map(g => g.key).join(',');
  assert.equal(keys(applyAgentFilters(groups, {})), keys(groups));
  assert.equal(keys(applyAgentFilters(groups, { harnesses: { claude: false } })).split(',').sort().join(','), 'codex,ollama');
  const docs = applyAgentFilters(groups, { text: 'DOCS' });
  assert.equal(keys(docs).split(',').sort().join(','), 'claude,ollama');
  assert.equal(docs.find(g => g.key === 'claude').instances.map(i => i.root.pid).join(','), '3');
  // cwd matches, and a helper's match keeps its whole instance.
  assert.equal(applyAgentFilters(groups, { text: '/w/etl' }).map(g => g.key).sort().join(','), 'codex,ollama');
  const special = applyAgentFilters(groups, { text: 'special' }).find(g => g.key === 'claude');
  assert.equal(special.instances[0].root.pid, 1);
  assert.equal(special.instances[0].children[0].pid, 2);
  // Input untouched.
  assert.equal(groups.find(g => g.key === 'claude').instances.length, 2);
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
  claude: 'Claude Code', 'claude-desktop': 'Claude', codex: 'Codex', cursor: 'Cursor', 'cursor-ide': 'Cursor',
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
  // claude-desktop is the Claude app hosting Code conversations: Claude's mark, infra.
  assert.equal(harnessMeta('claude-desktop').logo, harnessMeta('claude').logo);
  assert.equal(harnessMeta('claude-desktop').infra, true);
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

test('the session pulse animates only when motion is allowed; reduce stops transitions', () => {
  const uses = [...styleCSS.matchAll(/animation:\s*sc-breathe/g)];
  assert.equal(uses.length, 1);
  const guard = styleCSS.lastIndexOf('@media (prefers-reduced-motion: no-preference) {', uses[0].index);
  assert.ok(guard >= 0 && !styleCSS.slice(guard, uses[0].index).includes('}'),
    'the pulse animation must sit inside the no-preference block');
  assert.match(styleCSS, /@media \(prefers-reduced-motion: reduce\) \{\s*\* \{ animation: none !important; transition: none !important; \}/);
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
  assert.match(unknown, /data-harness-color="hsl\(\d+ 62% 62%\)"/);
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

// ---------- harness-first session rail ----------

// lib.js runs in its own VM realm: compare its arrays structurally.
const same = (actual, expected, msg) => assert.deepEqual(JSON.parse(JSON.stringify(actual)), expected, msg);
const T = (min) => new Date(Date.UTC(2026, 0, 1, 12, 0) - min * 60000).toISOString();
const railSessions = () => [
  { id: 'c1', harness: 'claude', repo: 'api', branch: 'main', status: 'active', last_seen_at: T(5) },
  { id: 'c2', harness: 'claude', repo: 'api', branch: 'main', status: 'idle', last_seen_at: T(1) },
  { id: 'c3', harness: 'claude', workspace: '/w/docs', status: 'ended', last_seen_at: T(90) },
  { id: 'c4', harness: 'claude', workspace: '/w/web', status: 'ended', last_seen_at: T(30) },
  { id: 'x1', harness: 'codex', repo: 'etl', branch: 'feat/x', status: 'active', last_seen_at: T(2) },
  { id: 'u1', harness: 'cursor', workspace: '/w/app', status: 'ended', last_seen_at: T(10) },
  { id: 'o1', harness: 'opencode', workspace: '/w/tool', status: 'ended', last_seen_at: T(20) },
];

test('groupSessionsByHarness orders groups by live recency and sinks ended-only groups', () => {
  const groups = groupSessionsByHarness(railSessions(), [], []);
  // codex (live 2m) before claude (live 5m; its idle 1m does not outrank an
  // active session inside the group but does count for group recency).
  same(groups.map(g => g.key), ['claude', 'codex', 'cursor', 'opencode']);
  const claude = groups[0];
  assert.equal(claude.label, 'Claude Code');
  // Active before idle, then the ended tail newest first.
  same(claude.live.map(f => f.session.id), ['c1', 'c2']);
  same(claude.ended.map(f => f.session.id), ['c4', 'c3']);
  assert.equal(sessionGroupCounts(claude), '1 active · 1 idle · 2 ended');
  // Ended-only groups keep their newest-first order at the bottom.
  same(groups.slice(2).map(g => g.live.length), [0, 0]);
  assert.ok(groups.every(g => g.infra === false));
});

test('groupSessionsByHarness nests sub-sessions one level under the top-most parent', () => {
  const sessions = [
    { id: 'p', harness: 'claude', repo: 'api', status: 'active', last_seen_at: T(9) },
    { id: 'k1', harness: 'claude', parent_id: 'p', status: 'active', last_seen_at: T(1) },
    { id: 'k2', harness: 'claude', parent_id: 'k1', status: 'idle', last_seen_at: T(3) }, // grandchild flattens
    { id: 'gone', harness: 'claude', status: 'ended', last_seen_at: T(60) },
    { id: 'orphan', harness: 'claude', parent_id: 'gone', status: 'active', last_seen_at: T(4) }, // live under an ended parent
    { id: 'cross', harness: 'codex', parent_id: 'p', status: 'active', last_seen_at: T(2) }, // other harness
    { id: 'missing', harness: 'claude', parent_id: 'not-listed', status: 'idle', last_seen_at: T(7) },
    { id: 'loopA', harness: 'claude', parent_id: 'loopB', status: 'ended', last_seen_at: T(70) },
    { id: 'loopB', harness: 'claude', parent_id: 'loopA', status: 'ended', last_seen_at: T(80) },
    { id: 'intoLoop', harness: 'claude', parent_id: 'loopA', status: 'ended', last_seen_at: T(85) },
  ];
  const [claude, codex] = groupSessionsByHarness(sessions, [], []);
  const fam = claude.live.find(f => f.session.id === 'p');
  same(fam.children.map(s => s.id), ['k1', 'k2']);
  same(claude.live.map(f => f.session.id), ['p', 'orphan', 'missing']);
  assert.equal(codex.key, 'codex');
  same(codex.live.map(f => f.session.id), ['cross']);
  assert.equal(familySize(claude.live), 5);
  // A parent_id cycle terminates and keeps every session exactly once.
  const endedIds = claude.ended.flatMap(f => [f.session.id, ...f.children.map(c => c.id)]).sort();
  same(endedIds, ['gone', 'intoLoop', 'loopA', 'loopB']);
});

test('groupSessionsByHarness folds infra into one trailing group of RSS totals', () => {
  const sessions = [
    ...railSessions(),
    { id: 'm1', harness: 'ollama', status: 'active', last_seen_at: T(0) },
    { id: 'i1', harness: 'cursor-ide', status: 'active', last_seen_at: T(0) },
    { id: 'z1', harness: 'modelsrv', status: 'active', last_seen_at: T(0) },
  ];
  const agents = [
    { pid: 1, name: 'ollama', kind: 'infra', rss_bytes: 3000 },
    { pid: 2, name: 'modelsrv', kind: 'infra', rss_bytes: 500 },
    { pid: 3, name: 'cursor-ide', kind: 'infra', rss_bytes: 1000 },
    { pid: 4, name: 'claude', kind: 'agent', rss_bytes: 99999 },
  ];
  const flat = groupSessionsByHarness(sessions, [], agents);
  const keys = flat.map(g => g.key);
  for (const k of ['ollama', 'cursor-ide', 'modelsrv']) assert.ok(!keys.includes(k), `${k} leaked into the rail`);
  const infra = flat[flat.length - 1];
  assert.equal(infra.key, 'infra');
  assert.equal(infra.infra, true);
  assert.equal(infra.label, 'Infrastructure');
  same(infra.items.map(i => [i.key, i.rss]), [['ollama', 3000], ['cursor-ide', 1000], ['modelsrv', 500]]);
  assert.equal(infra.rss, 4500);
  // Live trees, when present, are the RSS source (helpers included).
  const trees = [
    { root: { pid: 1, name: 'ollama', kind: 'infra' }, children: [{ pid: 9 }], rss_bytes: 7000 },
    { root: { pid: 4, name: 'claude', kind: 'agent' }, children: [], rss_bytes: 1 },
  ];
  const withTrees = groupSessionsByHarness(sessions, trees, agents);
  same(withTrees[withTrees.length - 1].items.map(i => [i.key, i.rss]), [['ollama', 7000]]);
  // No infra anywhere → no infra group.
  assert.ok(groupSessionsByHarness(railSessions(), [], []).every(g => !g.infra));
});

test('applySessionFilters: pills, text over repo/branch/workspace, live only', () => {
  const agents = [{ pid: 1, name: 'ollama', kind: 'infra', rss_bytes: 10 }];
  const groups = groupSessionsByHarness(railSessions(), [], agents);
  const keys = (gs) => gs.map(g => g.key);
  // No options: everything, infra last.
  same(keys(applySessionFilters(groups, {})), ['claude', 'codex', 'cursor', 'opencode', 'infra']);
  // A pill switched off hides only its group.
  same(keys(applySessionFilters(groups, { harnesses: { claude: false } })), ['codex', 'cursor', 'opencode', 'infra']);
  // Live only drops ended-only groups but keeps a live group's ended tail.
  const live = applySessionFilters(groups, { liveOnly: true });
  same(keys(live), ['claude', 'codex', 'infra']);
  assert.equal(live[0].ended.length, 2);
  // Text matches repo, branch, repo@branch, and workspace.
  same(keys(applySessionFilters(groups, { text: 'FEAT/' })), ['codex', 'infra']);
  same(keys(applySessionFilters(groups, { text: 'api@main' })), ['claude', 'infra']);
  const docs = applySessionFilters(groups, { text: '/w/docs' });
  same(keys(docs), ['claude', 'infra']);
  same(docs[0].live, []);
  same(docs[0].ended.map(f => f.session.id), ['c3']);
  // A family stays whole when only a sub-session matches.
  const nested = groupSessionsByHarness([
    { id: 'p', harness: 'claude', repo: 'api', status: 'active', last_seen_at: T(1) },
    { id: 'k', harness: 'claude', parent_id: 'p', workspace: '/w/special', status: 'active', last_seen_at: T(1) },
  ], [], []);
  const hit = applySessionFilters(nested, { text: 'special' });
  assert.equal(hit[0].live[0].session.id, 'p');
  assert.equal(hit[0].live[0].children[0].id, 'k');
  // The input groups are not mutated.
  assert.equal(groups[0].ended.length, 2);
});

test('sessionCountStrip counts live sessions and harnesses and shows coverage', () => {
  const groups = groupSessionsByHarness(railSessions(), [], [{ pid: 1, name: 'ollama', kind: 'infra' }]);
  assert.equal(sessionCountStrip(groups, { harnesses_active: 3, harnesses_seen: 2 }), 'Sessions 3 · Harnesses 2 · seeing 2/3');
  assert.equal(sessionCountStrip(groups, null), 'Sessions 3 · Harnesses 2');
  assert.equal(sessionCountStrip(groups, { harnesses_active: 0, harnesses_seen: 0 }), 'Sessions 3 · Harnesses 2');
  assert.equal(sessionCountStrip([], null), 'Sessions 0 · Harnesses 0');
});

test('harnessPillsHTML renders a delegated toggle per harness', () => {
  const html = harnessPillsHTML(['claude', 'codex'], { codex: false });
  assert.match(html, /class="harness-pill" data-action="toggle-harness" data-harness="claude" aria-pressed="true"/);
  assert.match(html, /class="harness-pill off" data-action="toggle-harness" data-harness="codex" aria-pressed="false"/);
  assert.match(html, /#logo-claude/);
  assert.match(html, /<span class="harness-label">Codex<\/span>/);
  assert.ok(!harnessPillsHTML(['"><img src=x>'], {}).includes('<img'));
  assert.equal(harnessPillsHTML([], {}), '');
});

test('middleTruncate keeps both ends of a long path', () => {
  assert.equal(middleTruncate('/short', 20), '/short');
  const out = middleTruncate('/Users/dev/workspace/deeply/nested/api-service', 24);
  assert.equal(out.length, 24);
  assert.ok(out.startsWith('/Users/dev'));
  assert.ok(out.endsWith('api-service'));
  assert.ok(out.includes('…'));
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

// ---------- session titles ----------

test('sessionTitle names the work, never the harness', () => {
  // repo wins.
  assert.equal(sessionTitle({ harness: 'claude', repo: 'secure-agent', branch: 'main' }), 'secure-agent@main');
  assert.equal(sessionTitle({ harness: 'claude', repo: 'secure-agent' }), 'secure-agent');
  // workspace next.
  assert.equal(sessionTitle({ harness: 'codex', workspace: '/work/api' }), 'api');
  // Unhelpful workspace "/" → use the joined process tree's cwd.
  assert.equal(sessionTitle({ harness: 'claude', workspace: '/', id: 'proc-132' }, '/work/myrepo'), 'myrepo');
  // Nothing usable → short id, never a bare "/".
  assert.equal(sessionTitle({ harness: 'claude', workspace: '/', id: 'proc-132' }), 'proc-132');
});

// ---------- CSP: no inline style attributes ----------
// The daemon serves the console with style-src 'self', which drops style
// attributes parsed from markup; sizes ride in data attributes instead.

test('percentage-sized renderers emit no style attributes', () => {
  const html = {
    hbars: hbarsHTML([{ label: 'a', value: 4 }, { label: 'b', value: 1 }]),
    waterfall: sessionWaterfallHTML([
      { kind: 12, ts: '2026-01-01T00:00:00Z', duration_ms: 2000, tool: 'Bash' },
      { kind: 5, ts: '2026-01-01T00:00:01Z' },
    ]),
    unknownChip: harnessChipHTML('mystery-agent'),
    hostMemory: resourceHostContextHTML({
      total_memory_bytes: 8 * 1024 ** 3, available_memory_bytes: 4 * 1024 ** 3,
      memory_pressure: 'normal', agent_memory_percent: 25, non_agent_memory_bytes: 2 * 1024 ** 3,
    }),
  };
  for (const [name, h] of Object.entries(html)) assert.ok(!h.includes('style='), `${name}: ${h}`);
  assert.match(html.hbars, /class="hbar-fill " data-w="100\.0"/);
  assert.match(html.hbars, /class="hbar-fill " data-w="25\.0"/);
  assert.match(html.waterfall, /class="wf-bar" data-left="0\.00" data-w="100\.00"/);
  assert.match(html.waterfall, /class="wf-dot conn" data-left="50\.00"/);
  assert.match(html.hostMemory, /class="resource-host-segment agent" data-w="25\.0"/);
  assert.match(html.hostMemory, /class="resource-host-segment other" data-w="25\.0"/);
  assert.match(html.hostMemory, /class="resource-host-segment available" data-w="50\.0"/);
});

test('index.html carries no style attributes', () => {
  assert.ok(!/\sstyle=/.test(indexHTML), 'index.html: move inline styles into style.css');
});

test('applyInlineMetrics writes the data attributes through the CSSOM', () => {
  const set = [];
  const el = dataset => ({ dataset, style: { setProperty: (k, v) => set.push(`${k}=${v}`) } });
  const bar = el({ left: '10.00', w: '42.50' });
  const glyph = el({ harnessColor: 'hsl(1 62% 62%)' });
  const found = { '[data-left]': [bar], '[data-w]': [bar], '[data-harness-color]': [glyph] };
  applyInlineMetrics({ querySelectorAll: sel => found[sel] || [] });
  assert.deepEqual(set, ['left=10.00%', 'width=42.50%', '--harness-color=hsl(1 62% 62%)']);
});

test('ruleTitle falls back to the shared title for secret-in-transcript', () => {
  const had = 'window' in ctx;
  const prev = ctx.window;
  ctx.window = {};
  try {
    assert.equal(ctx.ruleTitle('secret-in-transcript'), 'Secret appeared in an agent transcript');
  } finally {
    if (had) ctx.window = prev; else delete ctx.window;
  }
});

// ---------- finding card v2: the served explanation ----------

const EXPLAIN_NOW = Date.parse('2026-09-23T10:02:00Z');
const explainFlag = (over = {}) => ({
  id: 'f1', rule: 'sensitive-read-then-connect', agent: 'claude', pid: 4242,
  ts: '2026-09-23T10:00:00Z', severity: 3,
  explain: {
    what: 'Claude read a sensitive file in Claude skills (~/.claude/skills), then reached AWS 3 s later.',
    subject: { path: '/Users/me/.claude/skills/x/config', display: '~/.claude/skills/x/config', basename: 'config',
      category: 'other_sensitive', category_label: 'sensitive file', owner_label: 'Claude skills (~/.claude/skills)' },
    egress: [{ host: '2600:1f10:4a1b::fd73', port: 443, org: 'AWS', kind: 'ipv6', allowlisted: false, gap_seconds: 3 }],
    context: { harness: 'claude-code', repo: 'api', branch: 'main' },
    disposition: { state: 'benign-likely', text: 'Likely benign (advisor 93 %)', why: 'Skill config sync.' },
    actions: [],
    ...over,
  },
});

test('explainLines: who is agent · repo@branch, never a pid', () => {
  const l = ctx.explainLines(explainFlag(), EXPLAIN_NOW);
  assert.equal(l.who, 'claude · api@main');
  assert.equal(ctx.explainLines(explainFlag({ context: { repo: 'api' } }), EXPLAIN_NOW).who, 'claude · api');
  assert.ok(!/4242|pid/i.test(JSON.stringify(l)), JSON.stringify(l));
});

test('explainLines: who falls back to the harness, then the agent alone', () => {
  assert.equal(ctx.explainLines(explainFlag({ context: { harness: 'claude-code' } }), EXPLAIN_NOW).who, 'claude · claude-code');
  assert.equal(ctx.explainLines(explainFlag({ context: { harness: 'claude' } }), EXPLAIN_NOW).who, 'claude');
  assert.equal(ctx.explainLines(explainFlag({ context: undefined }), EXPLAIN_NOW).who, 'claude');
});

test('explainLines: meta is the read→connect gap then the age; no gap without egress', () => {
  assert.equal(ctx.explainLines(explainFlag(), EXPLAIN_NOW).meta, '3 s gap · 2m ago');
  const eg = (gap) => [{ host: 'api.example.com', port: 443, kind: 'dns', allowlisted: false, gap_seconds: gap }];
  assert.equal(ctx.explainLines(explainFlag({ egress: eg(120) }), EXPLAIN_NOW).meta, '2 min gap · 2m ago');
  assert.equal(ctx.explainLines(explainFlag({ egress: eg(-3) }), EXPLAIN_NOW).meta, '3 s gap · 2m ago');
  assert.equal(ctx.explainLines(explainFlag({ egress: [] }), EXPLAIN_NOW).meta, '2m ago');
  assert.equal(ctx.explainLines(explainFlag({ egress: undefined }), EXPLAIN_NOW).meta, '2m ago');
  // gap_seconds is 0 without a read item: no subject, no gap.
  assert.equal(ctx.explainLines(explainFlag({ subject: undefined, egress: eg(0) }), EXPLAIN_NOW).meta, '2m ago');
});

test('explainLines: what is the served sentence; verdict is text plus why', () => {
  const l = ctx.explainLines(explainFlag(), EXPLAIN_NOW);
  assert.equal(l.what, 'Claude read a sensitive file in Claude skills (~/.claude/skills), then reached AWS 3 s later.');
  assert.equal(l.verdict, 'Likely benign (advisor 93 %): Skill config sync.');
  const bare = ctx.explainLines(explainFlag({ disposition: { state: 'critical', text: 'Act now', why: '' } }), EXPLAIN_NOW);
  assert.equal(bare.verdict, 'Act now');
});

test('explainLines: cls follows disposition.state', () => {
  const cls = (state) => ctx.explainLines(explainFlag({ disposition: { state, text: 't', why: '' } }), EXPLAIN_NOW).cls;
  assert.equal(cls('acknowledged'), 'disp-acknowledged');
  assert.equal(cls('benign-likely'), 'disp-benign');
  assert.equal(cls('warning'), 'disp-warning');
  assert.equal(cls('critical'), 'disp-critical');
});

test('explainLines: null without explain', () => {
  assert.equal(ctx.explainLines({ id: 'x', rule: 'r', agent: 'a', pid: 1, evidence: [] }, EXPLAIN_NOW), null);
});

test('explainActionsHTML: recommended first, kill danger, others ghost; no pid, no IPv6 label; allow-path offered', () => {
  const host = '2600:1f10:4a1b::fd73';
  const f = explainFlag({ actions: [
    { id: 'allow-host', label: `Allow ${host} (AWS) for claude`, consequence: `Future connections from claude to ${host} are trusted.`,
      method: 'POST', path: '/allowlist', body: { agent: 'claude', host } },
    { id: 'allow-path', label: 'Always allow this file for claude', consequence: 'c', method: 'POST', path: '/guard/path-allow', body: {} },
    { id: 'mute-rule-host', label: 'Stop flagging this for <b>x</b>', consequence: 'c', method: 'POST', path: '/mute',
      body: { rule: 'sensitive-read-then-connect', host: 'x' } },
    { id: 'dismiss', label: 'Dismiss this flag', consequence: 'c', method: 'POST', path: '/flags/acknowledge', body: { flag_id: 'f1' } },
    { id: 'kill', label: 'Kill claude (pid 4242)', consequence: 'c', method: 'POST', path: '/kill', body: { pid: 4242 }, recommended: true },
  ] });
  const html = ctx.explainActionsHTML(f);
  const ids = [...html.matchAll(/data-action-id="([^"]+)"/g)].map(m => m[1]);
  assert.deepEqual(ids, ['kill', 'allow-host', 'allow-path', 'mute-rule-host', 'dismiss']);
  assert.match(html, /<button class="btn btn-danger btn-sm" data-action="explain-act" data-flag-id="f1" data-action-id="kill"/);
  assert.match(html, /class="btn btn-ghost btn-sm" data-action="explain-act" data-flag-id="f1" data-action-id="dismiss"/);
  assert.match(html, new RegExp(`data-action-id="allow-host" data-host="${host}"`));
  assert.match(html, />Allow this AWS address for claude</);
  assert.match(html, />Kill claude</);
  assert.match(html, /Stop flagging this for &lt;b&gt;x&lt;\/b&gt;/);
  const text = html.replace(/<[^>]*>/g, ' ');
  assert.ok(!/\bpid\b|4242|2600:/i.test(text), text);
  const rec = ctx.explainActionsHTML(explainFlag({ actions: [
    { id: 'dismiss', label: 'Dismiss this flag', consequence: 'c', method: 'POST', path: '/flags/acknowledge', body: { flag_id: 'f1' } },
    { id: 'allow-host', label: 'Allow api.example.com for claude', consequence: 'c', method: 'POST', path: '/allowlist',
      body: { agent: 'claude', host: 'api.example.com' }, recommended: true },
  ] }));
  assert.match(rec, /^<button class="btn btn-primary btn-sm" data-action="explain-act" data-flag-id="f1" data-action-id="allow-host"/);
  assert.equal(ctx.explainActionsHTML({ id: 'x' }), '');
});

// ---------- resources v2: names, capped lists, attention, harness groups ----------

const famSessions = [
  { id: 's-claude', harness: 'claude', repo: 'api-service', branch: 'main', workspace: '/w/api-service', root_pid: 100 },
  { id: 's-codex', harness: 'codex', workspace: '/w/data-pipeline', root_pid: 200 },
];

test('familyLabel: harness · repo@branch from the session joined by root pid', () => {
  assert.equal(familyLabel({ root_pid: 100, name: 'claude', workspace: '/w/elsewhere' }, famSessions), 'Claude Code · api-service@main');
  assert.equal(familyLabel({ root_pid: 9, name: 'claude' }, [{ harness: 'claude', repo: 'x', root_pid: 9 }]), 'Claude Code · x');
});

test('familyLabel: workspace folder without a repo; the family cwd when no session joins', () => {
  assert.equal(familyLabel({ root_pid: 200, name: 'codex', workspace: '/elsewhere' }, famSessions), 'Codex · data-pipeline');
  assert.equal(familyLabel({ root_pid: 555, name: 'claude', workspace: '/Users/franco' }, famSessions), 'Claude Code · franco');
});

test('familyLabel: the harness name alone, never a pid', () => {
  assert.equal(familyLabel({ root_pid: 7001, name: 'ollama', workspace: '/' }, []), 'Ollama');
  const numeric = familyLabel({ root_pid: 3755, name: 'codex', workspace: '/private/tmp/3755' }, null);
  assert.equal(numeric, 'Codex');
  for (const f of [{ root_pid: 100, name: 'claude' }, { root_pid: 200, name: 'codex' }, { root_pid: 42 }]) {
    assert.ok(!familyLabel(f, famSessions).includes(String(f.root_pid)), JSON.stringify(f));
  }
});

// ---------- memory by family ----------

const memTrees = [
  { root: { pid: 3432, name: 'claude', cwd: '/Applications/Claude.app' }, rss_bytes: 10522669875 },
  { root: { pid: 999, name: 'codex', cwd: '/Users/dev/workspace/data-pipeline' }, rss_bytes: 209715200 },
];
const memSessions = [
  ...Array.from({ length: 27 }, (_, i) => ({ id: `claude-${i}`, harness: 'claude', root_pid: 3432, repo: 'worktree-hunter', branch: 'main' })),
  { id: 'codex-1', harness: 'codex', root_pid: 999, workspace: '/Users/dev/workspace/data-pipeline' },
  { id: 'gone', harness: 'claude', root_pid: 4242, repo: 'ghost' },
];

test('memoryRowsByFamily: one row per live family, its RSS once, the session count in the label', () => {
  const rows = memoryRowsByFamily(memSessions, memTrees);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].label, 'Claude Code · worktree-hunter@main · 27 sessions');
  assert.equal(rows[0].rss, 10522669875);
  assert.equal(rows[0].infra, false);
  assert.equal(rows[1].label, 'Codex · data-pipeline');
  assert.equal(rows[1].rss, 209715200);
  assert.ok(!rows.some(r => r.label.includes('ghost')));
});

test('memoryRowsByFamily: a family is infra when its live tree root is infra', () => {
  const rows = memoryRowsByFamily([...memSessions, { id: 'ollama-1', harness: 'ollama', root_pid: 7001 }],
    [...memTrees, { root: { pid: 7001, name: 'ollama', kind: 'infra', cwd: '/' }, rss_bytes: 820000000 }]);
  assert.deepEqual(Array.from(rows, r => [r.pid, r.infra]), [[3432, false], [7001, true], [999, false]]);
});

test('renderChartMemory: one keyed bar per family; the badge counts agent families, not sessions or infra', () => {
  const saved = {};
  for (const k of ['window', 'document', 'patchList']) saved[k] = [k in ctx, ctx[k]];
  const chart = { innerHTML: '', querySelectorAll: () => [] };
  const badge = { textContent: '' };
  let got = null;
  const trees = [...memTrees, { root: { pid: 7001, name: 'ollama', kind: 'infra', cwd: '/' }, rss_bytes: 820000000 }];
  ctx.window = { SA: { t: { status: { trees }, sessions: [...memSessions, { id: 'ollama-1', harness: 'ollama', root_pid: 7001 }] } } };
  ctx.document = { getElementById: id => ({ 'chart-memory': chart, 'chart-mem-total': badge })[id] || null };
  ctx.patchList = (container, items, opts) => { got = { container, items, opts }; };
  try {
    renderChartMemory();
    assert.equal(badge.textContent, 2);
    assert.equal(got.container, chart);
    assert.deepEqual(Array.from(got.items, f => String(got.opts.key(f))), ['3432', '7001', '999']);
    const bars = got.items.map(got.opts.html);
    assert.ok(bars.every(b => b.startsWith('<div class="hbar-row">')));
    assert.equal(bars.filter(b => b.includes('27 sessions')).length, 1);
    assert.equal(bars.filter(b => b.includes('class="hbar-sub">infra<')).length, 1);
    // Process-tree fallback (no sessions): infra still comes from the root.
    ctx.window.SA.t.sessions = [];
    renderChartMemory();
    assert.equal(badge.textContent, 2);
    assert.deepEqual(Array.from(got.items, f => [String(got.opts.key(f)), f.infra]), [['3432', false], ['7001', true], ['999', false]]);
  } finally {
    for (const [k, [had, prev]] of Object.entries(saved)) if (had) ctx[k] = prev; else delete ctx[k];
  }
});

test('cappedList: the first limit rows, a Show N more button, the whole list once expanded', () => {
  const items = Array.from({ length: 20 }, (_, i) => i);
  const row = i => `<i>${i}</i>`;
  const c = cappedList(items, 12, row, 'family-procs:k', new Set());
  assert.equal(c.shown.length, 12);
  assert.equal(c.hidden, 8);
  assert.match(c.more, /<button type="button" [^>]*data-action="show-more" data-key="family-procs:k"[^>]*>Show 8 more<\/button>/);
  assert.equal((c.html.match(/<i>/g) || []).length, 12);
  assert.ok(c.html.endsWith(c.more));
  const open = cappedList(items, 12, row, 'family-procs:k', new Set(['family-procs:k']));
  assert.equal(open.shown.length, 20);
  assert.equal(open.hidden, 0);
  assert.equal(open.more, '');
  const short = cappedList([1, 2], 12, row, 'x');
  assert.equal(short.hidden, 0);
  assert.equal(short.more, '');
  assert.equal(short.html, '<i>1</i><i>2</i>');
  assert.match(cappedList(items, 1, row, '"><x', new Set()).more, /data-key="&quot;&gt;&lt;x"/);
});

test('resourceNeedsAttention: only families with a diagnosis, never infra, highest impact first, at most 5', () => {
  const GiB = 1024 ** 3;
  const fam = (key, rss, cpu, codes, kind) => ({ key, rss_bytes: rss * GiB, cpu_percent: cpu, kind, diagnoses: codes.map(code => ({ code })) });
  const list = [
    fam('quiet-big', 9, 0, []),
    fam('a', 1, 10, ['orphan-drift']),
    fam('b', 6, 20, ['heavy-memory']),
    fam('c', 2, 250, ['heavy-cpu']),
    fam('d', 3, 0, ['idle-heavy']),
    fam('e', 2.5, 0, ['rapid-growth']),
    fam('f', 1.5, 0, ['runaway-child']),
    fam('infra', 10, 0, ['heavy-memory'], 'infra'),
  ];
  assert.deepEqual(resourceNeedsAttention(list).map(f => f.key), ['c', 'b', 'd', 'e', 'f']);
  assert.deepEqual(resourceNeedsAttention(list, 2).map(f => f.key), ['c', 'b']);
  assert.deepEqual([...resourceNeedsAttention([fam('q', 1, 1, [])])], []);
  assert.deepEqual([...resourceNeedsAttention(null)], []);
});

test('resourceFamilyGroups: harness groups by memory, children nested under their orchestrator, infra trailing and uncounted', () => {
  const MB = 1024 ** 2;
  const f = (key, name, pid, rss, cpu, kind) => ({ key, name, root_pid: pid, rss_bytes: rss * MB, cpu_percent: cpu, kind });
  const families = [
    f('claude-a', 'claude', 100, 500, 10),
    f('codex-a', 'codex', 200, 300, 5),
    f('oc', 'openclaw', 300, 100, 1),
    f('oc-kid-1', 'codex', 301, 800, 30),
    f('oc-kid-2', 'codex', 302, 50, 2),
    f('claude-b', 'claude', 110, 900, 0),
    f('ollama', 'ollama', 700, 4000, 3, 'infra'),
    f('lms', 'lm-studio', 701, 2000, 1, 'infra'),
  ];
  const sessions = [
    { id: 's-oc', harness: 'openclaw', root_pid: 300 },
    { id: 's-kid-1', harness: 'codex', root_pid: 301, parent_id: 's-oc' },
    // A grandchild flattens under the top: one indent, never two.
    { id: 's-kid-2', harness: 'codex', root_pid: 302, parent_id: 's-kid-1' },
  ];
  const groups = resourceFamilyGroups(families, sessions);
  assert.deepEqual([...groups].map(g => g.key), ['claude', 'openclaw', 'codex', 'infra']);
  const [claude, oc, codex, infra] = groups;
  assert.equal(claude.label, 'Claude Code');
  assert.deepEqual([...claude.rows].map(r => r.family.key), ['claude-b', 'claude-a']);
  assert.equal(claude.families, 2);
  assert.equal(claude.rss, 1400 * MB);
  assert.equal(claude.cpu, 10);
  assert.equal(oc.rows.length, 1);
  assert.deepEqual([...oc.rows[0].children].map(c => c.key), ['oc-kid-1', 'oc-kid-2']);
  assert.equal(oc.families, 3);
  assert.equal(oc.rss, 950 * MB);
  assert.equal(oc.cpu, 33);
  assert.deepEqual([...codex.rows].map(r => r.family.key), ['codex-a']);
  assert.equal(infra.infra, true);
  assert.equal(infra.label, 'Infrastructure');
  assert.deepEqual([...infra.rows].map(r => r.family.key), ['ollama', 'lms']);
  assert.equal(groups.filter(g => !g.infra).reduce((n, g) => n + g.families, 0), 6);
  // A parent_id cycle has no top: both families stay top-level.
  const cyc = resourceFamilyGroups([f('x', 'codex', 1, 1, 0), f('y', 'codex', 2, 2, 0)],
    [{ id: 'sx', root_pid: 1, parent_id: 'sy' }, { id: 'sy', root_pid: 2, parent_id: 'sx' }]);
  assert.deepEqual([...cyc[0].rows].map(r => r.family.key), ['y', 'x']);
  assert.ok(cyc[0].rows.every(r => r.children.length === 0));
  // Infra never nests and nothing nests under infra.
  const inf = resourceFamilyGroups([f('m', 'ollama', 5, 1, 0, 'infra'), f('k', 'codex', 6, 1, 0)],
    [{ id: 'sm', root_pid: 5 }, { id: 'sk', root_pid: 6, parent_id: 'sm' }]);
  assert.deepEqual([...inf].map(g => g.key), ['codex', 'infra']);
});

// Minimal element for paintDrawerBack: children, id lookup, insertBefore,
// remove and click listeners.
class FakeEl {
  constructor(doc, tag, id = '') {
    this.ownerDocument = doc; this.tagName = tag; this.id = id;
    this.children = []; this.parent = null; this.listeners = {}; this.textContent = '';
  }
  querySelector(sel) {
    for (const c of this.children) {
      if ('#' + c.id === sel) return c;
      const hit = c.querySelector(sel);
      if (hit) return hit;
    }
    return null;
  }
  insertBefore(node, ref) {
    const i = ref ? this.children.indexOf(ref) : -1;
    node.parent = this;
    this.children.splice(i < 0 ? this.children.length : i, 0, node);
    return node;
  }
  remove() {
    if (!this.parent) return;
    this.parent.children.splice(this.parent.children.indexOf(this), 1);
    this.parent = null;
  }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  click() { (this.listeners.click || []).forEach(fn => fn({ type: 'click' })); }
}
const fakeDoc = { createElement: tag => new FakeEl(fakeDoc, tag) };

test('openDrawer back: the head shows ‹ label before the title and a click calls reopen once', () => {
  const head = new FakeEl(fakeDoc, 'header');
  const title = head.insertBefore(new FakeEl(fakeDoc, 'h3', 'drawer-title'), null);
  let calls = 0;
  const btn = ctx.paintDrawerBack(head, title, { label: 'Uninspected egress', reopen: () => { calls++; } });
  assert.equal(head.querySelector('#btn-drawer-back'), btn);
  assert.equal(btn.textContent, '‹ Uninspected egress');
  assert.equal(btn.className, 'btn btn-ghost drawer-back');
  assert.equal(head.children.indexOf(btn), head.children.indexOf(title) - 1);
  btn.click();
  assert.equal(calls, 1);
  ctx.paintDrawerBack(head, title, { label: 'Endpoint detail', reopen: () => {} });
  assert.equal(head.children.filter(c => c.id === 'btn-drawer-back').length, 1, 'a second open replaces the button');
});

test('openDrawer back: without back the button is absent', () => {
  const head = new FakeEl(fakeDoc, 'header');
  const title = head.insertBefore(new FakeEl(fakeDoc, 'h3', 'drawer-title'), null);
  assert.equal(ctx.paintDrawerBack(head, title, null), null);
  assert.equal(head.querySelector('#btn-drawer-back'), null);
  ctx.paintDrawerBack(head, title, { label: 'Uninspected egress', reopen: () => {} });
  ctx.paintDrawerBack(head, title, undefined);
  assert.equal(head.querySelector('#btn-drawer-back'), null, 'an open without back removes the previous button');
});

test('scopeBarHTML: session scope names the session and counts; pid scope names the family; unscoped is empty', () => {
  const s = ctx.scopeBarHTML({ session: '7f3a9c21-4b2e-4a1d-9c55-2e8f0d1a3b77', events: 12, flags: 1 });
  assert.match(s, /^<span>Scoped to session <b>[^<]+<\/b> · 12 events · 1 flag<\/span>/);
  assert.match(s, /data-action="clear-scope">Clear<\/button>$/);
  const p = ctx.scopeBarHTML({ pids: [5821, 5822], pidLabel: 'api-service <main>', events: 1, flags: 0 });
  assert.match(p, /^<span>Scoped to <b>api-service &lt;main&gt;<\/b> \(2 processes\) · 1 event · 0 flags<\/span>/);
  assert.equal(ctx.scopeBarHTML({ session: null, pids: null, events: 3, flags: 3 }), '');
  assert.equal(ctx.scopeBarHTML({ pids: [], events: 0, flags: 0 }), '');
});

test('attentionCount is posture.needs_you', () => {
  assert.equal(ctx.attentionCount({ needs_you: 13, groups: [{ items: [1, 2] }] }), 13);
  assert.equal(ctx.attentionCount({ needs_you: 0 }), 0);
  assert.equal(ctx.attentionCount(null), 0);
});

test('the tab bar is sticky and holds the posture pill and the scope bar', () => {
  const bar = indexHTML.split('id="tabs-bar"', 2)[1].split('<main>', 1)[0];
  assert.ok(bar.indexOf('<nav class="tabs" role="tablist"') >= 0);
  assert.ok(bar.indexOf('id="tabs-posture" data-action="goto-top"') > bar.indexOf('</nav>'));
  assert.ok(bar.indexOf('id="scope-bar"') > bar.indexOf('id="tabs-posture"'));
  assert.match(styleCSS, /\.tabs-bar \{\s*position: sticky; top: 0; z-index: 50;[^}]*background: var\(--bg-0\);/);
});

// ---------- optimistic attention removal ----------

test('mapPostureAttention: a removed item leaves items, groups and needs_you coherent', () => {
  const posture = {
    state: 'critical', summary: 's', needs_you: 4,
    items: [
      { kind: 'flag', id: 'f1' }, { kind: 'guard_pending', id: 'g1' },
      { kind: 'resource_pressure', id: 'r1' }, { kind: 'incident', id: 'i1' },
    ],
    groups: [
      { key: 'a', items: [{ kind: 'flag', id: 'f1' }, { kind: 'guard', id: 'g1' }] },
      { key: 'b', items: [{ kind: 'resource', id: 'r1' }, { kind: 'incident', id: 'i1' }] },
    ],
  };
  const sum = p => p.groups.reduce((n, g) => n + g.items.length, 0);
  const coherent = p => {
    assert.equal(p.needs_you, p.items.length);
    assert.equal(sum(p), p.needs_you);
  };

  let p = mapPostureAttention(posture, it => (it.kind === 'guard' && it.id === 'g1' ? null : it));
  assert.ok(!p.items.some(it => it.id === 'g1'));
  assert.equal(p.needs_you, 3);
  coherent(p);
  assert.equal(p.state, 'critical');
  assert.equal(p.summary, 's');

  p = mapPostureAttention(p, it => (it.kind === 'resource' && it.id === 'r1' ? null : it));
  assert.ok(!p.items.some(it => it.id === 'r1'));
  coherent(p);

  p = mapPostureAttention(p, it => (it.kind === 'incident' ? { ...it, status: 'acknowledged' } : it));
  assert.ok(p.items.some(it => it.id === 'i1'));
  assert.equal(p.needs_you, 2);
  coherent(p);

  p = mapPostureAttention(p, it => (it.kind === 'incident' ? null : it));
  assert.equal(p.groups.length, 1);
  assert.equal(p.needs_you, 1);
  coherent(p);
  assert.equal(posture.items.length, 4);
  assert.equal(posture.needs_you, 4);
});

// ---------- session origin: who spawned a session; identical rows fold ----------
const plain = (x) => JSON.parse(JSON.stringify(x));


test('sessionTitle appends the spawning agent when the session has an origin', () => {
  assert.equal(originAgent({ origin: 'martina (openclaw)' }), 'martina');
  assert.equal(originAgent({}), '');
  assert.equal(sessionTitle({ harness: 'codex', repo: 'career-ops', branch: 'main', origin: 'martina (openclaw)' }), 'career-ops@main · martina');
  assert.equal(sessionTitle({ harness: 'codex', workspace: '/Volumes/M/.openclaw', origin: 'margaret (openclaw)' }), '.openclaw · margaret');
  assert.equal(sessionTitle({ harness: 'codex', repo: 'career-ops', branch: 'main' }), 'career-ops@main');
});

test('familyLabel names the spawning agent of the joined session', () => {
  const sessions = [{ id: 'c1', harness: 'codex', repo: 'career-ops', branch: 'main', root_pid: 300, origin: 'martina (openclaw)' }];
  assert.equal(familyLabel({ root_pid: 300, name: 'codex', workspace: '/w' }, sessions), `${harnessMeta('codex').label} · martina`);
  assert.equal(familyLabel({ root_pid: 301, name: 'codex', workspace: '/w/api' }, sessions), `${harnessMeta('codex').label} · api`);
});

test('collapseSessionFamilies folds identical titles into one keyed row, stable across reorder', () => {
  const s = (id, started, status, extra) => ({ id, harness: 'codex', repo: 'career-ops', branch: 'main', started_at: started, status, ...(extra || {}) });
  const a = s('a', '2026-09-24T10:00:00Z', 'idle');
  const b = s('b', '2026-09-24T11:00:00Z', 'active');
  const c = s('c', '2026-09-24T09:00:00Z', 'active', { repo: 'api' });
  const fam = x => ({ session: x, children: [] });
  const title = x => sessionTitle(x);
  const rows = collapseSessionFamilies([fam(a), fam(c), fam(b)], 'codex', title);
  assert.equal(rows.length, 2);
  assert.deepEqual(plain(rows.map(r => r.key)), ['group:codex|career-ops@main', 'c']);
  assert.equal(rows[0].dup, true);
  assert.deepEqual(plain(rows[0].sessions.map(x => x.id)), ['b', 'a'], 'newest start first');
  assert.equal(rows[0].status, 'active', 'the most active member');
  assert.equal(rows[1].dup, false);
  const again = collapseSessionFamilies([fam(c), fam(b), fam(a)], 'codex', title);
  assert.deepEqual(plain(again.map(r => r.key).sort()), plain(rows.map(r => r.key).sort()));
  assert.deepEqual(plain(again.find(r => r.dup).sessions.map(x => x.id)), ['b', 'a']);
  // A family with sub-sessions never folds; a lone title stays a plain row.
  const parent = { session: s('p', '2026-09-24T08:00:00Z', 'active'), children: [s('k', '2026-09-24T08:30:00Z', 'active', { repo: 'x' })] };
  const mixed = collapseSessionFamilies([parent, fam(a)], 'codex', title);
  assert.deepEqual(plain(mixed.map(r => [r.key, r.dup])), [['p', false], ['a', false]]);
});

test('fmtHHMM reads a timestamp as local HH:MM', () => {
  const d = new Date(2026, 8, 24, 7, 5);
  assert.equal(fmtHHMM(d.toISOString()), '07:05');
  assert.equal(fmtHHMM(''), '');
});

test('collapseFamilyRows folds identical labels with summed memory, CPU and processes', () => {
  const sessions = [1, 2, 3].map(i => ({ id: 'm' + i, harness: 'codex', root_pid: 400 + i, origin: 'martina (openclaw)' }));
  const f = (pid, rss, cpu, n) => ({ key: `${pid}:1`, name: 'codex', root_pid: pid, rss_bytes: rss, cpu_percent: cpu, process_count: n });
  const rows = [f(401, 100, 1, 2), f(402, 300, 2, 3), f(999, 50, 1, 1), f(403, 200, 4, 1)].map(x => ({ family: x, children: [] }));
  const out = collapseFamilyRows(rows, 'codex', x => familyLabel(x, sessions));
  assert.equal(out.length, 2);
  const dup = out[0];
  assert.equal(dup.key, `group:codex|${harnessMeta('codex').label} · martina`);
  assert.equal(dup.families.length, 3);
  assert.deepEqual(plain([dup.rss_bytes, dup.cpu_percent, dup.process_count]), [600, 7, 6]);
  assert.deepEqual(plain(dup.families.map(x => x.root_pid)), [402, 403, 401], 'by memory');
  assert.equal(out[1].key, '999:1');
  const g = { key: 'codex', rows, families: 4, rss: 650, cpu: 8 };
  const shell = ctx.resourceFamilyGroupHTML(g, sessions, new Set());
  assert.match(shell, /<span class="family-group-counts">4 families · [^<]* CPU<\/span><\/summary>\s*<div class="family-group-body"><\/div>/, 'the shell carries counts and an empty body');
  const items = ctx.resourceFamilyGroupRows(g, sessions, new Set(), Date.now(), {});
  assert.deepEqual(plain(items.map(r => r.key)), [dup.key, '999:1'], 'body rows keyed by fold key and family key');
  const html = items.map(r => r.html).join('');
  assert.match(html, /data-action="toggle-family-dup" data-key="group:codex\|[^"]*martina" aria-expanded="false"><strong>[^<]*martina<\/strong><span class="family-dup-count">×3<\/span>/);
  const open = ctx.resourceFamilyGroupRows(g, sessions, new Set(), Date.now(), { [dup.key]: true }).map(r => r.html).join('');
  assert.equal((open.match(/class="family-row nested/g) || []).length, 3, 'expanded lists each family');
});

test('posture banner: Home lists nothing (the queue is the list)', () => {
  const items = [{ severity: 3, kind: 'flag', id: 'f1', title: 'a' }, { severity: 2, kind: 'flag', id: 'f2', title: 'b' }];
  assert.equal(ctx.postureItemsHTML(items, 'home', ['<li class="posture-advisor">x</li>']), '');
});

test('posture banner: other tabs cap content rows (items + extra) at 3, then "and N more" to Home', () => {
  const items = Array.from({ length: 7 }, (_, i) => ({ severity: 1, kind: 'uninspected_egress', id: 'u' + i, title: 'item ' + i }));
  const html = ctx.postureItemsHTML(items, 'egress', ['<li class="posture-advisor">advisor</li>']);
  // extra (1 line) counts toward the cap: only 2 items fit alongside it.
  assert.equal((html.match(/class="posture-item"/g) || []).length, 2);
  assert.match(html, /<li class="posture-more"><a href="#" data-action="goto-tab" data-tab="home">and 5 more<\/a><\/li>/);
  assert.ok(html.includes('item 1') && !html.includes('item 2'));
  assert.ok(html.endsWith('<li class="posture-advisor">advisor</li>'));
  assert.match(html, /data-action="open-uninspected">see endpoints</);
});

test('posture banner: content rows (items + extra) at exactly 3 need no "more" link', () => {
  const items = [
    { severity: 1, kind: 'uninspected_egress', id: 'u0', title: 'item 0' },
    { severity: 1, kind: 'uninspected_egress', id: 'u1', title: 'item 1' },
  ];
  const html = ctx.postureItemsHTML(items, 'egress', ['<li class="posture-advisor">advisor</li>']);
  assert.equal((html.match(/class="posture-item"/g) || []).length, 2);
  assert.ok(!html.includes('posture-more'));
  assert.ok(html.includes('item 0') && html.includes('item 1'));
  assert.ok(html.endsWith('<li class="posture-advisor">advisor</li>'));
});

test('posture banner: 3 or fewer items render all, no "more" link', () => {
  const items = [{ severity: 3, kind: 'incident', id: 'i<1', title: 'x' }];
  const html = ctx.postureItemsHTML(items, 'sessions', []);
  assert.equal((html.match(/class="posture-item"/g) || []).length, 1);
  assert.ok(!html.includes('posture-more'));
  assert.ok(html.includes('data-id="i&lt;1"'));
});

test('familyTitle: a known harness id shows its label; any other id keeps its case', () => {
  assert.equal(familyTitle('claude'), 'Claude Code');
  assert.equal(familyTitle('cursor-ide'), 'Cursor');
  assert.equal(familyTitle('lm-studio'), 'LM Studio');
  assert.equal(familyTitle('untagged:node'), 'untagged:node');
  assert.equal(familyTitle('lm-server'), 'lm-server');
  assert.equal(familyTitle(''), 'Unknown');
  assert.equal(ctx.harnessMeta('my-agent').label, 'my-agent');
  assert.equal(ctx.capFirst('nominal'), 'Nominal');
  assert.ok(!/\.egress-agent-name\s*\{[^}]*text-transform/.test(styleCSS), 'agent ids render in their own case');
});

test('attention subtitle: workspace "/" renders none; empty says why', () => {
  assert.equal(ctx.attentionSubtitle({ workspace: '/' }), '');
  assert.equal(ctx.attentionSubtitle({ workspace: '/Users/dev/api' }), '/Users/dev/api');
  assert.equal(ctx.attentionSubtitle({ key: 'machine' }), 'Monitoring gaps no agent session owns');
  assert.equal(ctx.attentionSubtitle({ key: 'agent:x', workspace: '' }), 'Signals could not be safely attributed to one live session');
});

// ---------- Events rows (trace legibility) ----------

test('eventRow labels each kind and details it from the /events fields', () => {
  const row = (e) => { const r = eventRow(e); return `${r.label}|${r.cls}|${r.detail}`; };
  assert.equal(row({ kind: 12, pid: 0, tool: 'Bash', tool_status: 'ok', duration_ms: 2500 }), 'TOOL|tool|Bash · ok · 2.5s');
  assert.equal(row({ kind: 12, pid: 0, tool: 'read_file', tool_status: 'running' }), 'TOOL|tool|read_file · running');
  assert.equal(row({ kind: 13, pid: 0, session_id: 's' }), 'TURN||');
  assert.equal(row({ kind: 14, pid: 0, model: 'claude-sonnet-4-5', tokens_in: 12000, tokens_out: 340, cost_usd: 0.0412 }),
    'MODEL||claude-sonnet-4-5 · 12.0k in / 340 out · $0.04');
  assert.equal(row({ kind: 14, pid: 0, model: 'gpt-5', tokens_in: 900, tokens_out: 12, cost_usd: 0.0021 }),
    'MODEL||gpt-5 · 900 in / 12 out · $0.0021');
  assert.equal(row({ kind: 14, pid: 0, model: 'kimi-k2', tokens_in: 10, tokens_out: 5, price_class: 'plan' }), 'MODEL||kimi-k2 · 10 in / 5 out · plan');
  assert.equal(row({ kind: 14, pid: 0, model: 'odd-model', tokens_in: 10, tokens_out: 5, price_class: 'unpriced-model' }), 'MODEL||odd-model · 10 in / 5 out · unpriced');
  assert.equal(row({ kind: 14, pid: 0, tokens_in: 1, tokens_out: 1 }), 'MODEL||unknown model · 1 in / 1 out · unpriced');
  assert.equal(row({ kind: 0, pid: 7, path: '/a/.env' }), 'OPEN||/a/.env');
  assert.equal(row({ kind: 1, pid: 7, path: '/a/b.ts' }), 'WRITE||/a/b.ts');
  assert.equal(row({ kind: 2, pid: 7, path: '/a/c.ts' }), 'DELETE||/a/c.ts');
  assert.equal(row({ kind: 3, pid: 7, exe_path: '/usr/bin/curl' }), 'EXEC||/usr/bin/curl');
  assert.equal(row({ kind: 5, pid: 7, remote_host: 'api.example.com', remote_port: 443 }), 'CONN|conn|api.example.com:443');
  assert.equal(row({ kind: 6, pid: 7, remote_host: '10.0.0.1', remote_port: 22 }), 'CONN|conn|10.0.0.1:22');
  assert.equal(row({ kind: 8, pid: 7, detail: 'Bash' }), 'TOOL USE|tool|Bash');
  assert.equal(row({ kind: 9, pid: 7, detail: 'aws-key' }), 'PROXY HIT|proxy|aws-key');
  assert.equal(row({ kind: 4, pid: 7, path: '/tcc' }), 'EVENT||/tcc');
});

test('eventWho names a pid-0 row by its session, else agent · PID', () => {
  const sessions = [{ id: 'sess-9', harness: 'hermes', repo: 'api-service', branch: 'main' }];
  const who = eventWho({ kind: 14, pid: 0, session_id: 'sess-9' }, sessions, '');
  assert.equal(who.text, 'api-service@main');
  assert.equal(who.harness, 'hermes');
  assert.ok(!who.text.includes('PID'));
  const unknown = eventWho({ kind: 12, pid: 0, session_id: 'abcdef1234567890' }, sessions, '');
  assert.ok(unknown.text.startsWith('session ') && !unknown.text.includes('PID'), unknown.text);
  assert.equal(eventWho({ kind: 0, pid: 42 }, sessions, 'Claude Code').text, 'Claude Code · PID 42');
  assert.equal(eventWho({ kind: 0, pid: 42 }, sessions, '').text, 'PID 42');
  assert.equal(eventWho({ kind: 0, pid: 42 }, sessions, '').title, 'PID 42');
});

test('eventTime shows HH:MM:SS today and the date on any other day', () => {
  const now = new Date(2026, 8, 24, 15, 0, 0);
  assert.equal(eventTime(new Date(2026, 8, 24, 9, 5, 7), now), '09:05:07');
  assert.equal(eventTime(new Date(2026, 4, 22, 13, 21, 7), now), 'May 22 13:21');
  assert.equal(eventTime(new Date(2026, 8, 23, 23, 59, 0), now), 'Sep 23 23:59');
});

test('eventsNewestFirst orders rows by ts descending without touching the input', () => {
  const input = [
    { ts: '2026-09-24T10:00:00.123456789Z', kind: 13 },
    { ts: '2026-05-22T13:21:07Z', kind: 12 },
    { ts: '2026-09-24T12:00:00-04:00', kind: 14 },
    { ts: '2026-09-24T10:00:01Z', kind: 0 },
  ];
  const out = eventsNewestFirst(input);
  assert.deepEqual(out.map(e => e.kind), [14, 0, 13, 12]);
  assert.equal(input[0].kind, 13);
});

test('applySessionFilters: text matches the spawning agent and the raw origin', () => {
  const groups = groupSessionsByHarness([
    { id: 'o1', harness: 'codex', repo: 'career-ops', branch: 'main', origin: 'martina (openclaw)', status: 'active', last_seen_at: T(1) },
    { id: 'o2', harness: 'codex', repo: 'career-ops', branch: 'main', status: 'active', last_seen_at: T(2) },
  ], [], []);
  const ids = (gs) => gs.flatMap(g => g.live.map(f => f.session.id));
  assert.deepEqual(plain(ids(applySessionFilters(groups, { text: 'martina' }))), ['o1']);
  assert.deepEqual(plain(ids(applySessionFilters(groups, { text: 'MARTINA (openclaw)' }))), ['o1']);
  assert.deepEqual(plain(ids(applySessionFilters(groups, { text: 'career-ops' }))), ['o1', 'o2']);
});

test('Processes row: a root whose /status tree root carries an origin names the agent', () => {
  const a = { pid: 4412, name: 'codex', cwd: '/Users/dev/.openclaw', root_pid: 4412 };
  const roots = new Map([[4412, { pid: 4412, name: 'codex', session_id: 's1', repo: 'career-ops', branch: 'main', origin: 'martina (openclaw)' }]]);
  const html = ctx.agentInstanceHTML({ root: a, children: [] }, Date.now(), {}, roots);
  assert.match(html, /<span class="agent-row-title">career-ops@main · martina<\/span>/);
  const bare = ctx.agentInstanceHTML({ root: a, children: [] }, Date.now(), {}, new Map());
  assert.match(bare, /<span class="agent-row-title">\.openclaw<\/span>/);
});
