// Console worktrees tab tests — zero dependencies. Evaluates lib.js and
// tab-worktrees.js in one fresh VM context, as the browser loads them.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const webDist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../daemon/internal/api/web_dist');
const ctx = { window: {} };
vm.createContext(ctx);
for (const f of ['lib.js', 'tab-worktrees.js']) {
  vm.runInContext(readFileSync(path.join(webDist, f), 'utf8'), ctx, { filename: f });
}
const { worktreeStateCounts, worktreeGroups, worktreeRowHTML, worktreeGroupHTML, worktreePathLabel, worktreeFilterHTML, worktreesSummaryText, worktreeDiskHTML, worktreeSizeLabel, fmtDisk,
  clutterGroups, clutterItemHTML, clutterGroupHTML, clutterPillsHTML, clutterSummaryText } = ctx;

const REPO = '/Users/x/code/app';
const report = () => ({
  duration_ms: 36211, cached: false, stale_days: 14,
  summary: { repos: 2, worktrees: 4 },
  repos: [
    { path: REPO, default_branch: 'origin/main', source: 'session', worktrees: [
      { path: REPO, branch: 'main', state: 'main', reasons: [] },
      { path: REPO + '/.worktrees/done', branch: 'feat/done', state: 'remove', stale: true, last_activity: '2026-09-01T00:00:00Z', idle_days: 22, reasons: ['merged into origin/main (squash)'] },
      { path: REPO + '/.worktrees/gone', branch: 'feat/gone', state: 'prune', idle_days: 0, reasons: ['directory is gone; git still lists it'] },
    ] },
    { path: '/Users/x/code/lib', worktrees: [
      { path: '/Users/x/.codex/worktrees/ab/lib', detached: true, state: 'keep', last_activity: '2026-09-23T00:00:00Z', idle_days: 0, reasons: ['<img src=x onerror=alert(1)>'] },
      { path: '/Users/x/code/lib/.worktrees/ev', branch: 'feat/"q"', state: 'review', stale: true, last_activity: '2026-09-20T00:00:00Z', idle_days: 3, reasons: ['ignored files that only live here: .env (17 B)'] },
    ] },
  ],
});

test('worktreeStateCounts: main rows are not counted; stale counted across states', () => {
  const c = worktreeStateCounts(report());
  assert.deepEqual({ ...c }, { all: 4, remove: 1, review: 1, keep: 1, prune: 1, stale: 2 });
});

test('worktreeGroups: filters by state and stale, drops repos left empty', () => {
  assert.equal(worktreeGroups(report(), {}).length, 2);
  const removable = worktreeGroups(report(), { state: 'remove' });
  assert.equal(removable.length, 1);
  assert.deepEqual([...removable[0].rows.map(r => r.state)], ['remove']);
  const stale = worktreeGroups(report(), { stale: true });
  assert.deepEqual([...stale.flatMap(g => g.rows.map(r => r.state))], ['remove', 'review']);
});

test('worktreeRowHTML: Remove only on remove, Prune only on prune, Ask advisor on review and keep, everything escaped', () => {
  const rep = report();
  const [done, gone] = rep.repos[0].worktrees.slice(1);
  const [keep, review] = rep.repos[1].worktrees;
  const doneHTML = worktreeRowHTML(done, rep.repos[0]);
  assert.match(doneHTML, /data-action="worktree-remove" data-path="\/Users\/x\/code\/app\/\.worktrees\/done" data-branch="feat\/done"/);
  assert.ok(!doneHTML.includes('worktree-prune'));
  assert.match(doneHTML, /<span class="wt-idle">22d idle<\/span>/);
  assert.match(doneHTML, /<span class="wt-stale">stale<\/span>/);
  const goneHTML = worktreeRowHTML(gone, rep.repos[0]);
  assert.match(goneHTML, /data-action="worktree-prune" data-repo="\/Users\/x\/code\/app"/);
  assert.match(goneHTML, /<span class="wt-idle">—<\/span>/);
  const keepHTML = worktreeRowHTML(keep, rep.repos[1]);
  assert.deepEqual([...keepHTML.matchAll(/data-action="([a-z-]+)"/g)].map(m => m[1]), ['worktree-ask', 'worktree-advise']);
  assert.ok(keepHTML.includes('&lt;img src=x onerror=alert(1)&gt;') && !keepHTML.includes('<img'));
  assert.match(keepHTML, /<span class="wt-branch">\(detached\)<\/span>/);
  const reviewHTML = worktreeRowHTML(review, rep.repos[1]);
  assert.deepEqual([...reviewHTML.matchAll(/data-action="([a-z-]+)"/g)].map(m => m[1]), ['worktree-ask', 'worktree-advise']);
  assert.ok(!doneHTML.includes('worktree-advise') && !goneHTML.includes('worktree-advise'));
  assert.ok(!doneHTML.includes('worktree-ask') && !goneHTML.includes('worktree-ask'));
  assert.ok(reviewHTML.includes('feat/&quot;q&quot;'));
});

test('worktreePathLabel: relative inside the repo, absolute outside', () => {
  assert.equal(worktreePathLabel(REPO + '/.worktrees/done', REPO), '.worktrees/done');
  assert.equal(worktreePathLabel(REPO + '/.worktrees/done', REPO + '/'), '.worktrees/done');
  assert.equal(worktreePathLabel('/Users/x/code/app-other/x', REPO), '/Users/x/code/app-other/x');
});

test('worktreeFilterHTML and summary line', () => {
  const html = worktreeFilterHTML(worktreeStateCounts(report()), { state: 'review', stale: true });
  assert.match(html, /class="wt-pill" data-action="worktree-filter" data-state="" aria-pressed="false">All <b>4<\/b>/);
  assert.match(html, /class="wt-pill on" data-action="worktree-filter" data-state="review" aria-pressed="true">Review <b>1<\/b>/);
  assert.match(html, /class="wt-pill on" data-action="worktree-stale" aria-pressed="true">Stale <b>2<\/b>/);
  assert.equal(worktreesSummaryText(report()), '2 repos · 4 worktrees · stale after 14 idle days · scanned in 36.2s');
  assert.equal(worktreesSummaryText({ ...report(), cached: true }), '2 repos · 4 worktrees · stale after 14 idle days · cached scan');
});

test('advisor notes: shown under their row, escaped, and never change the actions', () => {
  const rep = report();
  const keep = rep.repos[1].worktrees[0];
  const note = { assessment: 'remove', confidence: 0.8, rationale: '<script>alert(1)</script> looks disposable' };
  const html = worktreeRowHTML(keep, rep.repos[1], note);
  assert.ok(html.includes('<p class="wt-advice"><b>Advisor: remove</b> 80% · &lt;script&gt;alert(1)&lt;/script&gt; looks disposable</p>'));
  assert.ok(!html.includes('worktree-remove'), 'a remove note must not add a Remove button');
  const group = worktreeGroupHTML({ repo: rep.repos[1], rows: rep.repos[1].worktrees }, { [keep.path]: note });
  assert.equal((group.match(/class="wt-advice"/g) || []).length, 1);
  assert.ok(!worktreeRowHTML(keep, rep.repos[1]).includes('wt-advice'));
});

test('disk: volumes with a used bar, worktree and removable totals, reclaimed', () => {
  const html = worktreeDiskHTML({
    sizing: true,
    summary: { size_bytes: 3 * 1073741824, removable_bytes: 1073741824 },
    volumes: [{ mount: '/Volumes/<Work>', total_bytes: 2 * 1099511627776, free_bytes: 0.5 * 1099511627776 }],
    reclaimed: { bytes: 1610612736, count: 2, bytes_30d: 536870912, count_30d: 1 },
  });
  assert.ok(html.includes('<span class="wt-vol-name">/Volumes/&lt;Work&gt;</span>'));
  assert.ok(html.includes('data-w="75"'));
  assert.ok(html.includes('512.0 GB free of 2.0 TB'));
  assert.ok(html.includes('<b>Worktrees</b> 3.0 GB <span class="wt-measuring">measuring…</span>'));
  assert.ok(html.includes('<b>Removable</b> 1.0 GB'));
  assert.ok(html.includes('<b>Reclaimed</b> 1.5 GB over 2 cleanups · 512 MB in 30 days'));
  assert.ok(worktreeDiskHTML({ summary: {}, volumes: [] }).includes('<b>Reclaimed</b> nothing yet'));
});

test('sizes: row label, lower bound, repo groups biggest first', () => {
  assert.equal(worktreeSizeLabel({ size_bytes: 1610612736 }), '1.5 GB');
  assert.equal(worktreeSizeLabel({ size_bytes: 5242880, size_partial: true }), '≥5.0 MB');
  assert.equal(worktreeSizeLabel({}), '');
  assert.equal(fmtDisk(3 * 1099511627776), '3.0 TB');
  const rep = report();
  rep.repos[0].size_bytes = 10;
  rep.repos[1].size_bytes = 1000;
  assert.deepEqual([...worktreeGroups(rep, {}).map(g => g.repo.path)], ['/Users/x/code/lib', REPO]);
  const row = worktreeRowHTML({ ...rep.repos[0].worktrees[1], size_bytes: 1610612736 }, rep.repos[0]);
  assert.ok(row.includes('<span class="wt-size">1.5 GB</span>'));
});

const clutterReport = () => ({
  sizing: false,
  items: [
    { kind: 'tool-cache', name: 'go build', path: '/Users/x/Library/Caches/go-build', size_bytes: 8589934592, last_touched: '2026-09-22T00:00:00Z', idle_days: 1, action: 'clean', command: 'go clean -cache' },
    { kind: 'tmp', name: '.tmp', path: REPO + '/.tmp', project: REPO, size_bytes: 1048576, last_touched: '2026-09-01T00:00:00Z', idle_days: 22, action: 'trash' },
    { kind: 'repo-cache', name: 'node_modules', path: REPO + '/node_modules', project: REPO, size_bytes: 2097152, action: 'trash' },
    { kind: 'tool-cache', name: 'Hugging Face models', path: '/Users/x/.cache/huggingface', size_bytes: 1024, action: 'none', note: '<b>downloaded</b> models' },
  ],
  kinds: [{ kind: 'tmp', bytes: 1048576, count: 1 }, { kind: 'repo-cache', bytes: 2097152, count: 1 }, { kind: 'tool-cache', bytes: 8589935616, count: 2 }],
  reclaimed: { trashed_bytes: 3145728, trashed_count: 2 },
});

test('clutter: groups by project biggest first, machine caches under This machine, kind filter', () => {
  const groups = clutterGroups(clutterReport(), {});
  assert.deepEqual([...groups.map(g => g.project)], ['', REPO]);
  assert.equal(groups[1].bytes, 3145728);
  assert.deepEqual([...clutterGroups(clutterReport(), { kind: 'tmp' }).map(g => g.items.length)], [1]);
});

test('clutter: Move to Trash on trash items, Run <command> on clean items, nothing on list-only; escaped', () => {
  const rep = clutterReport();
  const trash = clutterItemHTML(rep.items[1], REPO);
  assert.match(trash, /data-action="clutter-trash" data-path="\/Users\/x\/code\/app\/\.tmp">Move to Trash<\/button>/);
  assert.ok(trash.includes('<span class="wt-path" title="/Users/x/code/app/.tmp">.tmp</span>'));
  assert.ok(trash.includes('<span class="wt-idle">22d idle</span>'));
  const clean = clutterItemHTML(rep.items[0], '');
  assert.match(clean, /data-action="clutter-clean" data-name="go build" title="go clean -cache">Run go clean -cache<\/button>/);
  assert.ok(clean.includes('<span class="wt-size">8.0 GB</span>'));
  const none = clutterItemHTML(rep.items[3], '');
  assert.ok(!none.includes('data-action='));
  assert.ok(none.includes('&lt;b&gt;downloaded&lt;/b&gt; models'));
});

test('clutter: pills carry bytes per kind; summary counts clearable bytes and what went to the Trash', () => {
  const pills = clutterPillsHTML(clutterReport(), { kind: 'tmp' });
  assert.ok(pills.includes('data-kind="" aria-pressed="false">All <b>8.0 GB</b>'));
  assert.ok(pills.includes('class="wt-pill on" data-action="clutter-filter" data-kind="tmp" aria-pressed="true">.tmp <b>1.0 MB</b>'));
  assert.equal(clutterSummaryText(clutterReport()),
    '4 items · 8.0 GB clearable · 3.0 MB moved to the Trash by cleanups (frees when the Trash is emptied)');
});

test('clutter: a project shows 8 rows until expanded', () => {
  const items = Array.from({ length: 11 }, (_, i) => ({ kind: 'repo-cache', name: 'node_modules', path: REPO + '/p' + i + '/node_modules', project: REPO, size_bytes: 1000 - i, action: 'trash' }));
  const g = { project: REPO, items, bytes: 0 };
  const closed = clutterGroupHTML(g, new Set());
  assert.equal((closed.match(/class="wt-row cl-row/g) || []).length, 8);
  assert.ok(closed.includes('data-action="clutter-more" data-project="/Users/x/code/app">Show 3 more</button>'));
  assert.ok(closed.includes('<span class="wt-repo-meta">11 items</span>'));
  const open = clutterGroupHTML(g, new Set([REPO]));
  assert.equal((open.match(/class="wt-row cl-row/g) || []).length, 11);
  assert.ok(!open.includes('clutter-more'));
});

test('clutter: Ask advisor on every project, "machine" for machine caches; the plan renders escaped, one step per line', () => {
  const g = { project: REPO, items: [], bytes: 0 };
  const plain = clutterGroupHTML(g, new Set());
  assert.ok(plain.includes('data-action="clutter-advise" data-project="/Users/x/code/app">Ask advisor</button>'));
  assert.ok(!plain.includes('cl-plan'));
  const machine = clutterGroupHTML({ project: '', items: [], bytes: 0 }, new Set(), { machine: { rationale: 'ok' } });
  assert.ok(machine.includes('data-action="clutter-advise" data-project="machine">Ask advisor</button>'));
  assert.ok(machine.includes('<div class="wt-advice cl-plan"><b>Advisor:</b> ok</div>'));
  const planned = clutterGroupHTML(g, new Set(), { [REPO]: { rationale: '<b>old</b> scratch', suggested_action: 'Trash .tmp\n\n<i>ask</i> feat/x' } });
  assert.ok(planned.includes('<b>Advisor:</b> &lt;b&gt;old&lt;/b&gt; scratch<ol><li>Trash .tmp</li><li>&lt;i&gt;ask&lt;/i&gt; feat/x</li></ol></div>'));
});

test('agent asks: status line under the row, escaped; Ask the agent disabled while one runs', () => {
  const rep = report();
  const keep = rep.repos[1].worktrees[0];
  const answered = worktreeRowHTML(keep, rep.repos[1], null,
    { harness: 'claude', status: 'answered', verdict: 'pr', detail: 'https://x/pull/<9>', cost_usd: 0.21 });
  assert.ok(answered.includes('<p class="wt-ask wt-ask-answered"><b>Asked claude:</b> pr — https://x/pull/&lt;9&gt; ($0.21)</p>'));
  const running = worktreeRowHTML(keep, rep.repos[1], null, { harness: 'codex', status: 'running' });
  assert.ok(running.includes("waiting for codex&#39;s answer…") || running.includes("waiting for codex's answer…"));
  assert.match(running, /data-action="worktree-ask" data-path="[^"]+" disabled>Ask the agent<\/button>/);
  const failed = worktreeRowHTML(keep, rep.repos[1], null, { harness: 'codex', status: 'timeout', verdict: 'none', detail: 'no answer within 15m0s' });
  assert.ok(failed.includes('wt-ask-timeout') && failed.includes('timeout — no answer within 15m0s'));
});
