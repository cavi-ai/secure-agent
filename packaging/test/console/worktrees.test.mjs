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
  clutterGroups, clutterItemHTML, clutterGroupHTML, clutterPillsHTML, clutterSummaryText,
  worktreeMatches, niceBytesCeil, removableEverywhere, reclaimTilesHTML, reclaimChartHTML, cleanupHistoryHTML, cleanupKind, cleanupEntryTitle,
  localDayKey, fmtDayKey, fmtElapsed, removalToastModel, removalToastHTML, reclaimDayText } = ctx;

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
  assert.deepEqual([...keepHTML.matchAll(/data-action="([a-z-]+)"/g)].map(m => m[1]), ['copy-path', 'worktree-reveal', 'worktree-ask', 'worktree-advise']);
  assert.ok(keepHTML.includes('&lt;img src=x onerror=alert(1)&gt;') && !keepHTML.includes('<img'));
  assert.match(keepHTML, /<span class="wt-branch">\(detached\)<\/span>/);
  const reviewHTML = worktreeRowHTML(review, rep.repos[1]);
  assert.deepEqual([...reviewHTML.matchAll(/data-action="([a-z-]+)"/g)].map(m => m[1]), ['copy-path', 'worktree-reveal', 'worktree-ask', 'worktree-advise']);
  // The path copies the full path; Show in Finder on every folder still on
  // disk (a prune row's folder is gone).
  assert.match(doneHTML, /<button type="button" class="wt-path" data-action="copy-path" data-path="\/Users\/x\/code\/app\/\.worktrees\/done" title="\/Users\/x\/code\/app\/\.worktrees\/done — click to copy">\.worktrees\/done<\/button>/);
  assert.ok(doneHTML.includes('data-action="worktree-reveal"') && !goneHTML.includes('worktree-reveal'));
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
  const at = Date.parse('2026-09-25T12:00:00Z');
  assert.equal(worktreesSummaryText({ ...report(), cached: true, generated_at: '2026-09-25T11:48:00Z', refreshing: true }, at),
    '2 repos · 4 worktrees · stale after 14 idle days · scanned 12m ago · refreshing…');
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
  // Removable and reclaimed moved to the tiles above.
  assert.ok(!html.includes('Removable') && !html.includes('Reclaimed'));
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
  assert.ok(clutterSummaryText({ ...clutterReport(), refreshing: true }).startsWith('4 items · 8.0 GB clearable · refreshing…'));
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

test('removals: step while running with Remove disabled; refusal and failure stay on the row, escaped', () => {
  const rep = report();
  const w = rep.repos[0].worktrees.find(x => x.state === 'remove');
  const running = worktreeRowHTML(w, rep.repos[0], null, null, { state: 'running', phase: 'deleting', step: 'deleting', bytes: 1610612736, files: 184203 });
  assert.ok(running.includes('<p class="wt-removal wt-removal-running" role="status"><span class="wt-steps" aria-hidden="true"><i class="on"></i><i class="on"></i><i class="on"></i><i class="on"></i></span><b>Removing…</b> deleting · 1.5 GB · 184,203 files</p>'));
  const checking = worktreeRowHTML(w, rep.repos[0], null, null, { state: 'running', phase: 'checking', step: 'checking it is still safe to remove' });
  assert.ok(checking.includes('<i class="on"></i><i class="on"></i><i class=""></i><i class=""></i></span><b>Removing…</b> checking it is still safe to remove</p>'));
  assert.ok(running.includes('disabled>Removing…</button>') && !running.includes('data-action="worktree-remove"'));
  const refused = worktreeRowHTML(w, rep.repos[0], null, null, { state: 'failed', row_state: 'keep', reasons: ['1 <b>untracked</b> file'] });
  assert.ok(refused.includes('<b>Not removed:</b> it is now keep — 1 &lt;b&gt;untracked&lt;/b&gt; file</p>'));
  assert.ok(refused.includes('>Try again</button>'));
  const failed = worktreeRowHTML(w, rep.repos[0], null, null, { state: 'failed', error: 'git worktree: signal: killed' });
  assert.ok(failed.includes('<p class="wt-removal wt-removal-failed" role="alert"><b>Removal failed:</b> git worktree: signal: killed</p>'));
  assert.ok(!worktreeRowHTML(w, rep.repos[0]).includes('wt-removal'));
});

test('state styles: each state has its own stripe and chip color; keep is not red', () => {
  const css = readFileSync(path.join(webDist, 'style.css'), 'utf8');
  const rule = sel => (css.match(new RegExp(sel.replace(/\./g, '\\.') + '\\s*\\{([^}]*)\\}')) || [])[1] || '';
  const stripes = ['remove', 'review', 'keep', 'prune'].map(st => rule(`.wt-row.wt-${st}`).match(/var\(--[a-z0-9-]+\)/)?.[0]);
  assert.equal(new Set(stripes).size, 4, `stripes ${stripes}`);
  const chips = ['remove', 'review', 'keep'].map(st => rule(`.wt-${st} .wt-state`).match(/color: (var\(--[a-z0-9-]+\))/)?.[1]);
  assert.equal(new Set(chips).size, 3, `chips ${chips}`);
  assert.ok(!rule('.wt-keep .wt-state').includes('--bad') && !rule('.wt-row.wt-keep').includes('--bad'), 'keep must not use the error red');
});

test('orphans: a missing repository comes first with its error; its folders offer Open folder, Reconnect when possible, Move to Trash', () => {
  const rep = report();
  const lost = '/Users/x/.cursor/worktrees/app/ctnj';
  const moved = '/Users/x/agents/wip';
  rep.repos.push({ path: '/gone/<b>app</b>', error: 'repository not found (moved or deleted)', size_bytes: 0, worktrees: [
    { path: lost, state: 'review', orphan: true, reasons: ['directory is not registered with git; its files are the only copy'] },
    { path: moved, state: 'review', orphan: true, reconnect: '/new/app', reasons: ['/new/app still records this worktree: Reconnect links it again'] },
  ] });
  const groups = worktreeGroups(rep, {});
  assert.equal(groups[0].repo.path, '/gone/<b>app</b>');
  const html = worktreeGroupHTML(groups[0]);
  assert.ok(html.includes('<span class="wt-repo-error">repository not found (moved or deleted) — the folders below still point to it</span>'));
  assert.ok(html.includes('&lt;b&gt;app&lt;/b&gt;') && !html.includes('worktree-hide'));
  const [a, b] = html.split('class="wt-row').slice(1);
  assert.ok(a.includes(`data-action="worktree-reveal" data-path="${lost}">Open folder</button>`));
  assert.ok(a.includes(`data-action="worktree-trash-orphan" data-path="${lost}">Move to Trash</button>`));
  assert.ok(!a.includes('worktree-reconnect') && !a.includes('worktree-ask') && !a.includes('worktree-advise'));
  assert.ok(b.includes(`data-action="worktree-reconnect" data-path="${moved}" data-repo="/new/app">Reconnect</button>`));
});

test('Remove all: offered for two or more removable rows with count and size; running removals do not count', () => {
  const rep = report();
  const repo = rep.repos[0];
  const one = worktreeGroupHTML({ repo, rows: repo.worktrees });
  assert.ok(!one.includes('worktree-remove-all'));
  const done = repo.worktrees.find(w => w.state === 'remove');
  repo.worktrees.push({ ...done, path: REPO + '/.worktrees/old', size_bytes: 1073741824 }, { ...done, path: REPO + '/.worktrees/older', size_bytes: 1073741824 });
  done.size_bytes = 1073741824;
  const three = worktreeGroupHTML({ repo, rows: repo.worktrees });
  assert.ok(three.includes(`data-action="worktree-remove-all" data-repo="${repo.path}">Remove all 3 · 3.0 GB</button>`));
  const running = worktreeGroupHTML({ repo, rows: repo.worktrees }, {}, {}, { [done.path]: { state: 'running' } });
  assert.ok(running.includes('>Remove all 2 · 2.0 GB</button>'));
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

test('search: rows whose branch, path or repository contains the text, any case', () => {
  const rep = report();
  assert.ok(worktreeMatches({ branch: 'feat/Done', path: '/x' }, { path: '/r' }, 'done'));
  assert.ok(worktreeMatches({ path: '/Users/x/code/app/.worktrees/a' }, { path: '/r' }, 'WORKTREES/A'));
  assert.ok(worktreeMatches({ path: '/x' }, { path: '/Users/x/code/lib' }, 'lib'));
  assert.ok(!worktreeMatches({ branch: 'feat/a', path: '/x' }, { path: '/r' }, 'zzz'));
  assert.ok(worktreeMatches({}, {}, '  '));
  const groups = worktreeGroups(rep, { q: 'ev' });
  assert.equal(JSON.stringify(groups.map(g => g.rows.map(w => w.path))), JSON.stringify([['/Users/x/code/lib/.worktrees/ev']]));
  assert.equal(JSON.stringify(worktreeGroups(rep, { q: 'feat/', state: 'remove' }).map(g => g.rows.length)), '[1]');
});

test('niceBytesCeil: 1, 2 or 5 × a power of ten in the printed unit', () => {
  const GB = 1073741824, MB = 1048576;
  assert.equal(niceBytesCeil(0), 0);
  assert.equal(niceBytesCeil(-5), 0);
  assert.equal(niceBytesCeil(1.2 * GB), 2 * GB);
  assert.equal(niceBytesCeil(3 * GB), 5 * GB);
  assert.equal(niceBytesCeil(6 * GB), 10 * GB);
  assert.equal(niceBytesCeil(420 * MB), 500 * MB);
  assert.equal(niceBytesCeil(1000), 1000);
  assert.equal(niceBytesCeil(1023 * MB), 2000 * MB);
  assert.equal(fmtDisk(niceBytesCeil(700 * GB)), fmtDisk(1000 * GB));
});

test('tiles: freed over the charted days, all time, removable now with Remove all across repositories, in the Trash', () => {
  const GB = 1073741824;
  const rep = report();
  rep.repos[0].worktrees.push({ path: REPO + '/.worktrees/old', branch: 'feat/old', state: 'remove', size_bytes: GB, reasons: [] });
  rep.repos[0].worktrees.find(w => w.state === 'remove').size_bytes = GB;
  rep.repos.push({ path: '/Users/x/gone', error: 'repository not found (moved or deleted)', worktrees: [
    { path: '/Users/x/.cursor/worktrees/gone/a', state: 'remove', orphan: true, size_bytes: 5 * GB, reasons: [] }] });
  const ledger = { totals: { bytes: 7 * GB, count: 9, trashed_bytes: 512 * 1048576, trashed_count: 2 },
    daily: [{ day: '2026-09-24', bytes: GB, trashed_bytes: 0, count: 1 }, { day: '2026-09-25', bytes: 2 * GB, trashed_bytes: 0, count: 2 }] };
  const html = reclaimTilesHTML(rep, ledger);
  const tile = cls => html.split(`class="rc-tile ${cls}"`)[1].split('</div>')[0];
  assert.match(tile('rc-freed'), /Freed · last 2 days[\s\S]*3\.0 GB[\s\S]*3 cleanups/);
  assert.match(tile('rc-alltime'), /Freed · all time[\s\S]*7\.0 GB[\s\S]*9 cleanups/);
  // Orphans and unreadable repositories never count as removable.
  assert.match(tile('rc-removable'), /Removable now[\s\S]*2\.0 GB[\s\S]*2 worktrees/);
  assert.ok(tile('rc-removable').includes('data-action="worktrees-remove-removable">Remove all 2</button>'));
  assert.match(tile('rc-trash'), /In the Trash[\s\S]*512 MB[\s\S]*frees when the Trash is emptied/);
  assert.equal(removableEverywhere(rep).rows.length, 2);
  // A running removal leaves the count; one removable row offers no Remove all.
  rep.removals = { [REPO + '/.worktrees/old']: { state: 'running' } };
  const one = reclaimTilesHTML(rep, ledger);
  assert.ok(!one.includes('worktrees-remove-removable') && one.includes('1 worktree<'));
  // Before the ledger loads, the report's totals stand in.
  const early = reclaimTilesHTML({ ...report(), reclaimed: { bytes: GB, count: 1, bytes_30d: GB, count_30d: 1, trashed_bytes: 0 } }, null);
  assert.match(early, /Freed · last 30 days[\s\S]*1\.0 GB[\s\S]*1 cleanup</);
});

test('chart: a column per day on one axis, freed under Trash, buttons only on days with cleanups, escaped', () => {
  const GB = 1073741824;
  const daily = [
    { day: '2026-09-23', bytes: 0, trashed_bytes: 0, count: 0 },
    { day: '2026-09-24', bytes: GB, trashed_bytes: GB, count: 2 },
    { day: '2026-09-25', bytes: 3 * GB, trashed_bytes: 0, count: 1 },
  ];
  const html = reclaimChartHTML(daily, '2026-09-25');
  assert.equal((html.match(/class="rc-col"/g) || []).length, 3);
  assert.equal((html.match(/data-action="reclaim-day"/g) || []).length, 2);
  // Axis top 5 GB: 2 GB is 40 %, split 50/50; 3 GB is 60 %, all freed.
  assert.ok(html.includes('data-day="2026-09-24"') && html.includes('<span class="rc-stack rc-some" data-h="40">'));
  assert.ok(html.includes('<i class="rc-seg rc-seg-trash" data-h="50"></i>') && html.includes('<i class="rc-seg rc-seg-freed" data-h="50"></i>'));
  assert.ok(html.includes('<span class="rc-stack rc-some" data-h="60">'));
  assert.ok(html.includes('aria-label="Yesterday: 1.0 GB freed by 2 cleanups, 1.0 GB moved to the Trash by 0 cleanups"'));
  assert.ok(html.includes('aria-label="Today: 3.0 GB freed by 1 cleanup"'));
  assert.ok(html.includes('<span>5.0 GB</span><span>2.5 GB</span><span>0</span>'));
  assert.ok(html.includes('<span>Sep 23</span><span>Sep 24</span><span>Today</span>'));
  assert.ok(html.includes('rc-key-freed') && html.includes('rc-key-trash'));
  // A day's column counts every cleanup; the Freed tile counts those that
  // freed space, like the all-time totals.
  const split = [{ day: '2026-09-25', bytes: GB, count: 1, trashed_bytes: GB, trashed_count: 2 }];
  assert.ok(reclaimChartHTML(split, '2026-09-25').includes('data-count="1" data-trash="1073741824" data-trash-count="2"'));
  assert.ok(reclaimChartHTML(split, '2026-09-25').includes('aria-label="Today: 1.0 GB freed by 1 cleanup, 1.0 GB moved to the Trash by 2 cleanups"'));
  assert.equal(JSON.stringify(reclaimDayText(0, 0, 5, 1)), JSON.stringify(['0 B freed by 0 cleanups', '5 B moved to the Trash by 1 cleanup']));
  assert.ok(reclaimChartHTML([{ day: '2026-09-25', bytes: 0, count: 0, trashed_bytes: 0, trashed_count: 1 }], '2026-09-25').includes('data-action="reclaim-day"'));
  assert.match(reclaimTilesHTML(report(), { totals: { count: 1 }, daily: split }), /Freed · last 1 days[\s\S]*1 cleanup</);
  const quiet = reclaimChartHTML([{ day: '2026-09-25', bytes: 0, trashed_bytes: 0, count: 0 }], '2026-09-25');
  assert.ok(quiet.includes('Nothing reclaimed in the last 1 days') && !quiet.includes('reclaim-day'));
  assert.equal(reclaimChartHTML([], '2026-09-25'), '');
  assert.ok(reclaimChartHTML([{ day: '<b>', bytes: 1, count: 1 }]).includes('data-day="&lt;b&gt;"'));
});

test('days: local keys, labels by hand, Today and Yesterday', () => {
  assert.equal(localDayKey(new Date(2026, 8, 5, 23, 59)), '2026-09-05');
  assert.equal(localDayKey('nonsense'), '');
  assert.equal(fmtDayKey('2026-09-25', '2026-09-25'), 'Today');
  assert.equal(fmtDayKey('2026-09-24', '2026-09-25'), 'Yesterday');
  assert.equal(fmtDayKey('2026-08-31', '2026-09-01'), 'Yesterday');
  assert.equal(fmtDayKey('2026-09-20', '2026-09-25'), 'Sep 20');
  assert.equal(fmtDayKey('2026-09-20', '2026-09-25', true), 'Sun, Sep 20');
  assert.equal(fmtElapsed(4200), '4s');
  assert.equal(fmtElapsed(72000), '1m 12s');
});

test('history: newest first by local day with bytes, kind and day filters, titles per action, escaped', () => {
  const GB = 1073741824;
  const at = (d, h, m) => new Date(2026, 8, d, h, m).toISOString();
  const ledger = { limit: 500, entries: [
    { ts: at(25, 15, 10), action: 'worktree-remove', path: '/r/app/.worktrees/done', repo: '/r/app', bytes: GB, detail: 'branch feat/done kept; merged into origin/main' },
    { ts: at(25, 11, 0), action: 'trash:orphan-worktree', path: '/r/.cursor/worktrees/app/ctnj', repo: '/r/app', bytes: 512 * 1048576 },
    { ts: at(25, 9, 0), action: 'ask:pr', path: '/r/app/.worktrees/ev', repo: '/r/app', detail: 'claude answered: <b>pr</b>' },
    { ts: at(23, 18, 5), action: 'clean:go', path: '/Users/x/Library/Caches/go-build', bytes: 2 * GB, detail: 'go clean -cache' },
    { ts: at(23, 8, 0), action: 'worktree-prune', path: '/r/app/.worktrees/gone', repo: '/r/app', detail: 'directory was already gone' },
  ] };
  const now = new Date(2026, 8, 25, 18, 0).getTime();
  const html = cleanupHistoryHTML(ledger, {}, now);
  assert.equal((html.match(/class="hx-day"/g) || []).length, 2);
  assert.ok(html.indexOf('Today') < html.indexOf('Wed, Sep 23'));
  assert.ok(html.includes('5 entries · 3.0 GB freed · 512 MB moved to the Trash'));
  assert.ok(html.includes('<span class="hx-day-bytes">1.0 GB freed</span>') && html.includes('<span class="hx-day-bytes">2.0 GB freed</span>'));
  assert.ok(html.includes('<span class="hx-title">Removed worktree</span>') && html.includes('.worktrees/done · app'));
  assert.ok(html.includes('Moved an orphan folder to the Trash') && html.includes('Ran go clean -cache') && html.includes('Pruned a missing worktree'));
  assert.ok(html.includes('Agent answered: pr') && html.includes('claude answered: &lt;b&gt;pr&lt;/b&gt;') && !html.includes('<b>pr</b>'));
  assert.ok(html.includes('<time class="hx-time" datetime="' + at(25, 15, 10) + '">3:10 PM</time>'));
  const removed = cleanupHistoryHTML(ledger, { kind: 'removed' }, now);
  assert.ok(removed.includes('1 entry · 1.0 GB freed') && !removed.includes('Ran go'));
  assert.ok(removed.includes('data-action="history-kind" data-kind="removed" aria-pressed="true"'));
  const day = cleanupHistoryHTML(ledger, { day: '2026-09-23' }, now);
  assert.ok(day.includes('2 entries · 2.0 GB freed') && day.includes('data-action="history-day" data-day=""') && day.includes('Wed, Sep 23 ×'));
  assert.ok(cleanupHistoryHTML(ledger, { kind: 'trash', day: '2026-09-23' }, now).includes('Nothing matches this filter.'));
  assert.ok(cleanupHistoryHTML({ entries: [] }, {}, now).includes('No cleanups yet.'));
  assert.ok(cleanupHistoryHTML({ entries: ledger.entries, limit: 5 }, {}, now).includes('Showing the newest 5 entries.'));
  assert.equal(cleanupKind('clean:npm'), 'clean');
  assert.equal(cleanupEntryTitle({ action: 'trash:tmp' }), 'Moved .tmp to the Trash');
});

test('progress toast: phases add up to one bar, running rows first with size and time, the end names what was reclaimed', () => {
  const GB = 1073741824;
  const paths = ['/r/a', '/r/b', '/r/c'];
  const running = removalToastModel(paths, {
    '/r/a': { state: 'removed', bytes: GB, branch: 'feat/a' },
    '/r/b': { state: 'running', phase: 'deleting', step: 'deleting', step_at: '2026-09-25T10:00:00Z', bytes: 2 * GB, files: 184203 },
    '/r/c': { state: 'running', phase: 'waiting', step: 'waiting for the current scan', started_at: '2026-09-25T09:59:58Z' },
  }, { '/r/b': 'feat/<b>' });
  assert.equal(running.running, 2);
  assert.equal(running.percent, Math.round((1 + 0.5 + 0.05) / 3 * 100));
  const html = removalToastHTML(running);
  assert.ok(html.includes('<p class="rt-title" role="status">Removing 3 worktrees</p>'));
  assert.ok(html.includes('<p class="rt-sub">1 of 3 done · 1.0 GB reclaimed so far</p>'));
  assert.ok(html.includes('aria-valuenow="52"><i data-w="52"></i>') && html.includes('rt-bar-running'));
  assert.ok(html.includes('<span class="rt-label">feat/&lt;b&gt;</span>') && html.includes('deleting · 2.0 GB · 184,203 files'));
  assert.ok(html.includes('data-since="2026-09-25T10:00:00Z"') && html.includes('data-since="2026-09-25T09:59:58Z"'));
  assert.ok(!html.includes('feat/a') && !html.includes('View cleanup history'));
  const unknown = removalToastModel(['/x/y'], {}, {});
  assert.ok(removalToastHTML(unknown).includes('Removing y') && removalToastHTML(unknown).includes('starting'));
  assert.ok(!removalToastHTML(unknown).includes('rt-sub'));
  const fresh = removalToastHTML(removalToastModel(['/r/a', '/r/b'], {}));
  assert.ok(fresh.includes('<p class="rt-sub">0 of 2 done</p>'));

  const done = removalToastModel(paths, {
    '/r/a': { state: 'removed', bytes: GB }, '/r/b': { state: 'removed', bytes: 2 * GB },
    '/r/c': { state: 'failed', row_state: 'keep', reasons: ['2 uncommitted changes'] },
  });
  const end = removalToastHTML(done);
  assert.ok(end.includes('Removed 2 of 3 worktrees') && end.includes('3.0 GB reclaimed · 1 not removed'));
  assert.ok(end.includes('rt-bar-partial') && end.includes('now keep — 2 uncommitted changes'));
  assert.ok(end.includes('data-action="worktrees-history">View cleanup history</button>'));
  const single = removalToastHTML(removalToastModel(['/r/a'], { '/r/a': { state: 'removed', bytes: GB, branch: 'feat/a' } }));
  assert.ok(single.includes('Removed feat/a</p>') && single.includes('1.0 GB reclaimed') && single.includes('rt-bar-done'));
  const refused = removalToastHTML(removalToastModel(['/r/a'], { '/r/a': { state: 'failed', error: 'git worktree: exit 128' } }, { '/r/a': 'feat/a' }));
  assert.ok(refused.includes('Not removed: feat/a') && refused.includes('git worktree: exit 128') && refused.includes('rt-bar-failed'));
  const many = removalToastModel(['/1', '/2', '/3', '/4', '/5', '/6'], {});
  assert.ok(removalToastHTML(many).includes('<li class="rt-more">and 2 more</li>'));
});
