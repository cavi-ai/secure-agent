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
const { worktreeStateCounts, worktreeGroups, worktreeRowHTML, worktreeGroupHTML, worktreePathLabel, worktreeFilterHTML, worktreesSummaryText } = ctx;

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
  assert.deepEqual([...keepHTML.matchAll(/data-action="([a-z-]+)"/g)].map(m => m[1]), ['worktree-advise']);
  assert.ok(keepHTML.includes('&lt;img src=x onerror=alert(1)&gt;') && !keepHTML.includes('<img'));
  assert.match(keepHTML, /<span class="wt-branch">\(detached\)<\/span>/);
  const reviewHTML = worktreeRowHTML(review, rep.repos[1]);
  assert.deepEqual([...reviewHTML.matchAll(/data-action="([a-z-]+)"/g)].map(m => m[1]), ['worktree-advise']);
  assert.ok(!doneHTML.includes('worktree-advise') && !goneHTML.includes('worktree-advise'));
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
