import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const context = vm.createContext({ window: {} });
const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
for (const file of ['lib.js', 'tab-worktrees.js']) vm.runInContext(readFileSync(new URL(file, web), 'utf8'), context);
const repo = { path: '/code/app' };
const row = (name, extra = {}) => ({ path: `/code/app/${name}`, branch: name, state: 'keep', head: 'abc', reasons: ['1 untracked file'], ...extra });

test('the cleanup queue sorts rows into lanes: safe, local work, check, not merged, in use', () => {
  const rows = [
    row('active', { in_use: true, reason_kinds: ['keep', 'agent'] }),
    row('open', { reasons: ['not merged; active 2 days ago'], reason_kinds: ['info'] }),
    row('check', { state: 'review', reasons: ['1 stash on this branch'], reason_kinds: ['review'] }),
    row('work', { reason_kinds: ['keep'] }),
    row('ready', { state: 'remove', reasons: ['merged into origin/main (squash)'], reason_kinds: ['safe'] }),
  ];
  const rep = { repos: [{ ...repo, worktrees: rows }] };
  const html = context.worktreeLanesHTML(context.worktreeGroups(rep, {}), rep, {});
  const at = s => html.indexOf(s);
  assert.ok(at('Safe to remove') < at('Has local work') && at('Has local work') < at('Check first')
    && at('Check first') < at('Not merged yet') && at('Not merged yet') < at('In use'));
  for (const name of ['ready', 'work', 'check', 'open', 'active']) {
    const lane = { ready: 'safe', work: 'work', check: 'check', open: 'open', active: 'active' }[name];
    const section = html.slice(at(`wt-lane-${lane}"`)).split('<section class="wt-lane ')[0];
    assert.ok(section.includes(`data-path="/code/app/${name}"`), `${name} in ${lane}`);
  }
  assert.match(html, /<details class="wt-row wt-remove wt-in-safe"/);
  const active = html.slice(at('data-path="/code/app/active"'));
  assert.ok(!active.includes('data-action="worktree-select"'));
});

test('a collapsed row tones its reason by kind, counts the other concerns, and shows idle age', () => {
  const html = w => context.worktreeRowHTML(w, repo).split('</summary>')[0];
  const work = html(row('work', { reasons: ['1 uncommitted change', '2 untracked files or directories', 'ignored files that only live here: .env (17 B)', 'no commits outside origin/main'],
    reason_kinds: ['keep', 'keep', 'review', 'safe'], last_activity: '2026-10-18T12:00:00Z', idle_days: 3 }));
  assert.match(html(row('x')), /class="wt-subtitle wt-tone-info"/, 'a reason with no kind is plain');
  assert.match(work, /<span class="wt-subtitle wt-tone-keep">Scan: 1 uncommitted change <span class="wt-more">\+2 more<\/span><\/span>/);
  assert.match(work, /<span class="wt-idle">3d idle<\/span>/);
  assert.match(work, /<details class="wt-row wt-keep wt-in-work"/);
  const safe = html(row('done', { state: 'remove', reasons: ['merged into origin/main (squash)'], reason_kinds: ['safe'] }));
  assert.match(safe, /<span class="wt-subtitle wt-tone-safe">Scan: merged into origin\/main \(squash\)<\/span>/);
  const live = html(row('live', { in_use: true, active_agent: 'codex', reasons: ['codex is working here'], reason_kinds: ['agent'] }));
  assert.match(live, /<span class="wt-subtitle wt-tone-agent">Scan: codex session active<\/span>/);
});

test('collapsed queue rows show one selection control and keep actions in their disclosure', () => {
  const w = row('review');
  const html = context.worktreeRowHTML(w, repo, { assessment: 'remove', confidence: 0.9, rationale: 'Review the files.' });
  assert.equal((html.match(/data-action="worktree-select"/g) || []).length, 1);
  const summary = html.split('</summary>')[0];
  assert.ok(!summary.includes('worktree-advise') && !summary.includes('worktree-review-trash'));
  assert.match(summary, /aria-label="Select review for removal"/);
  assert.ok(!html.includes('90%'));
});

test('closed rows expose structured advice conflicts without changing scanner policy', () => {
  const safe = row('done', { state: 'remove', reasons: ['merged into origin/main'] });
  const note = { assessment: 'keep', rationale: '<b>Agent is working here</b>' };
  const html = context.worktreeRowHTML(safe, repo, note);
  const summary = html.split('</summary>')[0];
  assert.match(summary, /Saved advice differs/);
  assert.match(summary, /Scan: merged into origin\/main/);
  assert.match(summary, /Inspect/);
  assert.match(html, /data-action="worktree-remove"/);
  assert.match(html, /data-action="worktree-advise"/);
  assert.equal(context.worktreeLane(safe), 'safe');
  assert.match(html, /Saved opinion: keep/);
  assert.match(html, /&lt;b&gt;Agent is working here&lt;\/b&gt;/);
  assert.match(html, /second opinion/);
  assert.match(html, /No active session detected by this scan/);
  assert.match(html, /does not detect live sessions or authorize removal/);
  for (const assessment of ['keep', 'review']) {
    assert.match(context.worktreeRowHTML(safe, repo, { assessment }).split('</summary>')[0], /Saved advice differs/);
  }
  for (const extra of [{ state: 'keep' }, { in_use: true }, { locked: true }, { error: 'unreadable' }]) {
    const blocked = context.worktreeRowHTML({ ...safe, ...extra }, repo, { assessment: 'remove' });
    assert.match(blocked.split('</summary>')[0], /Saved advice differs/);
    if (extra.in_use || extra.locked || extra.error) assert.ok(!blocked.includes('data-action="worktree-remove"'));
  }
  assert.doesNotMatch(context.worktreeRowHTML(safe, repo, { assessment: 'remove', rationale: 'keep active agent' }).split('</summary>')[0], /Saved advice differs/);
});

test('inspection has one disclosure and separates scan facts from saved advice without duplicate reasons', () => {
  const w = row('done', { state: 'remove', submodules: 1,
    reasons: ['merged into origin/main', '1 submodule with every commit on a remote', 'extra fact', 'extra fact'] });
  const html = context.worktreeRowHTML(w, repo, { assessment: 'keep', rationale: 'Check its files.' });
  assert.equal((html.match(/<details\b/g) || []).length, 1);
  assert.match(html, /<h5[^>]*>Scan checks<\/h5>/);
  assert.match(html, /<h5[^>]*>Saved advice<\/h5>/);
  const inspection = html.split('<div class="wt-inspection">')[1];
  assert.ok(!inspection.includes('merged into origin/main'));
  assert.ok(!inspection.includes('1 submodule with every commit on a remote'));
  assert.equal((inspection.match(/extra fact/g) || []).length, 1);
  assert.match(inspection, /1 populated/);
  assert.match(inspection, />Delete permanently<\/button>/);
  assert.match(context.worktreeRowHTML(row('review'), repo), />Review Trash move…<\/button>/);
});

test('populated submodules can be reviewed while local-only submodule state stays protected', () => {
  assert.equal(context.worktreeTrashBlock(row('clean', { submodules: 2 })), '');
  const why = 'submodule lib has a stash (removal loses it)';
  assert.equal(context.worktreeTrashBlock(row('local', { submodules: 1, submodule_local: [why] })), why);
  const html = context.worktreeRowHTML(row('local', { submodules: 1, submodule_local: [why] }), repo);
  assert.ok(!html.includes('data-action="worktree-review-trash"'));
  assert.match(html, /Open folder to resolve/);
});

test('batch review separates reclaimable space from files moved to Trash', () => {
  const rows = [row('ready', { state: 'remove', size_bytes: 1024 }), row('review', { size_bytes: 1048576 })];
  const rep = { repos: [{ ...repo, worktrees: rows }] };
  const html = context.worktreeSelectionHTML(rep, { selected: new Map(rows.map(w => [w.path, {}])) }, [{ repo, rows }]);
  assert.match(html, /Review 2 removals/);
  assert.match(html, /Reclaim estimate: 1 KB/);
  assert.match(html, /1 to Trash/);
  assert.match(html, /does not free disk space/);
});

test('removal review separates routes and escapes every worktree-provided value', () => {
  const approval = { ...row('<script>alert(1)</script>'), repo: '/code/<app>', submodules: 2, reasons: ['ignored .tmp/ <img src=x>'] };
  const html = context.worktreeSelectionReviewHTML([{ approval, size: { size_bytes: 1024 } }]);
  assert.match(html, /Move to Trash/);
  assert.match(html, /2 inspected submodules/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.ok(!html.includes('<script>') && !html.includes('<img'));
  assert.ok(!html.includes('State:') && !html.includes('HEAD:'));
});
