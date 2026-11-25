import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Exact worktrees and clutter markup for hostile served values: each value
// renders escaped once in text and attribute positions, and nested fragments render as markup.
const H = `<img src=x onerror=1>"'&amp;`;
const E = '&lt;img src=x onerror=1&gt;&quot;&#39;&amp;amp;';
const P = `${H}/${H}`;

const webDist = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const ctx = { window: {} };
vm.createContext(ctx);
for (const f of ['lib.js', 'tab-worktrees.js']) {
  vm.runInContext(readFileSync(new URL(f, webDist), 'utf8'), ctx, { filename: f });
}

function element() {
  return { innerHTML: '', textContent: '', hidden: false, classList: { toggle() {} }, contains: () => false,
    querySelectorAll: () => [], querySelector: () => null, insertAdjacentHTML(where, markup) { this.innerHTML += markup; } };
}

// Runs a tab renderer against a document holding the given elements and
// returns each element's markup.
function render(renderer, SA, ids) {
  const els = Object.fromEntries(ids.map(id => [id, element()]));
  ctx.document = { activeElement: null, getElementById: id => els[id] || null };
  ctx.window.SA = SA;
  ctx[renderer]();
  return Object.fromEntries(ids.map(id => [id, els[id].innerHTML]));
}

function clutterItem(it, project, removing) {
  ctx.window.SA = { clutter: { removing } };
  return ctx.clutterItemHTML(it, project);
}

const toast = (paths, removals, labels) => ctx.removalToastHTML(ctx.removalToastModel(paths, removals, labels));
const repo = { path: H };
const pruneRow = { path: P, branch: H, state: 'prune' };
const removeRow = { path: P, branch: H, state: 'remove', head: 'abc', reasons: [H], size_bytes: 1024 };
const orphan = { orphan: true, path: P, reconnect: H, state: 'keep', branch: H, reasons: [H, H + '2'], reason_kinds: [H, 'keep'], stale: true,
  last_activity: H, idle_days: 3, size_bytes: 1024, size_partial: true, submodules: 2, error: H };
const ledger = { totals: { bytes: 4096, count: 1, trashed_bytes: 1024, trashed_count: 2 }, daily: [{ day: H, bytes: 1024, count: 1 }] };
const entries = [
  { action: 'worktree-remove', ts: H, path: P, repo: H, bytes: 2048, detail: H },
  { action: 'trash:' + H, ts: H, path: H, bytes: 1024 },
  { action: 'clean:' + H, ts: H, path: H, detail: H },
  { action: 'ask:' + H, ts: H, path: H, detail: H },
  { action: H, ts: H, path: H },
];
const clutter = { kind: H, path: P, project: H, name: H, size_bytes: 1024, size_partial: true, last_touched: H, idle_days: 0, note: H, action: 'trash' };
const idleClutter = { kind: H, path: P, project: H, name: H, action: 'none' };
const worktreeIds = ['worktrees-container', 'worktree-pills', 'worktrees-disk', 'worktrees-errors', 'worktrees-reclaim'];
const clutterIds = ['clutter-container', 'clutter-pills'];

const cases = {
  'disk': () => ctx.worktreeDiskHTML({ volumes: [{ mount: H, total_bytes: 4096, free_bytes: 1024 }], summary: { size_bytes: 2048 }, sizing: true }),
  'tiles': () => ctx.reclaimTilesHTML({ repos: [{ path: H, worktrees: [{ path: P, state: 'remove', size_bytes: 2048 }] }], sizing: true }, ledger),
  'tiles unavailable': () => ctx.reclaimTilesHTML(null, null),
  'chart': () => ctx.reclaimChartHTML([{ day: H, bytes: 1024, count: 1, trashed_bytes: 3072, trashed_count: 1 }, { day: H }, { day: H, count: 2 }], H),
  'chart empty': () => ctx.reclaimChartHTML([{ day: H }], H),
  'history': () => ctx.cleanupHistoryHTML({ entries, limit: 5 }, {}, 86400000),
  'history day filter': () => ctx.cleanupHistoryHTML({ entries }, { kind: 'trash', day: H }, 86400000),
  'history empty': () => ctx.cleanupHistoryHTML({ entries: [] }, {}, 86400000),
  'toast running': () => toast(['/a', '/b', '/c', '/d', '/e'], { '/a': { state: 'running', phase: H, step: H, step_at: H, bytes: 1024, files: 3 },
    '/b': { state: 'failed', row_state: H, reasons: [H] }, '/c': { state: 'failed', error: H } }, { '/a': H, '/b': H, '/c': H, '/d': H, '/e': H }),
  'toast one running': () => toast(['/a'], { '/a': { state: 'running', phase: 'deleting', step: H } }, { '/a': H }),
  'toast removed': () => toast(['/a'], { '/a': { state: 'removed', bytes: 2048 } }, { '/a': H }),
  'toast partial': () => toast(['/a', '/b'], { '/a': { state: 'removed', bytes: 1024 }, '/b': { state: 'failed', error: H } }, { '/a': H, '/b': H }),
  'toast not removed': () => toast(['/a'], { '/a': { state: 'failed', error: H } }, { '/a': H }),
  'note with discuss': () => ctx.worktreeNoteHTML({ assessment: H, rationale: H }, P),
  'row orphan': () => ctx.worktreeRowHTML(orphan, repo, { assessment: H, rationale: H }, { status: H, harness: H, detail: H }, { state: 'failed', error: H }, H, { expanded: new Set([P]) }),
  'row orphan in use': () => ctx.worktreeRowHTML({ orphan: true, in_use: true, active_agent: H, path: P, state: 'keep' }, repo),
  'row remove': () => ctx.worktreeRowHTML({ ...removeRow, reason_kinds: ['safe'] }, repo, { assessment: 'keep', rationale: H }, null,
    { state: 'failed', row_state: H, reasons: [H] }, null, { selected: new Map([[P, {}]]), selectionBusy: true }),
  'row removing': () => ctx.worktreeRowHTML({ path: P, state: 'remove', head: 'abc', reasons: [] }, repo, null, null, { state: 'running', phase: 'checking', step: H, bytes: 1024, files: 2 }),
  'row prune': () => ctx.worktreeRowHTML(pruneRow, repo),
  'row review': () => ctx.worktreeRowHTML({ path: P, branch: H, state: 'review', head: 'abc', reasons: [H], reason_kinds: ['review'], last_activity: H, idle_days: 0 }, repo, null, null, null, H),
  'row reviewed delete': () => ctx.worktreeRowHTML({ path: P, branch: H, state: 'keep', head: 'abc', reasons: [H], reason_kinds: ['keep'], can_remove_reviewed: true }, repo,
    null, { status: 'answered', verdict: H, detail: H, harness: H, cost_usd: 0.5 }, null, H),
  'row waiting on agent': () => ctx.worktreeRowHTML({ path: P, branch: H, state: 'keep', head: 'abc', reasons: [H] }, repo, null, { status: 'running', harness: H }, null, H),
  'row unknown state': () => ctx.worktreeRowHTML({ path: P, branch: H, state: H, reasons: [H], reason_kinds: [H] }, repo),
  'group with options': () => ctx.worktreeGroupHTML({ repo: { path: H, default_branch: H, source: H, size_bytes: 4096, worktrees: [removeRow, pruneRow] }, rows: [pruneRow] }),
  'group with error': () => ctx.worktreeGroupHTML({ repo: { path: H, error: H, worktrees: [pruneRow] }, rows: [pruneRow] }),
  'group without options': () => ctx.worktreeGroupHTML({ repo: { path: H, worktrees: [pruneRow] }, rows: [pruneRow] }, null, null, null, null, {}, false),
  'lanes': () => {
    const lanesRepo = { path: H, worktrees: [removeRow, { ...removeRow, path: H, size_bytes: 2048 }] };
    return ctx.worktreeLanesHTML([{ repo: lanesRepo, rows: [pruneRow, { path: H, state: 'keep', in_use: true, active_agent: H }] }], { repos: [lanesRepo] }, { selectionBusy: true });
  },
  'filter pills': () => ctx.worktreeFilterHTML({ all: 3, safe: 1, work: 0, check: 1, open: 0, active: 1, stale: 2 }, { state: 'check' }),
  'filter pills stale': () => ctx.worktreeFilterHTML({ all: 3, safe: 1, work: 0, check: 1, open: 0, active: 1, stale: 2 }, { stale: true }),
  'selection bar': () => ctx.worktreeSelectionHTML({ repos: [{ path: H, worktrees: [removeRow, { path: H, state: 'review', size_bytes: 2048, size_partial: true }] }] },
    { selected: new Map([[P, {}], [H, {}]]), pendingRemovalSelections: new Set([H]) }, []),
  'selection review': () => ctx.worktreeSelectionReviewHTML([{ approval: { branch: H, path: P, reasons: [H], submodules: 2, state: 'remove' }, size: { size_bytes: 1024 } },
    { approval: { branch: '', path: H, reasons: [H, H], state: 'review' }, size: {} }]),
  'render worktrees error': () => render('renderWorktrees', { worktrees: { error: H } }, worktreeIds),
  'render worktrees report': () => render('renderWorktrees', { worktrees: { ledger, filter: {}, selected: new Map(), report: { repos: [{ path: H, worktrees: [{ path: H, state: 'main' }] }],
    volumes: [{ mount: H, total_bytes: 4096, free_bytes: 1024 }], summary: { size_bytes: 1024 }, errors: [H] } } }, worktreeIds),
  'render selection': () => render('renderWorktreeSelection', { worktrees: { report: { repos: [{ path: H, worktrees: [removeRow] }] }, filter: {}, selected: new Map([[P, {}]]) } }, ['worktrees-container']),
  'clutter trash': () => clutterItem(clutter, H),
  'clutter delete': () => clutterItem({ ...clutter, can_remove: true }, H),
  'clutter deleting': () => clutterItem({ ...clutter, can_remove: true }, H, new Set([P])),
  'clutter clean': () => clutterItem({ kind: 'tool-cache', path: H, name: H, command: H, action: 'clean', last_touched: H, idle_days: 4 }, ''),
  'clutter clean default': () => clutterItem({ kind: 'tool-cache', path: H, name: H, action: 'clean' }, ''),
  'clutter group': () => ctx.clutterGroupHTML({ project: H, bytes: 4096, items: Array(9).fill(idleClutter) }, new Set(), { [H]: { rationale: H, suggested_action: `${H}\n\n${H}` } }),
  'clutter machine group': () => ctx.clutterGroupHTML({ project: '', bytes: 0, items: [idleClutter] }, null, null),
  'clutter pills': () => ctx.clutterPillsHTML({ kinds: [{ kind: H, bytes: 1024 }, { kind: 'tmp', bytes: 2048 }] }, { kind: 'tmp' }),
  'render clutter error': () => render('renderClutter', { clutter: { error: H } }, clutterIds),
  'render clutter report': () => render('renderClutter', { clutter: { filter: {}, expanded: new Set(), report: { items: [clutter], kinds: [{ kind: H, bytes: 1024 }] } } }, clutterIds),
};

const prunedRow = `<details class="wt-row wt-prune wt-in-safe" data-path="${E}/${E}">\n    <summary class="wt-main">\n      <span class="wt-select-slot"></span>\n      <div class="wt-identity">\n        <div class="wt-title"><span class="wt-branch">${E}</span></div>\n        <span class="wt-subtitle wt-tone-info">Scan: Open to inspect contents</span>\n        \n      </div>\n      <div class="wt-facts">\n        <span class="wt-size">Measuring…</span>\n        <span class="wt-inspect-label">Inspect <svg class="icon wt-disclosure" aria-hidden="true"><use href="#i-arrow"/></svg></span>\n      </div>\n    </summary>\n    <div class="wt-inspection">\n      <div class="wt-inspection-header"><button type="button" class="wt-path" data-action="copy-path" data-path="${E}/${E}" title="${E}/${E} — click to copy">${E}</button>\n      <div class="wt-inspection-meta"></div></div>\n      <section class="wt-scan-checks"><h5>Scan checks</h5>\n      \n      \n      \n      \n      \n      </section>\n      <div class="wt-actions"><button type="button" class="btn btn-sm" data-action="worktree-prune" data-repo="${E}">Prune</button></div>\n      \n    </div>\n    \n  </details>`;
const trashedClutter = `<div class="wt-row cl-row cl-${E}" data-path="${E}/${E}">\n    <div class="wt-main">\n      <span class="wt-state cl-kind">${E}</span>\n      <span class="wt-branch">${E}</span>\n      <span class="wt-path" title="${E}/${E}">${E}</span>\n      <span class="wt-size">≥1 KB</span>\n      <span class="wt-idle">today</span>\n      <button type="button" class="btn btn-danger btn-sm" data-action="clutter-trash" data-path="${E}/${E}">Move to Trash</button>\n    </div>\n    <ul class="wt-reasons"><li>${E}</li></ul>\n  </div>`;
const idleRow = `<div class="wt-row cl-row cl-${E}" data-path="${E}/${E}">\n    <div class="wt-main">\n      <span class="wt-state cl-kind">${E}</span>\n      <span class="wt-branch">${E}</span>\n      <span class="wt-path" title="${E}/${E}">${E}</span>\n      <span class="wt-size"></span>\n      <span class="wt-idle">—</span>\n      \n    </div>\n    \n  </div>`;
const historyChips = on => `<button type="button" class="wt-pill${on === '' ? ' on' : ''}" data-action="history-kind" data-kind="" aria-pressed="${on === ''}">All</button><button type="button" class="wt-pill" data-action="history-kind" data-kind="removed" aria-pressed="false">Removed</button><button type="button" class="wt-pill${on === 'trash' ? ' on' : ''}" data-action="history-kind" data-kind="trash" aria-pressed="${on === 'trash'}">Moved to Trash</button><button type="button" class="wt-pill" data-action="history-kind" data-kind="clean" aria-pressed="false">Cleaned</button><button type="button" class="wt-pill" data-action="history-kind" data-kind="prune" aria-pressed="false">Pruned</button><button type="button" class="wt-pill" data-action="history-kind" data-kind="ask" aria-pressed="false">Agent answers</button>`;
const historyEntry = (kind, title, bytes, path, where, detail) => `<li class="hx-entry hx-${kind}">\n        <div class="hx-main">\n          <span class="hx-title">${title}</span>\n          <span class="hx-bytes">${bytes}</span>\n          <time class="hx-time" datetime="${E}"></time>\n        </div>\n        <div class="hx-path" title="${path}">${where}</div>\n        ${detail}\n      </li>`;
const toastHead = (title, close) => `<div class="rt-head">\n      <p class="rt-title" role="status">${title}</p>\n      <button type="button" class="btn btn-icon rt-close" data-action="removal-toast-close" title="${close}" aria-label="Close"><svg class="icon"><use href="#i-close"/></svg></button>\n    </div>\n    `;
const toastBar = (state, percent) => `<span class="rt-bar rt-bar-${state}" role="progressbar" aria-label="Removal progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${percent}"><i data-w="${percent}"></i></span>\n    `;
const running = (phase, step, since) => `<li class="rt-item rt-running rt-${phase}">\n        <span class="rt-label">${E}</span>\n        <span class="rt-step">${step}</span>\n        <span class="rt-elapsed" data-since="${since}"></span>\n      </li>`;
const failed = step => `<li class="rt-item rt-failed"><span class="rt-label">${E}</span><span class="rt-step">${step}</span></li>`;
const historyLink = '<button type="button" class="link-btn rt-history" data-action="worktrees-history">View cleanup history</button>';
const tilesMarkup = (removable, removableHint) => `<div class="rc-tile rc-freed">\n      <span class="rc-tile-label">Freed · last 1 days</span>\n      <span class="rc-tile-value">1 KB</span>\n      <span class="rc-tile-hint">1 cleanup</span>\n    </div><div class="rc-tile rc-alltime">\n      <span class="rc-tile-label">Freed · recorded</span>\n      <span class="rc-tile-value">4 KB</span>\n      <span class="rc-tile-hint">1 cleanup</span>\n    </div><div class="rc-tile rc-removable">\n      <span class="rc-tile-label">Removable now</span>\n      <span class="rc-tile-value">${removable}</span>\n      <span class="rc-tile-hint">${removableHint}</span>\n    </div><div class="rc-tile rc-trash">\n      <span class="rc-tile-label">Moved to the Trash</span>\n      <span class="rc-tile-value">1 KB</span>\n      <span class="rc-tile-hint">2 recorded cleanups · current Trash size is not measured</span>\n    </div>`;
const chartHead = days => `<div class="rc-chart-head">\n      <span class="rc-chart-title">Reclaimed per day</span>\n      <span class="rc-legend"><span class="rc-key rc-key-freed"></span>Freed<span class="rc-key rc-key-trash"></span>Moved to the Trash</span>\n    </div>\n    <div class="rc-chart" role="group" aria-label="Space reclaimed per day, last ${days} days">\n      `;
const chartAxis = `\n      <div class="rc-xaxis" aria-hidden="true"><span>${E}</span><span>${E}</span><span>${E}</span></div>\n    </div>`;
const rowHead = (state, lane, open, select, tone, scan, conflict, facts) => `<details class="wt-row wt-${state} wt-in-${lane}" data-path="${E}/${E}"${open}>\n    <summary class="wt-main">\n      <span class="wt-select-slot">${select}</span>\n      <div class="wt-identity">\n        <div class="wt-title"><span class="wt-branch">${E}</span></div>\n        <span class="wt-subtitle wt-tone-${tone}">Scan: ${scan}</span>\n        ${conflict}\n      </div>\n      <div class="wt-facts">\n        ${facts}\n        <span class="wt-inspect-label">Inspect <svg class="icon wt-disclosure" aria-hidden="true"><use href="#i-arrow"/></svg></span>\n      </div>\n    </summary>\n    <div class="wt-inspection">\n      <div class="wt-inspection-header"><button type="button" class="wt-path" data-action="copy-path" data-path="${E}/${E}" title="${E}/${E} — click to copy">${E}</button>\n      <div class="wt-inspection-meta">`;
const checkbox = extra => `<label class="wt-checkbox"><input type="checkbox" class="wt-select" data-action="worktree-select" data-path="${E}/${E}" aria-label="Select ${E} for removal"${extra}></label>`;
const sessionFact = '<p class="wt-session-fact">No active session detected by this scan.</p>';
const reviewHint = '<p class="wt-review-hint">Review the files before proceeding. Reviewed folders move to Trash; space is freed only when Trash is emptied.</p>';
const resolve = text => `<p class="wt-resolve">${text} <button type="button" class="link-btn" data-action="worktree-reveal" data-path="${E}/${E}">Open folder to resolve</button></p>`;
const openButton = label => `<button type="button" class="btn btn-ghost btn-sm wt-open" data-action="worktree-reveal" data-path="${E}/${E}" title="Show in Finder" aria-label="Show ${label} in Finder"><svg class="icon"><use href="#i-folder"/></svg></button>`;
const askButton = extra => `<button type="button" class="btn btn-primary btn-sm" data-action="worktree-ask" data-path="${E}/${E}" title="Ask active ${E} agent"${extra}>Ask ${E}</button>`;
const adviseButton = `<button type="button" class="btn btn-sm" data-action="worktree-advise" data-path="${E}/${E}" title="Refresh the saved second opinion; no agent is resumed">Ask advisor</button>`;
const discussButton = `<button type="button" class="link-btn" data-action="worktree-discuss" data-path="${E}/${E}">Discuss</button>`;
const savedAdvice = (differs, notes) => `<section class="wt-saved-advice"><h5>Saved advice</h5><p class="wt-advice-context">${differs}A saved second opinion does not detect live sessions or authorize removal. Ask advisor to refresh it.</p>${notes}</section>`;
const repoHead = (facts, tail) => `<section class="wt-repo">\n    <div class="wt-repo-head">\n      <div class="wt-repo-identity">\n        <h4 class="wt-repo-name">${E}</h4>\n        <span class="wt-repo-path" title="${E}">${E}</span>\n      </div>\n      <div class="wt-repo-facts">\n        ${facts}\n      </div>\n      ${tail}\n    </div>\n    `;
const repoOptions = advisable => `<details class="wt-repo-options"><summary>Repository options</summary><div class="wt-repo-actions"><button type="button" class="link-btn wt-group-ask" data-action="worktree-advise-all" data-repo="${E}" title="Ask the local advisor for a note on each keep, review and remove worktree of this repository, one at a time">Ask advisor about all ${advisable}</button><button type="button" class="link-btn wt-group-ask" data-action="worktree-discuss-all" data-repo="${E}" title="Ask the Agent tab about this repository's worktrees">Discuss all 2</button><button type="button" class="link-btn wt-hide" data-action="worktree-hide" data-repo="${E}">Hide repo</button></div></details>`;
const filterPill = (state, label, n, on) => `<button type="button" class="wt-pill${on ? ' on' : ''}" data-action="worktree-filter" data-state="${state}" aria-pressed="${on}">${label} <b>${n}</b></button>`;
const stalePill = (n, on) => `<button type="button" class="wt-pill${on ? ' on' : ''}" data-action="worktree-stale" aria-pressed="${on}">Stale <b>${n}</b></button>`;
const laneFilters = (n, on) => filterPill('safe', 'Safe to remove', n[0], on === 'safe') + filterPill('work', 'Has local work', n[1], on === 'work') + filterPill('check', 'Check first', n[2], on === 'check')
  + filterPill('open', 'Not merged yet', n[3], on === 'open') + filterPill('active', 'In use', n[4], on === 'active');
const clutterRowTail = `\n    <ul class="wt-reasons"><li>${E}</li></ul>\n  </div>`;
const clutterRowHead = `<div class="wt-row cl-row cl-${E}" data-path="${E}/${E}">\n    <div class="wt-main">\n      <span class="wt-state cl-kind">${E}</span>\n      <span class="wt-branch">${E}</span>\n      <span class="wt-path" title="${E}/${E}">${E}</span>\n      <span class="wt-size">≥1 KB</span>\n      <span class="wt-idle">today</span>\n      `;
const cleanRow = (idle, title, command) => `<div class="wt-row cl-row cl-tool-cache" data-path="${E}">\n    <div class="wt-main">\n      <span class="wt-state cl-kind">Tool caches</span>\n      <span class="wt-branch">${E}</span>\n      <span class="wt-path" title="${E}">${E}</span>\n      <span class="wt-size"></span>\n      <span class="wt-idle">${idle}</span>\n      <button type="button" class="btn btn-sm" data-action="clutter-clean" data-name="${E}" title="${title}">Run ${command}</button>\n    </div>\n    \n  </div>`;
const clutterPill = (kind, label, bytes, on) => `<button type="button" class="wt-pill${on ? ' on' : ''}" data-action="clutter-filter" data-kind="${kind}" aria-pressed="${on}">${label} <b>${bytes}</b></button>`;

const expected = {
  'disk': `<div class="wt-vol"><span class="wt-vol-name">${E}</span>\n      <span class="wt-vol-bar" aria-hidden="true"><i class="wt-vol-used" data-w="75"></i></span>\n      <span class="wt-vol-free">1 KB free of 4 KB</span></div>\n    <div class="wt-disk-stats">\n      <span><b>Worktrees</b> 2 KB <span class="wt-measuring">measuring…</span></span>\n    </div>`,
  'tiles': tilesMarkup('2 KB', '1 worktree · measuring…'),
  'tiles unavailable': `<div class="rc-tile rc-freed">\n      <span class="rc-tile-label">Freed · last 30 days</span>\n      <span class="rc-tile-value">—</span>\n      <span class="rc-tile-hint">cleanup history unavailable</span>\n    </div><div class="rc-tile rc-alltime">\n      <span class="rc-tile-label">Freed · recorded</span>\n      <span class="rc-tile-value">—</span>\n      <span class="rc-tile-hint">cleanup history unavailable</span>\n    </div><div class="rc-tile rc-removable">\n      <span class="rc-tile-label">Removable now</span>\n      <span class="rc-tile-value">0 B</span>\n      <span class="rc-tile-hint">0 worktrees</span>\n    </div><div class="rc-tile rc-trash">\n      <span class="rc-tile-label">Moved to the Trash</span>\n      <span class="rc-tile-value">—</span>\n      <span class="rc-tile-hint">cleanup history unavailable · current Trash size is not measured</span>\n    </div>`,
  'chart': chartHead(3) + `<div class="rc-yaxis" aria-hidden="true"><span>5 KB</span><span>3 KB</span><span>0</span></div>\n      <div class="rc-plot">\n        <div class="rc-grid" aria-hidden="true"><i></i><i></i><i></i></div>\n        <div class="rc-cols"><button type="button" class="rc-col" data-action="reclaim-day" data-day="${E}"\n        data-freed="1024" data-count="1" data-trash="3072" data-trash-count="1" aria-label="${E}: 1 KB freed by 1 cleanup, 3 KB moved to the Trash by 1 cleanup">\n        <span class="rc-stack rc-some" data-h="80">\n          <i class="rc-seg rc-seg-trash" data-h="75"></i>\n          <i class="rc-seg rc-seg-freed" data-h="25"></i>\n        </span>\n      </button><span class="rc-col" aria-hidden="true"></span><button type="button" class="rc-col" data-action="reclaim-day" data-day="${E}"\n        data-freed="0" data-count="2" data-trash="0" data-trash-count="0" aria-label="${E}: 0 B freed by 2 cleanups">\n        <span class="rc-stack" data-h="0">\n          \n          \n        </span>\n      </button></div>\n        \n      </div>` + chartAxis,
  'chart empty': chartHead(1) + `<div class="rc-yaxis" aria-hidden="true"><span></span><span></span><span>0</span></div>\n      <div class="rc-plot">\n        <div class="rc-grid" aria-hidden="true"><i></i><i></i><i></i></div>\n        <div class="rc-cols"><span class="rc-col" aria-hidden="true"></span></div>\n        <span class="rc-empty">Nothing reclaimed in the last 1 days</span>\n      </div>` + chartAxis,
  'history': `<div class="hx">\n      <div class="harness-pills hx-chips" role="group" aria-label="Filter the history">${historyChips('')}</div>\n      <p class="hx-summary">5 entries · 2 KB freed · 1 KB moved to the Trash</p>\n      <section class="hx-day">\n        <div class="hx-day-head"><span></span><span class="hx-day-bytes">2 KB freed</span></div>\n        <ul class="hx-list">`
    + historyEntry('removed', 'Removed worktree', '2 KB', `${E}/${E}`, `${E} · ${E}`, `<p class="hx-detail">${E}</p>`)
    + historyEntry('trash', `Moved ${E} to the Trash`, '1 KB', E, E, '')
    + historyEntry('clean', `Ran ${E}`, '', E, E, '')
    + historyEntry('ask', `Agent answered: ${E}`, '', E, E, `<p class="hx-detail">${E}</p>`)
    + historyEntry('other', E, '', E, E, '')
    + `</ul>\n      </section>\n      <p class="hx-note">Showing the newest 5 entries.</p>\n    </div>`,
  'history day filter': `<div class="hx">\n      <div class="harness-pills hx-chips" role="group" aria-label="Filter the history">${historyChips('trash')}<button type="button" class="wt-pill on hx-day-chip" data-action="history-day" data-day="" aria-label="Show every day">${E} ×</button></div>\n      <p class="hx-summary">0 entries · 0 B freed</p>\n      <div class="empty"><svg class="icon"><use href="#i-history"/></svg><span>Nothing matches this filter.</span></div>\n      \n    </div>`,
  'history empty': `<div class="hx">\n      <div class="harness-pills hx-chips" role="group" aria-label="Filter the history">${historyChips('')}</div>\n      <p class="hx-summary">0 entries · 0 B freed</p>\n      <div class="empty"><svg class="icon"><use href="#i-history"/></svg><span>No cleanups yet. Removing a worktree or clearing clutter books it here.</span></div>\n      \n    </div>`,
  'toast running': toastHead('Removing 5 worktrees', 'Hide — the rows keep the progress') + '<p class="rt-sub">2 of 5 done</p>\n    ' + toastBar('running', 40)
    + `<ul class="rt-items">${running(E, `${E} · 1 KB · 3 files`, E)}${running('starting', 'starting', '')}${running('starting', 'starting', '')}${failed(`now ${E} — ${E}`)}<li class="rt-more">and 1 more</li></ul>\n    `,
  'toast one running': toastHead(`Removing ${E}`, 'Hide — the rows keep the progress') + '\n    ' + toastBar('running', 50) + `<ul class="rt-items">${running('deleting', E, '')}</ul>\n    `,
  'toast removed': toastHead(`Removed ${E}`, 'Close') + '<p class="rt-sub">2 KB reclaimed</p>\n    ' + toastBar('done', 100) + '\n    ' + historyLink,
  'toast partial': toastHead('Removed 1 of 2 worktrees', 'Close') + '<p class="rt-sub">1 KB reclaimed · 1 not removed</p>\n    ' + toastBar('partial', 100) + `<ul class="rt-items">${failed(E)}</ul>\n    ` + historyLink,
  'toast not removed': toastHead(`Not removed: ${E}`, 'Close') + '\n    ' + toastBar('failed', 100) + `<ul class="rt-items">${failed(E)}</ul>\n    ` + historyLink,
  'note with discuss': `<p class="wt-advice"><b>Saved opinion: ${E}</b> · ${E} ${discussButton}</p>`,
  'row orphan': rowHead('keep', 'work', ' open', '', 'keep', 'this row cannot be marked for removal <span class="wt-more">+1 more</span>', '', '<span class="wt-size">≥1 KB</span><span class="wt-idle">3d idle</span>')
    + `<span class="wt-stale">stale</span></div></div>\n      <section class="wt-scan-checks"><h5>Scan checks</h5>\n      ${sessionFact}\n      <p class="wt-submodules"><svg class="icon" aria-hidden="true"><use href="#i-branch"/></svg><strong>Submodules</strong><span>2 populated · inspection incomplete</span></p>\n      <ul class="wt-reasons wt-reason-tags" role="list"><li class="wt-reason">${E}</li><li class="wt-reason wt-reason-keep">${E}2</li></ul>\n      ${reviewHint}\n      \n      </section>\n      <div class="wt-actions"><button type="button" class="btn btn-sm" data-action="worktree-reveal" data-path="${E}/${E}">Open folder</button><button type="button" class="btn btn-sm" data-action="worktree-reconnect" data-path="${E}/${E}" data-repo="${E}">Reconnect</button><button type="button" class="btn btn-danger btn-sm" data-action="worktree-trash-orphan" data-path="${E}/${E}">Move to Trash</button></div>\n      `
    + savedAdvice('', `<p class="wt-advice"><b>Saved opinion: ${E}</b> · ${E}</p><p class="wt-ask wt-ask-${E}"><b>Asked ${E}:</b> ${E} — ${E}</p>`) + `\n    </div>\n    <p class="wt-removal wt-removal-failed" role="alert"><b>Removal failed:</b> ${E}</p>\n  </details>`,
  'row orphan in use': rowHead('keep', 'active', '', '', 'agent', `${E} session active`, '', '<span class="wt-size">Measuring…</span>')
    + `<span class="wt-agent-live" title="${E} is working in this folder; removing it breaks that session">${E} working here</span></div></div>\n      <section class="wt-scan-checks"><h5>Scan checks</h5>\n      \n      \n      \n      ${reviewHint}\n      \n      </section>\n      <div class="wt-actions"><button type="button" class="btn btn-sm" data-action="worktree-reveal" data-path="${E}/${E}">Open folder</button><button type="button" class="btn btn-sm" disabled title="Cannot move to Trash: ${E} is working here">Move to Trash</button></div>\n      \n    </div>\n    \n  </details>`,
  'row remove': rowHead('remove', 'safe', '', checkbox(' checked disabled'), 'safe', E, '<span class="wt-advice-conflict">Saved advice differs</span>', '<span class="wt-size">1 KB</span>')
    + `</div></div>\n      <section class="wt-scan-checks"><h5>Scan checks</h5>\n      ${sessionFact}\n      \n      \n      \n      \n      </section>\n      <div class="wt-actions">${openButton(E)}<button type="button" class="btn btn-danger-solid btn-sm" data-action="worktree-remove" data-path="${E}/${E}" data-branch="${E}" title="Permanently delete this folder after a fresh check">Try again</button>${adviseButton}${discussButton}</div>\n      `
    + savedAdvice('This opinion differs from the scan above. ', `<p class="wt-advice"><b>Saved opinion: keep</b> · ${E}</p>`) + `\n    </div>\n    <p class="wt-removal wt-removal-failed" role="alert"><b>Not removed:</b> it is now ${E} — ${E}</p>\n  </details>`,
  'row removing': rowHead('remove', 'safe', '', '', 'keep', 'removal is already running', '', '<span class="wt-size">Measuring…</span>')
    + `</div></div>\n      <section class="wt-scan-checks"><h5>Scan checks</h5>\n      ${sessionFact}\n      \n      \n      \n      ${resolve('')}\n      </section>\n      <div class="wt-actions">${openButton(`${E}/${E}`)}<button type="button" class="btn btn-danger btn-sm" disabled>Removing…</button>${adviseButton}${discussButton}</div>\n      \n    </div>\n    <p class="wt-removal wt-removal-running" role="status"><span class="wt-steps" aria-hidden="true"><i class="on"></i><i class="on"></i><i class=""></i><i class=""></i></span><b>Removing…</b> ${E} · 1 KB · 2 files</p>\n  </details>`,
  'row prune': prunedRow,
  'row review': rowHead('review', 'check', '', checkbox(''), 'review', E, '', '<span class="wt-size">Measuring…</span><span class="wt-idle">today</span>')
    + `</div></div>\n      <section class="wt-scan-checks"><h5>Scan checks</h5>\n      ${sessionFact}\n      \n      \n      ${reviewHint}\n      \n      </section>\n      <div class="wt-actions">${openButton(E)}<button type="button" class="btn btn-warn-outline btn-sm" data-action="worktree-review-trash" data-path="${E}/${E}" title="Not confirmed safe: ${E}. Moves the folder to the Trash; the branch stays in git">Review Trash move…</button>${askButton('')}${adviseButton}${discussButton}</div>\n      \n    </div>\n    \n  </details>`,
  'row reviewed delete': rowHead('keep', 'work', '', checkbox(''), 'keep', E, '', '<span class="wt-size">Measuring…</span>')
    + `</div></div>\n      <section class="wt-scan-checks"><h5>Scan checks</h5>\n      ${sessionFact}\n      \n      \n      <p class="wt-review-hint">Review the ignored scratch files before deleting this folder. Its branch and committed source stay in git.</p>\n      \n      </section>\n      <div class="wt-actions">${openButton(E)}<button type="button" class="btn btn-danger btn-sm" data-action="worktree-remove" data-path="${E}/${E}" data-branch="${E}">Review permanent deletion…</button>${askButton('')}${adviseButton}${discussButton}</div>\n      `
    + savedAdvice('', `<p class="wt-ask wt-ask-answered"><b>Asked ${E}:</b> ${E} — ${E} (session $0.50)</p>`) + '\n    </div>\n    \n  </details>',
  'row waiting on agent': rowHead('keep', 'open', '', '', 'keep', 'waiting for the owning agent to finish', '', '<span class="wt-size">Measuring…</span>')
    + `</div></div>\n      <section class="wt-scan-checks"><h5>Scan checks</h5>\n      ${sessionFact}\n      \n      <ul class="wt-reasons wt-reason-tags" role="list"><li class="wt-reason">${E}</li></ul>\n      ${reviewHint}\n      ${resolve('')}\n      </section>\n      <div class="wt-actions">${openButton(E)}${askButton(' disabled')}${adviseButton}${discussButton}</div>\n      `
    + savedAdvice('', `<p class="wt-ask wt-ask-running"><b>Asked ${E}:</b> waiting for ${E}&#39;s answer as of the last read; Reload shows it</p>`) + '\n    </div>\n    \n  </details>',
  'row unknown state': rowHead(E, 'open', '', '', 'info', E, '', '<span class="wt-size">Measuring…</span>')
    + `</div></div>\n      <section class="wt-scan-checks"><h5>Scan checks</h5>\n      ${sessionFact}\n      \n      \n      \n      ${resolve('this row cannot be marked for removal')}\n      </section>\n      <div class="wt-actions">${openButton(E)}${discussButton}</div>\n      \n    </div>\n    \n  </details>`,
  'group with options': repoHead(`<span class="wt-repo-meta">${E} · ${E}</span>\n        <span class="wt-repo-size">4 KB</span>`, repoOptions(1)) + prunedRow + '\n  </section>',
  'group with error': repoHead('\n        ', `<span class="wt-repo-error">${E} — the folders below still point to it</span>`) + prunedRow + '\n  </section>',
  'group without options': repoHead('\n        ', '') + prunedRow + '\n  </section>',
  'lanes': `<section class="wt-lane wt-lane-safe" aria-labelledby="wt-lane-safe">\n      <div class="wt-lane-heading"><svg class="icon" aria-hidden="true"><use href="#i-shield"/></svg>\n        <div><h3 id="wt-lane-safe">Safe to remove <span class="wt-lane-count">1</span></h3><p>Merged, or every commit on a remote and idle. Each folder is checked again before it is deleted.</p></div><button type="button" class="btn btn-sm rc-remove-all" data-action="worktrees-remove-removable" disabled>Review 2 deletions · 3 KB</button></div>\n      `
    + repoHead('\n        ', repoOptions(2)) + prunedRow + '\n  </section>\n    </section>'
    + `<section class="wt-lane wt-lane-active" aria-labelledby="wt-lane-active">\n      <div class="wt-lane-heading"><svg class="icon" aria-hidden="true"><use href="#i-activity"/></svg>\n        <div><h3 id="wt-lane-active">In use <span class="wt-lane-count">1</span></h3><p>An agent is working in these folders.</p></div></div>\n      `
    + repoHead('\n        ', '') + `<details class="wt-row wt-keep wt-in-active" data-path="${E}">\n    <summary class="wt-main">\n      <span class="wt-select-slot"></span>\n      <div class="wt-identity">\n        <div class="wt-title"><span class="wt-branch">${E}</span></div>\n        <span class="wt-subtitle wt-tone-agent">Scan: ${E} session active</span>\n        \n      </div>\n      <div class="wt-facts">\n        <span class="wt-size">Measuring…</span>\n        <span class="wt-inspect-label">Inspect <svg class="icon wt-disclosure" aria-hidden="true"><use href="#i-arrow"/></svg></span>\n      </div>\n    </summary>\n    <div class="wt-inspection">\n      <div class="wt-inspection-header"><button type="button" class="wt-path" data-action="copy-path" data-path="${E}" title="${E} — click to copy">${E}</button>\n      <div class="wt-inspection-meta"><span class="wt-agent-live" title="${E} is working in this folder; removing it breaks that session">${E} working here</span></div></div>\n      <section class="wt-scan-checks"><h5>Scan checks</h5>\n      \n      \n      \n      ${reviewHint}\n      <p class="wt-resolve">${E} is working here <button type="button" class="link-btn" data-action="worktree-reveal" data-path="${E}">Open folder to resolve</button></p>\n      </section>\n      <div class="wt-actions"><button type="button" class="btn btn-ghost btn-sm wt-open" data-action="worktree-reveal" data-path="${E}" title="Show in Finder" aria-label="Show ${E} in Finder"><svg class="icon"><use href="#i-folder"/></svg></button><button type="button" class="btn btn-sm" data-action="worktree-advise" data-path="${E}" title="Refresh the saved second opinion; no agent is resumed">Ask advisor</button><button type="button" class="link-btn" data-action="worktree-discuss" data-path="${E}">Discuss</button></div>\n      \n    </div>\n    \n  </details>\n  </section>\n    </section>`,
  'filter pills': filterPill('', 'All', 3, false) + laneFilters([1, 0, 1, 0, 1], 'check') + stalePill(2, false),
  'filter pills stale': filterPill('', 'All', 3, false) + laneFilters([1, 0, 1, 0, 1], '') + stalePill(2, true),
  'selection bar': `<div class="wt-selection" role="group" aria-label="Worktree removal selection">\n    <div class="wt-selection-summary" role="status"><strong>2 selected</strong>\n      <span>Reclaim estimate: 1 KB · 1 to Trash (at least 2 KB (partial measurement)) · 2 hidden by filters · 1 pending removal</span>\n    </div>\n    <p class="wt-selection-hint">Moving to Trash does not free disk space until it is emptied.</p>\n    <div class="wt-selection-actions">\n      <button type="button" class="btn btn-sm" data-action="worktrees-select-visible" disabled>Select shown</button>\n      <button type="button" class="btn btn-sm" data-action="worktrees-clear-selection" title="Clear marks and cancel restoring marks after failures; removals already started continue">Clear selection</button>\n      <button type="button" class="btn btn-primary" data-action="worktrees-remove-selected">Review 2 removals</button>\n    </div>\n  </div>`,
  'selection review': `<div class="wt-confirm"><p class="wt-confirm-total"><strong>2 worktrees selected</strong><span>Reclaim estimate: 1 KB</span></p>\n    <section class="wt-confirm-group">\n    <h4>Checked deletion<span>1</span></h4><p>Permanently deletes these folders, including ignored .tmp scratch files and build output. Branches and committed work stay in git. Each folder is checked again before deletion.</p>\n    <ul><li><div><strong>${E}</strong><span>estimated 1 KB</span></div>\n      <code>${E}/${E}</code><p>${E}</p>\n      <p>Includes 2 inspected submodules. No local-only commits or stashes were found.</p></li></ul>\n    </section>\n    <section class="wt-confirm-group">\n    <h4>Move to Trash<span>1</span></h4><p>Moves these folders with their uncommitted, untracked and ignored files. This does not free disk space until Trash is emptied.</p>\n    <ul><li><div><strong>(detached)</strong><span>size unknown</span></div>\n      <code>${E}</code><p>${E}; ${E}</p>\n      </li></ul>\n    </section>\n    <p class="wt-confirm-note">Branches and commits stay in git. Files in Trash remain until it is emptied; putting them back does not register the worktree again.</p>\n  </div>`,
  'render worktrees error': { 'worktrees-container': `<div class="empty"><svg class="icon"><use href="#i-branch"/></svg><span>${E}</span></div>`, 'worktree-pills': '', 'worktrees-disk': '', 'worktrees-errors': '', 'worktrees-reclaim': '' },
  'render worktrees report': {
    'worktrees-container': '<div class="empty"><svg class="icon"><use href="#i-branch"/></svg><span>No linked worktrees found. Add a repository above if one is missing.</span></div>',
    'worktree-pills': filterPill('', 'All', 0, true) + laneFilters([0, 0, 0, 0, 0], '') + stalePill(0, false),
    'worktrees-disk': `<div class="wt-vol"><span class="wt-vol-name">${E}</span>\n      <span class="wt-vol-bar" aria-hidden="true"><i class="wt-vol-used" data-w="75"></i></span>\n      <span class="wt-vol-free">1 KB free of 4 KB</span></div>\n    <div class="wt-disk-stats">\n      <span><b>Worktrees</b> 1 KB</span>\n    </div>`,
    'worktrees-errors': `<li>${E}</li>`,
    'worktrees-reclaim': `<div class="rc-tiles">${tilesMarkup('0 B', '0 worktrees')}</div>` + chartHead(1) + `<div class="rc-yaxis" aria-hidden="true"><span>1 KB</span><span>512 B</span><span>0</span></div>\n      <div class="rc-plot">\n        <div class="rc-grid" aria-hidden="true"><i></i><i></i><i></i></div>\n        <div class="rc-cols"><button type="button" class="rc-col" data-action="reclaim-day" data-day="${E}"\n        data-freed="1024" data-count="1" data-trash="0" data-trash-count="0" aria-label="${E}: 1 KB freed by 1 cleanup">\n        <span class="rc-stack rc-some" data-h="100">\n          \n          <i class="rc-seg rc-seg-freed" data-h="100"></i>\n        </span>\n      </button></div>\n        \n      </div>` + chartAxis,
  },
  'render selection': { 'worktrees-container': '<div class="wt-selection" role="group" aria-label="Worktree removal selection">\n    <div class="wt-selection-summary" role="status"><strong>1 selected</strong>\n      <span>Reclaim estimate: 1 KB</span>\n    </div>\n    <p class="wt-selection-hint">Each worktree is inspected again before removal.</p>\n    <div class="wt-selection-actions">\n      <button type="button" class="btn btn-sm" data-action="worktrees-select-visible">Select shown 1</button>\n      <button type="button" class="btn btn-sm" data-action="worktrees-clear-selection">Clear selection</button>\n      <button type="button" class="btn btn-primary" data-action="worktrees-remove-selected">Review 1 removal</button>\n    </div>\n  </div>' },
  'clutter trash': trashedClutter,
  'clutter delete': clutterRowHead + `<button type="button" class="btn btn-danger btn-sm" data-action="clutter-remove" data-path="${E}/${E}">Delete cache</button><button type="button" class="btn btn-danger btn-sm" data-action="clutter-trash" data-path="${E}/${E}">Move to Trash</button>\n    </div>` + clutterRowTail,
  'clutter deleting': clutterRowHead + `<button type="button" class="btn btn-danger btn-sm" data-action="clutter-remove" data-path="${E}/${E}" disabled>Deleting…</button>\n    </div>` + clutterRowTail,
  'clutter clean': cleanRow('4d idle', E, E),
  'clutter clean default': cleanRow('—', '', 'clean'),
  'clutter group': `<section class="wt-repo">\n    <div class="wt-repo-head">\n      <span class="wt-repo-path" title="${E}">${E}</span>\n      <span class="wt-repo-meta">9 items</span>\n      <span class="wt-repo-size">4 KB</span>\n      <button type="button" class="link-btn wt-hide" data-action="clutter-advise" data-project="${E}">Ask advisor</button>\n    </div>\n    <div class="wt-advice cl-plan"><b>Advisor:</b> ${E}<ol><li>${E}</li><li>${E}</li></ol></div>\n    ${idleRow.repeat(8)}\n    <button type="button" class="link-btn cl-more" data-action="clutter-more" data-project="${E}">Show 1 more</button>\n  </section>`,
  'clutter machine group': `<section class="wt-repo">\n    <div class="wt-repo-head">\n      <span class="wt-repo-path" title="This machine">This machine</span>\n      <span class="wt-repo-meta">1 item</span>\n      \n      <button type="button" class="link-btn wt-hide" data-action="clutter-advise" data-project="machine">Ask advisor</button>\n    </div>\n    \n    <div class="wt-row cl-row cl-${E}" data-path="${E}/${E}">\n    <div class="wt-main">\n      <span class="wt-state cl-kind">${E}</span>\n      <span class="wt-branch">${E}</span>\n      <span class="wt-path" title="${E}/${E}">${E}/${E}</span>\n      <span class="wt-size"></span>\n      <span class="wt-idle">—</span>\n      \n    </div>\n    \n  </div>\n    \n  </section>`,
  'clutter pills': clutterPill('', 'All', '3 KB', false) + clutterPill(E, E, '1 KB', false) + clutterPill('tmp', '.tmp', '2 KB', true),
  'render clutter error': { 'clutter-container': `<div class="empty"><svg class="icon"><use href="#i-server"/></svg><span>${E}</span></div>`, 'clutter-pills': '' },
  'render clutter report': {
    'clutter-container': `<section class="wt-repo">\n    <div class="wt-repo-head">\n      <span class="wt-repo-path" title="${E}">${E}</span>\n      <span class="wt-repo-meta">1 item</span>\n      <span class="wt-repo-size">1 KB</span>\n      <button type="button" class="link-btn wt-hide" data-action="clutter-advise" data-project="${E}">Ask advisor</button>\n    </div>\n    \n    ${trashedClutter}\n    \n  </section>`,
    'clutter-pills': clutterPill('', 'All', '1 KB', true) + clutterPill(E, E, '1 KB', false),
  },
};

for (const [name, run] of Object.entries(cases)) {
  test(`worktrees tab markup: ${name}`, () => {
    assert.deepEqual(run(), expected[name]);
  });
}
