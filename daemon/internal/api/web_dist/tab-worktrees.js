// Worktrees tab: every git worktree the daemon found, grouped by repository,
// with its remove/review/keep/prune verdict and reasons. The report comes
// from GET /worktrees on tab open (the daemon caches a scan for 10 minutes);
// Rescan asks for a fresh one. Remove and Prune post /worktrees/remove, which
// inspects the worktree again and refuses anything but a fresh remove.

const WORKTREE_STATES = ['remove', 'review', 'keep', 'prune'];

// worktreeStateCounts: rows per state (main rows excluded) plus stale.
function worktreeStateCounts(rep) {
  const out = { all: 0, remove: 0, review: 0, keep: 0, prune: 0, stale: 0 };
  for (const repo of (rep && rep.repos) || []) {
    for (const w of repo.worktrees || []) {
      if (w.state === 'main') continue;
      out.all++;
      if (out[w.state] !== undefined) out[w.state]++;
      if (w.stale) out.stale++;
    }
  }
  return out;
}

// worktreeGroups: repositories with the rows the filter keeps, biggest
// first (the list is where disk comes back). filter.state is '' (all) or a
// state; filter.stale keeps stale rows only.
function worktreeGroups(rep, filter) {
  const f = filter || {};
  const groups = [];
  for (const repo of (rep && rep.repos) || []) {
    const rows = (repo.worktrees || []).filter(w => w.state !== 'main'
      && (!f.state || w.state === f.state) && (!f.stale || w.stale));
    if (rows.length) groups.push({ repo, rows });
  }
  return groups.sort((a, b) => (Number(b.repo.size_bytes) || 0) - (Number(a.repo.size_bytes) || 0));
}

// fmtDisk: fmtRSS up to GB, then TB (volumes are terabytes).
function fmtDisk(n) {
  n = Number(n);
  if (n >= 1099511627776) return (n / 1099511627776).toFixed(1) + ' TB';
  return fmtRSS(n) || '0 B';
}

// worktreeDiskHTML: the volumes holding the repositories (used share as a
// bar), what worktrees occupy and what is removable, and what cleanups
// have given back so far.
function worktreeDiskHTML(rep) {
  if (!rep) return '';
  const s = rep.summary || {};
  const vols = (rep.volumes || []).map(v => {
    const total = Number(v.total_bytes) || 0;
    const used = total ? Math.min(100, Math.round((1 - (Number(v.free_bytes) || 0) / total) * 100)) : 0;
    return `<div class="wt-vol"><span class="wt-vol-name">${escapeHTML(v.mount)}</span>
      <span class="wt-vol-bar" aria-hidden="true"><i class="wt-vol-used" data-w="${used}"></i></span>
      <span class="wt-vol-free">${escapeHTML(fmtDisk(v.free_bytes))} free of ${escapeHTML(fmtDisk(total))}</span></div>`;
  }).join('');
  const measuring = rep.sizing ? ' <span class="wt-measuring">measuring…</span>' : '';
  const r = rep.reclaimed;
  const reclaimed = r && r.count
    ? `${escapeHTML(fmtDisk(r.bytes))} over ${r.count} cleanup${r.count === 1 ? '' : 's'} · ${escapeHTML(fmtDisk(r.bytes_30d))} in 30 days`
    : 'nothing yet';
  return `${vols}
    <div class="wt-disk-stats">
      <span><b>Worktrees</b> ${escapeHTML(fmtDisk(s.size_bytes))}${measuring}</span>
      <span><b>Removable</b> ${escapeHTML(fmtDisk(s.removable_bytes))}</span>
      <span><b>Reclaimed</b> ${reclaimed}</span>
    </div>`;
}

// worktreeSizeLabel: a row's measured size; a walk that hit its bound reads
// as a lower bound.
function worktreeSizeLabel(w) {
  if (!w.size_bytes) return '';
  return (w.size_partial ? '≥' : '') + fmtDisk(w.size_bytes);
}

// worktreePathLabel: a worktree inside its repository reads relative to it.
function worktreePathLabel(path, repoPath) {
  const prefix = String(repoPath || '').replace(/\/$/, '') + '/';
  return String(path || '').startsWith(prefix) ? String(path).slice(prefix.length) : String(path || '');
}

function worktreeIdleLabel(w) {
  if (!w.last_activity) return '—';
  return w.idle_days === 0 ? 'today' : `${w.idle_days}d idle`;
}

// worktreeNoteHTML: the local advisor's note, shown under the reasons. It
// is advice only; the state and the buttons never depend on it.
function worktreeNoteHTML(note) {
  if (!note) return '';
  const conf = note.confidence ? ` ${Math.round(note.confidence * 100)}%` : '';
  return `<p class="wt-advice"><b>Advisor: ${escapeHTML(note.assessment || '')}</b>${escapeHTML(conf)} · ${escapeHTML(note.rationale || '')}</p>`;
}

// worktreeRowHTML: one worktree. Remove only on state remove, Prune only on
// state prune; the daemon enforces the same rule again on the request. Ask
// advisor on review and keep rows, where a second opinion helps.
function worktreeRowHTML(w, repo, note) {
  const branch = w.branch || (w.detached ? '(detached)' : '');
  const reasons = (w.reasons || []).map(r => `<li>${escapeHTML(r)}</li>`).join('');
  let action = '';
  if (w.state === 'remove') {
    action = `<button type="button" class="btn btn-danger btn-sm" data-action="worktree-remove" data-path="${escapeHTML(w.path)}" data-branch="${escapeHTML(branch)}">Remove</button>`;
  } else if (w.state === 'prune') {
    action = `<button type="button" class="btn btn-sm" data-action="worktree-prune" data-repo="${escapeHTML(repo.path)}">Prune</button>`;
  } else if (w.state === 'review' || w.state === 'keep') {
    action = `<button type="button" class="btn btn-sm" data-action="worktree-advise" data-path="${escapeHTML(w.path)}">Ask advisor</button>`;
  }
  return `<div class="wt-row wt-${escapeHTML(w.state)}" data-path="${escapeHTML(w.path)}">
    <div class="wt-main">
      <span class="wt-state">${escapeHTML(w.state)}</span>${w.stale ? '<span class="wt-stale">stale</span>' : ''}
      <span class="wt-branch">${escapeHTML(branch)}</span>
      <span class="wt-path" title="${escapeHTML(w.path)}">${escapeHTML(worktreePathLabel(w.path, repo.path))}</span>
      <span class="wt-size">${escapeHTML(worktreeSizeLabel(w))}</span>
      <span class="wt-idle">${escapeHTML(worktreeIdleLabel(w))}</span>
      ${action}
    </div>
    ${reasons ? `<ul class="wt-reasons">${reasons}</ul>` : ''}
    ${worktreeNoteHTML(note)}
  </div>`;
}

// worktreeGroupHTML: one repository block with its rows and a Hide button.
// advice maps a worktree path to its advisor note.
function worktreeGroupHTML(g, advice) {
  const meta = [g.repo.default_branch, g.repo.source].filter(Boolean).join(' · ');
  return `<section class="wt-repo">
    <div class="wt-repo-head">
      <span class="wt-repo-path" title="${escapeHTML(g.repo.path)}">${escapeHTML(g.repo.path)}</span>
      ${meta ? `<span class="wt-repo-meta">${escapeHTML(meta)}</span>` : ''}
      ${g.repo.size_bytes ? `<span class="wt-repo-size">${escapeHTML(fmtDisk(g.repo.size_bytes))}</span>` : ''}
      <button type="button" class="link-btn wt-hide" data-action="worktree-hide" data-repo="${escapeHTML(g.repo.path)}">Hide repo</button>
    </div>
    ${g.rows.map(w => worktreeRowHTML(w, g.repo, (advice || {})[w.path])).join('')}
  </section>`;
}

// worktreeFilterHTML: one pill per state with its count, then stale.
function worktreeFilterHTML(counts, filter) {
  const f = filter || {};
  const pill = (state, label, n) => `<button type="button" class="wt-pill${(f.state || '') === state ? ' on' : ''}" data-action="worktree-filter" data-state="${state}" aria-pressed="${(f.state || '') === state}">${label} <b>${n}</b></button>`;
  return pill('', 'All', counts.all)
    + WORKTREE_STATES.map(s => pill(s, s[0].toUpperCase() + s.slice(1), counts[s])).join('')
    + `<button type="button" class="wt-pill${f.stale ? ' on' : ''}" data-action="worktree-stale" aria-pressed="${!!f.stale}">Stale <b>${counts.stale}</b></button>`;
}

// worktreesSummaryText: the scan line under the header.
function worktreesSummaryText(rep) {
  if (!rep) return '';
  const s = rep.summary || {};
  const when = rep.cached ? 'cached scan' : `scanned in ${(Number(rep.duration_ms || 0) / 1000).toFixed(1)}s`;
  const n = (v, one, many) => `${v || 0} ${v === 1 ? one : many}`;
  return `${n(s.repos, 'repo', 'repos')} · ${n(s.worktrees, 'worktree', 'worktrees')} · stale after ${rep.stale_days || 0} idle days · ${when}`;
}

function renderWorktrees() {
  const SA = window.SA;
  const container = document.getElementById('worktrees-container');
  const pills = document.getElementById('worktree-pills');
  const summary = document.getElementById('worktrees-summary');
  const disk = document.getElementById('worktrees-disk');
  const errors = document.getElementById('worktrees-errors');
  if (!container) return;
  const state = SA.worktrees;
  const rep = state.report;

  if (!rep) {
    container.innerHTML = state.loading
      ? '<div class="loading">Scanning worktrees… the first scan reads every repository and can take a minute.</div>'
      : `<div class="empty"><svg class="icon"><use href="#i-branch"/></svg><span>${escapeHTML(state.error || 'No scan yet.')}</span></div>`;
    if (pills) pills.innerHTML = '';
    if (summary) summary.textContent = '';
    if (disk) disk.innerHTML = '';
    if (errors) errors.hidden = true;
    return;
  }
  const counts = worktreeStateCounts(rep);
  if (pills) pills.innerHTML = worktreeFilterHTML(counts, state.filter);
  if (summary) summary.textContent = worktreesSummaryText(rep) + (state.loading ? ' · rescanning…' : '');
  if (disk) {
    disk.innerHTML = worktreeDiskHTML(rep);
    applyInlineMetrics(disk);
  }
  if (errors) {
    const list = rep.errors || [];
    errors.hidden = list.length === 0;
    errors.innerHTML = list.map(e => `<li>${escapeHTML(e)}</li>`).join('');
  }
  const groups = worktreeGroups(rep, state.filter);
  container.innerHTML = groups.length
    ? groups.map(g => worktreeGroupHTML(g, rep.advice)).join('')
    : `<div class="empty"><svg class="icon"><use href="#i-branch"/></svg><span>${counts.all ? 'No worktree matches this filter.' : 'No linked worktrees found. Add a repository above if one is missing.'}</span></div>`;
}

// ---------- clutter ----------
// .tmp and .quarantine folders, build output, tool and app caches from
// GET /cleanup, grouped by project (machine-wide caches under "This
// machine"), biggest first. Move to Trash and tool clean post
// /cleanup/trash and /cleanup/clean; the daemon re-checks each request.

const CLUTTER_KINDS = [
  ['tmp', '.tmp'], ['quarantine', '.quarantine'], ['repo-cache', 'Build output'],
  ['tool-cache', 'Tool caches'], ['app-cache', 'App caches'],
];

function clutterKindLabel(kind) {
  const k = CLUTTER_KINDS.find(([id]) => id === kind);
  return k ? k[1] : kind;
}

// clutterGroups: items the filter keeps, grouped by project, biggest group
// first; items keep the daemon's biggest-first order.
function clutterGroups(rep, filter) {
  const f = filter || {};
  const byProject = new Map();
  for (const it of (rep && rep.items) || []) {
    if (f.kind && it.kind !== f.kind) continue;
    const key = it.project || '';
    if (!byProject.has(key)) byProject.set(key, { project: key, items: [], bytes: 0 });
    const g = byProject.get(key);
    g.items.push(it);
    g.bytes += Number(it.size_bytes) || 0;
  }
  return [...byProject.values()].sort((a, b) => b.bytes - a.bytes);
}

function clutterItemHTML(it, project) {
  const size = it.size_bytes ? (it.size_partial ? '≥' : '') + fmtDisk(it.size_bytes) : '';
  const idle = it.last_touched ? (it.idle_days === 0 ? 'today' : `${it.idle_days}d idle`) : '—';
  const label = project ? worktreePathLabel(it.path, project) : it.path;
  let action = '';
  if (it.action === 'trash') {
    action = `<button type="button" class="btn btn-danger btn-sm" data-action="clutter-trash" data-path="${escapeHTML(it.path)}">Move to Trash</button>`;
  } else if (it.action === 'clean') {
    action = `<button type="button" class="btn btn-sm" data-action="clutter-clean" data-name="${escapeHTML(it.name)}" title="${escapeHTML(it.command || '')}">Run ${escapeHTML(it.command || 'clean')}</button>`;
  }
  const notes = [it.note].filter(Boolean).map(n => `<li>${escapeHTML(n)}</li>`).join('');
  return `<div class="wt-row cl-row cl-${escapeHTML(it.kind)}" data-path="${escapeHTML(it.path)}">
    <div class="wt-main">
      <span class="wt-state cl-kind">${escapeHTML(clutterKindLabel(it.kind))}</span>
      <span class="wt-branch">${escapeHTML(it.name)}</span>
      <span class="wt-path" title="${escapeHTML(it.path)}">${escapeHTML(label)}</span>
      <span class="wt-size">${escapeHTML(size)}</span>
      <span class="wt-idle">${escapeHTML(idle)}</span>
      ${action}
    </div>
    ${notes ? `<ul class="wt-reasons">${notes}</ul>` : ''}
  </div>`;
}

// CLUTTER_GROUP_ROWS caps the rows a project shows until expanded: a
// machine holds thousands of build folders.
const CLUTTER_GROUP_ROWS = 8;

function clutterGroupHTML(g, expanded) {
  const title = g.project || 'This machine';
  const open = expanded && expanded.has(g.project);
  const shown = open ? g.items : g.items.slice(0, CLUTTER_GROUP_ROWS);
  const more = g.items.length - shown.length;
  return `<section class="wt-repo">
    <div class="wt-repo-head">
      <span class="wt-repo-path" title="${escapeHTML(title)}">${escapeHTML(title)}</span>
      <span class="wt-repo-meta">${g.items.length} item${g.items.length === 1 ? '' : 's'}</span>
      ${g.bytes ? `<span class="wt-repo-size">${escapeHTML(fmtDisk(g.bytes))}</span>` : ''}
    </div>
    ${shown.map(it => clutterItemHTML(it, g.project)).join('')}
    ${more > 0 ? `<button type="button" class="link-btn cl-more" data-action="clutter-more" data-project="${escapeHTML(g.project)}">Show ${more} more</button>` : ''}
  </section>`;
}

function clutterPillsHTML(rep, filter) {
  const f = filter || {};
  const total = ((rep && rep.kinds) || []).reduce((n, k) => n + (Number(k.bytes) || 0), 0);
  const pill = (kind, label, bytes) => `<button type="button" class="wt-pill${(f.kind || '') === kind ? ' on' : ''}" data-action="clutter-filter" data-kind="${kind}" aria-pressed="${(f.kind || '') === kind}">${escapeHTML(label)} <b>${escapeHTML(fmtDisk(bytes))}</b></button>`;
  return pill('', 'All', total) + ((rep && rep.kinds) || []).map(k => pill(k.kind, clutterKindLabel(k.kind), k.bytes)).join('');
}

function clutterSummaryText(rep) {
  if (!rep) return '';
  const items = rep.items || [];
  const clearable = items.filter(it => it.action !== 'none').reduce((n, it) => n + (Number(it.size_bytes) || 0), 0);
  let text = `${items.length} item${items.length === 1 ? '' : 's'} · ${fmtDisk(clearable)} clearable`;
  if (rep.sizing) text += ' · measuring…';
  const r = rep.reclaimed;
  if (r && r.trashed_count) text += ` · ${fmtDisk(r.trashed_bytes)} moved to the Trash by cleanups (frees when the Trash is emptied)`;
  return text;
}

function renderClutter() {
  const SA = window.SA;
  const container = document.getElementById('clutter-container');
  const pills = document.getElementById('clutter-pills');
  const summary = document.getElementById('clutter-summary');
  if (!container) return;
  const state = SA.clutter;
  const rep = state.report;
  if (!rep) {
    container.innerHTML = state.loading
      ? '<div class="loading">Looking for clutter…</div>'
      : `<div class="empty"><svg class="icon"><use href="#i-server"/></svg><span>${escapeHTML(state.error || 'No inventory yet.')}</span></div>`;
    if (pills) pills.innerHTML = '';
    if (summary) summary.textContent = '';
    return;
  }
  if (pills) pills.innerHTML = clutterPillsHTML(rep, state.filter);
  if (summary) summary.textContent = clutterSummaryText(rep) + (state.loading ? ' · rescanning…' : '');
  const groups = clutterGroups(rep, state.filter);
  container.innerHTML = groups.length
    ? groups.map(g => clutterGroupHTML(g, state.expanded)).join('')
    : '<div class="empty"><svg class="icon"><use href="#i-server"/></svg><span>Nothing to clear.</span></div>';
}
