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

// worktreeGroups: repositories with the rows the filter keeps. filter.state
// is '' (all) or a state; filter.stale keeps stale rows only.
function worktreeGroups(rep, filter) {
  const f = filter || {};
  const groups = [];
  for (const repo of (rep && rep.repos) || []) {
    const rows = (repo.worktrees || []).filter(w => w.state !== 'main'
      && (!f.state || w.state === f.state) && (!f.stale || w.stale));
    if (rows.length) groups.push({ repo, rows });
  }
  return groups;
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

// worktreeRowHTML: one worktree. Remove only on state remove, Prune only on
// state prune; the daemon enforces the same rule again on the request.
function worktreeRowHTML(w, repo) {
  const branch = w.branch || (w.detached ? '(detached)' : '');
  const reasons = (w.reasons || []).map(r => `<li>${escapeHTML(r)}</li>`).join('');
  let action = '';
  if (w.state === 'remove') {
    action = `<button type="button" class="btn btn-danger btn-sm" data-action="worktree-remove" data-path="${escapeHTML(w.path)}" data-branch="${escapeHTML(branch)}">Remove</button>`;
  } else if (w.state === 'prune') {
    action = `<button type="button" class="btn btn-sm" data-action="worktree-prune" data-repo="${escapeHTML(repo.path)}">Prune</button>`;
  }
  return `<div class="wt-row wt-${escapeHTML(w.state)}" data-path="${escapeHTML(w.path)}">
    <div class="wt-main">
      <span class="wt-state">${escapeHTML(w.state)}</span>${w.stale ? '<span class="wt-stale">stale</span>' : ''}
      <span class="wt-branch">${escapeHTML(branch)}</span>
      <span class="wt-path" title="${escapeHTML(w.path)}">${escapeHTML(worktreePathLabel(w.path, repo.path))}</span>
      <span class="wt-idle">${escapeHTML(worktreeIdleLabel(w))}</span>
      ${action}
    </div>
    ${reasons ? `<ul class="wt-reasons">${reasons}</ul>` : ''}
  </div>`;
}

// worktreeGroupHTML: one repository block with its rows and a Hide button.
function worktreeGroupHTML(g) {
  const meta = [g.repo.default_branch, g.repo.source].filter(Boolean).join(' · ');
  return `<section class="wt-repo">
    <div class="wt-repo-head">
      <span class="wt-repo-path" title="${escapeHTML(g.repo.path)}">${escapeHTML(g.repo.path)}</span>
      ${meta ? `<span class="wt-repo-meta">${escapeHTML(meta)}</span>` : ''}
      <button type="button" class="link-btn wt-hide" data-action="worktree-hide" data-repo="${escapeHTML(g.repo.path)}">Hide repo</button>
    </div>
    ${g.rows.map(w => worktreeRowHTML(w, g.repo)).join('')}
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
    if (errors) errors.hidden = true;
    return;
  }
  const counts = worktreeStateCounts(rep);
  if (pills) pills.innerHTML = worktreeFilterHTML(counts, state.filter);
  if (summary) summary.textContent = worktreesSummaryText(rep) + (state.loading ? ' · rescanning…' : '');
  if (errors) {
    const list = rep.errors || [];
    errors.hidden = list.length === 0;
    errors.innerHTML = list.map(e => `<li>${escapeHTML(e)}</li>`).join('');
  }
  const groups = worktreeGroups(rep, state.filter);
  container.innerHTML = groups.length
    ? groups.map(worktreeGroupHTML).join('')
    : `<div class="empty"><svg class="icon"><use href="#i-branch"/></svg><span>${counts.all ? 'No worktree matches this filter.' : 'No linked worktrees found. Add a repository above if one is missing.'}</span></div>`;
}
