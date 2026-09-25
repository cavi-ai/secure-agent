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

// worktreeMatches: the search box keeps rows whose branch, path or
// repository contains the text, ignoring case.
function worktreeMatches(w, repo, q) {
  const needle = String(q || '').trim().toLowerCase();
  if (!needle) return true;
  return [w.branch, w.path, repo && repo.path].some(s => String(s || '').toLowerCase().includes(needle));
}

// worktreeGroups: repositories with the rows the filter keeps, biggest
// first (the list is where disk comes back). filter.state is '' (all) or a
// state; filter.stale keeps stale rows only; filter.q is the search text.
function worktreeGroups(rep, filter) {
  const f = filter || {};
  const groups = [];
  for (const repo of (rep && rep.repos) || []) {
    const rows = (repo.worktrees || []).filter(w => w.state !== 'main'
      && (!f.state || w.state === f.state) && (!f.stale || w.stale) && worktreeMatches(w, repo, f.q));
    if (rows.length) groups.push({ repo, rows });
  }
  // A repository that could not be read (moved, deleted) comes first: its
  // folders need a decision. Then the biggest.
  return groups.sort((a, b) => (b.repo.error ? 1 : 0) - (a.repo.error ? 1 : 0)
    || (Number(b.repo.size_bytes) || 0) - (Number(a.repo.size_bytes) || 0));
}

// fmtDisk: fmtRSS up to GB, then TB (volumes are terabytes).
function fmtDisk(n) {
  n = Number(n);
  if (n >= 1099511627776) return (n / 1099511627776).toFixed(1) + ' TB';
  return fmtRSS(n) || '0 B';
}

// worktreeDiskHTML: the volumes holding the repositories (used share as a
// bar) and what worktrees occupy. Removable and reclaimed space are the
// tiles above (reclaimTilesHTML).
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
  return `${vols}
    <div class="wt-disk-stats">
      <span><b>Worktrees</b> ${escapeHTML(fmtDisk(s.size_bytes))}${measuring}</span>
    </div>`;
}

// ---------- reclaimed space: tiles, daily chart, history ----------
// The ledger (GET /cleanup/ledger?days=30) books every cleanup with the
// bytes it gave back; moves to the Trash count apart until the Trash is
// emptied.

const RECLAIM_DAYS = 30;
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// localDayKey: YYYY-MM-DD of a timestamp in this browser's time zone (the
// daemon's daily series uses the same machine's zone).
function localDayKey(ts) {
  const d = ts instanceof Date ? ts : new Date(ts);
  if (!isFinite(d.getTime())) return '';
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

// fmtDayKey: "Sep 25" from YYYY-MM-DD, parsed by hand (Date.parse reads a
// bare date as UTC); "Today" and "Yesterday" relative to todayKey.
function fmtDayKey(key, todayKey, withWeekday) {
  const [y, m, d] = String(key || '').split('-').map(Number);
  if (!y || !m || !d) return String(key || '');
  if (todayKey && key === todayKey) return 'Today';
  const date = new Date(y, m - 1, d);
  if (todayKey) {
    const [ty, tm, td] = todayKey.split('-').map(Number);
    const yesterday = new Date(ty, tm - 1, td - 1);
    if (localDayKey(yesterday) === key) return 'Yesterday';
  }
  const label = `${MONTHS[m - 1]} ${d}`;
  return withWeekday ? `${['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][date.getDay()]}, ${label}` : label;
}

// niceBytesCeil: the axis top for max bytes: 1, 2 or 5 × a power of ten in
// the unit fmtDisk would print max in.
function niceBytesCeil(max) {
  max = Number(max) || 0;
  if (max <= 0) return 0;
  let unit = 1;
  while (max / unit >= 1024 && unit < 1099511627776) unit *= 1024;
  const v = max / unit;
  const mag = Math.pow(10, Math.floor(Math.log10(v)));
  const f = v / mag;
  const nice = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
  return nice * mag * unit;
}

// removableEverywhere: every removable row of every readable repository
// with no removal running, and their bytes.
function removableEverywhere(rep) {
  const rows = [];
  for (const repo of (rep && rep.repos) || []) {
    if (repo.error) continue;
    for (const w of removableRows(repo, rep.removals)) rows.push({ w, repo });
  }
  return { rows, bytes: rows.reduce((n, r) => n + (Number(r.w.size_bytes) || 0), 0) };
}

// reclaimTilesHTML: what the charted days freed, what cleanups freed all
// time, what Remove can free now (Remove all across repositories when two
// or more rows are removable), and what waits in the Trash. Before the
// ledger loads the report's totals stand in.
function reclaimTilesHTML(rep, ledger) {
  const totals = (ledger && ledger.totals) || (rep && rep.reclaimed) || {};
  const daily = (ledger && ledger.daily) || null;
  const freed = daily ? daily.reduce((n, d) => n + (Number(d.bytes) || 0), 0) : Number(totals.bytes_30d) || 0;
  const freedCount = daily ? daily.reduce((n, d) => n + (Number(d.count) || 0), 0) : Number(totals.count_30d) || 0;
  const rm = removableEverywhere(rep);
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  const tile = (cls, label, value, hint, extra) => `<div class="rc-tile ${cls}">
      <span class="rc-tile-label">${label}</span>
      <span class="rc-tile-value">${escapeHTML(value)}</span>
      <span class="rc-tile-hint">${hint}</span>${extra || ''}
    </div>`;
  const removeAll = rm.rows.length >= 2
    ? `<button type="button" class="btn btn-danger btn-sm rc-remove-all" data-action="worktrees-remove-removable">Remove all ${rm.rows.length}</button>`
    : '';
  return tile('rc-freed', `Freed · last ${daily ? daily.length : RECLAIM_DAYS} days`, fmtDisk(freed), escapeHTML(plural(freedCount, 'cleanup', 'cleanups')))
    + tile('rc-alltime', 'Freed · all time', fmtDisk(totals.bytes), escapeHTML(plural(Number(totals.count) || 0, 'cleanup', 'cleanups')))
    + tile('rc-removable', 'Removable now', fmtDisk(rm.bytes), escapeHTML(plural(rm.rows.length, 'worktree', 'worktrees')) + (rep && rep.sizing ? ' · measuring…' : ''), removeAll)
    + tile('rc-trash', 'In the Trash', fmtDisk(totals.trashed_bytes), 'frees when the Trash is emptied');
}

// reclaimDayText: a day's numbers as the column label and tooltip read
// them: freed with its cleanups, then what went to the Trash.
function reclaimDayText(bytes, count, trashBytes, trashCount) {
  const n = (v, one, many) => `${v} ${v === 1 ? one : many}`;
  const lines = [`${fmtDisk(bytes)} freed by ${n(Number(count) || 0, 'cleanup', 'cleanups')}`];
  if (Number(trashBytes) || Number(trashCount)) lines.push(`${fmtDisk(trashBytes)} moved to the Trash by ${n(Number(trashCount) || 0, 'cleanup', 'cleanups')}`);
  return lines;
}

// reclaimChartHTML: one column per day of the daily series on one byte
// axis: bytes freed at the base, bytes moved to the Trash stacked on top.
// A day with cleanups is a button that opens the history at that day; its
// numbers ride in data attributes for the tooltip and in its label.
function reclaimChartHTML(daily, todayKey) {
  if (!daily || !daily.length) return '';
  const total = d => (Number(d.bytes) || 0) + (Number(d.trashed_bytes) || 0);
  const top = niceBytesCeil(Math.max(...daily.map(total)));
  const cols = daily.map(d => {
    const sum = total(d);
    const count = Number(d.count) || 0;
    const trashCount = Number(d.trashed_count) || 0;
    if (!sum && !count && !trashCount) return '<span class="rc-col" aria-hidden="true"></span>';
    const freedPct = sum ? Math.round((Number(d.bytes) || 0) / sum * 100) : 0;
    const label = `${fmtDayKey(d.day, todayKey)}: ${reclaimDayText(d.bytes, count, d.trashed_bytes, trashCount).join(', ')}`;
    return `<button type="button" class="rc-col" data-action="reclaim-day" data-day="${escapeHTML(d.day)}"
        data-freed="${Number(d.bytes) || 0}" data-count="${count}" data-trash="${Number(d.trashed_bytes) || 0}" data-trash-count="${trashCount}" aria-label="${escapeHTML(label)}">
        <span class="rc-stack${sum ? ' rc-some' : ''}" data-h="${top ? Math.round(sum / top * 1000) / 10 : 0}">
          ${d.trashed_bytes ? `<i class="rc-seg rc-seg-trash" data-h="${100 - freedPct}"></i>` : ''}
          ${d.bytes ? `<i class="rc-seg rc-seg-freed" data-h="${freedPct}"></i>` : ''}
        </span>
      </button>`;
  }).join('');
  const mid = Math.floor(daily.length / 2);
  const empty = top ? '' : `<span class="rc-empty">Nothing reclaimed in the last ${daily.length} days</span>`;
  return `<div class="rc-chart-head">
      <span class="rc-chart-title">Reclaimed per day</span>
      <span class="rc-legend"><span class="rc-key rc-key-freed"></span>Freed<span class="rc-key rc-key-trash"></span>Moved to the Trash</span>
    </div>
    <div class="rc-chart" role="group" aria-label="Space reclaimed per day, last ${daily.length} days">
      <div class="rc-yaxis" aria-hidden="true"><span>${escapeHTML(top ? fmtDisk(top) : '')}</span><span>${escapeHTML(top ? fmtDisk(top / 2) : '')}</span><span>0</span></div>
      <div class="rc-plot">
        <div class="rc-grid" aria-hidden="true"><i></i><i></i><i></i></div>
        <div class="rc-cols">${cols}</div>
        ${empty}
      </div>
      <div class="rc-xaxis" aria-hidden="true"><span>${escapeHTML(fmtDayKey(daily[0].day))}</span><span>${escapeHTML(fmtDayKey(daily[mid].day))}</span><span>${escapeHTML(fmtDayKey(daily[daily.length - 1].day, todayKey))}</span></div>
    </div>`;
}

// History kinds: filter chips over the ledger's actions.
const CLEANUP_KINDS = [['removed', 'Removed'], ['trash', 'Moved to Trash'], ['clean', 'Cleaned'], ['prune', 'Pruned'], ['ask', 'Agent answers']];

function cleanupKind(action) {
  const a = String(action || '');
  if (a === 'worktree-remove') return 'removed';
  if (a === 'worktree-prune') return 'prune';
  if (a.startsWith('trash:')) return 'trash';
  if (a.startsWith('clean:')) return 'clean';
  if (a.startsWith('ask:')) return 'ask';
  return 'other';
}

function cleanupEntryTitle(e) {
  const a = String(e.action || '');
  const rest = a.slice(a.indexOf(':') + 1);
  switch (cleanupKind(a)) {
    case 'removed': return 'Removed worktree';
    case 'prune': return 'Pruned a missing worktree';
    case 'trash': return rest === 'orphan-worktree' ? 'Moved an orphan folder to the Trash' : `Moved ${clutterKindLabel(rest)} to the Trash`;
    case 'clean': return `Ran ${e.detail || rest + ' clean'}`;
    case 'ask': return `Agent answered: ${rest}`;
    default: return a;
  }
}

// cleanupHistoryHTML: the ledger newest first, grouped by local day with
// each day's bytes; filter.kind keeps one kind, filter.day one day.
function cleanupHistoryHTML(ledger, filter, nowMs) {
  const f = filter || {};
  const all = (ledger && ledger.entries) || [];
  const todayKey = localDayKey(new Date(nowMs || Date.now()));
  const entries = all.filter(e => (!f.kind || cleanupKind(e.action) === f.kind) && (!f.day || localDayKey(e.ts) === f.day));
  const trashed = e => cleanupKind(e.action) === 'trash';
  const freed = entries.reduce((n, e) => n + (trashed(e) ? 0 : Number(e.bytes) || 0), 0);
  const toTrash = entries.reduce((n, e) => n + (trashed(e) ? Number(e.bytes) || 0 : 0), 0);
  const chip = (kind, label) => `<button type="button" class="wt-pill${(f.kind || '') === kind ? ' on' : ''}" data-action="history-kind" data-kind="${kind}" aria-pressed="${(f.kind || '') === kind}">${escapeHTML(label)}</button>`;
  const chips = chip('', 'All') + CLEANUP_KINDS.map(([k, l]) => chip(k, l)).join('')
    + (f.day ? `<button type="button" class="wt-pill on hx-day-chip" data-action="history-day" data-day="" aria-label="Show every day">${escapeHTML(fmtDayKey(f.day, todayKey, true))} ×</button>` : '');
  const summary = `${entries.length} entr${entries.length === 1 ? 'y' : 'ies'} · ${fmtDisk(freed)} freed`
    + (toTrash ? ` · ${fmtDisk(toTrash)} moved to the Trash` : '');
  const days = [];
  for (const e of entries) {
    const key = localDayKey(e.ts);
    if (!days.length || days[days.length - 1].key !== key) days.push({ key, entries: [], bytes: 0 });
    const day = days[days.length - 1];
    day.entries.push(e);
    if (!trashed(e)) day.bytes += Number(e.bytes) || 0;
  }
  const entryHTML = e => {
    const kind = cleanupKind(e.action);
    const at = new Date(e.ts);
    const repoName = e.repo ? String(e.repo).replace(/\/$/, '').split('/').pop() : '';
    const where = e.repo ? `${worktreePathLabel(e.path, e.repo)} · ${repoName}` : String(e.path || '');
    return `<li class="hx-entry hx-${kind}">
        <div class="hx-main">
          <span class="hx-title">${escapeHTML(cleanupEntryTitle(e))}</span>
          <span class="hx-bytes">${e.bytes ? escapeHTML(fmtDisk(e.bytes)) : ''}</span>
          <time class="hx-time" datetime="${escapeHTML(e.ts)}">${isFinite(at.getTime()) ? escapeHTML(fmtDayClock(at).split(' ').slice(1).join(' ')) : ''}</time>
        </div>
        <div class="hx-path" title="${escapeHTML(e.path)}">${escapeHTML(where)}</div>
        ${e.detail && kind !== 'clean' ? `<p class="hx-detail">${escapeHTML(e.detail)}</p>` : ''}
      </li>`;
  };
  const body = days.length
    ? days.map(d => `<section class="hx-day">
        <div class="hx-day-head"><span>${escapeHTML(fmtDayKey(d.key, todayKey, true))}</span><span class="hx-day-bytes">${d.bytes ? escapeHTML(fmtDisk(d.bytes)) + ' freed' : ''}</span></div>
        <ul class="hx-list">${d.entries.map(entryHTML).join('')}</ul>
      </section>`).join('')
    : `<div class="empty"><svg class="icon"><use href="#i-history"/></svg><span>${all.length ? 'Nothing matches this filter.' : 'No cleanups yet. Removing a worktree or clearing clutter books it here.'}</span></div>`;
  const capped = ledger && ledger.limit && all.length >= ledger.limit
    ? `<p class="hx-note">Showing the newest ${all.length} entries.</p>` : '';
  return `<div class="hx">
      <div class="harness-pills hx-chips" role="group" aria-label="Filter the history">${chips}</div>
      <p class="hx-summary">${escapeHTML(summary)}</p>
      ${body}
      ${capped}
    </div>`;
}

// ---------- removal progress (toast) ----------
// The share of a removal done when each phase begins; the delete itself
// has no progress of its own.
const REMOVAL_PHASE_DONE = { waiting: 0.05, checking: 0.15, measuring: 0.3, deleting: 0.5 };

// fmtElapsed: "4s", "1m 12s".
function fmtElapsed(ms) {
  const s = Math.max(0, Math.floor((Number(ms) || 0) / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
}

// removalToastModel: the removals of one group as the toast shows them.
// labels maps a path to its branch as the row showed it.
function removalToastModel(paths, removals, labels) {
  const items = (paths || []).map(p => {
    const r = (removals || {})[p] || { path: p, state: 'running' };
    return {
      path: p, label: (labels || {})[p] || r.branch || String(p).split('/').filter(Boolean).pop() || String(p),
      state: r.state || 'running', phase: r.phase || '', step: r.step || 'starting',
      since: r.step_at || r.started_at || '', bytes: Number(r.bytes) || 0, files: Number(r.files) || 0,
      error: r.error || '', rowState: r.row_state || '', reasons: r.reasons || [],
    };
  });
  let removed = 0, failed = 0, bytes = 0, progress = 0;
  for (const it of items) {
    if (it.state === 'removed') { removed++; bytes += it.bytes; progress += 1; }
    else if (it.state === 'failed') { failed++; progress += 1; }
    else progress += REMOVAL_PHASE_DONE[it.phase] || 0;
  }
  const total = items.length;
  return { items, total, removed, failed, running: total - removed - failed, bytes,
    percent: total ? Math.round(progress / total * 100) : 0 };
}

// removalSizeText: "1.5 GB · 184,203 files" once measured.
function removalSizeText(bytes, files) {
  return [bytes ? fmtDisk(bytes) : '', files ? `${Number(files).toLocaleString('en-US')} files` : ''].filter(Boolean).join(' · ');
}

// removalToastHTML: the progress toast: a title, one bar for the group,
// the running removals with their phase, size and time in it, and what
// failed. Finished, it names what was reclaimed and links the history.
function removalToastHTML(m) {
  const done = m.running === 0;
  const first = m.items[0] || {};
  let title;
  if (!done) title = m.total === 1 ? `Removing ${first.label}` : `Removing ${m.total} worktrees`;
  else if (m.total === 1 && m.removed) title = `Removed ${first.label}`;
  else if (m.total === 1) title = `Not removed: ${first.label}`;
  else title = `Removed ${m.removed} of ${m.total} worktrees`;
  // A single running removal's phase and size are its item line.
  const sub = done
    ? [m.bytes ? `${fmtDisk(m.bytes)} reclaimed` : '', m.failed && m.total > 1 ? `${m.failed} not removed` : ''].filter(Boolean).join(' · ')
    : m.total === 1 ? ''
      : [`${m.removed + m.failed} of ${m.total} done`, m.bytes ? `${fmtDisk(m.bytes)} reclaimed so far` : ''].filter(Boolean).join(' · ');
  const shown = m.items.filter(it => it.state !== 'removed').sort((a, b) => (a.state === 'running' ? 0 : 1) - (b.state === 'running' ? 0 : 1));
  const cap = 4;
  const itemHTML = it => {
    if (it.state === 'failed') {
      const why = it.rowState ? `now ${it.rowState}${it.reasons.length ? ' — ' + it.reasons.join('; ') : ''}` : it.error;
      return `<li class="rt-item rt-failed"><span class="rt-label">${escapeHTML(it.label)}</span><span class="rt-step">${escapeHTML(why || 'failed')}</span></li>`;
    }
    const size = removalSizeText(it.bytes, it.files);
    return `<li class="rt-item rt-running rt-${escapeHTML(it.phase || 'starting')}">
        <span class="rt-label">${escapeHTML(it.label)}</span>
        <span class="rt-step">${escapeHTML(it.step)}${size ? ` · ${escapeHTML(size)}` : ''}</span>
        <span class="rt-elapsed" data-since="${escapeHTML(it.since)}"></span>
      </li>`;
  };
  const more = shown.length > cap ? `<li class="rt-more">and ${shown.length - cap} more</li>` : '';
  const state = done ? (m.failed ? (m.removed ? 'partial' : 'failed') : 'done') : 'running';
  return `<div class="rt-head">
      <p class="rt-title" role="status">${escapeHTML(title)}</p>
      <button type="button" class="btn btn-icon rt-close" data-action="removal-toast-close" title="${done ? 'Close' : 'Hide — the rows keep the progress'}" aria-label="Close"><svg class="icon"><use href="#i-close"/></svg></button>
    </div>
    ${sub ? `<p class="rt-sub">${escapeHTML(sub)}</p>` : ''}
    <span class="rt-bar rt-bar-${state}" role="progressbar" aria-label="Removal progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${m.percent}"><i data-w="${m.percent}"></i></span>
    ${shown.length ? `<ul class="rt-items">${shown.slice(0, cap).map(itemHTML).join('')}${more}</ul>` : ''}
    ${done ? '<button type="button" class="link-btn rt-history" data-action="worktrees-history">View cleanup history</button>' : ''}`;
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

// worktreeAskHTML: the latest request to the worktree's owning agent.
function worktreeAskHTML(ask) {
  if (!ask) return '';
  let text;
  if (ask.status === 'running') text = `waiting for ${ask.harness}'s answer…`;
  else if (ask.status === 'answered' && ask.verdict !== 'none') {
    text = `${ask.verdict}${ask.detail ? ' — ' + ask.detail : ''}${ask.cost_usd ? ` ($${Number(ask.cost_usd).toFixed(2)})` : ''}`;
  } else text = `${ask.status}${ask.detail ? ' — ' + ask.detail : ''}`;
  return `<p class="wt-ask wt-ask-${escapeHTML(ask.status)}"><b>Asked ${escapeHTML(ask.harness)}:</b> ${escapeHTML(text)}</p>`;
}

// worktreeRemovalHTML: a removal's step while it runs (with the size being
// deleted once measured and a mark per phase passed), or why it did not
// remove the worktree.
function worktreeRemovalHTML(rm) {
  if (!rm || rm.state === 'removed') return '';
  if (rm.state === 'running') {
    const at = Object.keys(REMOVAL_PHASE_DONE).indexOf(rm.phase);
    const marks = Object.keys(REMOVAL_PHASE_DONE).map((p, i) => `<i class="${i <= at ? 'on' : ''}"></i>`).join('');
    const size = removalSizeText(rm.bytes, rm.files);
    return `<p class="wt-removal wt-removal-running" role="status"><span class="wt-steps" aria-hidden="true">${marks}</span><b>Removing…</b> ${escapeHTML(rm.step || 'starting')}${size ? ` · ${escapeHTML(size)}` : ''}</p>`;
  }
  const text = rm.row_state
    ? `<b>Not removed:</b> it is now ${escapeHTML(rm.row_state)}${(rm.reasons || []).length ? ' — ' + escapeHTML(rm.reasons.join('; ')) : ''}`
    : `<b>Removal failed:</b> ${escapeHTML(rm.error || 'unknown error')}`;
  return `<p class="wt-removal wt-removal-failed" role="alert">${text}</p>`;
}

// worktreeRowHTML: one worktree. Remove only on state remove, Prune only on
// state prune; the daemon enforces the same rule again on the request. Ask
// the agent and Ask advisor on review and keep rows, where work may remain.
// A running removal disables Remove and shows its step.
function worktreeRowHTML(w, repo, note, ask, removal) {
  const branch = w.branch || (w.detached ? '(detached)' : '');
  const reasons = (w.reasons || []).map(r => `<li>${escapeHTML(r)}</li>`).join('');
  let action = '';
  if (w.orphan) {
    // Git no longer records this folder: open it, link it to the repository
    // that still records it (moved repo), or move it to the Trash.
    action = `<button type="button" class="btn btn-sm" data-action="worktree-reveal" data-path="${escapeHTML(w.path)}">Open folder</button>`
      + (w.reconnect ? `<button type="button" class="btn btn-sm" data-action="worktree-reconnect" data-path="${escapeHTML(w.path)}" data-repo="${escapeHTML(w.reconnect)}">Reconnect</button>` : '')
      + `<button type="button" class="btn btn-danger btn-sm" data-action="worktree-trash-orphan" data-path="${escapeHTML(w.path)}">Move to Trash</button>`;
  } else if (w.state === 'remove') {
    action = removal && removal.state === 'running'
      ? '<button type="button" class="btn btn-danger btn-sm" disabled>Removing…</button>'
      : `<button type="button" class="btn btn-danger btn-sm" data-action="worktree-remove" data-path="${escapeHTML(w.path)}" data-branch="${escapeHTML(branch)}">${removal && removal.state === 'failed' ? 'Try again' : 'Remove'}</button>`;
  } else if (w.state === 'prune') {
    action = `<button type="button" class="btn btn-sm" data-action="worktree-prune" data-repo="${escapeHTML(repo.path)}">Prune</button>`;
  } else if (w.state === 'review' || w.state === 'keep') {
    const busy = ask && ask.status === 'running' ? ' disabled' : '';
    action = `<button type="button" class="btn btn-sm" data-action="worktree-ask" data-path="${escapeHTML(w.path)}"${busy}>Ask the agent</button>`
      + `<button type="button" class="btn btn-sm" data-action="worktree-advise" data-path="${escapeHTML(w.path)}">Ask advisor</button>`;
  }
  // Every folder still on disk opens in Finder; orphans carry Open folder
  // in their actions already.
  const open = w.orphan || w.state === 'prune' ? ''
    : `<button type="button" class="btn btn-ghost btn-sm wt-open" data-action="worktree-reveal" data-path="${escapeHTML(w.path)}" title="Show in Finder" aria-label="Show ${escapeHTML(branch || w.path)} in Finder"><svg class="icon"><use href="#i-folder"/></svg></button>`;
  return `<div class="wt-row wt-${escapeHTML(w.state)}" data-path="${escapeHTML(w.path)}">
    <div class="wt-main">
      <span class="wt-state">${escapeHTML(w.state)}</span>${w.stale ? '<span class="wt-stale">stale</span>' : ''}
      <span class="wt-branch">${escapeHTML(branch)}</span>
      <button type="button" class="wt-path" data-action="copy-path" data-path="${escapeHTML(w.path)}" title="${escapeHTML(w.path)} — click to copy">${escapeHTML(worktreePathLabel(w.path, repo.path))}</button>
      <span class="wt-size">${escapeHTML(worktreeSizeLabel(w))}</span>
      <span class="wt-idle">${escapeHTML(worktreeIdleLabel(w))}</span>
      ${open}${action}
    </div>
    ${reasons ? `<ul class="wt-reasons">${reasons}</ul>` : ''}
    ${worktreeNoteHTML(note)}
    ${worktreeAskHTML(ask)}
    ${worktreeRemovalHTML(removal)}
  </div>`;
}

// removableRows: a repository's rows in state remove with no removal
// running.
function removableRows(repo, removals) {
  return ((repo && repo.worktrees) || []).filter(w => w.state === 'remove' && !w.orphan
    && !((removals || {})[w.path] && removals[w.path].state === 'running'));
}

// worktreeGroupHTML: one repository block with its rows and a Hide button.
// Two or more removable rows add Remove all with their count and size.
// advice, asks and removals map a worktree path to its advisor note, latest
// ask and latest removal.
function worktreeGroupHTML(g, advice, asks, removals) {
  const meta = [g.repo.default_branch, g.repo.source].filter(Boolean).join(' · ');
  return `<section class="wt-repo">
    <div class="wt-repo-head">
      <span class="wt-repo-path" title="${escapeHTML(g.repo.path)}">${escapeHTML(g.repo.path)}</span>
      ${meta ? `<span class="wt-repo-meta">${escapeHTML(meta)}</span>` : ''}
      ${g.repo.size_bytes ? `<span class="wt-repo-size">${escapeHTML(fmtDisk(g.repo.size_bytes))}</span>` : ''}
      ${g.repo.error
        ? `<span class="wt-repo-error">${escapeHTML(g.repo.error)} — the folders below still point to it</span>`
        : worktreeRemoveAllHTML(g.repo, removals)
          + `<button type="button" class="link-btn wt-hide" data-action="worktree-hide" data-repo="${escapeHTML(g.repo.path)}">Hide repo</button>`}
    </div>
    ${g.rows.map(w => worktreeRowHTML(w, g.repo, (advice || {})[w.path], (asks || {})[w.path], (removals || {})[w.path])).join('')}
  </section>`;
}

function worktreeRemoveAllHTML(repo, removals) {
  const rows = removableRows(repo, removals);
  if (rows.length < 2) return '';
  const bytes = rows.reduce((n, w) => n + (Number(w.size_bytes) || 0), 0);
  return `<button type="button" class="btn btn-danger btn-sm wt-remove-all" data-action="worktree-remove-all" data-repo="${escapeHTML(repo.path)}">Remove all ${rows.length}${bytes ? ' · ' + escapeHTML(fmtDisk(bytes)) : ''}</button>`;
}

// worktreeFilterHTML: one pill per state with its count, then stale.
function worktreeFilterHTML(counts, filter) {
  const f = filter || {};
  const pill = (state, label, n) => `<button type="button" class="wt-pill${(f.state || '') === state ? ' on' : ''}" data-action="worktree-filter" data-state="${state}" aria-pressed="${(f.state || '') === state}">${label} <b>${n}</b></button>`;
  return pill('', 'All', counts.all)
    + WORKTREE_STATES.map(s => pill(s, s[0].toUpperCase() + s.slice(1), counts[s])).join('')
    + `<button type="button" class="wt-pill${f.stale ? ' on' : ''}" data-action="worktree-stale" aria-pressed="${!!f.stale}">Stale <b>${counts.stale}</b></button>`;
}

// worktreesSummaryText: the scan line under the header. A cached scan
// names its age; a background rescan says so.
function worktreesSummaryText(rep, nowMs) {
  if (!rep) return '';
  const s = rep.summary || {};
  const age = rep.cached && fmtAge(rep.generated_at, nowMs);
  const when = rep.cached ? (age ? `scanned ${age} ago` : 'cached scan') : `scanned in ${(Number(rep.duration_ms || 0) / 1000).toFixed(1)}s`;
  const n = (v, one, many) => `${v || 0} ${v === 1 ? one : many}`;
  return `${n(s.repos, 'repo', 'repos')} · ${n(s.worktrees, 'worktree', 'worktrees')} · stale after ${rep.stale_days || 0} idle days · ${when}`
    + (rep.refreshing ? ' · refreshing…' : '');
}

function renderWorktrees() {
  const SA = window.SA;
  const container = document.getElementById('worktrees-container');
  const pills = document.getElementById('worktree-pills');
  const summary = document.getElementById('worktrees-summary');
  const disk = document.getElementById('worktrees-disk');
  const errors = document.getElementById('worktrees-errors');
  const reclaim = document.getElementById('worktrees-reclaim');
  if (!container) return;
  const state = SA.worktrees;
  const rep = state.report;
  if (reclaim) {
    const ledger = state.ledger;
    reclaim.innerHTML = rep || ledger
      ? `<div class="rc-tiles">${reclaimTilesHTML(rep, ledger)}</div>${ledger ? reclaimChartHTML(ledger.daily, localDayKey(new Date())) : ''}`
      : '';
    reclaim.classList.toggle('rc-reloading', !!state.ledgerLoading && !!ledger);
    applyInlineMetrics(reclaim);
  }

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
    ? groups.map(g => worktreeGroupHTML(g, rep.advice, rep.asks, rep.removals)).join('')
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

// clutterPlanHTML: the local advisor's plan for a project: a summary and
// its steps, as text.
function clutterPlanHTML(plan) {
  if (!plan) return '';
  const steps = String(plan.suggested_action || '').split('\n').filter(Boolean).map(s => `<li>${escapeHTML(s)}</li>`).join('');
  return `<div class="wt-advice cl-plan"><b>Advisor:</b> ${escapeHTML(plan.rationale || '')}${steps ? `<ol>${steps}</ol>` : ''}</div>`;
}

function clutterGroupHTML(g, expanded, advice) {
  const title = g.project || 'This machine';
  const key = g.project || 'machine';
  const open = expanded && expanded.has(g.project);
  const shown = open ? g.items : g.items.slice(0, CLUTTER_GROUP_ROWS);
  const more = g.items.length - shown.length;
  return `<section class="wt-repo">
    <div class="wt-repo-head">
      <span class="wt-repo-path" title="${escapeHTML(title)}">${escapeHTML(title)}</span>
      <span class="wt-repo-meta">${g.items.length} item${g.items.length === 1 ? '' : 's'}</span>
      ${g.bytes ? `<span class="wt-repo-size">${escapeHTML(fmtDisk(g.bytes))}</span>` : ''}
      <button type="button" class="link-btn wt-hide" data-action="clutter-advise" data-project="${escapeHTML(key)}">Ask advisor</button>
    </div>
    ${clutterPlanHTML((advice || {})[key])}
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
  else if (rep.refreshing) text += ' · refreshing…';
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
    ? groups.map(g => clutterGroupHTML(g, state.expanded, rep.advice)).join('')
    : '<div class="empty"><svg class="icon"><use href="#i-server"/></svg><span>Nothing to clear.</span></div>';
}
