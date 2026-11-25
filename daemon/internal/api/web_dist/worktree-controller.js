// Worktree Hunter and clutter: the two reports, their loaders, the clutter
// size polling, the removal progress toast and the actions on both tabs.
// createWorktreeController builds one state object; the worktreeCtl*
// functions below read and write it.
const WORKTREE_STALE_MS = 60000;
// Worktrees are not telemetry: the tab reads the report when the view opens
// with none loaded, on Reload (the daemon's saved scan) and on Rescan (a new
// scan); nothing reads it on a timer.
const WORKTREE_TIMEOUT_MS = 200000;
// A removal answers in its own request: the daemon may wait for a running
// scan, then bounds `git worktree remove` at 10 minutes.
const WORKTREE_REMOVE_TIMEOUT_MS = WORKTREE_TIMEOUT_MS + 10 * 60 * 1000;
// While the daemon is still measuring clutter sizes, the open tab re-reads
// the cached inventory (cheap: no rescan) until the sizes land.
const WORKTREE_SIZING_POLL_MS = 5000;
const WORKTREE_SIZING_POLLS = 60;
// Removal progress: one toast follows the removals this page sent, from the
// request to its reply, and those a report read showed running (another
// tab, the CLI) as of that read. A removal that starts after the group
// finished opens a new group. The rows show the same progress, so hiding
// the toast loses nothing.
const WORKTREE_REMOVAL_TOAST_LINGER_MS = 8000;
// The cleanup ledger: the daily series behind the reclaimed chart and the
// entries behind the history drawer. Loaded with the tab, after a
// cleanup lands, and when the history opens.
const WORKTREE_LEDGER_LIMIT = 500;
// Ask the local advisor for a project's cleanup plan; the plan arrives in
// GET /cleanup's advice, re-read every 5 s for up to a minute.
const WORKTREE_CLUTTER_PLAN_POLLS = 12;
const WORKTREE_CLUTTER_PLAN_EVERY_MS = 5000;

function createWorktreeController({ request, toast, confirm, render, renderSelection = () => render(['worktrees']), markDirty, visible, now, history, discuss, toastHost }) {
  const s = {
    request, toast, confirm, render, renderSelection, markDirty, visible, now, history, discuss, toastHost,
    worktreesState: { report: null, loading: false, loadingRefresh: false, error: '', loadedAt: 0, filter: { state: '', stale: false, q: '' },
      ledger: null, ledgerLoading: false, ledgerAt: 0, selected: new Map(), expanded: new Set(), selectionBusy: false, pendingRemovalSelections: new Map() },
    removalGroup: { paths: [], labels: {}, hidden: false, finished: false },
    removalTicker: null,
    removalLinger: null,
    // The removals this page sent, by path: running until the reply, then
    // its outcome. Every report read keeps them (overlayRemovals).
    removals: new Map(),
    // Batches of removals in progress; the toast's group ends after them.
    removalBatches: 0,
    // Clutter: loaded with the tab like worktrees; re-read while sizes land.
    clutterState: { report: null, loading: false, error: '', loadedAt: 0, filter: { kind: '' }, expanded: new Set(), removing: new Set() },
    clutterSizingTimer: null,
    clutterSizingPolls: 0
  };
  const { worktreesState, clutterState } = s;

  return {
    get worktreesState() { return worktreesState; },
    get clutterState() { return clutterState; },
    loadWorktrees: refresh => worktreeCtlLoadWorktrees(s, refresh),
    loadClutter: refresh => worktreeCtlLoadClutter(s, refresh),
    loadLedger: () => worktreeCtlLoadLedger(s),
    activate: view => worktreeCtlActivate(s, view),
    closeRemovalToast: () => worktreeCtlCloseRemovalToast(s),
    addRepo: path => worktreeCtlAddRepo(s, path),
    setWorktreeFilter(state) { worktreesState.filter = nextWorktreeFilter(worktreesState.filter, state || ''); },
    toggleStaleFilter() { worktreesState.filter.stale = !worktreesState.filter.stale; },
    setWorktreeSearch(q) { worktreesState.filter.q = q; },
    setClutterKind(kind) { clutterState.filter.kind = kind || ''; },
    expandClutterProject(project) { clutterState.expanded.add(project || ''); },
    removeWorktree: (path, branch) => worktreeCtlRemoveWorktree(s, path, branch),
    removeAllWorktrees: repoPath => worktreeCtlRemoveAllWorktrees(s, repoPath),
    removeAllRemovable: () => worktreeCtlRemoveAllRemovable(s),
    toggleWorktreeSelection: path => worktreeCtlToggleWorktreeSelection(s, path),
    selectVisibleWorktrees: globalSearchTerm => worktreeCtlSelectVisibleWorktrees(s, globalSearchTerm),
    clearWorktreeSelection: () => worktreeCtlClearWorktreeSelection(s),
    removeSelectedWorktrees: () => worktreeCtlRemoveSelectedWorktrees(s),
    revealWorktree: path => worktreeCtlRevealWorktree(s, path),
    reconnectWorktree: (path, repo) => worktreeCtlReconnectWorktree(s, path, repo),
    trashOrphanWorktree: path => worktreeCtlTrashOrphanWorktree(s, path),
    trashReviewedWorktree: path => worktreeCtlTrashReviewedWorktree(s, path),
    discussWorktree: path => discuss({ path }),
    discussWorktreeGroup: repo => discuss({ repo }),
    adviseWorktree: path => worktreeCtlAdviseWorktree(s, path),
    adviseWorktreeGroup: repo => worktreeCtlAdviseWorktreeGroup(s, repo),
    trashClutter: path => worktreeCtlTrashClutter(s, path),
    removeClutter: path => worktreeCtlRemoveClutter(s, path),
    adviseClutterProject: project => worktreeCtlAdviseClutterProject(s, project),
    cleanClutter: name => worktreeCtlCleanClutter(s, name),
    askWorktreeAgent: path => worktreeCtlAskWorktreeAgent(s, path),
    pruneWorktrees: repo => worktreeCtlPruneWorktrees(s, repo),
    hideWorktreeRepo: repo => worktreeCtlHideWorktreeRepo(s, repo)
  };
}

function worktreeCtlRemovalGroupRunning(s) {
  const { worktreesState, removalGroup } = s;
  const removals = (worktreesState.report && worktreesState.report.removals) || {};
  return s.removalBatches > 0 || removalGroup.paths.some(p => !removals[p] || removals[p].state === 'running');
}

// setRemoval records the state of a removal this page sent, on the page
// and in the report on screen.
function worktreeCtlSetRemoval(s, path, removal) {
  s.removals.set(path, removal);
  const rep = s.worktreesState.report;
  if (rep) (rep.removals || (rep.removals = {}))[path] = removal;
}

// overlayRemovals lays this page's removals over a report read: one still
// waiting for its reply stays running, and a row removed after the report's
// scan stays gone. A finished one older than the report's scan is dropped.
function worktreeCtlOverlayRemovals(s, rep) {
  const scanned = Date.parse(rep.generated_at);
  for (const [path, removal] of s.removals) {
    if (removal.state !== 'running' && isFinite(scanned) && scanned > Date.parse(removal.finished_at)) {
      s.removals.delete(path);
      continue;
    }
    (rep.removals || (rep.removals = {}))[path] = removal;
    if (removal.state === 'removed') worktreeCtlDropRows(rep, [path]);
  }
}

function worktreeCtlTrackRemovals(s, paths, labels) {
  const { removalGroup } = s;
  if (!paths.length) return;
  if (!worktreeCtlRemovalGroupRunning(s)) Object.assign(removalGroup, { paths: [], labels: {} });
  for (const p of paths) if (!removalGroup.paths.includes(p)) removalGroup.paths.push(p);
  Object.assign(removalGroup.labels, labels || {});
  removalGroup.hidden = false;
  removalGroup.finished = false;
  clearTimeout(s.removalLinger);
  worktreeCtlPaintRemovalToast(s);
}

// adoptRemovals: removals running in a fresh report that no group
// tracks, labeled with their row's branch.
function worktreeCtlAdoptRemovals(s, rep) {
  const { removalGroup } = s;
  const running = Object.entries((rep && rep.removals) || {})
    .filter(([p, r]) => r.state === 'running' && !removalGroup.paths.includes(p)).map(([p]) => p);
  if (!running.length) return;
  const labels = {};
  for (const repo of rep.repos || []) {
    for (const w of repo.worktrees || []) if (w.branch && running.includes(w.path)) labels[w.path] = w.branch;
  }
  worktreeCtlTrackRemovals(s, running, labels);
}

function worktreeCtlTickRemovalElapsed(s) {
  const at = s.now();
  document.querySelectorAll('#removal-toast .rt-elapsed[data-since]').forEach(el => {
    const t = Date.parse(el.dataset.since);
    el.textContent = isFinite(t) ? fmtElapsed(at - t) : '';
  });
}

function worktreeCtlCloseRemovalToast(s) {
  const { removalGroup } = s;
  removalGroup.hidden = true;
  if (!worktreeCtlRemovalGroupRunning(s)) Object.assign(removalGroup, { paths: [], labels: {} });
  worktreeCtlPaintRemovalToast(s);
}

function worktreeCtlPaintRemovalToast(s) {
  const { worktreesState, removalGroup, toastHost } = s;
  const host = document.getElementById('toast-container');
  let el = document.getElementById('removal-toast');
  const running = worktreeCtlRemovalGroupRunning(s);
  const m = removalToastModel(removalGroup.paths, worktreesState.report && worktreesState.report.removals, removalGroup.labels);
  // The group's end: the ledger has new rows; a clean finish closes the
  // toast after a moment, a failure keeps it until closed.
  if (removalGroup.paths.length && !running && !removalGroup.finished) {
    removalGroup.finished = true;
    worktreeCtlLoadLedger(s);
    if (!m.failed) s.removalLinger = setTimeout(() => worktreeCtlCloseRemovalToast(s), WORKTREE_REMOVAL_TOAST_LINGER_MS);
  }
  if (!running) {
    clearInterval(s.removalTicker);
    s.removalTicker = null;
  }
  if (!host || !removalGroup.paths.length || removalGroup.hidden) {
    if (el) el.remove();
    clearInterval(s.removalTicker);
    s.removalTicker = null;
    if (host) toastHost.hideWhenEmpty(host);
    return;
  }
  if (!el) {
    el = document.createElement('div');
    el.id = 'removal-toast';
    host.appendChild(el);
    toastHost.show(host);
  }
  // A running removal this page did not send is shown as of the last read.
  m.external = m.items.some(it => it.state === 'running' && !s.removals.has(it.path));
  el.className = 'toast toast-sticky removal-toast ' + (running ? 'info' : m.failed ? (m.removed ? 'info' : 'danger') : 'success');
  const html = removalToastHTML(m);
  if (el._html !== html) {
    el.innerHTML = html;
    el._html = html;
    applyInlineMetrics(el);
  }
  worktreeCtlTickRemovalElapsed(s);
  if (running && !s.removalTicker) s.removalTicker = setInterval(() => worktreeCtlTickRemovalElapsed(s), 1000);
}

// loadWorktrees reads the report: the daemon's saved scan, or a new scan
// when refresh is asked (Rescan). One read at a time.
async function worktreeCtlLoadWorktrees(s, refresh) {
  const { worktreesState, removalGroup, request, toast, markDirty, now } = s;
  if (worktreesState.loading) return;
  worktreesState.loading = true;
  worktreesState.loadingRefresh = !!refresh;
  worktreesState.error = '';
  markDirty('worktrees');
  try {
    const r = await request('/worktrees' + (refresh ? '?refresh=1' : ''), { timeoutMs: WORKTREE_TIMEOUT_MS });
    if (!r.ok) throw new Error((await r.text()).trim() || String(r.status));
    const rep = await r.json();
    worktreeCtlOverlayRemovals(s, rep);
    worktreesState.report = rep;
    worktreeCtlReconcileWorktreeSelection(s);
    worktreesState.loadedAt = now();
    worktreeCtlAdoptRemovals(s, rep);
    if (removalGroup.paths.length) worktreeCtlPaintRemovalToast(s);
  } catch (err) {
    worktreesState.error = 'Worktree scan failed: ' + (err.message || err);
    if (worktreesState.report) toast(worktreesState.error, 'danger');
  } finally {
    worktreesState.loading = false;
    worktreesState.loadingRefresh = false;
    markDirty('worktrees');
  }
}

async function worktreeCtlLoadLedger(s) {
  const { worktreesState, request, toast, markDirty, now, history } = s;
  if (worktreesState.ledgerLoading) return;
  worktreesState.ledgerLoading = true;
  markDirty('worktrees');
  try {
    const r = await request(`/cleanup/ledger?days=${RECLAIM_DAYS}&limit=${WORKTREE_LEDGER_LIMIT}`);
    if (!r.ok) throw new Error((await r.text()).trim() || String(r.status));
    worktreesState.ledger = { ...(await r.json()), limit: WORKTREE_LEDGER_LIMIT };
    worktreesState.ledgerAt = now();
  } catch (err) {
    if (history.open()) toast("Couldn't read the cleanup history: " + (err.message || err), 'danger');
  } finally {
    worktreesState.ledgerLoading = false;
    markDirty('worktrees');
    history.paint();
  }
}

function worktreeCtlFollowClutterSizing(s) {
  const { clutterState, visible } = s;
  const rep = clutterState.report;
  if (rep && (rep.sizing || rep.refreshing) && visible('clutter') && !s.clutterSizingTimer && s.clutterSizingPolls < WORKTREE_SIZING_POLLS) {
    s.clutterSizingPolls++;
    s.clutterSizingTimer = setTimeout(() => {
      s.clutterSizingTimer = null;
      if (visible('clutter')) worktreeCtlLoadClutter(s, false);
    }, WORKTREE_SIZING_POLL_MS);
  }
}

async function worktreeCtlLoadClutter(s, refresh) {
  const { clutterState, request, toast, markDirty, now } = s;
  if (clutterState.loading) return;
  clutterState.loading = true;
  clutterState.error = '';
  markDirty('clutter');
  try {
    const r = await request('/cleanup' + (refresh ? '?refresh=1' : ''), { timeoutMs: WORKTREE_TIMEOUT_MS });
    if (!r.ok) throw new Error((await r.text()).trim() || String(r.status));
    clutterState.report = await r.json();
    clutterState.loadedAt = now();
    if (!clutterState.report.sizing && !clutterState.report.refreshing) s.clutterSizingPolls = 0;
  } catch (err) {
    clutterState.error = 'Clutter scan failed: ' + (err.message || err);
    if (clutterState.report) toast(clutterState.error, 'danger');
  } finally {
    clutterState.loading = false;
    markDirty('clutter');
    worktreeCtlFollowClutterSizing(s);
  }
}

// The tab opened: read the worktree report when none is loaded, the clutter
// inventory and the ledger when missing or stale, and follow clutter sizing.
function worktreeCtlActivate(s, view) {
  const { worktreesState, clutterState, now } = s;
  if (view === 'worktrees' && !worktreesState.report) worktreeCtlLoadWorktrees(s, false);
  if (view === 'clutter' && (!clutterState.report || now() - clutterState.loadedAt > WORKTREE_STALE_MS)) {
    worktreeCtlLoadClutter(s, false);
  }
  if (view === 'clutter') worktreeCtlFollowClutterSizing(s);
  if (view === 'worktrees' && (!worktreesState.ledger || now() - worktreesState.ledgerAt > WORKTREE_STALE_MS)) {
    worktreeCtlLoadLedger(s);
  }
}

// dropWorktreeRows removes rows the daemon just removed, pruned or moved to
// the Trash, so the tab updates without reading the report.
function worktreeCtlDropWorktreeRows(s, paths) {
  const { worktreesState } = s;
  if (!worktreesState.report) return;
  worktreeCtlDropRows(worktreesState.report, paths);
  for (const path of paths) {
    worktreesState.selected.delete(path);
    worktreesState.pendingRemovalSelections.delete(path);
  }
  worktreeCtlReconcileWorktreeSelection(s);
}

// dropRows takes rows out of a report with their sizes and counts.
function worktreeCtlDropRows(rep, paths) {
  const gone = new Set(paths);
  for (const repo of rep.repos || []) {
    const dropped = (repo.worktrees || []).filter(w => gone.has(w.path));
    if (!dropped.length) continue;
    repo.worktrees = repo.worktrees.filter(w => !gone.has(w.path));
    for (const w of dropped) {
      const size = Number(w.size_bytes) || 0;
      repo.size_bytes = Math.max(0, (Number(repo.size_bytes) || 0) - size);
      if (rep.summary) {
        rep.summary.worktrees = Math.max(0, (rep.summary.worktrees || 0) - 1);
        rep.summary.size_bytes = Math.max(0, (Number(rep.summary.size_bytes) || 0) - size);
        if (w.state === 'remove') rep.summary.removable_bytes = Math.max(0, (Number(rep.summary.removable_bytes) || 0) - size);
      }
    }
  }
}

function worktreeCtlSelectedWorktree(s, path) {
  const rep = s.worktreesState.report;
  for (const repo of (rep && rep.repos) || []) {
    const w = (repo.worktrees || []).find(w => w.path === path);
    if (w) return { w, repo, approval: worktreeSelectionApproval(w, repo, rep) };
  }
  return null;
}

const worktreeCtlSameApproval = (a, b) => !!a && !!b && JSON.stringify(a) === JSON.stringify(b);

function worktreeCtlReconcileWorktreeSelection(s) {
  const { worktreesState, toast } = s;
  for (const [path] of worktreesState.pendingRemovalSelections) {
    const removal = ((worktreesState.report && worktreesState.report.removals) || {})[path];
    if (!worktreeCtlSelectedWorktree(s, path) || (removal && removal.state === 'removed')) worktreesState.pendingRemovalSelections.delete(path);
  }
  const changed = [];
  for (const [path, approved] of worktreesState.selected) {
    const current = worktreeCtlSelectedWorktree(s, path);
    if (current && worktreeCtlSameApproval(approved, current.approval)) continue;
    worktreesState.selected.delete(path);
    changed.push(path);
  }
  if (changed.length) toast(`Removed from selection because inspection facts changed or the worktree is no longer eligible: ${changed.join(', ')}`, 'info');
}

function worktreeCtlToggleWorktreeSelection(s, path) {
  const { worktreesState, renderSelection } = s;
  if (worktreesState.selectionBusy) return;
  if (worktreesState.selected.has(path)) worktreesState.selected.delete(path);
  else {
    const current = worktreeCtlSelectedWorktree(s, path);
    if (!current || !current.approval) return;
    worktreesState.selected.set(path, current.approval);
  }
  renderSelection();
}

function worktreeCtlSelectVisibleWorktrees(s, globalSearchTerm) {
  const { worktreesState, renderSelection } = s;
  if (worktreesState.selectionBusy) return;
  const rep = worktreesState.report;
  for (const { repo, rows } of worktreeGroups(rep, worktreesState.filter, globalSearchTerm)) {
    for (const w of rows) {
      const approval = worktreeSelectionApproval(w, repo, rep);
      if (approval) worktreesState.selected.set(w.path, approval);
    }
  }
  renderSelection();
}

function worktreeCtlClearWorktreeSelection(s) {
  const { worktreesState, renderSelection } = s;
  if (worktreesState.selectionBusy) return;
  worktreesState.selected.clear();
  worktreesState.pendingRemovalSelections.clear();
  renderSelection();
}

async function worktreeCtlRemoveSelectedWorktrees(s) {
  const { worktreesState, render, confirm, toast } = s;
  if (worktreesState.selectionBusy) return;
  worktreeCtlReconcileWorktreeSelection(s);
  if (!worktreesState.selected.size) { render(['worktrees']); return; }
  // Capture the exact approvals and displayed estimates before opening the
  // dialog. A later refresh may invalidate them, never expand the batch.
  const rows = [...worktreesState.selected].map(([path, approval]) => {
    const { w } = worktreeCtlSelectedWorktree(s, path);
    return Object.freeze({ approval, size: Object.freeze({ size_bytes: w.size_bytes, size_partial: w.size_partial }) });
  });
  worktreesState.selectionBusy = true;
  render(['worktrees']);
  let removing = false;
  let trashed = false;
  try {
    const ok = await confirm(worktreeSelectionConfirm(rows), { title: 'Review worktree removal', okLabel: `Confirm ${rows.length} removal${rows.length === 1 ? '' : 's'}`, messageHTML: worktreeSelectionReviewHTML(rows), focusCancel: true });
    if (!ok) return;
    // One request per row in the confirmed order, each checked against the
    // page right before it is sent.
    for (const { approval } of rows) {
      const path = approval.path;
      const current = worktreeCtlSelectedWorktree(s, path);
      if (!worktreeCtlSameApproval(worktreesState.selected.get(path), approval) || !current || !worktreeCtlSameApproval(current.approval, approval)) {
        worktreesState.selected.delete(path);
        toast(`Skipped ${path}: its inspection facts or selection changed. Review it again before removal.`, 'info');
        continue;
      }
      if (worktreeDeletesPermanently(approval)) {
        worktreesState.pendingRemovalSelections.set(path, approval);
        worktreesState.selected.delete(path);
        worktreeCtlTrackRemovals(s, [path], approval.branch ? { [path]: approval.branch } : {});
        if (!removing) { removing = true; s.removalBatches++; }
        await worktreeCtlRemoveOne(s, approval);
        continue;
      }
      try {
        const { r, text } = await worktreeCtlPostWorktree(s, '/worktrees/review-trash', { path, head: approval.head, reasons: approval.reasons });
        if (!r.ok) throw new Error(text.trim() || String(r.status));
        worktreeCtlDropWorktreeRows(s, [path]);
        trashed = true;
        toast(`Moved ${path} to the Trash`, 'success');
      } catch (err) {
        toast(`Could not remove ${path}: ${err.message || err}. Press Rescan if its facts may have changed.`, 'danger');
      }
    }
  } catch (err) {
    toast(`Could not review selected worktrees: ${err.message || err}`, 'danger');
  } finally {
    if (removing) {
      s.removalBatches--;
      worktreeCtlPaintRemovalToast(s);
    } else if (trashed) worktreeCtlLoadLedger(s);
    worktreesState.selectionBusy = false;
    render(['worktrees']);
  }
}

// Worktree actions. The daemon re-inspects before removing and answers 409
// with the fresh verdict when the worktree is no longer removable.
async function worktreeCtlPostWorktree(s, path, body, timeoutMs = WORKTREE_TIMEOUT_MS) {
  const r = await s.request(path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body), timeoutMs
  });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* http.Error text */ }
  return { r, text, json };
}

async function worktreeCtlRemoveWorktree(s, path, branch) {
  const { confirm, toast } = s;
  const current = worktreeCtlSelectedWorktree(s, path);
  const reviewed = current?.approval?.can_remove_reviewed ? current.approval : null;
  const rows = reviewed ? [{approval:reviewed,size:current.w}] : null;
  const ok = await confirm(
    reviewed ? worktreeSelectionConfirm(rows) : `git deletes ${path} and its ignored files. ${branch ? `Branch ${branch} and its commits stay.` : 'Its commits stay reachable from other refs.'}`,
    { title: 'Remove worktree', okLabel: 'Remove', ...(reviewed ? {messageHTML:worktreeSelectionReviewHTML(rows),focusCancel:true} : {}) });
  if (!ok) return;
  if (reviewed && !worktreeCtlSameApproval(reviewed, worktreeCtlSelectedWorktree(s, path)?.approval)) {
    toast('Inspection facts changed. Review the worktree again before deletion.', 'info');
    return;
  }
  await worktreeCtlRemoveRows(s, [reviewed || { path, branch }]);
}

// removeRows: one removal request per row, one after another in the given
// order; rows not sent yet show as waiting their turn. Each reply updates
// the page as it lands, and a failure does not stop the rest.
async function worktreeCtlRemoveRows(s, rows) {
  const labels = {};
  for (const w of rows) {
    if (w.branch) labels[w.path] = w.branch;
    worktreeCtlSetRemoval(s, w.path, { path: w.path, state: 'running', phase: 'waiting', step: 'waiting for its turn' });
  }
  worktreeCtlTrackRemovals(s, rows.map(w => w.path), labels);
  s.removalBatches++;
  s.render(['worktrees']);
  try {
    for (const w of rows) await worktreeCtlRemoveOne(s, w);
  } finally {
    s.removalBatches--;
    worktreeCtlPaintRemovalToast(s);
    s.render(['worktrees']);
  }
}

// removeOne sends one POST /worktrees/remove and applies its reply: the
// row leaves on success; on a refusal or failure it stays, with the fresh
// verdict when the reply carries one, and a mark taken for it comes back.
async function worktreeCtlRemoveOne(s, w) {
  const { worktreesState, render, now } = s;
  const path = w.path;
  const at = new Date(now()).toISOString();
  worktreeCtlSetRemoval(s, path, { path, state: 'running', phase: 'checking', step: 'checking it is still safe to remove', started_at: at, step_at: at });
  render(['worktrees']);
  worktreeCtlPaintRemovalToast(s);
  let reply = null;
  let failure = '';
  try {
    reply = await worktreeCtlPostWorktree(s, '/worktrees/remove', { path,
      ...(w.can_remove_reviewed ? { review: { head: w.head, reasons: w.reasons } } : {}) }, WORKTREE_REMOVE_TIMEOUT_MS);
  } catch (err) {
    failure = String(err.message || err);
  }
  const finished_at = new Date(now()).toISOString();
  const { r, text, json } = reply || {};
  let removal;
  if (r && r.ok && json && json.status === 'ok') {
    removal = { path, state: 'removed', branch: json.branch || w.branch || '', bytes: Number(json.bytes) || 0, finished_at };
    worktreeCtlDropWorktreeRows(s, [path]);
  } else if (r && r.status === 409 && json && json.state) {
    const reasons = json.reasons || [];
    removal = { path, state: 'failed', error: `not removed: it is now ${json.state}`, row_state: json.state, reasons, finished_at };
    const row = worktreeCtlSelectedWorktree(s, path);
    if (row) Object.assign(row.w, { state: json.state, reasons, reason_kinds: [] });
  } else {
    removal = { path, state: 'failed', error: failure || (text || '').trim() || String(r ? r.status : 'no reply'), finished_at };
  }
  worktreeCtlSetRemoval(s, path, removal);
  worktreeCtlRestoreMark(s, path, removal);
  render(['worktrees']);
  worktreeCtlPaintRemovalToast(s);
}

// restoreMark: a removal that failed while its approval still matches the
// row puts the mark back for review; a removed row's mark is gone.
function worktreeCtlRestoreMark(s, path, removal) {
  const { worktreesState, toast } = s;
  const approved = worktreesState.pendingRemovalSelections.get(path);
  if (!approved) return;
  worktreesState.pendingRemovalSelections.delete(path);
  const current = removal.state === 'failed' && worktreeCtlSelectedWorktree(s, path);
  if (current && worktreeCtlSameApproval(approved, current.approval)) {
    worktreesState.selected.set(path, approved);
    toast(`Removal failed; marked again for review: ${path}`, 'info');
  }
}

// Remove all: every removable row of one repository after one dialog.
async function worktreeCtlRemoveAllWorktrees(s, repoPath) {
  const { worktreesState, confirm } = s;
  if (worktreesState.selectionBusy) return;
  const rep = worktreesState.report;
  const repo = rep && (rep.repos || []).find(r => r.path === repoPath);
  const rows = removableRows(repo, rep && rep.removals);
  if (!rows.length) return;
  const bytes = rows.reduce((n, w) => n + (Number(w.size_bytes) || 0), 0);
  const ok = await confirm(
    `git deletes ${rows.length} worktrees of ${repoPath}${bytes ? ` (${fmtDisk(bytes)})` : ''} and their ignored files. Their branches and commits stay; each is checked again before it goes.`,
    { title: 'Remove all', okLabel: `Remove ${rows.length}` });
  if (!ok) return;
  await worktreeCtlRemoveRows(s, rows);
}

// Remove every removable worktree of every repository after one dialog
// that counts them per repository.
async function worktreeCtlRemoveAllRemovable(s) {
  const { worktreesState, confirm } = s;
  if (worktreesState.selectionBusy) return;
  const { rows, bytes } = removableEverywhere(worktreesState.report);
  if (!rows.length) return;
  const perRepo = new Map();
  for (const { repo } of rows) perRepo.set(repo.path, (perRepo.get(repo.path) || 0) + 1);
  const list = [...perRepo].map(([p, n]) => `${p} (${n})`).join(', ');
  const ok = await confirm(
    `git deletes ${rows.length} worktrees${bytes ? ` (${fmtDisk(bytes)})` : ''} and their ignored files: ${list}. Their branches and commits stay; each is checked again before it goes.`,
    { title: 'Remove all removable worktrees', okLabel: `Remove ${rows.length}` });
  if (!ok) return;
  await worktreeCtlRemoveRows(s, rows.map(r => r.w));
}

// Folders git no longer records: open in Finder, link again to the
// repository that still records them, or move to the Trash.
async function worktreeCtlRevealWorktree(s, path) {
  try {
    const { r, text } = await worktreeCtlPostWorktree(s, '/worktrees/reveal', { path });
    if (!r.ok) throw new Error(text.trim() || String(r.status));
  } catch (err) {
    s.toast('Could not open the folder: ' + (err.message || err), 'danger');
  }
}

async function worktreeCtlReconnectWorktree(s, path, repo) {
  const { confirm, toast } = s;
  const ok = await confirm(`git worktree repair links ${path} to ${repo} again. Nothing is deleted.`,
    { title: 'Reconnect worktree', okLabel: 'Reconnect' });
  if (!ok) return;
  try {
    const { r, text } = await worktreeCtlPostWorktree(s, '/worktrees/reconnect', { path });
    if (!r.ok) throw new Error(text.trim() || String(r.status));
    toast(`Reconnected ${path} to ${repo}`, 'success');
    worktreeCtlLoadWorktrees(s, false);
  } catch (err) {
    toast('Could not reconnect: ' + (err.message || err), 'danger');
  }
}

async function worktreeCtlTrashOrphanWorktree(s, path) {
  const { confirm, toast, render } = s;
  const ok = await confirm(`Move ${path} to the Trash? Git no longer records it, so its files are the only copy; you can put it back from the Trash until you empty it.`,
    { title: 'Move to Trash', okLabel: 'Move to Trash' });
  if (!ok) return;
  try {
    const { r, text, json } = await worktreeCtlPostWorktree(s, '/worktrees/trash', { path });
    if (!r.ok) throw new Error(text.trim() || String(r.status));
    const bytes = Number(json && json.result && json.result.bytes) || 0;
    worktreeCtlDropWorktreeRows(s, [path]);
    render(['worktrees']);
    toast(bytes ? `Moved ${path} to the Trash — ${fmtDisk(bytes)}` : `Moved ${path} to the Trash`, 'success');
    worktreeCtlLoadLedger(s);
  } catch (err) {
    toast('Could not move it to the Trash: ' + (err.message || err) + '. Press Rescan if its facts may have changed.', 'danger');
  }
}

// The listed keep or review row for path that can go to the Trash.
function worktreeCtlTrashableWorktree(s, path) {
  const { worktreesState } = s;
  for (const repo of (worktreesState.report && worktreesState.report.repos) || []) {
    const row = (repo.worktrees || []).find(w => w.path === path && (w.state === 'review' || w.state === 'keep') && !w.orphan);
    if (row) return row;
  }
  return null;
}

async function worktreeCtlTrashReviewedWorktree(s, path) {
  const { confirm, toast, render } = s;
  const row = worktreeCtlTrashableWorktree(s, path);
  if (!row || worktreeTrashBlock(row)) return;
  const ok = await confirm(worktreeTrashConfirm(row), { title: 'Remove worktree', okLabel: 'Remove' });
  if (!ok) return;
  try {
    const { r, text, json } = await worktreeCtlPostWorktree(s, '/worktrees/review-trash',
      { path, head: row.head, reasons: row.reasons });
    if (!r.ok) throw new Error(text.trim() || String(r.status));
    const dest = json && json.result && json.result.trash_path;
    worktreeCtlDropWorktreeRows(s, [path]);
    render(['worktrees']);
    toast(`Moved to Trash${dest ? ': ' + dest : ''}`, 'success');
    worktreeCtlLoadLedger(s);
  } catch (err) {
    toast('Could not move reviewed worktree: ' + (err.message || err) + '. Press Rescan if its facts may have changed.', 'danger');
  }
}

async function worktreeCtlAdviseWorktree(s, path) {
  const { toast } = s;
  try {
    const { r, text, json } = await worktreeCtlPostWorktree(s, '/worktrees/advise', { path });
    if (!r.ok) throw new Error(text.trim() || String(r.status));
    if (!json || !json.queued) {
      toast('The advisor is off or busy — no note queued', 'info');
      return;
    }
    toast('Asked the local advisor — once it answers, Reload shows the note under the row', 'info');
  } catch (err) {
    toast('Failed to ask the advisor: ' + (err.message || err), 'danger');
  }
}

// Ask the advisor about a whole repository: the daemon answers 202 with the
// number of rows it will work through, and the notes are taken row by row.
async function worktreeCtlAdviseWorktreeGroup(s, repo) {
  const { toast } = s;
  try {
    const { r, text, json } = await worktreeCtlPostWorktree(s, '/worktrees/advise', { repo });
    if (!r.ok) throw new Error(text.trim() || String(r.status));
    if (!json || !json.queued) {
      toast('The advisor is off or busy — no note queued', 'info');
      return;
    }
    toast(worktreeGroupAskText(json), 'info');
  } catch (err) {
    toast('Failed to ask the advisor: ' + (err.message || err), 'danger');
  }
}

async function worktreeCtlRemoveClutter(s, path) {
  const { clutterState, confirm, render, toast } = s;
  const it = ((clutterState.report && clutterState.report.items) || []).find(x => x.path === path);
  if (!it || !it.can_remove || clutterState.removing.has(path)) return;
  const ok = await confirm(`Permanently delete ${path}? This frees disk space immediately. The cache will be rebuilt when needed. This cannot be undone.`,
    { title: 'Delete build cache', okLabel: 'Delete cache' });
  if (!ok || clutterState.removing.has(path)) return;
  clutterState.removing.add(path);
  render(['clutter']);
  try {
    const { r, text, json } = await worktreeCtlPostWorktree(s, '/cleanup/remove', { path }, WORKTREE_TIMEOUT_MS + 10 * 60 * 1000);
    if (!r.ok) throw new Error(text.trim() || String(r.status));
    const bytes = Number(json && json.result && json.result.bytes) || 0;
    clutterState.report.items = clutterState.report.items.filter(x => x.path !== path);
    toast(`Deleted ${path} — ${json && json.result && json.result.bytes_partial ? 'at least ' : ''}${fmtDisk(bytes)} cleared`, 'success');
    worktreeCtlLoadLedger(s);
  } catch (err) {
    toast('Cache deletion failed: ' + (err.message || err), 'danger');
  } finally {
    clutterState.removing.delete(path);
    render(['clutter']);
    worktreeCtlLoadClutter(s, false);
  }
}

async function worktreeCtlTrashClutter(s, path) {
  const { clutterState, confirm, render, toast } = s;
  if (clutterState.removing.has(path)) return;
  const ok = await confirm(`Move ${path} to the Trash? You can put it back from the Trash until you empty it.`,
    { title: 'Move to Trash', okLabel: 'Move to Trash' });
  if (!ok) return;
  try {
    const { r, text, json } = await worktreeCtlPostWorktree(s, '/cleanup/trash', { path });
    if (!r.ok) throw new Error(text.trim() || String(r.status));
    const bytes = Number(json && json.result && json.result.bytes) || 0;
    const rep = clutterState.report;
    if (rep) {
      rep.items = (rep.items || []).filter(it => it.path !== path);
      // Unknown totals stay unknown; the ledger reload reports the move.
      const t = rep.reclaimed;
      if (t) {
        t.trashed_bytes = (Number(t.trashed_bytes) || 0) + bytes;
        t.trashed_count = (Number(t.trashed_count) || 0) + 1;
      }
    }
    render(['clutter']);
    toast(`Moved ${path} to the Trash — ${fmtDisk(bytes)} frees when you empty it`, 'success');
    worktreeCtlLoadLedger(s);
  } catch (err) {
    toast('Failed to move to the Trash: ' + (err.message || err), 'danger');
  }
}

async function worktreeCtlAdviseClutterProject(s, project) {
  const { clutterState, request, toast, markDirty } = s;
  try {
    const { r, text, json } = await worktreeCtlPostWorktree(s, '/cleanup/advise', { project });
    if (!r.ok) throw new Error(text.trim() || String(r.status));
    if (!json || !json.queued) {
      toast('The advisor is off or busy — no plan queued', 'info');
      return;
    }
    toast('Asked the local advisor for a plan — it appears under the project when it answers', 'info');
    for (let i = 0; i < WORKTREE_CLUTTER_PLAN_POLLS; i++) {
      await new Promise(res => setTimeout(res, WORKTREE_CLUTTER_PLAN_EVERY_MS));
      const g = await request('/cleanup', { timeoutMs: WORKTREE_TIMEOUT_MS });
      if (!g.ok) break;
      const rep = await g.json();
      clutterState.report = rep;
      markDirty('clutter');
      if (rep.advice && rep.advice[project]) break;
    }
  } catch (err) {
    toast('Failed to ask the advisor: ' + (err.message || err), 'danger');
  }
}

async function worktreeCtlCleanClutter(s, name) {
  const { clutterState, confirm, toast } = s;
  const it = ((clutterState.report && clutterState.report.items) || []).find(x => x.name === name && x.action === 'clean');
  const ok = await confirm(`Run \`${(it && it.command) || name}\`? The tool clears its own cache; it may take a few minutes.`,
    { title: 'Clean cache', okLabel: 'Run', danger: false });
  if (!ok) return;
  toast(`Running ${(it && it.command) || name}…`, 'info');
  try {
    const { r, text, json } = await worktreeCtlPostWorktree(s, '/cleanup/clean', { name });
    if (!r.ok) throw new Error(text.trim() || String(r.status));
    const bytes = Number(json && json.result && json.result.bytes) || 0;
    toast(`${name}: ${fmtDisk(bytes)} reclaimed`, 'success');
    worktreeCtlLoadClutter(s, false);
    worktreeCtlLoadLedger(s);
  } catch (err) {
    toast('Clean failed: ' + (err.message || err), 'danger');
  }
}

// Resume the agent that worked in the worktree with the cleanup request;
// its answer lands in the report's asks, which Reload reads.
async function worktreeCtlAskWorktreeAgent(s, path) {
  const { worktreesState, confirm, render, toast } = s;
  const ok = await confirm(
    `Resume the agent that worked in ${path}? It gets a fixed request: open a pull request for work worth keeping, or say the worktree can go. It runs with your agent settings (it may commit and push) for up to 15 minutes.`,
    { title: 'Ask the agent', okLabel: 'Ask', danger: false });
  if (!ok) return;
  try {
    const { r, text, json } = await worktreeCtlPostWorktree(s, '/worktrees/ask', { path });
    if (!r.ok) throw new Error(text.trim() || String(r.status));
    const ask = json && json.ask;
    const rep = worktreesState.report;
    if (rep && ask) (rep.asks || (rep.asks = {}))[path] = ask;
    worktreeCtlReconcileWorktreeSelection(s);
    render(['worktrees']);
    toast(`Asked ${ask ? ask.harness : 'the agent'} — once it answers, Reload shows it under the row`, 'info');
  } catch (err) {
    toast('Could not ask the agent: ' + (err.message || err), 'danger');
  }
}

async function worktreeCtlPruneWorktrees(s, repo) {
  const { confirm, render, toast } = s;
  const ok = await confirm(`Drop git's entries for worktrees of ${repo} whose directory is gone?`,
    { title: 'Prune worktrees', okLabel: 'Prune', danger: false });
  if (!ok) return;
  try {
    const { r, text, json } = await worktreeCtlPostWorktree(s, '/worktrees/remove', { repo, prune: true });
    if (!r.ok) throw new Error(text.trim() || String(r.status));
    const pruned = (json && json.pruned) || [];
    worktreeCtlDropWorktreeRows(s, pruned);
    render(['worktrees']);
    toast(`Pruned ${pruned.length} worktree entr${pruned.length === 1 ? 'y' : 'ies'}`, 'success');
    worktreeCtlLoadLedger(s);
  } catch (err) {
    toast('Failed to prune: ' + (err.message || err), 'danger');
  }
}

async function worktreeCtlHideWorktreeRepo(s, repo) {
  const { worktreesState, render, toast } = s;
  try {
    const { r, text } = await worktreeCtlPostWorktree(s, '/worktrees/repos', { path: repo, hidden: true });
    if (!r.ok) throw new Error(text.trim() || String(r.status));
    const rep = worktreesState.report;
    if (rep) rep.repos = (rep.repos || []).filter(x => x.path !== repo);
    worktreeCtlReconcileWorktreeSelection(s);
    render(['worktrees']);
    toast(`Hidden ${repo} — adding it again brings it back`, 'info');
  } catch (err) {
    toast('Failed to hide the repository: ' + (err.message || err), 'danger');
  }
}

// Track a repository by path; true when it was added.
async function worktreeCtlAddRepo(s, path) {
  const { toast } = s;
  try {
    const { r, text, json } = await worktreeCtlPostWorktree(s, '/worktrees/repos', { path });
    if (!r.ok) throw new Error(text.trim() || String(r.status));
    toast(`Added ${(json && json.path) || path}`, 'success');
    worktreeCtlLoadWorktrees(s, false);
    return true;
  } catch (err) {
    toast('Failed to add the repository: ' + (err.message || err), 'danger');
    return false;
  }
}
