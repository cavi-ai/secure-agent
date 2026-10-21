import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../daemon/internal/api/web_dist');
const plain = x => JSON.parse(JSON.stringify(x));
const reply = (body, ok = true) => ({
  ok, status: ok ? 200 : 500,
  text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
  json: async () => body
});
const REPO = '/code/app';
const WT = `${REPO}/.worktrees/a`;

function fakeDocument() {
  const host = { id: 'toast-container', children: [], appendChild(el) { host.children.push(el); } };
  return {
    host,
    getElementById: id => (id === 'toast-container' ? host : host.children.find(el => el.id === id) || null),
    createElement: () => ({
      id: '', className: '', innerHTML: '',
      remove() { host.children = host.children.filter(el => el !== this); },
      querySelectorAll: () => []
    }),
    querySelectorAll: () => []
  };
}

// Builds the controller with fake collaborators. respond(url, req) answers
// each request; a thrown error models a network failure.
function build({ respond = () => reply({}), confirmed = true, shown = {}, nowMs = 1_000_000, historyOpen = false, ledgerReply = () => reply({ days: [] }) } = {}) {
  const document = fakeDocument();
  const timers = [];
  const ctx = {
    Date, JSON, document, window: {},
    setTimeout: (fn, ms) => timers.push({ fn, ms }),
    clearTimeout: () => {},
    setInterval: () => 1,
    clearInterval: () => {}
  };
  vm.createContext(ctx);
  for (const file of ['lib.js', 'tab-worktrees.js', 'worktree-controller.js']) {
    vm.runInContext(readFileSync(path.join(web, file), 'utf8'), ctx, { filename: file });
  }
  const log = { requests: [], toasts: [], confirms: [], renders: [], dirty: [], ledger: 0, ledgerUrls: [], painted: 0, discussed: [], hostShown: 0, hostHidden: 0 };
  const clock = { at: nowMs };
  const controller = ctx.createWorktreeController({
    request: async (url, req = {}) => {
      if (url.startsWith('/cleanup/ledger')) {
        log.ledger++;
        log.ledgerUrls.push(url);
        return ledgerReply();
      }
      log.requests.push({ url, method: req.method || 'GET', body: req.body ? JSON.parse(req.body) : undefined });
      return respond(url, req);
    },
    toast: (message, type) => log.toasts.push({ message, type }),
    confirm: async (message, opts) => { log.confirms.push({ message, opts }); return typeof confirmed === 'function' ? confirmed(message, opts) : confirmed; },
    render: names => log.renders.push(names),
    markDirty: (...names) => log.dirty.push(names),
    visible: view => shown[view] === true,
    now: () => clock.at,
    history: { open: () => historyOpen, paint: () => { log.painted++; } },
    discuss: target => log.discussed.push(target),
    toastHost: { show: () => { log.hostShown++; }, hideWhenEmpty: () => { log.hostHidden++; } }
  });
  return { controller, log, document, timers, clock, ctx };
}

// A note poll that started before a rescan and lands after it must not put
// the older report (with its removed rows) back.
test('an older worktree read landing last does not overwrite a newer report', async () => {
  let landPoll;
  const older = { repos: [{ path: REPO, worktrees: [{ path: WT, branch: 'feat/a', state: 'remove' }] }], advice: {} };
  const newer = { repos: [{ path: REPO, worktrees: [] }], advice: {} };
  const { controller, timers } = build({
    respond: (url, req) => {
      if (url === '/worktrees/advise') return reply({ queued: true });
      if (url === '/worktrees') return new Promise(resolve => { landPoll = () => resolve(reply(older)); });
      if (url === '/worktrees?refresh=1') return reply(newer);
      return reply({});
    }
  });
  const advising = controller.adviseWorktree(WT);
  for (let i = 0; i < 20 && !timers.length; i++) await new Promise(resolve => setImmediate(resolve));
  timers.shift().fn(); // the note poll's wait ends; its read is now in flight
  for (let i = 0; i < 20 && !landPoll; i++) await new Promise(resolve => setImmediate(resolve));
  await controller.loadWorktrees(true);
  assert.equal(controller.worktreesState.report, newer);
  landPoll();
  for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(controller.worktreesState.report, newer, 'the older read landed last and was applied');
  void advising;
});

const worktreeReport = () => ({
  repos: [{
    path: REPO, size_bytes: 3000,
    worktrees: [
      { path: WT, branch: 'feat/a', state: 'remove', size_bytes: 1000 },
      { path: `${REPO}/.worktrees/b`, branch: 'feat/b', state: 'remove', size_bytes: 2000 },
      { path: `${REPO}/.worktrees/c`, branch: 'feat/c', state: 'keep', size_bytes: 0 }
    ]
  }],
  summary: { worktrees: 3, size_bytes: 3000, removable_bytes: 3000 }
});

const selectionReport = () => ({
  repos: [
    { path: REPO, worktrees: [
      { path: WT, branch: 'feat/a', state: 'remove', head: 'aaa', reasons: ['merged into origin/main'], size_bytes: 1024 },
      { path: `${REPO}/review`, branch: 'feat/review', state: 'review', head: 'bbb', reasons: ['1 untracked file'], size_partial: true, size_bytes: 2048 },
      { path: `${REPO}/keep`, branch: 'feat/keep', state: 'keep', head: 'ccc', reasons: ['unmerged commits'] }
    ] },
    { path: '/code/lib', worktrees: [{ path: '/code/lib/other', branch: 'feat/other', state: 'remove', head: 'ddd', reasons: [] }] }
  ]
});

test('selection spans repositories and filters; select shown respects both searches and excludes unsafe rows', async () => {
  const rep = selectionReport();
  const { controller } = build({ respond: () => reply(rep) });
  await controller.loadWorktrees(false);
  controller.setWorktreeSearch('other');
  controller.selectVisibleWorktrees('feat/other');
  controller.setWorktreeSearch('');
  controller.setWorktreeFilter('check');
  controller.selectVisibleWorktrees('untracked');
  assert.deepEqual([...controller.worktreesState.selected.keys()], ['/code/lib/other', `${REPO}/review`]);
  controller.toggleWorktreeSelection(WT);
  assert.equal(controller.worktreesState.selected.size, 3);
  controller.toggleWorktreeSelection(WT);
  assert.equal(controller.worktreesState.selected.size, 2);
  for (const extra of [{ state: 'main' }, { state: 'prune' }, { orphan: true }, { locked: true }, { in_use: true }, { conflicts: 1 }, { git_operation: 'rebase' }, { partly_staged: 1 }, { submodules: 1, submodule_local: ['submodule lib has a stash (removal loses it)'] }, { loose_commits: 1 }, { error: 'unreadable' }]) {
    Object.assign(rep.repos[0].worktrees[0], selectionReport().repos[0].worktrees[0], extra);
    controller.toggleWorktreeSelection(WT);
    assert.equal(controller.worktreesState.selected.has(WT), false, JSON.stringify(extra));
    rep.repos[0].worktrees[0] = selectionReport().repos[0].worktrees[0];
  }
  rep.removals = { [WT]: { state: 'running' } };
  controller.toggleWorktreeSelection(WT);
  assert.equal(controller.worktreesState.selected.has(WT), false);
  rep.removals = {};
  rep.asks = { [WT]: { status: 'running' } };
  controller.toggleWorktreeSelection(WT);
  assert.equal(controller.worktreesState.selected.has(WT), false);
  rep.asks = {};
  rep.repos[0].error = 'missing repository';
  controller.toggleWorktreeSelection(WT);
  assert.equal(controller.worktreesState.selected.has(WT), false);
  controller.clearWorktreeSelection();
  assert.equal(controller.worktreesState.selected.size, 0);
});

test('selection approvals copy reasons and survive sizing or advisor updates, but invalidate once when facts change', async () => {
  const rep = selectionReport();
  const { controller, log } = build({ respond: () => reply(rep) });
  await controller.loadWorktrees(false);
  controller.toggleWorktreeSelection(WT);
  const approval = controller.worktreesState.selected.get(WT);
  assert.ok(Object.isFrozen(approval) && Object.isFrozen(approval.reasons));
  rep.repos[0].worktrees[0].size_bytes = 9999;
  rep.advice = { [WT]: { assessment: 'keep' } };
  await controller.loadWorktrees(false);
  assert.equal(controller.worktreesState.selected.get(WT), approval);
  rep.repos[0].worktrees[0].reasons.push('new local files');
  assert.equal(approval.reasons.length, 1);
  await controller.loadWorktrees(false);
  assert.equal(controller.worktreesState.selected.size, 0);
  assert.match(log.toasts.at(-1).message, /selection.*changed|changed.*selection/i);
  const messages = log.toasts.length;
  await controller.loadWorktrees(false);
  assert.equal(log.toasts.length, messages);
});

test('note polling reconciles changed selections, and dropped rows lose their approvals', async () => {
  let rep = selectionReport();
  const { controller, timers } = build({ respond: url => url === '/worktrees/advise' ? reply({ queued: true }) : url === '/worktrees/remove' ? reply({ pruned: [WT] }) : reply(rep) });
  await controller.loadWorktrees(false);
  controller.toggleWorktreeSelection(`${REPO}/review`);
  const advising = controller.adviseWorktree(`${REPO}/review`);
  for (let i = 0; i < 20 && !timers.length; i++) await new Promise(resolve => setImmediate(resolve));
  rep = selectionReport();
  rep.repos[0].worktrees[1].head = 'new-head';
  rep.advice = { [`${REPO}/review`]: { assessment: 'remove' } };
  timers.shift().fn();
  await advising;
  assert.equal(controller.worktreesState.selected.size, 0);
  controller.toggleWorktreeSelection(WT);
  await controller.pruneWorktrees(REPO);
  assert.equal(controller.worktreesState.selected.size, 0);
});

test('bulk selection is single flight from dialog start; cancel preserves marks and sends no writes', async () => {
  let decide;
  const { controller, log } = build({ respond: () => reply(selectionReport()), confirmed: () => new Promise(resolve => { decide = resolve; }) });
  await controller.loadWorktrees(false);
  controller.toggleWorktreeSelection(WT);
  const removing = controller.removeSelectedWorktrees();
  assert.equal(controller.worktreesState.selectionBusy, true);
  controller.clearWorktreeSelection();
  controller.toggleWorktreeSelection('/code/lib/other');
  controller.selectVisibleWorktrees('');
  await controller.removeSelectedWorktrees();
  await controller.removeAllRemovable();
  await controller.removeAllWorktrees(REPO);
  assert.equal(log.confirms.length, 1);
  assert.equal(controller.worktreesState.selected.size, 1);
  decide(false);
  await removing;
  assert.equal(controller.worktreesState.selectionBusy, false);
  assert.equal(controller.worktreesState.selected.size, 1);
  assert.equal(log.requests.filter(r => r.method === 'POST').length, 0);
});

test('bulk removal stays single flight while a request is pending and keeps failed approvals for explicit retry', async () => {
  let finish;
  const rep = selectionReport();
  const { controller, log } = build({ respond: url => url === '/worktrees' ? reply(rep) : new Promise(resolve => { finish = resolve; }) });
  await controller.loadWorktrees(false);
  controller.toggleWorktreeSelection(WT);
  const removing = controller.removeSelectedWorktrees();
  for (let i = 0; i < 20 && !finish; i++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(controller.worktreesState.selectionBusy, true);
  await controller.removeSelectedWorktrees();
  controller.toggleWorktreeSelection('/code/lib/other');
  assert.equal(log.confirms.length, 1);
  assert.equal(log.requests.filter(r => r.method === 'POST').length, 1);
  finish(reply('connection closed after request', false));
  await removing;
  assert.equal(controller.worktreesState.selected.size, 1);
  assert.equal(controller.worktreesState.selected.has(WT), true);
  assert.equal(controller.worktreesState.selectionBusy, false);
  assert.equal(log.requests.filter(r => r.method === 'POST').length, 1, 'no automatic retry');
});

test('an accepted async removal restores its mark after unchanged terminal failure without retrying', async () => {
  let rep = selectionReport();
  const { controller, log } = build({ respond: (url, req) => url === '/worktrees' ? reply(rep) : reply({ removal: { path: JSON.parse(req.body).path, state: 'running' } }) });
  await controller.loadWorktrees(false);
  controller.toggleWorktreeSelection(WT);
  const approved = controller.worktreesState.selected.get(WT);
  await controller.removeSelectedWorktrees();
  assert.equal(controller.worktreesState.selected.has(WT), false);
  await controller.loadWorktrees(false);
  assert.equal(controller.worktreesState.selected.has(WT), false, 'still running');
  rep = selectionReport();
  rep.removals = { [WT]: { path: WT, state: 'failed', error: 'permission denied' } };
  await controller.loadWorktrees(false);
  assert.equal(controller.worktreesState.selected.get(WT), approved);
  assert.equal(log.requests.filter(r => r.method === 'POST').length, 1, 'restoring a mark sends no write');
  controller.clearWorktreeSelection();
  await controller.loadWorktrees(false);
  assert.equal(controller.worktreesState.selected.has(WT), false, 'terminal restoration is consumed once');
});

test('async failure does not restore changed approvals, removed rows, missing rows, or cleared intent', async () => {
  for (const outcome of ['changed', 'removed', 'missing', 'clear']) {
    let rep = selectionReport();
    const { controller, log } = build({ respond: (url, req) => url === '/worktrees' ? reply(rep) : reply({ removal: { path: JSON.parse(req.body).path, state: 'running' } }) });
    await controller.loadWorktrees(false);
    controller.toggleWorktreeSelection(WT);
    await controller.removeSelectedWorktrees();
    if (outcome === 'clear') controller.clearWorktreeSelection();
    rep = selectionReport();
    rep.removals = { [WT]: { path: WT, state: outcome === 'removed' ? 'removed' : 'failed' } };
    if (outcome === 'changed') rep.repos[0].worktrees[0].head = 'new-head';
    if (outcome === 'missing') rep.repos[0].worktrees.shift();
    await controller.loadWorktrees(false);
    assert.equal(controller.worktreesState.selected.has(WT), false, outcome);
    rep = selectionReport();
    rep.removals = { [WT]: { path: WT, state: 'failed' } };
    await controller.loadWorktrees(false);
    assert.equal(controller.worktreesState.selected.has(WT), false, `${outcome} cannot restore stale intent later`);
    assert.equal(log.requests.filter(r => r.method === 'POST').length, 1);
  }
});

test('bulk review names every path and route, sends captured head/reasons, and continues after per-path failure', async () => {
  const rep = selectionReport();
  const { controller, log, document } = build({ respond: (url, req) => {
    if (url === '/worktrees') return reply(rep);
    const body = JSON.parse(req.body);
    if (body.path === `${REPO}/keep`) return reply('permission denied', false);
    if (url === '/worktrees/remove') return reply({ removal: { path: body.path, state: 'running' } });
    return reply({ result: { trash_path: '/trash/review' } });
  } });
  await controller.loadWorktrees(false);
  for (const p of [WT, `${REPO}/keep`, `${REPO}/review`, '/code/lib/other']) controller.toggleWorktreeSelection(p);
  await controller.removeSelectedWorktrees();
  const dialog = log.confirms[0].message;
  for (const p of [WT, `${REPO}/keep`, `${REPO}/review`, '/code/lib/other']) assert.ok(dialog.includes(p));
  assert.match(dialog, /Checked deletion/);
  assert.match(dialog, /Trash/);
  assert.match(dialog, /1 untracked file/);
  assert.match(dialog, /branches and commits stay/i);
  assert.match(dialog, /does not register/i);
  assert.match(dialog, /unknown/i);
  assert.match(dialog, /partial|at least/i);
  assert.deepEqual(plain(log.requests.filter(r => r.method === 'POST')), [
    { url: '/worktrees/remove', method: 'POST', body: { path: WT, async: true } },
    { url: '/worktrees/review-trash', method: 'POST', body: { path: `${REPO}/keep`, head: 'ccc', reasons: ['unmerged commits'] } },
    { url: '/worktrees/review-trash', method: 'POST', body: { path: `${REPO}/review`, head: 'bbb', reasons: ['1 untracked file'] } },
    { url: '/worktrees/remove', method: 'POST', body: { path: '/code/lib/other', async: true } }
  ]);
  assert.deepEqual([...controller.worktreesState.selected.keys()], [`${REPO}/keep`]);
  assert.match(log.toasts.find(t => t.message.includes('permission denied')).message, new RegExp(`${REPO}/keep`));
  assert.match(document.getElementById('removal-toast').innerHTML, /Removing/);
  assert.equal(log.ledger, 1);
  assert.equal(log.requests.filter(r => r.method === 'GET').length, 2, 'one final report read');
});

test('bulk confirmation cannot promote routes or include new selections, and revalidates before each request', async () => {
  const rep = selectionReport();
  let controller;
  const built = build({ respond: (url, req) => {
    if (url === '/worktrees') return reply(rep);
    rep.repos[0].worktrees[1].head = 'changed-during-first-request';
    return reply({ removal: { path: JSON.parse(req.body).path, state: 'running' } });
  }, confirmed: () => {
    rep.repos[0].worktrees[2].state = 'remove';
    controller.worktreesState.selected.set('/code/lib/other', { path: '/code/lib/other' });
    return true;
  } });
  controller = built.controller;
  await controller.loadWorktrees(false);
  for (const p of [WT, `${REPO}/review`, `${REPO}/keep`]) controller.toggleWorktreeSelection(p);
  await controller.removeSelectedWorktrees();
  assert.deepEqual(built.log.requests.filter(r => r.method === 'POST').map(r => r.body.path), [WT]);
  assert.equal(built.log.requests.some(r => r.url === '/worktrees/review-trash'), false);
});

test('loadWorktrees reads the report, stamps the time and marks the panel dirty around the request', async () => {
  const { controller, log } = build({ respond: () => reply(worktreeReport()) });
  await controller.loadWorktrees(false);
  assert.deepEqual(plain(log.requests), [{ url: '/worktrees', method: 'GET' }]);
  assert.equal(controller.worktreesState.report.repos.length, 1);
  assert.equal(controller.worktreesState.loadedAt, 1_000_000);
  assert.equal(controller.worktreesState.loading, false);
  assert.equal(controller.worktreesState.error, '');
  assert.deepEqual(plain(log.dirty), [['worktrees'], ['worktrees']]);
  await controller.loadWorktrees(true);
  assert.equal(log.requests[1].url, '/worktrees?refresh=1');
});

test('loadWorktrees failure keeps the old report, names the error and toasts only when a report is on screen', async () => {
  let answer = () => reply('  scan exploded \n', false);
  const { controller, log } = build({ respond: () => answer() });
  await controller.loadWorktrees(false);
  assert.equal(controller.worktreesState.error, 'Worktree scan failed: scan exploded');
  assert.equal(controller.worktreesState.report, null);
  assert.deepEqual(log.toasts, []);
  answer = () => reply(worktreeReport());
  await controller.loadWorktrees(false);
  answer = () => reply('', false);
  await controller.loadWorktrees(true);
  assert.equal(controller.worktreesState.error, 'Worktree scan failed: 500');
  assert.equal(controller.worktreesState.report.repos.length, 1);
  assert.deepEqual(plain(log.toasts), [{ message: 'Worktree scan failed: 500', type: 'danger' }]);
  assert.equal(controller.worktreesState.loading, false);
});

test('removeWorktree: confirms, starts one async removal, records it and shows the progress toast', async () => {
  const removal = { path: WT, state: 'running', phase: 'checking', step: 'checking' };
  const { controller, log, document } = build({ respond: url => (url === '/worktrees' ? reply(worktreeReport()) : reply({ removal })) });
  await controller.loadWorktrees(false);
  log.requests.length = 0;
  await controller.removeWorktree(WT, 'feat/a');
  assert.equal(log.confirms[0].message, `git deletes ${WT} and its ignored files. Branch feat/a and its commits stay.`);
  assert.deepEqual(plain(log.confirms[0].opts), { title: 'Remove worktree', okLabel: 'Remove' });
  assert.deepEqual(plain(log.requests), [{ url: '/worktrees/remove', method: 'POST', body: { path: WT, async: true } }]);
  assert.equal(controller.worktreesState.report.removals[WT].state, 'running');
  assert.deepEqual(plain(log.renders), [['worktrees']]);
  const toast = document.getElementById('removal-toast');
  assert.match(toast.innerHTML, /Removing feat\/a/);
  assert.match(toast.className, /info/);
  assert.equal(log.hostShown, 1);
});

test('removeWorktree: a declined dialog sends nothing; a refused start toasts the daemon text and tracks nothing', async () => {
  const declined = build({ confirmed: false });
  await declined.controller.removeWorktree(WT, '');
  assert.match(declined.log.confirms[0].message, /Its commits stay reachable from other refs\./);
  assert.deepEqual(declined.log.requests, []);

  const { controller, log, document } = build({ respond: url => (url === '/worktrees' ? reply(worktreeReport()) : reply('worktree is dirty now', false)) });
  await controller.loadWorktrees(false);
  await controller.removeWorktree(WT, 'feat/a');
  assert.deepEqual(plain(log.toasts), [{ message: `Could not start removing ${WT}: worktree is dirty now`, type: 'danger' }]);
  assert.equal(controller.worktreesState.report.removals, undefined);
  assert.equal(document.getElementById('removal-toast'), null);
  assert.deepEqual(plain(log.renders), [['worktrees']]);
});

test('removeAllWorktrees: counts the removable rows in the dialog and starts one removal per row; one refusal does not stop the rest', async () => {
  const other = `${REPO}/.worktrees/b`;
  const { controller, log, document } = build({
    respond: (url, req) => {
      if (url === '/worktrees') return reply(worktreeReport());
      const { path: p } = JSON.parse(req.body);
      return p === WT ? reply('busy', false) : reply({ removal: { path: p, state: 'running' } });
    }
  });
  await controller.loadWorktrees(false);
  log.requests.length = 0;
  await controller.removeAllWorktrees(REPO);
  assert.equal(log.confirms[0].message,
    `git deletes 2 worktrees of ${REPO} (3 KB) and their ignored files. Their branches and commits stay; each is checked again before it goes.`);
  assert.deepEqual(plain(log.confirms[0].opts), { title: 'Remove all', okLabel: 'Remove 2' });
  assert.deepEqual(plain(log.requests.map(r => r.body)), [{ path: WT, async: true }, { path: other, async: true }]);
  assert.deepEqual(plain(log.toasts), [{ message: `Could not start removing ${WT}: busy`, type: 'danger' }]);
  assert.deepEqual(Object.keys(controller.worktreesState.report.removals), [other]);
  assert.match(document.getElementById('removal-toast').innerHTML, /Removing feat\/b/);
});

test('removeAllWorktrees: a repository with nothing removable asks nothing', async () => {
  const { controller, log } = build({ respond: () => reply(worktreeReport()) });
  await controller.loadWorktrees(false);
  await controller.removeAllWorktrees('/code/other');
  assert.deepEqual(log.confirms, []);
  assert.equal(log.requests.length, 1);
});

test('removeAllRemovable: one dialog counts rows per repository, then one removal per row', async () => {
  const { controller, log } = build({ respond: (url, req) => (url === '/worktrees' ? reply(worktreeReport()) : reply({ removal: { path: JSON.parse(req.body).path, state: 'running' } })) });
  await controller.loadWorktrees(false);
  await controller.removeAllRemovable();
  assert.match(log.confirms[0].message, new RegExp(`${REPO} \\(2\\)`));
  assert.equal(log.confirms[0].opts.okLabel, 'Remove 2');
  assert.equal(log.requests.filter(r => r.url === '/worktrees/remove').length, 2);
});

test('trashClutter: moves the item out of the report, adds to the trashed totals and reloads the ledger', async () => {
  const clutter = { items: [{ path: '/c/a', name: 'a' }, { path: '/c/b', name: 'b' }], reclaimed: { trashed_bytes: 10, trashed_count: 1 } };
  const { controller, log } = build({ respond: (url, req) => (url === '/cleanup' ? reply(clutter) : reply({ result: { bytes: 2048 } })) });
  await controller.loadClutter(false);
  log.requests.length = 0;
  await controller.trashClutter('/c/a');
  assert.equal(log.confirms[0].message, 'Move /c/a to the Trash? You can put it back from the Trash until you empty it.');
  assert.deepEqual(plain(log.requests), [{ url: '/cleanup/trash', method: 'POST', body: { path: '/c/a' } }]);
  const rep = controller.clutterState.report;
  assert.deepEqual(plain(rep.items), [{ path: '/c/b', name: 'b' }]);
  assert.deepEqual(plain(rep.reclaimed), { trashed_bytes: 2058, trashed_count: 2 });
  assert.deepEqual(plain(log.renders), [['clutter']]);
  assert.deepEqual(plain(log.toasts), [{ message: 'Moved /c/a to the Trash — 2 KB frees when you empty it', type: 'success' }]);
  assert.equal(log.ledger, 1);
});

test('trashClutter: a refused move leaves the report and the ledger alone and toasts the daemon text', async () => {
  const clutter = { items: [{ path: '/c/a', name: 'a' }], reclaimed: { trashed_bytes: 10, trashed_count: 1 } };
  const { controller, log } = build({ respond: url => (url === '/cleanup' ? reply(clutter) : reply('in use', false)) });
  await controller.loadClutter(false);
  await controller.trashClutter('/c/a');
  assert.equal(controller.clutterState.report.items.length, 1);
  assert.deepEqual(plain(controller.clutterState.report.reclaimed), { trashed_bytes: 10, trashed_count: 1 });
  assert.deepEqual(plain(log.toasts), [{ message: 'Failed to move to the Trash: in use', type: 'danger' }]);
  assert.deepEqual(log.renders, []);
  assert.equal(log.ledger, 0);
});

test('pruneWorktrees: drops the pruned rows and their sizes from the report and reloads the ledger', async () => {
  const { controller, log } = build({ respond: (url, req) => (url === '/worktrees' ? reply(worktreeReport()) : reply({ pruned: [WT] })) });
  await controller.loadWorktrees(false);
  log.requests.length = 0;
  await controller.pruneWorktrees(REPO);
  assert.equal(log.confirms[0].message, `Drop git's entries for worktrees of ${REPO} whose directory is gone?`);
  assert.deepEqual(plain(log.confirms[0].opts), { title: 'Prune worktrees', okLabel: 'Prune', danger: false });
  assert.deepEqual(plain(log.requests), [{ url: '/worktrees/remove', method: 'POST', body: { repo: REPO, prune: true } }]);
  const rep = controller.worktreesState.report;
  assert.equal(rep.repos[0].worktrees.length, 2);
  assert.equal(rep.repos[0].size_bytes, 2000);
  assert.deepEqual(plain(rep.summary), { worktrees: 2, size_bytes: 2000, removable_bytes: 2000 });
  assert.deepEqual(plain(log.renders), [['worktrees']]);
  assert.deepEqual(plain(log.toasts), [{ message: 'Pruned 1 worktree entry', type: 'success' }]);
  assert.equal(log.ledger, 1);
});

test('pruneWorktrees: a refused prune keeps every row and toasts the failure', async () => {
  const { controller, log } = build({ respond: url => (url === '/worktrees' ? reply(worktreeReport()) : reply('git failed', false)) });
  await controller.loadWorktrees(false);
  await controller.pruneWorktrees(REPO);
  assert.equal(controller.worktreesState.report.repos[0].worktrees.length, 3);
  assert.deepEqual(plain(log.toasts), [{ message: 'Failed to prune: git failed', type: 'danger' }]);
  assert.deepEqual(log.renders, []);
  assert.equal(log.ledger, 0);
});

test('activate loads only what is stale for the view it was given', async () => {
  const { controller, log, clock } = build({ respond: url => reply(url === '/cleanup' ? { items: [] } : worktreeReport()) });
  controller.activate('resources');
  assert.deepEqual(log.requests, []);
  controller.activate('clutter');
  await new Promise(res => setImmediate(res));
  assert.deepEqual(plain(log.requests), [{ url: '/cleanup', method: 'GET' }]);
  assert.equal(log.ledger, 0);
  controller.activate('worktrees');
  await new Promise(res => setImmediate(res));
  assert.deepEqual(log.requests.map(r => r.url), ['/cleanup', '/worktrees']);
  assert.equal(log.ledger, 1);
  controller.worktreesState.ledger = { days: [] };
  controller.worktreesState.ledgerAt = clock.at;
  controller.activate('worktrees');
  controller.activate('clutter');
  await new Promise(res => setImmediate(res));
  assert.equal(log.requests.length, 2);
  assert.equal(log.ledger, 1);
  clock.at += 60001;
  controller.activate('worktrees');
  await new Promise(res => setImmediate(res));
  assert.equal(log.requests.length, 3);
  assert.equal(log.ledger, 2);
});

test('worktree filters toggle state and All clears stale while preserving search', () => {
  const { controller } = build();
  controller.setWorktreeFilter('review');
  controller.toggleStaleFilter();
  controller.setWorktreeSearch('feat');
  assert.deepEqual(plain(controller.worktreesState.filter), { state: 'review', stale: true, q: 'feat' });
  controller.setWorktreeFilter('review');
  assert.deepEqual(plain(controller.worktreesState.filter), { state: '', stale: true, q: 'feat' });
  controller.setWorktreeFilter('prune');
  assert.deepEqual(plain(controller.worktreesState.filter), { state: 'prune', stale: true, q: 'feat' });
  controller.setWorktreeFilter(undefined);
  assert.deepEqual(plain(controller.worktreesState.filter), { state: '', stale: false, q: 'feat' });
  controller.setClutterKind('cache');
  controller.expandClutterProject('proj');
  controller.expandClutterProject('proj');
  assert.equal(controller.clutterState.filter.kind, 'cache');
  assert.deepEqual([...controller.clutterState.expanded], ['proj']);
  controller.setClutterKind(undefined);
  assert.equal(controller.clutterState.filter.kind, '');
});

test('the removal toast adopts removals it did not start, finishes with a ledger reload, and closes on request', async () => {
  const running = worktreeReport();
  running.removals = { [WT]: { path: WT, state: 'running', phase: 'deleting', step: 'deleting' } };
  const done = worktreeReport();
  done.removals = { [WT]: { path: WT, state: 'removed', bytes: 1000 } };
  let report = running;
  const { controller, log, document, timers } = build({ respond: () => reply(report), shown: { worktrees: true } });
  await controller.loadWorktrees(false);
  assert.match(document.getElementById('removal-toast').innerHTML, /Removing feat\/a/);
  assert.equal(log.ledger, 0);
  assert.deepEqual(timers.map(t => t.ms), [1500]);

  report = done;
  await controller.loadWorktrees(false);
  assert.match(document.getElementById('removal-toast').innerHTML, /Removed feat\/a/);
  assert.match(document.getElementById('removal-toast').className, /success/);
  assert.equal(log.ledger, 1);
  assert.equal(timers.at(-1).ms, 8000);

  controller.closeRemovalToast();
  assert.equal(document.getElementById('removal-toast'), null);
  assert.equal(log.hostHidden, 1);
});

test('a failed removal keeps its toast open for the user to close', async () => {
  const failed = worktreeReport();
  failed.removals = { [WT]: { path: WT, state: 'failed', error: 'locked' } };
  const { controller, log, document, timers } = build({ respond: url => (url === '/worktrees' ? reply(failed) : reply({ removal: { path: WT, state: 'failed', error: 'locked' } })) });
  await controller.loadWorktrees(false);
  await controller.removeWorktree(WT, 'feat/a');
  const el = document.getElementById('removal-toast');
  assert.match(el.className, /danger/);
  assert.match(el.innerHTML, /Not removed: feat\/a/);
  assert.equal(log.ledger, 1);
  assert.equal(timers.some(t => t.ms === 8000), false);
});

test('addRepo reports whether the repository was added and reloads the list on success', async () => {
  const ok = build({ respond: url => (url === '/worktrees/repos' ? reply({ path: '/code/new' }) : reply(worktreeReport())) });
  assert.equal(await ok.controller.addRepo('/code/new'), true);
  assert.deepEqual(plain(ok.log.requests[0]), { url: '/worktrees/repos', method: 'POST', body: { path: '/code/new' } });
  assert.deepEqual(plain(ok.log.toasts), [{ message: 'Added /code/new', type: 'success' }]);
  assert.equal(ok.log.requests[1].url, '/worktrees');

  const bad = build({ respond: () => reply('not a git repository', false) });
  assert.equal(await bad.controller.addRepo('/tmp/x'), false);
  assert.deepEqual(plain(bad.log.toasts), [{ message: 'Failed to add the repository: not a git repository', type: 'danger' }]);
  assert.equal(bad.log.requests.length, 1);
});

test('discuss actions hand the collaborator a path or a repository target', () => {
  const { controller, log } = build();
  controller.discussWorktree(WT);
  controller.discussWorktreeGroup(REPO);
  assert.deepEqual(plain(log.discussed), [{ path: WT }, { repo: REPO }]);
});

test('loadLedger stores the ledger with its limit, stamps the time and repaints the history', async () => {
  const { controller, log } = build({ ledgerReply: () => reply({ days: [{ day: '2026-10-01' }] }) });
  await controller.loadLedger();
  assert.deepEqual(log.ledgerUrls, ['/cleanup/ledger?days=30&limit=500']);
  assert.deepEqual(plain(controller.worktreesState.ledger), { days: [{ day: '2026-10-01' }], limit: 500 });
  assert.equal(controller.worktreesState.ledgerAt, 1_000_000);
  assert.equal(controller.worktreesState.ledgerLoading, false);
  assert.deepEqual(plain(log.dirty), [['worktrees'], ['worktrees']]);
  assert.equal(log.painted, 1);
  assert.deepEqual(log.toasts, []);
});

test('loadLedger failure toasts only while the history drawer is open and keeps the old ledger', async () => {
  for (const historyOpen of [true, false]) {
    const { controller, log } = build({ historyOpen, ledgerReply: () => reply('ledger offline', false) });
    controller.worktreesState.ledger = { days: [], limit: 500 };
    await controller.loadLedger();
    assert.deepEqual(plain(log.toasts), historyOpen ? [{ message: "Couldn't read the cleanup history: ledger offline", type: 'danger' }] : []);
    assert.deepEqual(plain(controller.worktreesState.ledger), { days: [], limit: 500 });
    assert.equal(controller.worktreesState.ledgerLoading, false);
    assert.equal(log.painted, 1);
  }
});
