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
const replyWith = (body, status) => ({ ...reply(body, status < 300), status });
// removed: the daemon's answer to a removal that went through.
const removed = (path, branch = '', bytes = 0) => replyWith({ status: 'ok', removed: path, branch, reasons: [], bytes, bytes_partial: false }, 200);
const settle = async () => { for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve)); };
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

test('reviewed scratch deletion uses pinned permanent removal and retains the confirmation facts', async () => {
  const rep = selectionReport();
  const row = rep.repos[0].worktrees[1];
  row.can_remove_reviewed = true;
  row.reasons = ['scratch files that only live here: .tmp/ (47 files, 700.4 KB)', '1 commit retained on the branch'];
  const {controller, log} = build({respond:(url, req) => url === '/worktrees'
    ? reply(rep) : removed(JSON.parse(req.body).path, row.branch, 2048)});
  await controller.loadWorktrees(false);
  controller.toggleWorktreeSelection(row.path);
  await controller.removeSelectedWorktrees();
  assert.deepEqual(plain(log.requests.filter(r => r.method === 'POST')), [{url:'/worktrees/remove',method:'POST',
    body:{path:row.path,review:{head:row.head,reasons:row.reasons}}}]);
  assert.equal(controller.worktreesState.report.repos[0].worktrees.some(w => w.path === row.path), false);
  assert.match(log.confirms[0].opts.messageHTML, /ignored .tmp scratch files/);
  assert.match(log.confirms[0].opts.messageHTML, /Branches and committed work stay in git/);
  assert.match(log.confirms[0].message, /47 files, 700.4 KB/);
});

test('a single reviewed removal refuses a changed snapshot after confirmation', async () => {
  const rep = selectionReport();
  const row = rep.repos[0].worktrees[1];
  row.can_remove_reviewed = true;
  const {controller, log} = build({respond:() => reply(rep), confirmed:() => {row.can_remove_reviewed = false; return true;}});
  await controller.loadWorktrees(false);
  await controller.removeWorktree(row.path, row.branch);
  assert.equal(log.requests.some(r => r.method === 'POST'), false);
  assert.match(log.toasts.at(-1).message, /Inspection facts changed/);
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

test('asking the advisor schedules no read; Reload reconciles changed selections, and dropped rows lose their approvals', async () => {
  let rep = selectionReport();
  const { controller, log, timers } = build({ respond: url => url === '/worktrees/advise' ? reply({ queued: true }) : url === '/worktrees/remove' ? reply({ pruned: [WT] }) : reply(rep) });
  await controller.loadWorktrees(false);
  controller.toggleWorktreeSelection(`${REPO}/review`);
  await controller.adviseWorktree(`${REPO}/review`);
  assert.deepEqual(timers, []);
  assert.match(log.toasts.at(-1).message, /Reload shows the note under the row/);
  assert.equal(log.requests.filter(r => r.url === '/worktrees').length, 1);
  rep = selectionReport();
  rep.repos[0].worktrees[1].head = 'new-head';
  rep.advice = { [`${REPO}/review`]: { assessment: 'remove' } };
  await controller.loadWorktrees(false);
  assert.equal(controller.worktreesState.selected.size, 0);
  assert.match(log.toasts.at(-1).message, /inspection facts changed/);
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

test('a failed removal of an unchanged row puts its mark back once, without retrying', async () => {
  const { controller, log } = build({ respond: url => url === '/worktrees' ? reply(selectionReport()) : reply('permission denied', false) });
  await controller.loadWorktrees(false);
  controller.toggleWorktreeSelection(WT);
  const approved = controller.worktreesState.selected.get(WT);
  await controller.removeSelectedWorktrees();
  assert.equal(controller.worktreesState.selected.get(WT), approved);
  assert.deepEqual(plain(log.toasts.at(-1)), { message: `Removal failed; marked again for review: ${WT}`, type: 'info' });
  assert.equal(controller.worktreesState.report.removals[WT].error, 'permission denied');
  assert.equal(controller.worktreesState.report.repos[0].worktrees[0].path, WT);
  assert.equal(log.requests.filter(r => r.method === 'POST').length, 1, 'restoring a mark sends no write');
  controller.clearWorktreeSelection();
  await controller.loadWorktrees(false);
  assert.equal(controller.worktreesState.selected.has(WT), false, 'the mark comes back once');
});

test('a removal reply does not restore a mark for a changed verdict, a removed row or a row gone from the page', async () => {
  for (const outcome of ['changed', 'removed', 'missing']) {
    const rep = selectionReport();
    let finish;
    const { controller, log } = build({ respond: url => url === '/worktrees' ? reply(rep) : new Promise(resolve => { finish = resolve; }) });
    await controller.loadWorktrees(false);
    controller.toggleWorktreeSelection(WT);
    const removing = controller.removeSelectedWorktrees();
    for (let i = 0; i < 20 && !finish; i++) await new Promise(resolve => setImmediate(resolve));
    if (outcome === 'missing') controller.worktreesState.report.repos[0].worktrees.shift();
    finish(outcome === 'removed' ? removed(WT, 'feat/a', 1024)
      : outcome === 'changed' ? replyWith({ error: 'not removable', state: 'keep', reasons: ['new local files'] }, 409)
      : reply('permission denied', false));
    await removing;
    assert.equal(controller.worktreesState.selected.has(WT), false, outcome);
    const row = controller.worktreesState.report.repos[0].worktrees.find(w => w.path === WT);
    if (outcome === 'changed') assert.deepEqual(plain([row.state, row.reasons]), ['keep', ['new local files']]);
    else assert.equal(row, undefined, outcome);
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
    if (url === '/worktrees/remove') return removed(body.path);
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
    { url: '/worktrees/remove', method: 'POST', body: { path: WT } },
    { url: '/worktrees/review-trash', method: 'POST', body: { path: `${REPO}/keep`, head: 'ccc', reasons: ['unmerged commits'] } },
    { url: '/worktrees/review-trash', method: 'POST', body: { path: `${REPO}/review`, head: 'bbb', reasons: ['1 untracked file'] } },
    { url: '/worktrees/remove', method: 'POST', body: { path: '/code/lib/other' } }
  ]);
  assert.deepEqual([...controller.worktreesState.selected.keys()], [`${REPO}/keep`]);
  const failure = log.toasts.find(t => t.message.includes('permission denied')).message;
  assert.match(failure, new RegExp(`${REPO}/keep`));
  assert.match(failure, /Press Rescan if its facts may have changed/);
  const shown = controller.worktreesState.report.repos.flatMap(r => r.worktrees.map(w => w.path));
  assert.deepEqual(shown, [`${REPO}/keep`]);
  assert.match(document.getElementById('removal-toast').innerHTML, /Removed 2 of 2 worktrees/);
  assert.equal(log.ledger, 1);
  assert.equal(log.requests.filter(r => r.method === 'GET').length, 1, 'no report read after the batch');
});

test('bulk confirmation cannot promote routes or include new selections, and revalidates before each request', async () => {
  const rep = selectionReport();
  let controller;
  const built = build({ respond: (url, req) => {
    if (url === '/worktrees') return reply(rep);
    rep.repos[0].worktrees[1].head = 'changed-during-first-request';
    return removed(JSON.parse(req.body).path);
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

test('removeWorktree: confirms, sends one removal with the removal deadline, shows it removing until the reply, then drops the row', async () => {
  let finish;
  let timeout;
  const { controller, log, document, ctx } = build({ respond: (url, req) => {
    if (url === '/worktrees') return reply(worktreeReport());
    timeout = req.timeoutMs;
    return new Promise(resolve => { finish = resolve; });
  } });
  await controller.loadWorktrees(false);
  log.requests.length = 0;
  const removing = controller.removeWorktree(WT, 'feat/a');
  for (let i = 0; i < 20 && !finish; i++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(log.confirms[0].message, `git deletes ${WT} and its ignored files. Branch feat/a and its commits stay.`);
  assert.deepEqual(plain(log.confirms[0].opts), { title: 'Remove worktree', okLabel: 'Remove' });
  assert.deepEqual(plain(log.requests), [{ url: '/worktrees/remove', method: 'POST', body: { path: WT } }]);
  assert.equal(timeout, vm.runInContext('WORKTREE_TIMEOUT_MS', ctx) + 10 * 60 * 1000);
  assert.equal(controller.worktreesState.report.removals[WT].state, 'running');
  const toast = document.getElementById('removal-toast');
  assert.match(toast.innerHTML, /Removing feat\/a/);
  assert.match(toast.className, /info/);
  assert.ok(log.hostShown >= 1);
  finish(removed(WT, 'feat/a', 1000));
  await removing;
  assert.equal(controller.worktreesState.report.repos[0].worktrees.some(w => w.path === WT), false);
  assert.equal(controller.worktreesState.report.removals[WT].state, 'removed');
  assert.match(document.getElementById('removal-toast').innerHTML, /Removed feat\/a/);
  assert.equal(log.ledger, 1);
});

test('removeWorktree: a declined dialog sends nothing; a refused removal keeps the row and shows the daemon text', async () => {
  const declined = build({ confirmed: false });
  await declined.controller.removeWorktree(WT, '');
  assert.match(declined.log.confirms[0].message, /Its commits stay reachable from other refs\./);
  assert.deepEqual(declined.log.requests, []);

  const { controller, log, document } = build({ respond: url => (url === '/worktrees' ? reply(worktreeReport()) : reply('worktree is dirty now', false)) });
  await controller.loadWorktrees(false);
  await controller.removeWorktree(WT, 'feat/a');
  assert.deepEqual(plain(log.toasts), []);
  assert.equal(controller.worktreesState.report.repos[0].worktrees[0].path, WT);
  assert.deepEqual(plain([controller.worktreesState.report.removals[WT].state, controller.worktreesState.report.removals[WT].error]), ['failed', 'worktree is dirty now']);
  const toast = document.getElementById('removal-toast');
  assert.match(toast.innerHTML, /Not removed: feat\/a/);
  assert.match(toast.innerHTML, /worktree is dirty now/);
  assert.match(toast.className, /danger/);
});

test('removeAllWorktrees: counts the removable rows in the dialog and sends one removal per row in order; one refusal does not stop the rest', async () => {
  const other = `${REPO}/.worktrees/b`;
  const { controller, log, document } = build({
    respond: (url, req) => {
      if (url === '/worktrees') return reply(worktreeReport());
      const { path: p } = JSON.parse(req.body);
      return p === WT ? reply('busy', false) : removed(p, 'feat/b', 2000);
    }
  });
  await controller.loadWorktrees(false);
  log.requests.length = 0;
  await controller.removeAllWorktrees(REPO);
  assert.equal(log.confirms[0].message,
    `git deletes 2 worktrees of ${REPO} (3 KB) and their ignored files. Their branches and commits stay; each is checked again before it goes.`);
  assert.deepEqual(plain(log.confirms[0].opts), { title: 'Remove all', okLabel: 'Remove 2' });
  assert.deepEqual(plain(log.requests.map(r => r.body)), [{ path: WT }, { path: other }]);
  const rep = controller.worktreesState.report;
  assert.deepEqual(rep.repos[0].worktrees.map(w => w.path), [WT, `${REPO}/.worktrees/c`]);
  assert.deepEqual(plain([rep.removals[WT].state, rep.removals[WT].error, rep.removals[other].state]), ['failed', 'busy', 'removed']);
  const toast = document.getElementById('removal-toast').innerHTML;
  assert.match(toast, /Removed 1 of 2 worktrees/);
  assert.match(toast, /busy/);
});

test('removeAllWorktrees: a repository with nothing removable asks nothing', async () => {
  const { controller, log } = build({ respond: () => reply(worktreeReport()) });
  await controller.loadWorktrees(false);
  await controller.removeAllWorktrees('/code/other');
  assert.deepEqual(log.confirms, []);
  assert.equal(log.requests.length, 1);
});

test('removeAllRemovable: one dialog counts rows per repository, then one removal per row', async () => {
  const { controller, log } = build({ respond: (url, req) => (url === '/worktrees' ? reply(worktreeReport()) : removed(JSON.parse(req.body).path)) });
  await controller.loadWorktrees(false);
  await controller.removeAllRemovable();
  assert.match(log.confirms[0].message, new RegExp(`${REPO} \\(2\\)`));
  assert.equal(log.confirms[0].opts.okLabel, 'Remove 2');
  assert.equal(log.requests.filter(r => r.url === '/worktrees/remove').length, 2);
});

test('removeClutter: confirms permanent deletion and blocks duplicate requests while pending', async () => {
  let complete;
  let timeout;
  let started;
  const requestStarted = new Promise(resolve => { started = resolve; });
  const clutter = { items: [{ path: '/c/cache', can_remove: true }] };
  const { controller, log } = build({ respond: (url, req) => {
    if (url === '/cleanup') return reply(clutter);
    timeout = req.timeoutMs;
    return new Promise(resolve => { complete = () => resolve(reply({ result: { bytes: 2048 } })); started(); });
  } });
  await controller.loadClutter(false);
  const deletion = controller.removeClutter('/c/cache');
  await requestStarted;
  assert.equal(controller.clutterState.removing.has('/c/cache'), true);
  await controller.removeClutter('/c/cache');
  await controller.trashClutter('/c/cache');
  assert.equal(log.requests.filter(r => r.method === 'POST').length, 1);
  assert.match(log.confirms[0].message, /Permanently delete.*cannot be undone/);
  assert.ok(timeout >= 600000);
  complete();
  await deletion;
  assert.equal(controller.clutterState.removing.has('/c/cache'), false);
  assert.deepEqual(plain(controller.clutterState.report.items), []);
  assert.equal(log.ledger, 1);
  assert.match(log.toasts[0].message, /2 KB cleared/);
});

test('removeClutter: scratch items never offer permanent deletion', async () => {
  const { controller, log } = build({ respond: () => reply({ items: [{ path: '/c/.tmp', action: 'trash' }] }) });
  await controller.loadClutter(false);
  await controller.removeClutter('/c/.tmp');
  assert.equal(log.confirms.length, 0);
  assert.equal(log.requests.filter(r => r.method === 'POST').length, 0);
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

test('activate loads only what is stale for the view it was given; a loaded worktree report is read again only on request', async () => {
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
  assert.deepEqual(log.requests.map(r => r.url), ['/cleanup', '/worktrees']);
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

test('the removal toast adopts removals a report lists as running without a timer, finishes with a ledger reload on Reload, and closes on request', async () => {
  const running = worktreeReport();
  running.removals = { [WT]: { path: WT, state: 'running', phase: 'deleting', step: 'deleting' } };
  const done = worktreeReport();
  done.removals = { [WT]: { path: WT, state: 'removed', bytes: 1000 } };
  let report = running;
  const { controller, log, document, timers } = build({ respond: () => reply(report), shown: { worktrees: true } });
  await controller.loadWorktrees(false);
  assert.match(document.getElementById('removal-toast').innerHTML, /Removing feat\/a/);
  assert.match(document.getElementById('removal-toast').innerHTML, /Reload shows the outcome/);
  assert.equal(log.ledger, 0);
  assert.deepEqual(timers, []);

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
  const { controller, log, document, timers } = build({ respond: url => (url === '/worktrees' ? reply(failed) : reply('locked', false)) });
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

test('a report with pending work schedules no timer that reads /worktrees', async () => {
  const pending = [{ sizing: true }, { refreshing: true }, { asks: { [WT]: { status: 'running', harness: 'codex' } } },
    { removals: { [WT]: { path: WT, state: 'running', phase: 'deleting', step: 'deleting' } } }];
  for (const extra of pending) {
    const { controller, log, timers } = build({ respond: () => reply({ ...worktreeReport(), ...extra }), shown: { worktrees: true } });
    await controller.loadWorktrees(false);
    controller.activate('worktrees');
    for (let i = 0; i < 5 && timers.length; i++) {
      for (const t of timers.splice(0)) t.fn();
      await settle();
    }
    assert.equal(log.requests.filter(r => r.url.startsWith('/worktrees')).length, 1, JSON.stringify(extra));
  }
});

test('opening the worktrees view twice more than a minute apart reads the report once', async () => {
  const { controller, log, clock } = build({ respond: () => reply(worktreeReport()) });
  controller.activate('worktrees');
  await settle();
  clock.at += 60001;
  controller.activate('worktrees');
  await settle();
  assert.deepEqual(log.requests.map(r => r.url), ['/worktrees']);
});

test('Remove sends one request without async; the row is removing until the reply, then gone or back with the reason', async () => {
  let finish;
  const { controller, log, document, ctx } = build({ respond: url => (url === '/worktrees' ? reply(worktreeReport()) : new Promise(resolve => { finish = resolve; })) });
  await controller.loadWorktrees(false);
  const removing = controller.removeWorktree(WT, 'feat/a');
  await settle();
  assert.deepEqual(plain(log.requests.filter(r => r.method === 'POST')), [{ url: '/worktrees/remove', method: 'POST', body: { path: WT } }]);
  assert.match(ctx.worktreeRemovalHTML(controller.worktreesState.report.removals[WT]), /Removing…/);
  assert.match(document.getElementById('removal-toast').innerHTML, /Removing feat\/a/);
  finish(reply({ status: 'ok', removed: WT, branch: 'feat/a', reasons: ['merged into origin/main'], bytes: 1024, bytes_partial: false }));
  await removing;
  const rep = controller.worktreesState.report;
  assert.equal(rep.repos[0].worktrees.some(w => w.path === WT), false);
  assert.deepEqual(plain(rep.summary), { worktrees: 2, size_bytes: 2000, removable_bytes: 2000 });
  assert.match(document.getElementById('removal-toast').innerHTML, /Removed feat\/a/);
  assert.match(document.getElementById('removal-toast').innerHTML, /1 KB reclaimed/);
  assert.equal(log.ledger, 1);
  assert.equal(log.requests.filter(r => r.method === 'GET').length, 1, 'no report read after the removal');

  const refused = build({ respond: url => (url === '/worktrees' ? reply(worktreeReport())
    : replyWith({ error: 'not removable', state: 'keep', reasons: ['2 uncommitted changes'] }, 409)) });
  await refused.controller.loadWorktrees(false);
  await refused.controller.removeWorktree(WT, 'feat/a');
  const row = refused.controller.worktreesState.report.repos[0].worktrees.find(w => w.path === WT);
  assert.equal(row.state, 'keep');
  assert.deepEqual(plain(row.reasons), ['2 uncommitted changes']);
  assert.match(refused.ctx.worktreeRemovalHTML(refused.controller.worktreesState.report.removals[WT]), /Not removed/);
  assert.match(refused.document.getElementById('removal-toast').innerHTML, /2 uncommitted changes/);
  assert.equal(refused.log.requests.filter(r => r.method === 'GET').length, 1);
});

test('Remove is sent while a report read is pending, and reports landing during or after it keep the removal', async () => {
  let reads = 0;
  const held = [];
  let finish;
  const { controller, log, clock } = build({ respond: url => {
    if (url.startsWith('/worktrees?') || url === '/worktrees') return reads++ === 0 ? reply(worktreeReport()) : new Promise(resolve => held.push(resolve));
    return new Promise(resolve => { finish = resolve; });
  } });
  await controller.loadWorktrees(false);
  const reading = controller.loadWorktrees(false);
  const removing = controller.removeWorktree(WT, 'feat/a');
  await settle();
  assert.equal(log.requests.filter(r => r.method === 'POST').length, 1, 'sent while the read is pending');
  held.shift()(reply({ ...worktreeReport(), generated_at: new Date(clock.at - 5000).toISOString() }));
  await reading;
  assert.equal(controller.worktreesState.report.removals[WT].state, 'running');
  clock.at += 1000;
  finish(reply({ status: 'ok', removed: WT, branch: 'feat/a', reasons: [], bytes: 1000 }));
  await removing;
  const late = controller.loadWorktrees(true);
  await settle();
  held.shift()(reply({ ...worktreeReport(), generated_at: new Date(clock.at - 2000).toISOString() }));
  await late;
  assert.equal(controller.worktreesState.report.repos[0].worktrees.some(w => w.path === WT), false);
  assert.equal(controller.worktreesState.report.removals[WT].state, 'removed');
});

test('a batch sends its removals one after another in the confirmed order and applies each reply', async () => {
  const rep = worktreeReport();
  rep.repos[0].worktrees[2].state = 'remove';
  const finishes = [];
  const { controller, log } = build({ respond: url => (url === '/worktrees' ? reply(rep) : new Promise(resolve => finishes.push(resolve))) });
  await controller.loadWorktrees(false);
  const removing = controller.removeAllWorktrees(REPO);
  const posts = () => log.requests.filter(r => r.method === 'POST').map(r => r.body.path);
  for (let i = 0; i < 3; i++) {
    await settle();
    assert.equal(posts().length, i + 1, `request ${i + 1} waits for the reply before it`);
    finishes[i](i === 1 ? reply('git failed', false) : reply({ status: 'ok', removed: posts()[i], bytes: 100 }));
  }
  await removing;
  assert.deepEqual(posts(), [WT, `${REPO}/.worktrees/b`, `${REPO}/.worktrees/c`]);
  assert.deepEqual(controller.worktreesState.report.repos[0].worktrees.map(w => w.path), [`${REPO}/.worktrees/b`]);
  assert.equal(controller.worktreesState.report.removals[`${REPO}/.worktrees/b`].error, 'git failed');
});

test('Reload reads the report without refresh and Rescan with refresh=1; the summary names which runs', async () => {
  const held = [];
  const { controller, log, ctx } = build({ respond: () => new Promise(resolve => held.push(resolve)) });
  const reload = controller.loadWorktrees(false);
  assert.equal(ctx.worktreesReadingText(controller.worktreesState), ' · reloading…');
  held.shift()(reply(worktreeReport()));
  await reload;
  assert.equal(ctx.worktreesReadingText(controller.worktreesState), '');
  const rescan = controller.loadWorktrees(true);
  assert.equal(ctx.worktreesReadingText(controller.worktreesState), ' · rescanning…');
  held.shift()(reply(worktreeReport()));
  await rescan;
  assert.deepEqual(log.requests.map(r => r.url), ['/worktrees', '/worktrees?refresh=1']);
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
