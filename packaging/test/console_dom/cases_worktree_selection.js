// Exercise selection, filtering, cancellation and mixed removal with fixture data.
(() => {
  const { scenarios, iso, openTab, wait, idle, ready } = window.DomTest;
  const mode = ['selection', 'review', 'execute', 'failure', 'asyncfailure'].find(value => scenarios.has(`worktreeselection=${value}`));
  const repo = '/synthetic/project-with-a-complete-repository-name';
  const other = '/synthetic/second-project-with-a-complete-repository-name';
  const review = `${repo}/.worktrees/reviewed-temporary-files`;
  const safe = `${repo}/.worktrees/merged`;
  const live = `${repo}/.worktrees/live`;
  const selectedSafe = `${other}/.worktrees/merged-branch`;
  const reasons = ['ignored files that only live here: .tmp/ (3 files, 1 MB)', 'merged into origin/main (squash)'];
  const row = (path, state, extra = {}) => ({
    path, state, head: 'a'.repeat(40), branch: `feat/${path.split('/').pop()}`,
    idle_days: 20, reasons: ['merged into origin/main (squash)'], size_bytes: 1048576, ...extra,
  });
  const report = {
    generated_at: iso(1000), duration_ms: 10, stale_days: 14,
    repos: [
      { path: repo, default_branch: 'origin/main', worktrees: [
        row(review, 'review', { reasons }), row(safe, 'remove'),
        row(live, 'keep', { in_use: true, active_agent: 'codex', reasons: ['codex is working here'] }),
      ] },
      { path: other, default_branch: 'origin/main', worktrees: [row(selectedSafe, 'remove', { size_partial: true })] },
    ],
    summary: { repos: 2, worktrees: 4, remove: 2, review: 1, keep: 1, size_bytes: 4194304 },
    advice: { [review]: { assessment: 'remove', confidence: 0.92, rationale: 'Merged; remaining local files are temporary.' } },
    removals: {},
  };
  const writes = [];
  const originalFetch = window.fetch;
  const response = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  window.fetch = async (url, options = {}) => {
    const path = String(url).split('?')[0];
    if (path === '/worktrees') return response(structuredClone(report));
    if (path === '/worktrees/remove' || path === '/worktrees/review-trash') {
      const body = JSON.parse(options.body);
      writes.push({ path, body });
      if (path === '/worktrees/review-trash' && mode === 'failure') return new Response('worktree changed since review; refresh and inspect it again', { status: 409 });
      if (path === '/worktrees/remove') {
        const running = { path: body.path, state: 'running', phase: 'checking', step: 'checking it is still safe to remove' };
        report.removals[body.path] = mode === 'asyncfailure'
          ? { path: body.path, state: 'failed', error: 'synthetic removal failure' } : running;
        return response({ removal: running }, 202);
      }
      for (const project of report.repos) project.worktrees = project.worktrees.filter(item => item.path !== body.path);
      return response({ result: { path: body.path, trash_path: '/synthetic/Trash/reviewed-temporary-files', bytes: 1048576 } });
    }
    return originalFetch(url, options);
  };

  ready().then(async () => {
    const probe = {};
    try {
      openTab('worktrees');
      await wait(() => document.querySelector('[data-action="worktree-select"]'));
      await idle();
      const marked = () => window.SA.worktrees.selected;
      const select = path => Array.from(document.querySelectorAll('[data-action="worktree-select"]')).find(button => button.dataset.path === path);
      const bar = () => document.querySelector('.wt-selection');
      const remove = () => document.querySelector('[data-action="worktrees-remove-selected"]');
      const toggle = path => { const button = select(path); button.focus(); button.click(); };
      const search = document.getElementById('worktree-search');
      const setSearch = value => { search.value = value; search.dispatchEvent(new Event('input', { bubbles: true })); };
      probe.blocked = !select(live) || select(live).disabled && select(live).title.includes('working here');
      toggle(review);
      await idle();
      probe.marked = marked().has(review) && select(review).getAttribute('aria-pressed') === 'true';
      probe.keyboardFocus = document.activeElement === select(review);
      const advisor = document.querySelector('.wt-advice');
      probe.marked = probe.marked && advisor.textContent.includes('92%') && !!advisor.querySelector('[data-action="worktree-select"]');
      toggle(selectedSafe);
      await idle();
      probe.crossRepo = marked().size === 2 && marked().has(review) && marked().has(selectedSafe);
      setSearch('reviewed-temporary-files');
      await idle();
      probe.filterRetains = marked().size === 2 && !!remove() && !select(selectedSafe);
      document.querySelector('[data-action="worktrees-clear-selection"]').click();
      await idle();
      probe.clear = marked().size === 0;
      document.querySelector('[data-action="worktrees-select-visible"]').click();
      await idle();
      probe.selectVisible = marked().size === 1 && marked().has(review);
      setSearch('');
      await idle();
      toggle(selectedSafe);
      await idle();
      const sizeText = bar().textContent;
      probe.partialSize = /at least|≥|partial|lower bound/i.test(sizeText);
      if (mode === 'selection') {
        bar().scrollIntoView({ block: 'start' });
        probe.fits = document.documentElement.scrollWidth <= innerWidth;
        document.body.dataset.worktreeSelectionProbe = JSON.stringify(probe);
        return;
      }
      remove().click();
      await wait(() => !document.getElementById('confirm-layer').hidden);
      document.getElementById('confirm-cancel').click();
      await idle();
      probe.cancelled = writes.length === 0 && marked().size === 2;
      remove().click();
      await wait(() => !document.getElementById('confirm-layer').hidden);
      const message = document.getElementById('confirm-message').textContent;
      probe.reviewPaths = message.includes(review) && message.includes(selectedSafe) && !message.includes(live);
      probe.reviewActions = /Trash/.test(message) && /delet|git remove|checked removal/i.test(message);
      probe.reviewRisks = message.includes('.tmp/') && /branch|commits/.test(message) && /until.*empt(?:y|ied)|empty.*Trash/.test(message);
      probe.fits = document.documentElement.scrollWidth <= innerWidth;
      const dialog = document.querySelector('#confirm-layer [role="dialog"]') || document.getElementById('confirm-message').parentElement;
      const bounds = dialog.getBoundingClientRect();
      probe.dialogFits = bounds.left >= 0 && bounds.right <= innerWidth + 1 && bounds.top >= 0 && bounds.bottom <= innerHeight + 1;
      if (mode !== 'review') {
        let confirms = 0;
        const confirm = window.saConfirm;
        window.saConfirm = (...args) => { confirms++; return confirm(...args); };
        // A second invocation while the original review is open must be ignored.
        remove().click();
        probe.oneConfirmation = confirms === 0;
        document.getElementById('confirm-ok').click();
        await wait(() => writes.length === 2 && !window.SA.worktrees.selectionBusy);
        await idle();
        probe.routes = writes.length === 2 && writes.some(write => write.path === '/worktrees/remove' && write.body.path === selectedSafe && write.body.async === true)
          && writes.some(write => write.path === '/worktrees/review-trash' && write.body.path === review);
        const trashed = writes.find(write => write.path === '/worktrees/review-trash');
        probe.payload = trashed?.body.head === 'a'.repeat(40) && JSON.stringify(trashed.body.reasons) === JSON.stringify(reasons);
        probe.noReplay = writes.length === 2;
        if (mode === 'failure') {
          probe.failedRetained = marked().size === 1 && marked().has(review) && !marked().has(selectedSafe);
          probe.failureNamed = document.body.textContent.includes('worktree changed since review');
        } else if (mode === 'asyncfailure') {
          probe.failedRetained = marked().size === 1 && marked().has(selectedSafe) && !marked().has(review);
          probe.failureNamed = document.body.textContent.includes('synthetic removal failure');
        } else {
          probe.selectionCleared = marked().size === 0;
          probe.trashedGone = !Array.from(document.querySelectorAll('.wt-row')).some(element => element.dataset.path === review);
        }
      }
    } catch (error) { probe.error = String(error); }
    document.body.dataset.worktreeSelectionProbe = JSON.stringify(probe);
  });
})();
