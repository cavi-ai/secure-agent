// Shared worktree and harness filter interactions.
(() => {
  const { data, openTab, stamp } = window.DomTest;
  for (const row of data['/worktrees'].repos[0].worktrees) {
    if (row.state !== 'main') row.stale = row.state === 'remove' || row.state === 'review';
  }
  setTimeout(() => openTab('system/worktrees'), 1500);
  setTimeout(async () => {
    const receipt = {};
    const settle = () => new Promise(resolve => setTimeout(resolve, 100));
    const wt = state => document.querySelector(`#worktree-pills [data-state="${state}"]`);
    const stale = () => document.querySelector('#worktree-pills [data-action="worktree-stale"]');
    const rows = () => document.querySelectorAll('#worktrees-container .wt-row').length;
    try {
      const total = rows();
      wt('prune').focus(); wt('prune').click(); await settle();
      receipt.state = rows() === 1 && wt('prune').getAttribute('aria-pressed') === 'true';
      receipt.focus = document.activeElement === wt('prune');
      wt('prune').click(); await settle();
      receipt.deselect = rows() === total && wt('').getAttribute('aria-pressed') === 'true';
      stale().click(); await settle();
      receipt.stale = wt('').getAttribute('aria-pressed') === 'false' && rows() === 2;
      wt('prune').click(); await settle();
      receipt.intersection = rows() === 0 && stale().textContent.trim() === 'Stale 0' && wt('prune').textContent.trim() === 'Prune 0';
      wt('').click(); await settle();
      receipt.all = rows() === total && stale().getAttribute('aria-pressed') === 'false';
      const search = document.getElementById('worktree-search');
      search.value = 'no-such-worktree'; search.dispatchEvent(new Event('input', {bubbles:true})); await settle();
      receipt.searchEmpty = document.getElementById('worktrees-container').textContent.includes('No worktree matches this filter.');
      search.value = ''; search.dispatchEvent(new Event('input', {bubbles:true}));
      openTab('sessions/board'); await settle();
      const pill = () => document.querySelector('#session-harness-pills [data-harness="codex"]');
      const all = () => document.querySelector('#session-harness-pills [data-action="all-harnesses"]');
      // Narrow screens open the detail pane, which hides the filters.
      // Return through the visible Back control before testing focus.
      if (!pill().getClientRects().length) {
        document.querySelector('#session-detail [data-action="session-list"]').click();
        await settle();
      }
      receipt.harnessVisible = !!pill().getClientRects().length;
      pill().focus(); pill().click(); await settle();
      receipt.harnessOff = pill().getAttribute('aria-pressed') === 'false' && !document.querySelector('#session-rail [data-harness="codex"]');
      receipt.harnessFocus = document.activeElement === pill();
      pill().click(); await settle();
      receipt.harnessOn = pill().getAttribute('aria-pressed') === 'true' && !!document.querySelector('#session-rail [data-harness="codex"]');
      pill().click(); await settle();
      const q = document.getElementById('session-cwd-filter');
      q.value = 'api'; q.dispatchEvent(new Event('input', {bubbles:true})); await settle();
      all().click(); await settle();
      receipt.harnessAll = all().getAttribute('aria-pressed') === 'true' && q.value === 'api' && document.getElementById('session-live-only').checked;
      openTab('sessions/processes'); await settle();
      receipt.shared = document.querySelector('#agent-harness-pills [data-action="all-harnesses"]').getAttribute('aria-pressed') === 'true';
    } catch (error) { receipt.error = error.message; }
    stamp('filter-regression-probe', JSON.stringify(receipt));
  }, 3000);
})();
