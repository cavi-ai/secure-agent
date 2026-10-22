(() => {
  const {data, ready, idle, wait, openTab, iso} = window.DomTest;
  const params = new URLSearchParams(location.search);
  const width = Number(window.frameElement?.width || params.get('layoutwidth'));
  // An iframe exercises exact CSS viewport widths below Chrome's minimum window size.
  if (window.parent === window && !params.has('layoutchild')) {
    const frame = document.createElement('iframe');
    frame.width = String(width);
    frame.height = '900';
    frame.frameBorder = '0';
    frame.src = `harness.html?worktreelayout&layoutchild&layoutwidth=${width}`;
    window.addEventListener('message', event => {
      if (event.source === frame.contentWindow && event.data?.worktreeLayoutProbe) {
        document.body.dataset.worktreeLayoutProbe = JSON.stringify(event.data.worktreeLayoutProbe);
      }
    });
    document.addEventListener('DOMContentLoaded', () => document.body.prepend(frame), {once:true});
    return;
  }
  const repo = '/synthetic/project-with-a-complete-repository-name';
  const rows = Array.from({length:8}, (_, index) => ({
    path: `${repo}/.worktrees/branch-${index}`, branch: `fix/branch-${index}`, state: 'remove',
    head: 'a'.repeat(40), size_bytes: 24 * 1024 * 1024, last_activity: iso(86400000), idle_days: 1,
    reasons: ['merged into origin/main (squash)'], reason_kinds: ['safe'],
  }));
  data['/worktrees'] = {
    generated_at: iso(1000), duration_ms: 10, stale_days: 14,
    repos: [{path:repo, source:'session', default_branch:'origin/main', size_bytes:201326592, worktrees:rows}],
    summary: {repos:1, worktrees:8, remove:8}, advice:{}, asks:{}, removals:{},
  };
  const rect = element => {
    const r = element.getBoundingClientRect();
    return [r.left, r.top, r.width, r.height];
  };
  const same = (before, after) => before.every((value, index) => Math.abs(value - after[index]) < 1);
  ready().then(async () => {
    const probe = {};
    try {
      openTab('worktrees');
      await wait(() => document.querySelector('.wt-repo-options'));
      await idle();
      const container = document.getElementById('worktrees-container');
      const options = container.querySelector('.wt-repo-options');
      const summary = options.querySelector('summary');
      const identity = container.querySelector('.wt-repo-identity');
      const facts = container.querySelector('.wt-repo-facts');
      const before = [rect(identity), rect(facts), rect(summary)];
      summary.click();
      await idle();
      probe.viewport = innerWidth === width;
      probe.geometry = {width, actualWidth:innerWidth, before, after:[rect(identity), rect(facts), rect(summary)]};
      probe.headerStable = probe.geometry.after.every((value, index) => same(before[index], value));
      probe.fits = document.documentElement.scrollWidth <= innerWidth;
      const row = container.querySelector('.wt-row');
      const checkbox = row.querySelector('.wt-select');
      row.querySelector('.wt-main').click();
      await idle();
      row.scrollIntoView({block:'center'});
      await idle();
      checkbox.focus({preventScroll:true});
      const geometry = rect(row);
      const scrollBefore = scrollY;
      checkbox.click();
      // Check synchronously and after a frame: replacement can flash for just one frame.
      probe.selectionNodes = row.isConnected && checkbox.isConnected && options.isConnected;
      probe.selectionOpen = row.open && options.open;
      probe.selectionFocus = document.activeElement === checkbox;
      await idle();
      probe.selectionChecked = checkbox.checked && window.SA.worktrees.selected.has(rows[0].path);
      probe.selectionGeometry = same(geometry, rect(row));
      probe.geometry.selection = {before:geometry, after:rect(row), scrollBefore, scrollAfter:scrollY};
      probe.laneAccent = getComputedStyle(row.querySelector('.wt-main')).boxShadow !== 'none';
      probe.selectionOpen = probe.selectionOpen && row.open && options.open;
      // toggle events are asynchronous: selection immediately after opening must retain it.
      const next = container.querySelectorAll('.wt-row')[1];
      next.querySelector('.wt-main').click();
      next.querySelector('.wt-select').click();
      await idle();
      probe.rapidDisclosure = next.isConnected && next.open && window.SA.worktrees.expanded.has(rows[1].path);
      container.querySelector('[data-action="worktrees-select-visible"]').click();
      await idle();
      probe.bulkSelection = row.isConnected && options.open && row.open
        && container.querySelectorAll('.wt-select:checked').length === rows.length;
      container.querySelector('[data-action="worktrees-clear-selection"]').click();
      await idle();
      probe.clearSelection = row.isConnected && options.open && row.open && !checkbox.checked
        && !window.SA.worktrees.selected.size && !container.querySelector('.wt-select:checked');
      checkbox.closest('label').click();
      await idle();
      probe.labelSelection = row.isConnected && row.open && checkbox.checked
        && window.SA.worktrees.selected.has(rows[0].path);
      // Model a report arriving while focused controls hold a full render.
      const stale = container.querySelectorAll('.wt-row')[2].querySelector('.wt-select');
      window.SA.worktrees.report.repos[0].worktrees[2].in_use = true;
      stale.click();
      probe.rejectedSelection = !stale.checked && !window.SA.worktrees.selected.has(rows[2].path);
      window.SA.worktrees.selectionBusy = true;
      checkbox.click();
      probe.busySelection = checkbox.checked && window.SA.worktrees.selected.has(rows[0].path);
      window.SA.worktrees.selectionBusy = false;
      probe.fits = probe.fits && document.documentElement.scrollWidth <= innerWidth;
    } catch (error) {probe.error = error.message;}
    document.body.dataset.worktreeLayoutProbe = JSON.stringify(probe);
    window.parent.postMessage({worktreeLayoutProbe:probe}, '*');
  });
})();
