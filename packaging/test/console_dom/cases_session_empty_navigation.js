// Empty session navigation interactions.
(() => {
  const { data, iso, openTab, realFetch: readingFetch } = window.DomTest;
  setTimeout(() => openTab('sessions'), 1500);
  setTimeout(() => {
    window.SA.harnessFilter.harnesses = {claude: false};
    const input = document.getElementById('session-cwd-filter');
    input.value = 'missing-project'; input.dispatchEvent(new Event('input', {bubbles: true}));
  }, 2500);
  setTimeout(async () => {
    const receipt = {};
    const checkpoint = () => readingFetch('/__console_frame_checkpoint', {cache: 'no-store'});
    const detail = document.getElementById('session-detail');
    const panel = document.getElementById('session-board-panel');
    const input = document.getElementById('session-cwd-filter');
    const narrow = window.matchMedia('(max-width: 900px)').matches;
    const backs = () => [...detail.querySelectorAll('[data-action="session-list"]')].filter(node => node.getClientRects().length);
    try {
      await checkpoint();
      const before = sessionStorage.getItem('sa.harness-filter'), selection = window.SA.selectedSessionId, hash = location.hash;
      receipt.missingBack = backs().length === (narrow ? 1 : 0) && (!narrow || backs()[0].getBoundingClientRect().height >= 44);
      receipt.copy = detail.textContent.includes('No live sessions match these filters.') && !!detail.querySelector('[data-action="clear-harness-filter"]');
      if (narrow) backs()[0].click(); else window.showSessionList();
      receipt.searchFocus = document.activeElement === input && !!input.getClientRects().length && panel.dataset.pane === 'list';
      receipt.preserved = input.value === 'missing-project' && window.SA.harnessFilter.harnesses.claude === false && window.SA.harnessFilter.liveOnly
        && sessionStorage.getItem('sa.harness-filter') === before && window.SA.selectedSessionId === selection && location.hash === hash;
      // A retained selection disappearing keeps the existing unavailable route.
      input.value = ''; input.dispatchEvent(new Event('input', {bubbles: true}));
      await window.selectSession('sess-codex-3');
      window.SA.t.sessions = [];
      window.SA.renderSessionBoard(); await checkpoint();
      receipt.unavailable = detail.textContent.includes('Session unavailable.') && backs().length === 1 && (!narrow || backs()[0].getBoundingClientRect().height >= 44);
      window.SA.harnessFilter.harnesses = {};
      const live = document.getElementById('session-live-only');
      live.checked = false; live.dispatchEvent(new Event('change', {bubbles: true}));
      await checkpoint();
      receipt.noData = detail.textContent.includes('No sessions available.') && backs().length === (narrow ? 1 : 0);
      if (narrow) backs()[0].click(); else window.showSessionList();
      receipt.noDataFocus = document.activeElement === input && panel.dataset.pane === 'list';
      receipt.bounds = document.documentElement.scrollWidth <= document.documentElement.clientWidth;
    } catch (error) { receipt.error = error.message; }
    document.body.dataset.sessionEmptyNavigation = JSON.stringify(receipt);
  }, 3500);
})();
