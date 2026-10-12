// Search filter recovery interactions.
(() => {
  const { openTab, realFetch: readingFetch } = window.DomTest;
  setTimeout(() => openTab('sessions'), 1500);
  setTimeout(async () => {
    const receipt = {};
    const checkpoint = () => readingFetch('/__console_frame_checkpoint', {cache: 'no-store'});
    const panel = document.getElementById('session-board-panel');
    const input = document.getElementById('session-cwd-filter');
    const agentInput = document.getElementById('agent-filter-text');
    const live = document.getElementById('session-live-only');
    const narrow = matchMedia('(max-width:900px)').matches;
    const filter = (target, value) => { target.value = value; target.dispatchEvent(new Event('input', {bubbles: true})); };
    const clear = async container => {
      const button = container.querySelector('[data-action="clear-harness-filter"]');
      if (!button?.getClientRects().length) throw new Error('Clear filter must be visible before activation');
      button.focus({preventScroll: true}); button.click(); await checkpoint();
    };
    const reset = expectedLive => {
      const saved = JSON.parse(sessionStorage.getItem('sa.harness-filter'));
      return saved.text === '' && Object.keys(saved.harnesses).length === 0 && saved.liveOnly === expectedLive
        && input.value === '' && agentInput.value === '' && live.checked === expectedLive;
    };
    const searchFocused = target => document.activeElement === target && target.isConnected && !!target.getClientRects().length;
    try {
      window.SA.harnessFilter.harnesses = {claude: false};
      filter(input, 'missing-project'); await checkpoint();
      const origin = document.getElementById(narrow ? 'session-detail' : 'session-rail');
      receipt.origin = origin.textContent.includes('No live sessions match these filters.') && (!narrow || panel.dataset.pane === 'detail');
      await clear(origin);
      receipt.recovery = panel.dataset.pane === 'list' && searchFocused(input);
      receipt.reset = reset(true);
      receipt.results = !!document.querySelector('#session-rail [data-action="select-session"]')?.getClientRects().length;
      filter(input, 'retry-search'); await checkpoint();
      receipt.retry = window.SA.harnessFilter.text === 'retry-search' && searchFocused(input);

      window.SA.t.sessions = [];
      live.checked = false; live.dispatchEvent(new Event('change', {bubbles: true}));
      filter(input, 'missing-project'); await checkpoint();
      await clear(document.getElementById('session-rail'));
      receipt.empty = panel.dataset.pane === 'list' && searchFocused(input) && reset(false)
        && !document.querySelector('#session-rail [data-action="select-session"]') && document.getElementById('session-detail').textContent.includes('No sessions available.');

      openTab('sessions/processes'); await checkpoint();
      window.SA.harnessFilter.harnesses = {claude: false};
      filter(agentInput, 'missing-agent-project'); await checkpoint();
      const pane = panel.dataset.pane, hash = location.hash;
      await clear(document.getElementById('agents-container'));
      receipt.agents = searchFocused(agentInput) && panel.dataset.pane === pane && location.hash === hash && reset(false);
      receipt.agentResults = !!document.querySelector('#agents-container .agent-row');
      receipt.bounds = document.documentElement.scrollWidth <= document.documentElement.clientWidth;
    } catch (error) { receipt.error = error.message; }
    document.body.dataset.sessionSearchRecovery = JSON.stringify(receipt);
  }, 2500);
})();
