// Session Hooks view: one session with failed, injecting and unrecorded
// blocking hooks, a second with none, and the probe the case checks.
(() => {
  const { iso, openTab, route, ready } = window.DomTest;
  const requested = [];
  const hooks = {
    'sess-claude-1': [
      { event: 'PreToolUse', script: 'secret_guard.py', runs: 42, errors: 42, blocks: 0, chars: 0, total_ms: 1260, last_at: iso(0) },
      { event: 'UserPromptSubmit', script: 'prompt-hook.sh', runs: 5, errors: 0, blocks: 0, chars: 4500, total_ms: 80, last_at: iso(0) },
      { event: 'PreToolUse', script: '', runs: 1, errors: 0, blocks: 1, chars: 120, total_ms: 0, last_at: iso(0) },
    ],
    'sess-cursor-2': [],
  };
  for (const [id, rows] of Object.entries(hooks)) {
    route('/sessions/' + id + '/hooks', () => {
      requested.push(id);
      return { ok: true, status: 200, json: async () => structuredClone(rows) };
    });
  }

  ready().then(async () => {
    const probe = {};
    try {
      openTab('sessions');
      await window.selectSession('sess-claude-1');
      await window.setSessionView('hooks');
      const detail = document.querySelector('#session-detail');
      const rows = [...detail.querySelectorAll('table.sd-hooks tbody tr')];
      probe.table = rows.length === 3 && rows[0].textContent.includes('secret_guard.py');
      probe.failedRow = rows[0].classList.contains('sd-hook-failed') && !rows[1].classList.contains('sd-hook-failed');
      probe.unrecorded = rows[2].textContent.includes('not recorded');
      probe.fits = detail.scrollWidth <= detail.clientWidth && document.documentElement.scrollWidth <= innerWidth;
      // Selecting another session while Hooks is open loads that session's hooks.
      await window.selectSession('sess-cursor-2');
      probe.reloaded = window.SA.sessionView === 'hooks' && requested.includes('sess-cursor-2')
        && document.querySelector('#session-detail').textContent.includes('No hook runs recorded');
    } catch (error) { probe.error = error.message; }
    document.body.dataset.hooksProbe = JSON.stringify(probe);
  });
})();
