// Session Hooks view: one session with failed, injecting and unrecorded
// blocking hooks, a second with none, and the probe the case checks.
(() => {
  const { iso, openTab, route, ready, wait, idle, scenarios } = window.DomTest;
  const requested = [];
  const hooks = {
    'sess-claude-1': [
      { event: 'PreToolUse', script: 'secret_guard.py', runs: 42, errors: 42, blocks: 0, chars: 0, total_ms: 1260, last_at: iso(0) },
      { event: 'UserPromptSubmit', script: 'prompt-hook.sh', runs: 5, errors: 0, blocks: 0, chars: 4500, total_ms: 80, last_at: iso(0) },
      { event: 'PreToolUse', script: '', runs: 1, errors: 0, blocks: 1, chars: 120, total_ms: 0, last_at: iso(0) },
      { event: 'Stop', script: 'cancelled.py', runs: 2, errors: 0, cancelled: 2, blocks: 0, chars: 0, total_ms: 0, duration_samples: 0, char_samples: 0, last_at: iso(0) },
    ],
    'sess-cursor-2': [],
  };
  let unavailable = false;
  let recovered = false;
  const finding = { id: 'hook:handler-1', kind: 'execution-errors', harness: 'codex', event: 'PreToolUse', handler_id: 'handler-1', config_id: 'revision-1', script: 'secret_guard.py', title: 'Hook repeatedly failed', detail: 'Three consecutive observed execution errors.', next_action: 'Repair the unavailable dependency, then retry.', limits: ["The associated action's outcome is unknown."], count: 3, first_at: iso(3000), last_at: iso(1000), needs_action: true };
  for (const id of Object.keys(hooks)) route('/sessions/' + id + '/overview', () => ({
    ok: true, status: 200, json: async () => ({ session_id: id, observed_at: iso(0), requests: [], findings: [], coverage: null, resources: null,
      hook_health: unavailable ? { available: false, findings: [] } : { available: true, since: iso(1800000), until: iso(0), observed_runs: 50, unattributed_runs: 1, truncated: false, findings: recovered || id !== 'sess-claude-1' ? [] : [finding] } }),
  }));
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
      await wait(() => !!window.SA.sessionOverview?.hook_health);
      const detail = document.querySelector('#session-detail');
      const rows = [...detail.querySelectorAll('table.sd-hooks tbody tr')];
      probe.table = rows.length === 4 && rows[0].textContent.includes('secret_guard.py');
      probe.failedRow = rows[0].classList.contains('sd-hook-failed') && !rows[1].classList.contains('sd-hook-failed');
      probe.unrecorded = rows[2].textContent.includes('not recorded');
      probe.cancelled = !rows[3].classList.contains('sd-hook-failed') && rows[3].textContent.includes('unknown') && detail.textContent.includes('Cancelled');
      probe.actionable = detail.textContent.includes('Repair the unavailable dependency') && detail.textContent.includes("action's outcome is unknown") && detail.textContent.includes('Handler: handler-1');
      probe.startsAtFindings = detail.querySelector('.session-detail-body').scrollTop === 0;
      probe.fits = detail.scrollWidth <= detail.clientWidth && document.documentElement.scrollWidth <= innerWidth;
      if (scenarios.has('shot')) { document.body.dataset.hooksProbe = JSON.stringify(probe); return; }
      unavailable = true;
      window.SA.refreshSessionOverview(true);
      await wait(() => window.SA.sessionOverview?.hook_health?.available === false); await idle();
      probe.unavailable = detail.textContent.includes('Hook assessment unavailable') && !detail.textContent.includes('No repair or advisory');
      unavailable = false; recovered = true;
      window.SA.refreshSessionOverview(true);
      await wait(() => window.SA.sessionOverview?.hook_health?.available === true); await idle();
      probe.recovery = detail.textContent.includes('No repair or advisory pattern') && !detail.textContent.includes('Needs repair');
      // Selecting another session while Hooks is open loads that session's hooks.
      await window.selectSession('sess-cursor-2');
      probe.reloaded = window.SA.sessionView === 'hooks' && requested.includes('sess-cursor-2')
        && document.querySelector('#session-detail').textContent.includes('No hook runs recorded');
    } catch (error) { probe.error = error.message; }
    document.body.dataset.hooksProbe = JSON.stringify(probe);
  });
})();
