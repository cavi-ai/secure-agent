(() => {
  const { data, ready, route, wait } = window.DomTest;
  const plan = data['/advisor/plan'];
  const instruction = { ready: true, path: '/fixture/AGENTS.md',
    instruction: 'Reference credentials by variable name.', revision: 'a'.repeat(64) };
  const fresh = { ...instruction, revision: 'b'.repeat(64) };
  const probe = {};
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status });
  let expired = false, reconnecting = false, finishRead, applied;
  route('/snapshot', () => expired ? json({ error: 'console token required' }, 403) : undefined);
  route('/advisor/plan', async () => {
    if (!reconnecting) return json({ ...plan, instruction });
    if (!applied) await new Promise(resolve => { finishRead = resolve; });
    return json({ ...plan, instruction: applied ? { ...fresh, applied: true } : fresh });
  });
  route('/agent/instructions', ({ method, body }) => {
    applied = method === 'POST' ? JSON.parse(body) : null;
    return json({ ...fresh, applied: true });
  });

  ready().then(async () => {
    const drawer = document.getElementById('drawer');
    const button = () => drawer.querySelector('[data-action="apply-agent-instruction"]');
    window.openPlanDrawer(plan.subject);
    probe.initial = await wait(() => button()?.dataset.revision === instruction.revision);
    expired = true;
    document.getElementById('btn-refresh').click();
    probe.paused = await wait(() => drawer.inert && document.body.classList.contains('is-paused'));
    expired = false;
    reconnecting = true;
    location.hash = 'ct=replacement-token';
    probe.resumed = await wait(() => !drawer.hidden && !drawer.inert
      && document.getElementById('session-ended').hidden);
    probe.refreshed = await wait(() => !!finishRead);
    probe.staleHidden = !button() || drawer.inert;
    finishRead?.();
    if (await wait(() => !drawer.inert && button()?.dataset.revision === fresh.revision)) {
      button().click();
      probe.applied = await wait(() => applied?.subject === plan.subject && applied.revision === fresh.revision
        && drawer.textContent.includes('Already applied'));
    }
    document.body.dataset.playbookReconnect = JSON.stringify(probe);
  });
})();
