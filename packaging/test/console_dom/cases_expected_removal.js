// Expected exception removal: two exceptions, the removal route with its
// uncertain, failed-read and invalid answers, and the probe the case checks.
(() => {
  const { data, scenarios, iso, openTab, route, wait, idle, ready } = window.DomTest;
  data['/expected'] = [
    { key: 'claude|gh|/synthetic/credentials|example.test', agent: 'claude', reader: 'gh', path: '/synthetic/credentials', dest: 'example.test', created_at: iso(60000), hits: 2 },
    { key: 'claude|*|/synthetic/.env.test|*', scope: 'file', agent: 'claude', reader: '*', path: '/synthetic/.env.test', dest: '*', created_at: iso(60000), hits: 0 },
  ];
  let deletes = 0;
  route('/expected', ({ method, query }) => {
    if (method === 'DELETE') {
      const key = query.get('key');
      if (!data['/expected'].some(row => row.key === key)) throw new Error('Wrong exception target');
      deletes++;
      data['/expected'] = data['/expected'].filter(row => row.key !== key);
      return { ok: true, json: async () => ({ status: 'ok', key: scenarios.has('removaluncertain') ? 'wrong-key' : key }) };
    }
    if (scenarios.has('removalreadfail') && deletes) return { ok: false, status: 503, text: async () => 'Unavailable' };
    return { ok: true, json: async () => scenarios.has('removalinvalid') ? null : structuredClone(data['/expected']) };
  });

  ready().then(async () => {
    const probe = {};
    try {
      openTab('policy');
      const list = document.getElementById('policy-expected');
      await wait(() => list.textContent.includes('Remove exception') || list.textContent.includes('The daemon returned invalid records.'));
      await idle();
      if (scenarios.has('removalinvalid')) {
        probe.unavailable = list.textContent.includes('The daemon returned invalid records.') && !list.querySelector('[data-action="forget-expected"]');
        probe.noWrite = !deletes;
      } else {
        const file = scenarios.has('expectedremove=file');
        const key = file ? 'claude|*|/synthetic/.env.test|*' : 'claude|gh|/synthetic/credentials|example.test';
        const removeButtons = () => Array.from(list.querySelectorAll('[data-action="forget-expected"]'));
        const button = removeButtons().find(el => el.dataset.key === key);
        probe.label = button.textContent === 'Remove exception' && button.getAttribute('aria-label').includes(file ? '/synthetic/.env.test' : '/synthetic/credentials');
        probe.target = button.getBoundingClientRect().height >= 44;
        button.focus(); button.click();
        const message = document.getElementById('confirm-message').textContent;
        probe.scope = file ? message.includes('all readers and destinations for this agent and file') : message.includes('gh reads /synthetic/credentials, then reaches example.test');
        probe.consequence = message.includes('remaining exceptions and policies') && message.includes('Past activity and exposure are unchanged');
        document.getElementById('confirm-cancel').click();
        await wait(() => document.activeElement === button);
        probe.cancelled = !deletes && document.activeElement === button && button.isConnected;
        button.click(); document.getElementById('confirm-ok').click();
        await wait(() => list.textContent.includes('Exception removal saved') || list.textContent.includes('Removal not confirmed'));
        probe.oneWrite = deletes === 1;
        if (scenarios.has('removaluncertain')) {
          probe.uncertain = list.textContent.includes('Removal not confirmed') && !removeButtons().some(el => el.dataset.key === key);
          await window.forgetExpected(key);
          probe.noReplay = deletes === 1;
          list.querySelector('[data-action="policy-refresh"]').click();
          probe.refreshed = await wait(() => !list.textContent.includes('Removal not confirmed'));
          probe.authoritative = !list.textContent.includes(file ? 'Non-secret file' : 'reads');
        } else {
          probe.saved = list.textContent.includes('Exception removal saved') && !removeButtons().some(el => el.dataset.key === key);
          probe.remaining = document.getElementById('badge-expected').textContent === '1';
          probe.feedback = list.textContent.includes('Remaining exceptions and policies still apply; past activity is unchanged');
          if (scenarios.has('removalreadfail')) probe.retained = list.textContent.includes('current status is unavailable') && !list.querySelector('[data-action="forget-expected"]');
        }
      }
      probe.fits = document.documentElement.scrollWidth <= innerWidth;
    } catch (error) { probe.error = String(error); }
    document.body.dataset.expectedRemovalProbe = JSON.stringify(probe);
  });
})();
