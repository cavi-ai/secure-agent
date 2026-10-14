// Session Hooks view: one session with failed, injecting and unrecorded
// blocking hooks, a second with none, and the probe the case checks.
(() => {
  const { data, iso, openTab, route, ready, wait, idle, scenarios } = window.DomTest;
  const requested = [];
  const hooks = {
    'sess-claude-1': [
      { harness:'claude', event: 'PreToolUse', script: 'secret_guard.py', runs: 42, errors: 42, blocks: 0, chars: 0, total_ms: 1260, last_at: iso(0) },
      { event: 'UserPromptSubmit', script: 'prompt-hook.sh', runs: 5, errors: 0, blocks: 0, chars: 4500, total_ms: 80, last_at: iso(0) },
      { event: 'PreToolUse', script: '', runs: 1, errors: 0, blocks: 1, chars: 120, total_ms: 0, last_at: iso(0) },
      { event: 'Stop', script: 'cancelled.py', runs: 2, errors: 0, cancelled: 2, blocks: 0, chars: 0, total_ms: 0, duration_samples: 0, char_samples: 0, last_at: iso(0) },
    ],
    'sess-cursor-2': [],
  };
  let unavailable = false;
  let recovered = false;
  let hostStale = false;
  const harnesses = ['claude', 'codex', 'openclaw', 'hermes', 'opencode'];
  const hostReports = () => harnesses.map(harness => ({ report: { type: 'hook_forwarder', version: 2, harness,
    forwarder_id: harness + '-bridge', sequence: recovered ? 2 : 1, ts: iso(1000), state: recovered ? 'connected' : 'error',
    pending: recovered ? 0 : 3, delivery_failures: 2, dropped: 1,
    health: { source_state: 'connected', report_error: false,
      ...(recovered ? {} : { capture_error: 'unsupported-protocol', delivery_error: 'recorder-unavailable' }),
      outbox: { persisted: recovered ? 0 : 2, recovered: 1, ...(recovered ? {} : { error: 'outbox-full' }) } } },
    received_at: iso(1000), freshness: hostStale ? 'stale' : 'recent',
    assessment:{state:hostStale?'unknown':recovered?'no-active-error':'needs-action',title:'Hook delivery observation',evidence_gap:true,limits:['Host observations only'],
      issues:hostStale||recovered?[]:[{stage:'capture',code:'unsupported-protocol',next_action:'Use the supported native protocol.'},{stage:'delivery',code:'recorder-unavailable',next_action:'Restore the recorder and retry retained completions using their original delivery IDs.'},{stage:'persistence',code:'outbox-full',next_action:'Restore outbox storage without discarding pending evidence.'}]} }));
  route('/status',()=>({ok:true,status:200,json:async()=>({...data['/status'],hook_ingestion:{available:true,since:iso(30000),rejected:0,harnesses:[],forwarders:hostReports()}})}));
  data['/status'].hook_ingestion={available:true,since:iso(30000),rejected:0,harnesses:[],forwarders:hostReports()};
  const deliveryItem={kind:'hook_delivery',id:'hook-delivery:hermes-bridge',priority:1,title:'Hermes hook delivery needs attention',detail:'3 queued completions',hook_delivery:hostReports().find(r=>r.report.harness==='hermes')};
  data['/posture'].items.push({...deliveryItem,severity:1});
  data['/posture'].groups.push({key:'hook-host:hermes-bridge',label:'Hermes forwarding host',agent:'hermes',items:[deliveryItem]});
  data['/posture'].needs_you=data['/posture'].items.length;
  data['/posture'].coverage_items.push({kind:'hook_evidence_gap',id:'hook-gap:hermes-bridge',title:'Hermes hook evidence is incomplete',detail:'Dropped completions may be unrecoverable.'});
  data['/posture'].coverage_count=data['/posture'].coverage_items.length;
  let evidenceFailed=false, holdEvidence=false, releaseEvidence=null;
  route('/sessions/sess-claude-1/hook-evidence',({query})=>{
    const response=()=>({ok:!evidenceFailed,status:evidenceFailed?503:200,json:async()=>({session_id:'sess-claude-1',filter:{harness:query.get('harness'),event:query.get('event'),event_scope:query.get('event_scope')||'group',script:query.get('script')||'',handler_id:query.get('handler_id')||'',config_id:query.get('config_id')||''},since:iso(1800000),until:iso(0),truncated:false,
      rows:[{id:'recorded-run',ts:iso(1000),status:'error',duration_ms:0,evidence:{handler_id:query.get('handler_id')||'',config_id:query.get('config_id')||'',reason_code:'timeout',duration_known:true,chars_known:false}}]})});
    return holdEvidence?new Promise(resolve=>{releaseEvidence=()=>resolve(response())}):response();
  });
  const finding = { id: 'hook:handler-1', kind: 'execution-errors', harness: 'codex', event: 'PreToolUse', handler_id: 'codex-handler:'+'a'.repeat(64), config_id: 'c'.repeat(200), script: 'secret_guard.py', title: 'Hook repeatedly failed', detail: 'Three consecutive observed execution errors.', next_action: 'Repair the unavailable dependency, then retry.', limits: ["The associated action's outcome is unknown."], count: 3, first_at: iso(3000), last_at: iso(1000), needs_action: true };
  for (const id of Object.keys(hooks)) route('/sessions/' + id + '/overview', () => ({
    ok: true, status: 200, json: async () => ({ session_id: id, observed_at: iso(0), requests: [], findings: [], coverage: null, resources: null,
      hook_ingestion: { available: true, since: iso(30000), rejected: 2, last_rejected_at: iso(1000), harnesses: [{ harness: 'codex', accepted: 12, last_received_at: iso(1000) }], forwarders: hostReports() },
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
      openTab('home');
      probe.setupEntry=!!document.querySelector('#coverage-list [data-action="hook-setup"]');
      probe.coverageDelivery=!!document.querySelector('#coverage-list [data-action="hook-delivery-inspect"][data-id="hermes-bridge"]');
      const priorSession=window.SA.selectedSessionId;
      const head=[...document.querySelectorAll('#attention-list .need-head')].find(el=>el.textContent.includes('Hermes hook delivery'));
      head?.click();
      await wait(()=>!!document.querySelector('#drawer [data-action="hook-delivery-inspect"]'));
      document.querySelector('#drawer [data-action="hook-delivery-inspect"]')?.click();
      await wait(()=>document.querySelector('#drawer-body')?.textContent.includes('3 queued'));
      probe.deliveryAttention=!!head && document.querySelector('#drawer-body').textContent.includes('original delivery IDs');
      probe.deliveryUnscoped=document.querySelector('#drawer-body').textContent.includes('Session ID not supplied') && window.SA.selectedSessionId===priorSession;
      document.querySelector('#btn-drawer-close').click();
      [...document.querySelectorAll('#attention-list .need-head')].find(el=>el.textContent.includes('Hermes hook delivery'))?.click();
      const previousItems=data['/posture'].items, previousGroups=data['/posture'].groups;
      hostStale=true;
      data['/posture'].items=previousItems.filter(item=>item.kind!=='hook_delivery');
      data['/posture'].groups=previousGroups.filter(group=>group.key!=='hook-host:hermes-bridge');
      data['/posture'].needs_you=data['/posture'].items.length;
      window.SA.t.posture=data['/posture']; window.SA.reconcileAttention();
      await wait(()=>document.querySelector('#drawer-body').textContent.includes('current connection state unknown'));
      probe.deliveryUnverified=document.querySelector('#drawer-body').textContent.includes('current connection state unknown') && !document.querySelector('#drawer-body').textContent.includes('No items need your attention');
      document.querySelector('#btn-drawer-close').click();
      hostStale=false;
      data['/posture'].items=previousItems; data['/posture'].groups=previousGroups; data['/posture'].needs_you=previousItems.length;
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
      probe.actionable = detail.textContent.includes('Repair the unavailable dependency') && detail.textContent.includes("action's outcome is unknown") && detail.textContent.includes('Handler: codex-handler:');
      const ingestion = detail.querySelector('[data-session-part="hook-ingestion"]');
      ingestion.open = true;
      probe.ingestion = ingestion.textContent.includes('all sessions') && ingestion.textContent.includes('12 accepted deliveries') && ingestion.textContent.includes('2 rejected') && ingestion.textContent.includes('original delivery IDs');
      probe.hostHealth = ingestion.textContent.includes('Forwarding error (host reported)') && ingestion.textContent.includes('3 queued') && ingestion.textContent.includes('1 dropped') && ingestion.textContent.includes('not establish complete delivery');
      const reports = [...ingestion.querySelectorAll('article')];
      probe.harnessParity = reports.length === harnesses.length && harnesses.every(harness => reports.some(row => row.querySelector('h5').textContent.startsWith(harness + ' ·')
        && ['Source connected', 'unsupported-protocol', 'recorder-unavailable', 'outbox-full', '2 persisted', '1 recovered', 'original delivery IDs'].every(text => row.textContent.includes(text))));
      probe.startsAtFindings = detail.querySelector('.session-detail-body').scrollTop === 0;
      probe.fits = detail.scrollWidth <= detail.clientWidth && document.documentElement.scrollWidth <= innerWidth;
      if (scenarios.has('shot')) { document.body.dataset.hooksProbe = JSON.stringify(probe); return; }
      detail.querySelector('[data-session-part="hook-health"] [data-action="hook-evidence"]').click();
      await wait(()=>document.querySelector('#drawer-body')?.textContent.includes('recorded-run'));
      probe.evidence=document.querySelector('#drawer-body').textContent.includes('timeout') && document.querySelector('#drawer-body').textContent.includes('0ms') && document.querySelector('#drawer-body').textContent.includes('unknown');
      const panel=document.querySelector('#drawer .drawer-panel'), evidenceBody=document.querySelector('#drawer-body');
      probe.evidenceFits=panel.scrollWidth<=panel.clientWidth && evidenceBody.scrollWidth<=evidenceBody.clientWidth && document.documentElement.scrollWidth<=innerWidth;
      if(scenarios.has('evidenceshot')) { document.body.dataset.hooksProbe=JSON.stringify(probe);return; }
      evidenceFailed=true;
      document.querySelector('#drawer-foot [data-action="hook-evidence"]').click();
      await wait(()=>document.querySelector('#drawer-body').textContent.includes('unavailable'));
      probe.evidenceFailure=document.querySelector('#drawer-body').textContent.includes('recovery is unknown') && !document.querySelector('#drawer-body').textContent.includes('No matching retained');
      evidenceFailed=false;
      document.querySelector('#drawer-foot [data-action="hook-evidence"]').click();
      await wait(()=>document.querySelector('#drawer-body').textContent.includes('recorded-run'));
      probe.evidenceRetry=document.querySelector('#drawer-body').textContent.includes('recorded-run');
      holdEvidence=true;
      document.querySelector('#drawer-foot [data-action="hook-evidence"]').click();
      await wait(()=>!!releaseEvidence);
      document.querySelector('#btn-drawer-close').click();
      detail.querySelector('[data-action="hook-setup"]').click();
      await wait(()=>document.querySelector('#drawer-title-text').textContent.includes('setup'));
      releaseEvidence(); await idle();
      probe.evidenceOwnership=document.querySelector('#drawer-title-text').textContent.includes('setup') && !document.querySelector('#drawer-body').textContent.includes('recorded-run');
      probe.setup=['Claude Code','Codex','OpenClaw','Hermes','OpenCode','real completion','protection coverage'].every(text=>document.querySelector('#drawer-body').textContent.includes(text));
      document.querySelector('#btn-drawer-close').click();
      hostStale = true;
      window.SA.refreshSessionOverview(true);
      await wait(() => window.SA.sessionOverview?.hook_ingestion?.forwarders?.[0]?.freshness === 'stale'); await idle();
      probe.hostStale = detail.textContent.includes('current connection state unknown') && !detail.textContent.includes('Source connected');
      hostStale = false;
      unavailable = true;
      window.SA.refreshSessionOverview(true);
      await wait(() => window.SA.sessionOverview?.hook_health?.available === false); await idle();
      probe.unavailable = detail.textContent.includes('Hook assessment unavailable') && !detail.textContent.includes('No repair or advisory');
      unavailable = false; recovered = true;
      window.SA.refreshSessionOverview(true);
      await wait(() => window.SA.sessionOverview?.hook_health?.available === true); await idle();
      probe.recovery = detail.textContent.includes('No repair or advisory pattern') && !detail.textContent.includes('Needs repair');
      probe.hostRecovery = detail.textContent.includes('Source connected (host reported)') && detail.textContent.includes('0 queued') && detail.textContent.includes('1 dropped') && detail.textContent.includes('may not be recoverable');
      probe.healthRecovery = [...detail.querySelectorAll('[data-session-part="hook-ingestion"] article')].every(row => row.textContent.includes('0 persisted')
        && !['unsupported-protocol', 'recorder-unavailable', 'outbox-full'].some(code => row.textContent.includes(code)));
      // Selecting another session while Hooks is open loads that session's hooks.
      await window.selectSession('sess-cursor-2');
      probe.reloaded = window.SA.sessionView === 'hooks' && requested.includes('sess-cursor-2')
        && document.querySelector('#session-detail').textContent.includes('No hook runs recorded');
    } catch (error) { probe.error = error.message; }
    document.body.dataset.hooksProbe = JSON.stringify(probe);
  });
})();
