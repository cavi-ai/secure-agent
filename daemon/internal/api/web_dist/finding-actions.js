// Write actions for findings, guard rules and egress: each applies its
// expected result to the telemetry first, sends the request, then keeps the
// result or puts it back.
// createFindingActions builds one state object; the findingAct* functions
// below take it first.
function createFindingActions({ request, toast, refetch, writes, telemetry, cardNote, cssq, drawer, flags, loadPolicy }) {
  const { stage, write, send } = writes;
  const s = { request, toast, refetch, writes, telemetry, cardNote, cssq, drawer, flags, loadPolicy, stage, write, send };

  return {
    bulkAllowHosts: (...args) => findingActBulkAllowHosts(s, ...args),
    assessHost: (...args) => findingActAssessHost(s, ...args),
    allowHost: (...args) => findingActAllowHost(s, ...args),
    openFDASettings: (...args) => findingActOpenFDASettings(s, ...args),
    muteFlag: (...args) => findingActMuteFlag(s, ...args),
    explainAct: (...args) => findingActExplain(s, ...args),
    routineAct: (...args) => findingActRoutine(s, ...args),
    explainAllowOrg: (...args) => findingActExplainAllowOrg(s, ...args),
    patternAct: (...args) => findingActPattern(s, ...args),
    unmuteFlag: (...args) => findingActUnmuteFlag(s, ...args),
    promoteVendorKeys: (...args) => findingActPromoteVendorKeys(s, ...args),
    promoteRule: (...args) => findingActPromoteRule(s, ...args),
    demoteRule: (...args) => findingActDemoteRule(s, ...args),
    removeAllowlistEntry: (...args) => findingActRemoveAllowlistEntry(s, ...args)
  };
}

const findingActAllowRowSel = (s, agent, host) => `#firewall-container [data-action="allowlist-remove"][data-agent="${s.cssq(agent)}"][data-host="${s.cssq(host)}"]`;

function findingActStageAllow(s, agent, hosts) {
  const { stage, telemetry } = s;
  const hit = x => x.agent === agent && hosts.includes(x.host);
  return stage(['allowlist', 'suggestions', 'uninspected'], ['firewall', 'endpoints'], () => {
    const t = telemetry();
    const have = t.allowlist || [];
    t.allowlist = have.concat(hosts.filter(h => !have.some(p => p.agent === agent && p.host === h)).map(host => ({ agent, host })));
    t.suggestions = (t.suggestions || []).filter(x => !hit(x));
    t.uninspected = (t.uninspected || []).filter(x => !hit(x));
  });
}

const findingActWithMode = (s, rules, mode) => {
  const t = s.telemetry();
  const st = t.status;
  if (!st || !st.firewall_stats) return;
  const stats = { ...st.firewall_stats };
  rules.forEach(r => { if (stats[r]) stats[r] = { ...stats[r], mode }; });
  t.status = { ...st, firewall_stats: stats };
};

// A pattern card's served action (Attention, Flags), found by pattern key +
// action id (+ host). Before the request (reverted if it fails) the card's
// open count drops by the submitted flag ids — all of them for a mute —
// and reads 0 open with its buttons disabled once none is left; those
// flags leave the lists; the next snapshot reconciles the pattern.
function findingActStagePatternDone(s, key, submitted) {
  const { stage, telemetry } = s;
  return stage(['patterns', 'flags', 'flagsView', 'posture'], ['flags', 'attention', 'posture', 'chart-flags', 'status', 'tab-badges'], () => {
    Object.assign(telemetry(), patternAfterOptimisticDismiss(telemetry(), key, submitted));
  });
}

// Bulk allow: one click for a group the operator has already judged (all
// hosts under one suffix for one agent). Sequential and bounded — the
// allowlist is a user-owned file, not a bulk-import target.
async function findingActBulkAllowHosts(s, agent, hosts) {
  const { request, toast, refetch, cardNote, drawer } = s;
  const list = String(hosts || '').split(',').filter(Boolean);
  const revert = findingActStageAllow(s, agent, list);
  drawer.refill();
  let ok = 0;
  for (const host of list) {
    try {
      const res = await request('/allowlist', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent, host })
      });
      if (res.ok) ok++;
    } catch { /* continue; the toast reports the tally */ }
  }
  // None landed: put everything back. A partial run keeps the optimistic
  // rows until the reconcile below shows which ones the daemon took.
  if (ok === 0 && list.length) { revert(); drawer.refill(); }
  toast(`Allowlisted ${ok} of ${list.length} hosts for ${agent}`, ok === list.length ? 'success' : ok ? 'warn' : 'danger');
  await refetch();
  if (ok) list.forEach(host => cardNote(findingActAllowRowSel(s, agent, host), '.mute-row', 'firewall-container', 'allowlisted'));
  drawer.refill();
}

// Ask the advisor what an endpoint is — the functionality that turns a raw
// IP into a decision. The daemon answers with a cached verdict immediately
// and queues a fresh assessment; the console polls a few times for the
// verdict to land, then re-renders the row.
async function findingActAssessHost(s, agent, host) {
  const { request, toast } = s;
  try {
    const res = await request('/advisor/assess-host', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent, host })
    });
    if (res.status === 503) {
      toast('Advisor is off — enable it in Settings for endpoint guidance.', 'info');
      return;
    }
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json().catch(() => ({}));
    toast(data.verdict ? 'Advisor verdict loaded' : 'Asking the advisor…', 'info');
    await findingActPollHostVerdict(s, agent, host, !!data.verdict);
  } catch (err) {
    toast(`Advisor assessment failed: ${err.message || err}`, 'danger');
  }
}

// Poll for a fresh host verdict (bounded): the model answers in seconds, and
// /egress/uninspected carries the stored verdict once it lands.
async function findingActPollHostVerdict(s, agent, host, hadVerdict) {
  const { refetch, telemetry, drawer } = s;
  const rounds = hadVerdict ? 1 : 8;
  for (let i = 0; i < rounds; i++) {
    await refetch({ slow: true });
    const row = (telemetry().uninspected || []).find(e => e.agent === agent && e.host === host);
    if (row && row.assessment) break;
    await new Promise(r => setTimeout(r, 1500));
  }
  drawer.refillOpen();
}

async function findingActAllowHost(s, agent, host) {
  const { request, toast, refetch, write, cardNote, drawer } = s;
  const revert = findingActStageAllow(s, agent, [host]);
  drawer.refill();
  await write(revert, () => request('/allowlist', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent, host })
  }), {
    ok: async () => {
      toast(`Allowlisted ${host} for ${agent}`, 'success');
      cardNote(findingActAllowRowSel(s, agent, host), '.mute-row', 'firewall-container', 'allowlisted');
      await refetch();
      drawer.refill();
    },
    failed: () => {
      drawer.refill();
      toast(`Failed to allowlist ${host}.`, 'danger');
    },
    error: err => {
      drawer.refill();
      toast(`Error allowlisting ${host}: ${err}`, 'danger');
    }
  });
}

async function findingActOpenFDASettings(s) {
  const { request, toast } = s;
  try {
    const res = await request('/ui/open-fda', { method: 'POST' });
    if (res.ok) {
      toast('Opening System Settings → Full Disk Access', 'info');
    } else {
      toast('Could not open settings — open Setup & Permissions from the menu bar instead.', 'danger');
    }
  } catch (err) {
    toast(`Could not open settings: ${err}`, 'danger');
  }
}

async function findingActMuteFlag(s, rule, host, agent) {
  const { request, toast, refetch, stage, write, telemetry, cardNote, cssq } = s;
  agent = agent || '';
  const revert = stage(['mutes'], ['flags'], () => {
    telemetry().mutes = [...(telemetry().mutes || []), agent ? { rule, host, agent } : { rule, host }];
  });
  return write(revert, () => request('/mute', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(agent ? { rule, host, agent } : { rule, host })
  }), {
    ok: () => {
      const who = agent ? ` from ${agent}` : '';
      toast(host === '*'
        ? `Dismissed ${rule}${who} — future flags of this class are suppressed`
        : `Muted ${rule} for ${host}${who} — future flags suppressed`, 'success');
      cardNote(`#flags-list [data-action="unmute"][data-rule="${cssq(rule)}"][data-host="${cssq(host)}"][data-agent="${cssq(agent)}"]`, '.mute-row', 'flags-list', 'muted');
      refetch();
    },
    failed: async res => toast(`Failed to mute: ${await res.text()}`, 'danger'),
    error: err => toast(`Error muting: ${err}`, 'danger')
  });
}

// A served explanation action (finding card, attention item). The request
// comes from flag.explain.actions, found by flag id + action id (+ host:
// allow-host appears once per destination); each id runs the console's
// existing optimistic path. allow-host, mute and dismiss resolve the flag,
// so its card leaves the list; POST /allowlist does not acknowledge the
// flag on the daemon, so the allow is followed by /flags/acknowledge.
async function findingActExplain(s, flagId, actionId, host) {
  const { toast, refetch, send, flags, drawer, cardNote, loadPolicy } = s;
  const f = flags.find(flagId);
  const a = f && f.explain && (f.explain.actions || []).find(x => x.id === actionId
    && (!host || (x.body && x.body.host) === host));
  if (!a) {
    toast('That action is no longer offered for this finding — the list is refreshing.', 'info');
    refetch();
    return;
  }
  const body = a.body || {};
  switch (a.id) {
    case 'inspect-file':
      return window.openFileDetail(body.path, { back: drawer.back() });

    case 'review-local':
      return window.analyzeAgentActivity(body.flag_ids);
    case 'expect':
    case 'expect-file':
      if (!await window.saConfirm(a.consequence, { title: 'Confirm security exception', okLabel: 'Save exception' })) return;
      try {
        await send(a.method, a.path, body);
        toast('Exception saved; unmatched evidence stays open. Revoke under Policy.', 'success');
        refetch(); loadPolicy();
      } catch (err) {toast('Exception not saved: ' + (err.message || err), 'danger');}
      return;

    case 'dismiss':
      return window.dismissFlag(f.id);
    case 'kill':
      if (await window.killProcess(Number(body.pid), body.started_at, f.agent)) {
        window.markLabel('flag:' + f.id, 'not_ok', 'kill', { quiet: true });
      }
      return;
    case 'open-incident':
      return window.openIncidentReport(new URLSearchParams(String(a.path).split('?')[1] || '').get('id') || '', { back: drawer.back() });
    case 'mute-rule-host':
    case 'mute-class':
      if (await findingActMuteFlag(s, body.rule, body.host, body.agent)) { const done = flags.drop(f.id); done.commit?.(); }
      return;
    case 'allow-host': {
      const revertAllow = findingActStageAllow(s, body.agent, [body.host]);
      const revertDrop = flags.drop(f.id);
      try {
        await send(a.method, a.path, body);
      } catch (err) {
        revertDrop();
        revertAllow();
        toast(`Failed to allowlist ${body.host}: ${err.message || err}`, 'danger');
        return;
      }
      try {
        await send('POST', '/flags/acknowledge', { flag_id: f.id });
      } catch (err) {
        revertDrop();
        toast(`Allowlisted ${body.host}, but the flag was not marked reviewed: ${err.message || err}`, 'danger');
        refetch();
        return;
      }
      revertDrop.commit?.();
      if (revertDrop.isCurrent?.() !== false) drawer.closeFlag(f.id);
      toast(`Allowlisted ${body.host} for ${body.agent}`, 'success');
      cardNote('', '', 'flags-list', 'allowlisted');
      refetch();
      return;
    }
    case 'allow-path': {
      const revertDrop = flags.drop(f.id);
      try {
        await send(a.method, a.path, body);
      } catch (err) {
        revertDrop();
        toast(`Failed to allow ${body.path}: ${err.message || err}`, 'danger');
        return;
      }
      try {
        await send('POST', '/flags/acknowledge', { flag_id: f.id });
      } catch (err) {
        revertDrop();
        toast(`Allowed ${body.path}, but the flag was not marked reviewed: ${err.message || err}`, 'danger');
        refetch();
        return;
      }
      revertDrop.commit?.();
      if (revertDrop.isCurrent?.() !== false) drawer.closeFlag(f.id);
      toast(`Allowed ${body.path} for ${body.agent}`, 'success');
      refetch();
      return;
    }
  }
}

// A routine group's served action: Treat as routine (confirmed; every
// exact pair its flags cite is expected) or Dismiss all. The group and its
// flags leave the page before the request; a failure puts them back.
async function findingActRoutine(s, key, actionId) {
  const { request, toast, refetch, stage, telemetry, loadPolicy } = s;
  const rg = (telemetry().routine || []).find(r => r.key === key);
  const a = rg && (rg.actions || []).find(x => x.id === actionId);
  if (!a) {
    toast('That action is no longer offered — the list is refreshing.', 'info');
    refetch();
    return;
  }
  if (a.id === 'expect-all' && !await window.saConfirm(a.consequence, { title: 'Treat as routine', okLabel: 'Treat as routine', danger: false })) return;
  const ids = (a.body && a.body.flag_ids) || [];
  const revert = stage(['routine', 'patterns', 'flags', 'flagsView', 'posture'], ['flags', 'attention', 'posture', 'chart-flags', 'status', 'tab-badges'], () => {
    Object.assign(telemetry(), routineAfterOptimistic(telemetry(), key, ids));
  });
  let out = {};
  try {
    const res = await request(a.path, { method: a.method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(a.body || {}) });
    if (!res.ok) throw new Error(await res.text());
    out = await res.json().catch(() => ({}));
  } catch (err) {
    revert();
    toast(`${a.label} failed: ${err.message || err}`, 'danger');
    return;
  }
  revert.commit?.();
  toast(a.id === 'expect-all'
    ? `${Number(out.added) || 0} exact reads marked expected; ${Number(out.acknowledged) || 0} flags reviewed`
    : `Dismissed ${ids.length} flags — the rules keep watching`, 'success');
  refetch();
  if (a.id === 'expect-all') loadPolicy();
}

// One destination organization's allow-host choices at once: every served
// allow for its hosts, in order, then one acknowledgement — the requests
// the per-host buttons sent one at a time. Reverted when none lands.
async function findingActExplainAllowOrg(s, flagId, org) {
  const { toast, refetch, send, flags, drawer, cardNote } = s;
  const f = flags.find(flagId);
  const hosts = new Set((egressByOrg(f).get(org) || []).map(e => e.host));
  const acts = ((f && f.explain && f.explain.actions) || []).filter(a => a.id === 'allow-host' && a.body && hosts.has(a.body.host));
  if (!acts.length) {
    toast('That action is no longer offered for this finding — the list is refreshing.', 'info');
    refetch();
    return;
  }
  const agent = acts[0].body.agent;
  const revertAllow = findingActStageAllow(s, agent, acts.map(a => a.body.host));
  const revertDrop = flags.drop(f.id);
  let ok = 0;
  for (const a of acts) {
    try { await send(a.method, a.path, a.body); ok++; } catch { /* the toast reports the tally */ }
  }
  if (!ok) {
    revertDrop();
    revertAllow();
    toast(`Failed to allowlist ${org} for ${agent}`, 'danger');
    return;
  }
  try {
    await send('POST', '/flags/acknowledge', { flag_id: f.id });
  } catch (err) {
    revertDrop();
    toast(`Allowlisted ${org}, but the flag was not marked reviewed: ${err.message || err}`, 'danger');
    refetch();
    return;
  }
  revertDrop.commit?.();
  if (revertDrop.isCurrent?.() !== false) drawer.closeFlag(f.id);
  toast(`Allowlisted ${ok} of ${acts.length} ${org} addresses for ${agent}`, ok === acts.length ? 'success' : 'warn');
  cardNote('', '', 'flags-list', 'allowlisted');
  refetch();
}

async function findingActPattern(s, key, actionId, host) {
  const { toast, refetch, send, telemetry, drawer, cardNote, cssq, loadPolicy } = s;
  const p = (telemetry().patterns || []).find(x => x.key === key);
  const a = p && !p.dismissed && (p.actions || []).find(x => x.id === actionId
    && (!host || (x.body && x.body.host) === host));
  if (!a) {
    toast('That action is no longer offered for this pattern — the list is refreshing.', 'info');
    refetch();
    return;
  }
  const body = a.body || {};
  const dismiss = (p.actions || []).find(x => x.id === 'dismiss-all');
  const openIds = (dismiss && dismiss.body && dismiss.body.flag_ids) || [];
  switch (a.id) {
    case 'inspect-file':
      return window.openFileDetail(body.path, { back: drawer.back() });
    case 'review-local':
      return window.analyzeAgentActivity(body.flag_ids);
    case 'expect':
    case 'expect-file': {
      if (!await window.saConfirm(a.consequence, { title: 'Confirm security exception', okLabel: 'Save exception' })) return;
      try {
        await send(a.method, a.path, body);
        toast('Exception saved; unmatched evidence stays open. Revoke under Policy.', 'success');
        refetch(); loadPolicy();
      } catch (err) { toast('Exception not saved: ' + (err.message || err), 'danger'); }
      return;
    }

    case 'kill':
      return window.killProcess(Number(body.pid), body.started_at, p.agent);
    case 'mute-rule-host':
    case 'mute-class':
      if (await findingActMuteFlag(s, body.rule, body.host, body.agent)) { const done = findingActStagePatternDone(s, key); done.commit?.(); }
      return;
    case 'dismiss-all': {
      const revert = findingActStagePatternDone(s, key, openIds);
      try {
        await send(a.method, a.path, body);
      } catch (err) {
        revert();
        toast(`Failed to dismiss the pattern: ${err.message || err}`, 'danger');
        return;
      }
      revert.commit?.();
      toast(`Dismissed ${openIds.length} flag${openIds.length === 1 ? '' : 's'} — the rule keeps watching`, 'info');
      cardNote(`[data-pattern-key="${cssq(key)}"] .pattern-open`, '.log-row', 'flags-list', 'dismissed');
      refetch();
      return;
    }
    case 'allow-host': {
      const revertAllow = findingActStageAllow(s, body.agent, [body.host]);
      const revert = findingActStagePatternDone(s, key, openIds);
      try {
        await send(a.method, a.path, body);
      } catch (err) {
        revert();
        revertAllow();
        toast(`Failed to allowlist ${body.host}: ${err.message || err}`, 'danger');
        return;
      }
      if (openIds.length) {
        try {
          await send('POST', '/flags/acknowledge', { flag_ids: openIds });
        } catch (err) {
          revert();
          toast(`Allowlisted ${body.host}, but its flags were not marked reviewed: ${err.message || err}`, 'danger');
          refetch();
          return;
        }
      }
      revert.commit?.();
      toast(`Allowlisted ${body.host} for ${body.agent}`, 'success');
      refetch();
      return;
    }
  }
}

async function findingActUnmuteFlag(s, rule, host, agent) {
  const { request, toast, refetch, stage, write, telemetry, cardNote } = s;
  agent = agent || '';
  const revert = stage(['mutes'], ['flags'], () => {
    telemetry().mutes = (telemetry().mutes || []).filter(m => !(m.rule === rule && m.host === host && (m.agent || '') === agent));
  });
  await write(revert, () => {
    const q = `rule=${encodeURIComponent(rule)}&host=${encodeURIComponent(host)}` + (agent ? `&agent=${encodeURIComponent(agent)}` : '');
    return request(`/mute?${q}`, { method: 'DELETE' });
  }, {
    ok: () => {
      toast(`Unmuted ${rule} for ${host}${agent ? ` from ${agent}` : ''}`, 'info');
      cardNote('', '', 'flags-list', 'unmuted');
      refetch();
    },
    failed: () => toast(`Failed to unmute.`, 'danger'),
    error: err => toast(`Error unmuting: ${err}`, 'danger')
  });
}

async function findingActPromoteVendorKeys(s) {
  const { request, toast, refetch, stage, write, telemetry, cardNote } = s;
  const stats = (telemetry().status && telemetry().status.firewall_stats) || {};
  const revert = stage(['status'], ['firewall'], () => findingActWithMode(s, monitorVendorKeyIDs(stats), 'block'));
  await write(revert, () => request('/firewall/mode', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'vendor-key', mode: 'block' })
  }), {
    ok: async res => {
      const body = await res.json().catch(() => ({}));
      const n = (body.promoted || []).length;
      toast(n ? `Promoted ${n} vendor-key rule${n === 1 ? '' : 's'} to block.` : 'Vendor-key rules already blocking.', 'success');
      cardNote('', '', 'firewall-container', 'vendor keys blocking');
      refetch();
    },
    failed: () => toast('Failed to promote vendor-key rules.', 'danger'),
    error: err => toast(`Error promoting vendor-key rules: ${err}`, 'danger')
  });
}

async function findingActPromoteRule(s, rule) {
  const { request, toast, refetch, stage, write, cardNote, cssq } = s;
  const revert = stage(['status'], ['firewall'], () => findingActWithMode(s, [rule], 'block'));
  await write(revert, () => request('/firewall/mode', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rule, mode: 'block' })
  }), {
    ok: () => {
      toast(`Rule “${rule}” promoted to block.`, 'success');
      cardNote(`#firewall-container [data-rule="${cssq(rule)}"]`, '.fw-rule', 'firewall-container', 'blocking');
      refetch();
    },
    failed: () => toast(`Failed to promote “${rule}”.`, 'danger'),
    error: err => toast(`Error promoting “${rule}”: ${err}`, 'danger')
  });
}

// Blocking must be reversible — a rule you can only tighten is a ratchet.
async function findingActDemoteRule(s, rule) {
  const { request, toast, refetch, stage, write, cardNote, cssq } = s;
  const revert = stage(['status'], ['firewall'], () => findingActWithMode(s, [rule], 'monitor'));
  await write(revert, () => request('/firewall/mode', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rule, mode: 'monitor' })
  }), {
    ok: () => {
      toast(`Rule “${rule}” back to monitor.`, 'success');
      cardNote(`#firewall-container [data-rule="${cssq(rule)}"]`, '.fw-rule', 'firewall-container', 'monitoring');
      refetch();
    },
    failed: () => toast(`Failed to demote “${rule}”.`, 'danger'),
    error: err => toast(`Error demoting “${rule}”: ${err}`, 'danger')
  });
}

async function findingActRemoveAllowlistEntry(s, agent, host) {
  const { request, toast, stage, write, telemetry, cardNote } = s;
  const revert = stage(['allowlist'], ['firewall'], () => {
    telemetry().allowlist = (telemetry().allowlist || []).filter(p => !(p.agent === agent && p.host === host));
  });
  await write(revert, () => request('/allowlist', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent, host })
  }), {
    ok: () => {
      toast(`Removed ${host} for ${agent}.`, 'info');
      cardNote('', '', 'firewall-container', 'removed');
    },
    failed: () => toast(`Failed to remove ${host}.`, 'danger'),
    error: err => toast(`Error removing ${host}: ${err}`, 'danger')
  });
}
