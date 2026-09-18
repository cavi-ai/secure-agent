// Secure Agent console — pure logic. No DOM access in this file.
//
// Loaded as a classic script before app.js (top-level functions become page
// globals), and unit-tested under `node --test` by evaluating the file in a
// fresh VM context (packaging/test/console/lib.test.mjs). Keep it free of
// window/document references so both consumers work.

function escapeHTML(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// fmtTime: deterministic local HH:MM:SS. toLocaleTimeString varies by locale
// (zero-padding, a "24:00" midnight quirk in some), which can re-wrap the
// 68px timeline column — build the string by hand instead.
function fmtTime(d) {
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function eventKey(e) {
  return `${e.ts}|${e.pid}|${e.kind}|${e.detail || e.path || e.remote_host || ''}`;
}

// sessionShort: the display form of a harness session id (first 8 chars),
// shared by the flag card chip and the timeline filter chip.
function sessionShort(id) {
  return String(id || '').slice(0, 8);
}

// filterEventsBySession: the timeline's session drill-down. Client-side over
// the already-fetched window — the events API has no session filter, and the
// loaded window is what the timeline can show anyway.
function filterEventsBySession(events, sessionId) {
  if (!sessionId) return events || [];
  return (events || []).filter(e => e.session_id === sessionId);
}

function filterEventsByPids(events, pids) {
  if (!pids || !pids.length) return events || [];
  const set = new Set(pids.map(Number));
  return (events || []).filter(e => set.has(Number(e.pid)));
}

function scopedBySession(items, sessionId, pids) {
  if (sessionId) return filterEventsBySession(items, sessionId);
  if (pids && pids.length) return filterEventsByPids(items, pids);
  return items || [];
}

function filterSessionRows(rows, q) {
  const s = String(q || '').trim().toLowerCase();
  if (!s) return rows || [];
  return (rows || []).filter(r => {
    const label = String((r && r.label) || '').toLowerCase();
    const cwd = String((r && r.root && r.root.cwd) || '').toLowerCase();
    const name = String((r && r.root && r.root.name) || '').toLowerCase();
    return label.includes(s) || cwd.includes(s) || name.includes(s);
  });
}

function unactedLast24h(flags, nowMs) {
  const cutoff = nowMs - 24 * 3600e3;
  return (flags || []).filter(f => {
    if (!f || f.acknowledged || (f.severity || 0) < 2) return false;
    const t = Date.parse(f.ts);
    return Number.isFinite(t) && t >= cutoff;
  });
}

// flagHost extracts the egress destination host from a flag's evidence
// (the host a mute/disposition applies to), or '' for hostless rules.
function flagHost(flag) {
  for (const ev of (flag && flag.evidence) || []) {
    let m = ev.match(/connected to ([^:\s]+):\d+/) || ev.match(/connecting to ([^:\s]+):\d+/);
    if (m) return m[1];
  }
  return '';
}

// ---------- sparkline (rolling events/sec window) ----------

// Age the bucket ring by `steps` seconds (newest bucket is last). Steps
// beyond the window length reset the whole ring.
function advanceBuckets(buckets, steps) {
  const n = Math.min(steps, buckets.length);
  for (let i = 0; i < n; i++) { buckets.shift(); buckets.push(0); }
  return buckets;
}

// Map an event timestamp onto a bucket index. Events older than the window
// clamp into the OLDEST bucket: the shape still reflects "something happened"
// without inventing recency.
function bucketIndexFor(nowMs, tsMs, bucketCount) {
  if (!tsMs) return bucketCount - 1;
  const ageSec = Math.floor((nowMs - tsMs) / 1000);
  return Math.max(0, bucketCount - 1 - ageSec);
}

// Polyline points for the masthead sparkline SVG. Baseline is y=baseY; values
// scale to at most `span` pixels above it. maxFloor keeps a quiet line flat
// instead of amplifying noise.
function sparkPoints(buckets, width, baseY, span, maxFloor) {
  const max = Math.max(maxFloor || 2, ...buckets);
  const n = buckets.length;
  return buckets.map((v, i) => {
    const x = (i / (n - 1)) * width;
    const y = baseY - (v / max) * span;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
}

// ---------- incident report markdown ----------

function parseMarkdownToHTML(md) {
  if (!md) return '';
  let html = escapeHTML(md);

  // Code blocks
  html = html.replace(/```([\s\S]*?)```/g, (_, code) => `<pre class="md-codeblock"><code>${code}</code></pre>`);
  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code class="md-inline-code">$1</code>');
  // Headers
  html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
  html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
  html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');
  // Bold
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  // Bullet lists
  html = html.replace(/^\- (.*$)/gim, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');
  // Paragraphs
  html = html.replace(/\n\n/g, '<br/><br/>');

  return `<div class="markdown-view">${html}</div>`;
}

// ---------- rollup chart ----------

// rollupSeries shapes hourly rollup points into zero-filled per-bucket totals
// covering exactly `hours` buckets ending at the current UTC hour. Event kinds
// ("event:…") and flag kinds ("flag:sN") are separated so the chart can draw
// activity bars with flag markers.
function rollupSeries(points, hours, nowMs) {
  const HOUR = 3600000;
  const nowHour = Math.floor(nowMs / HOUR);
  const firstHour = nowHour - hours + 1;
  const events = new Array(hours).fill(0);
  const flags = new Array(hours).fill(0);
  const labels = new Array(hours).fill('');
  for (const p of points || []) {
    const h = Math.floor(Date.parse(p.bucket + ':00:00Z') / HOUR);
    const idx = h - firstHour;
    if (isNaN(h) || idx < 0 || idx >= hours) continue;
    if (String(p.kind).startsWith('flag:')) flags[idx] += p.count;
    else events[idx] += p.count;
  }
  for (let i = 0; i < hours; i++) {
    const d = new Date((firstHour + i) * HOUR);
    labels[i] = hours <= 48
      ? String(d.getHours()).padStart(2, '0') + ':00'
      : d.toLocaleDateString([], { month: 'numeric', day: 'numeric' });
  }
  return { labels, events, flags };
}

// Parse the correlator's evidence sentences into the causal nodes they
// describe (sensitive read → egress connection → …) and append a
// severity-colored verdict node. Unrecognized sentences fall back to a raw
// node so the audit truth is never hidden by a parser gap.
// ---------- evidence chain ----------

function buildEvidenceChain(flag) {
  const nodes = [];
  const ts = (s) => {
    const d = Date.parse(s);
    return isNaN(d) ? '' : fmtTime(new Date(d));
  };
  for (const ev of (flag.evidence || [])) {
    let m;
    if ((m = ev.match(/^(.*?) \(pid (\d+)\) read (.+) at (.+)$/))) {
      nodes.push({ icon: 'i-key', cls: 'cn-read', label: m[3], sub: `sensitive read · ${ts(m[4])}` });
    } else if ((m = ev.match(/^then connected to (.+:\d+) at (.+)$/))) {
      nodes.push({ icon: 'i-globe', cls: 'cn-egress', label: m[1], sub: `egress · ${ts(m[2])}` });
    } else if ((m = ev.match(/accessed keychain file (.+) at (.+)$/))) {
      nodes.push({ icon: 'i-key', cls: 'cn-read', label: m[1], sub: `keychain access · ${ts(m[2])}` });
    } else if ((m = ev.match(/executed (.+) at (.+)$/))) {
      nodes.push({ icon: 'i-power', cls: 'cn-read', label: m[1], sub: `keychain CLI · ${ts(m[2])}` });
    } else if ((m = ev.match(/modified TCC service '(.+)' at (.+)$/))) {
      nodes.push({ icon: 'i-alert', cls: 'cn-read', label: `TCC: ${m[1]}`, sub: `privacy tamper · ${ts(m[2])}` });
    } else if ((m = ev.match(/^Local proxy detected security violation '(.+)' while connecting to (.+)$/))) {
      nodes.push({ icon: 'i-shield', cls: 'cn-read', label: m[1], sub: 'payload inspection' });
      nodes.push({ icon: 'i-globe', cls: 'cn-egress', label: m[2], sub: 'destination' });
    } else {
      nodes.push({ icon: 'i-alert', cls: '', label: ev, sub: '' });
    }
  }
  if (nodes.length === 0) return nodes;
  nodes.push({
    icon: flag.severity >= 3 ? 'i-alert' : 'i-shield',
    cls: flag.severity >= 3 ? 'cn-verdict-bad' : 'cn-verdict-warn',
    label: flag.severity >= 3 ? 'Critical flag raised' : 'Flag raised',
    sub: flag.rule || ''
  });
  return nodes;
}

// ---------- agent families ----------

function familyTitle(name) {
  const s = String(name || 'unknown');
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function fmtRSS(n) {
  n = Number(n);
  if (!n || n < 0) return '';
  if (n < 1024) return Math.round(n) + ' B';
  if (n < 1048576) return Math.round(n / 1024) + ' KB';
  if (n < 1073741824) {
    const mb = n / 1048576;
    return (mb >= 10 ? mb.toFixed(0) : mb.toFixed(1)) + ' MB';
  }
  return (n / 1073741824).toFixed(1) + ' GB';
}

function fmtCPU(value) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return '';
  const n = Number(value);
  return n.toFixed(1).replace(/\.0$/, '') + '%';
}

// A score of 1 means the session is at the first-slice warning threshold:
// either 4 GiB resident memory or one full CPU core.
function resourceImpact(session) {
  if (!session) return 0;
  const memory = Math.max(0, Number(session.rss_bytes) || 0) / (4 * 1024 ** 3);
  const cpu = Math.max(0, Number(session.cpu_percent) || 0) / 100;
  return Math.max(memory, cpu);
}

function resourceSparkPoints(samples, field, width, height) {
  const values = (samples || [])
    .filter(sample => sample && sample[field] !== null && sample[field] !== undefined && Number.isFinite(Number(sample[field])))
    .map(sample => Number(sample[field]));
  if (!values.length) return '';
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min;
  return values.map((value, index) => {
    const x = values.length === 1 ? width / 2 : (index / (values.length - 1)) * width;
    const y = range === 0 ? height / 2 : height - ((value - min) / range) * height;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
}

function resourceDiagnosisText(diagnosis) {
  if (!diagnosis) return '';
  const fallbacks = {
    'heavy-memory': 'Heavy memory use',
    'heavy-cpu': 'High CPU use',
    'rapid-growth': 'Memory is growing quickly',
    'idle-heavy': 'Idle session retains substantial memory',
    'runaway-child': 'One child dominates session memory',
    'orphan-drift': 'Detached processes are still consuming resources',
  };
  return escapeHTML(diagnosis.summary || fallbacks[diagnosis.code] || 'Resource pressure detected');
}

function fmtAge(iso, nowMs) {
  const t = Date.parse(iso);
  if (!isFinite(t)) return '';
  const sec = Math.max(0, Math.floor(((nowMs || Date.now()) - t) / 1000));
  if (sec < 60) return sec + 's';
  if (sec < 3600) return Math.floor(sec / 60) + 'm';
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return m ? `${h}h${m}m` : `${h}h`;
}

function isFamilyRoot(a, members) {
  if (a.root_pid) return Number(a.root_pid) === Number(a.pid);
  return !members.some(m => Number(m.pid) === Number(a.ppid));
}

function childrenOf(root, members) {
  const rid = Number(root.pid);
  return (members || []).filter(m => Number(m.pid) !== rid && Number(m.root_pid || m.ppid) === rid);
}

function groupAgents(agents) {
  const byName = new Map();
  for (const a of agents || []) {
    const name = a.name || 'unknown';
    if (!byName.has(name)) byName.set(name, []);
    byName.get(name).push(a);
  }
  const families = [];
  for (const [name, members] of byName) {
    const roots = members.filter(a => isFamilyRoot(a, members));
    let earliest = '';
    let rss = 0;
    let orphanCount = 0;
    for (const m of members) {
      if (m.rss_bytes) rss += Number(m.rss_bytes);
      if (m.is_orphan) orphanCount++;
      if (m.started_at && (!earliest || m.started_at < earliest)) earliest = m.started_at;
    }
    families.push({
      name,
      title: familyTitle(name),
      members,
      roots,
      earliest,
      rss,
      orphanCount
    });
  }
  families.sort((a, b) => a.name.localeCompare(b.name));
  return families;
}

function familyShouldExpand(family, familyCount, totalInstances, userOpen) {
  if (userOpen && Object.prototype.hasOwnProperty.call(userOpen, family.name)) {
    return !!userOpen[family.name];
  }
  return familyCount === 1 || totalInstances <= 3 || family.orphanCount > 0;
}

function cwdLabel(cwd) {
  if (!cwd) return '';
  const s = String(cwd).replace(/\/+$/, '');
  const i = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
  return i >= 0 ? s.slice(i + 1) : s;
}

function sessionRows(agents, trees) {
  if (trees && trees.length) {
    return trees.map(t => {
      const root = t.root || {};
      const children = t.children || [];
      return {
        root,
        children,
        label: cwdLabel(root.cwd) || familyTitle(root.name),
        rss: Number(t.rss_bytes || 0),
        lastSeen: t.last_seen_at || '',
        pids: [Number(root.pid), ...children.map(k => Number(k.pid))],
      };
    });
  }
  const list = agents || [];
  const roots = list.filter(a => isFamilyRoot(a, list));
  const rows = roots.map(root => {
    const children = childrenOf(root, list);
    let rss = Number(root.rss_bytes || 0);
    let lastSeen = root.last_seen_at || '';
    for (const k of children) {
      rss += Number(k.rss_bytes || 0);
      if (k.last_seen_at && k.last_seen_at > lastSeen) lastSeen = k.last_seen_at;
    }
    return {
      root,
      children,
      label: cwdLabel(root.cwd) || familyTitle(root.name),
      rss,
      lastSeen,
      pids: [Number(root.pid), ...children.map(k => Number(k.pid))],
    };
  });
  rows.sort((a, b) => (b.lastSeen || '').localeCompare(a.lastSeen || ''));
  return rows;
}

function sessionStripRows(rows, n) {
  const cap = n == null ? 3 : Number(n);
  return (rows || []).slice(0, cap > 0 ? cap : 0);
}

function sessionNeedsYou(row, flags) {
  const pids = new Set((row && row.pids ? row.pids : []).map(Number));
  let n = 0;
  for (const f of flags || []) {
    if (f.acknowledged) continue;
    if (pids.has(Number(f.pid))) n++;
  }
  return n;
}

// Build the operator's attention queue around whole agent sessions. Signals
// without a PID (guard prompts and uninspected egress) join a live session
// only when the agent name identifies exactly one session; ambiguous work is
// kept in an explicit agent-level group rather than guessed onto a process.
function buildAttentionGroups(data) {
  data = data || {};
  const resources = data.resources || {};
  const resourceSessions = resources.sessions || [];
  const fallbackRows = resourceSessions.length ? [] : sessionRows(
    (data.status && data.status.agents) || [], data.status && data.status.trees
  );
  const sessions = resourceSessions.map(s => ({
    key: String(s.key || s.root_pid || ''),
    agent: s.name || '',
    workspace: s.workspace || '',
    label: cwdLabel(s.workspace) || familyTitle(s.name),
    rootPid: Number(s.root_pid || 0),
    pids: (s.processes || []).map(p => Number(p.pid)).filter(Number.isFinite),
    rssBytes: Number(s.rss_bytes || 0),
    cpuPercent: Number(s.cpu_percent || 0),
    processCount: Number(s.process_count || (s.processes || []).length || 0),
    diagnoses: s.diagnoses || [],
    control: s.control || {},
  })).concat(fallbackRows.map(row => ({
    key: String((row.root && (row.root.root_pid || row.root.pid)) || ''),
    agent: (row.root && row.root.name) || '',
    workspace: (row.root && row.root.cwd) || '',
    label: row.label,
    rootPid: Number((row.root && row.root.pid) || 0),
    pids: row.pids || [],
    rssBytes: Number(row.rss || 0),
    cpuPercent: 0,
    processCount: (row.pids || []).length,
    diagnoses: [],
    control: {},
  })));

  const byPID = new Map();
  const byAgent = new Map();
  sessions.forEach(session => {
    session.pids.forEach(pid => byPID.set(Number(pid), session));
    if (session.rootPid) byPID.set(session.rootPid, session);
    const key = String(session.agent || '').toLowerCase();
    if (key) byAgent.set(key, [...(byAgent.get(key) || []), session]);
  });

  const groups = new Map();
  const targetFor = (agent, pid) => {
    const direct = byPID.get(Number(pid));
    if (direct) return direct;
    const matches = byAgent.get(String(agent || '').toLowerCase()) || [];
    if (matches.length === 1) return matches[0];
    return null;
  };
  const groupFor = (agent, pid) => {
    const session = targetFor(agent, pid);
    const key = session ? `session:${session.key}` : `agent:${agent || 'unattributed'}`;
    if (!groups.has(key)) {
      groups.set(key, {
        key,
        label: session ? session.label : `${agent || 'Unattributed'} activity`,
        agent: session ? session.agent : (agent || 'unknown'),
        workspace: session ? session.workspace : '',
        rootPid: session ? session.rootPid : 0,
        pids: session ? session.pids : [],
        rssBytes: session ? session.rssBytes : 0,
        cpuPercent: session ? session.cpuPercent : 0,
        processCount: session ? session.processCount : 0,
        items: [],
      });
    }
    return groups.get(key);
  };
  const add = (agent, pid, item) => groupFor(agent, pid).items.push(item);

  sessions.forEach(session => {
    if (!session.control.pending_id) return;
    const diagnosis = session.diagnoses[0] || {};
    add(session.agent, session.rootPid, {
      kind: 'resource', priority: 4, id: session.control.pending_id,
      action: session.control.next_action || 'intervention',
      title: 'Resource pressure',
      detail: diagnosis.summary || 'This session exceeded its configured resource budget.',
    });
  });
  (data.guardPending || []).forEach(prompt => add(prompt.agent, 0, {
    kind: 'guard', priority: 5, id: prompt.id, title: 'Guard decision',
    detail: `${prompt.tool || 'Tool'} wants access to ${prompt.path || 'a protected path'}`,
    rule: prompt.rule_id || '', path: prompt.path || '', scopeText: prompt.scope_text || '',
  }));
  (data.incidents || []).forEach(incident => {
    const status = (incident.workflow && incident.workflow.status) || 'open';
    const risk = String(incident.risk || '').toUpperCase();
    if (status === 'resolved' || (risk !== 'CRITICAL' && risk !== 'HIGH')) return;
    add(incident.agent, incident.pid, {
      kind: 'incident', priority: 3, id: incident.id, title: 'Critical incident',
      detail: incident.summary || incident.rule || 'A security incident needs review.', status,
    });
  });
  (data.flags || []).forEach(flag => {
    if (flag.acknowledged || Number(flag.severity || 0) < 3) return;
    add(flag.agent, flag.pid, {
      kind: 'flag', priority: 2, id: flag.id, title: 'Critical finding',
      detail: `${flag.rule || 'Security rule'}${(flag.evidence || [])[0] ? ` — ${flag.evidence[0]}` : ''}`,
    });
  });
  (data.uninspected || []).forEach(row => {
    const group = groupFor(row.agent, row.pid);
    let item = group.items.find(candidate => candidate.kind === 'egress');
    if (!item) {
      item = { kind: 'egress', priority: 1, title: 'Uninspected egress', detail: '', count: 0, hosts: [] };
      group.items.push(item);
    }
    item.count += Number(row.count || 0);
    if (row.host && !item.hosts.includes(row.host)) item.hosts.push(row.host);
    item.detail = `${item.count} connection${item.count === 1 ? '' : 's'} across ${item.hosts.length} endpoint${item.hosts.length === 1 ? '' : 's'} bypassed inspection.`;
  });

  return [...groups.values()]
    .filter(group => group.items.length)
    .map(group => ({ ...group, items: group.items.sort((a, b) => b.priority - a.priority) }))
    .sort((a, b) => {
      const pa = a.items[0] ? a.items[0].priority : 0;
      const pb = b.items[0] ? b.items[0].priority : 0;
      return pb - pa || b.items.length - a.items.length || a.label.localeCompare(b.label);
    });
}

function sessionStripHTML(rows, total, now, flags) {
  rows = rows || [];
  if (!rows.length) return '';
  const items = rows.map(row => {
    const need = sessionNeedsYou(row, flags);
    const rss = fmtRSS(row.rss);
    const seen = row.lastSeen ? fmtAge(row.lastSeen, now) : '';
    return `<button type="button" class="session-strip-row" data-action="goto-tab" data-tab="sessions">
      <span class="session-strip-label">${escapeHTML(row.label)}</span>
      ${rss ? `<span class="session-strip-meta">${escapeHTML(rss)}</span>` : ''}
      ${seen ? `<span class="session-strip-meta">${escapeHTML(seen)}</span>` : ''}
      ${need ? `<span class="session-strip-need">${need}</span>` : ''}
    </button>`;
  }).join('');
  const more = Number(total) > rows.length
    ? `<button type="button" class="session-strip-more" data-action="goto-tab" data-tab="sessions">View all ${Number(total)}</button>`
    : '';
  return `<div class="session-strip">${items}${more}</div>`;
}

function renderProcessRow(a, now, nested) {
  const abs = a.started_at ? fmtTime(new Date(a.started_at)) : '';
  const age = a.started_at ? fmtAge(a.started_at, now) : '';
  const seenAge = a.last_seen_at ? fmtAge(a.last_seen_at, now) : '';
  const stale = a.last_seen_at
    ? (now - Date.parse(a.last_seen_at)) > 10 * 60 * 1000
    : true;
  const rss = fmtRSS(a.rss_bytes);
  const cwd = a.cwd ? `<div class="agent-cwd">${escapeHTML(a.cwd)}</div>` : '';
  const status = a.is_orphan
    ? '<span class="agent-status orphan">leftover</span>'
    : '<span class="agent-status live">live</span>';
  return `
      <div class="agent-instance${nested ? ' nested' : ''}${a.is_orphan ? ' orphan' : ''}${stale ? ' stale' : ''}">
        <div class="agent-info">
          <div class="agent-name">
            <span class="agent-pid">PID ${a.pid}</span>
            ${status}
            ${abs ? `<span class="agent-meta-item" title="started ${escapeHTML(a.started_at)}">${escapeHTML(abs)}${age ? ' · ' + age : ''}</span>` : ''}
            ${seenAge ? `<span class="agent-meta-item agent-lastseen" title="last event ${escapeHTML(a.last_seen_at)}">active ${escapeHTML(seenAge)} ago</span>` : `<span class="agent-meta-item agent-lastseen">no activity</span>`}
            ${rss ? `<span class="agent-meta-item">${escapeHTML(rss)}</span>` : ''}
          </div>
          ${cwd}
        </div>
        <button type="button" class="btn btn-danger btn-sm" data-action="kill" data-pid="${a.pid}" data-started="${escapeHTML(a.started_at || '')}" data-family="${escapeHTML(a.name || '')}"><svg class="icon"><use href="#i-power"/></svg><span>Terminate</span></button>
      </div>`;
}

function sessionBoardHTML(rows, now, helpOpen) {
  helpOpen = helpOpen || {};
  return rows.map(row => {
    const a = row.root;
    const rss = fmtRSS(row.rss);
    const seenAge = row.lastSeen ? fmtAge(row.lastSeen, now) : '';
    const stale = row.lastSeen ? (now - Date.parse(row.lastSeen)) > 10 * 60 * 1000 : true;
    const open = helpOpen[a.pid] ? ' open' : '';
    const helpers = row.children.length
      ? `<details class="session-helpers"${open} data-pid="${a.pid}"><summary class="session-helpers-sum">${row.children.length} helper${row.children.length === 1 ? '' : 's'}</summary>${row.children.map(c => renderProcessRow(c, now, true)).join('')}</details>`
      : '';
    return `
      <div class="session-row${a.is_orphan ? ' orphan' : ''}${stale ? ' stale' : ''}">
        <button type="button" class="session-main" data-action="filter-pids" data-pids="${escapeHTML(row.pids.join(','))}" data-label="${escapeHTML(row.label)}" title="${escapeHTML(a.cwd || '')}">
          <span class="session-label">${escapeHTML(row.label)}</span>
          <span class="agent-pid">${escapeHTML(a.name)} · PID ${a.pid}</span>
          ${seenAge ? `<span class="agent-meta-item agent-lastseen">active ${escapeHTML(seenAge)} ago</span>` : `<span class="agent-meta-item agent-lastseen">no activity</span>`}
          ${rss ? `<span class="agent-meta-item">${escapeHTML(rss)}</span>` : ''}
        </button>
        <button type="button" class="btn btn-danger btn-sm" data-action="kill" data-pid="${a.pid}" data-started="${escapeHTML(a.started_at || '')}" data-family="${escapeHTML(a.name || '')}"><svg class="icon"><use href="#i-power"/></svg><span>Terminate</span></button>
        ${helpers}
      </div>`;
  }).join('');
}

function monitorVendorKeyIDs(stats) {
  return Object.keys(stats || {}).filter(id =>
    stats[id] && stats[id].type === 'vendor-key' && stats[id].mode !== 'block'
  ).sort();
}

function inspectionVisible(status, audit) {
  return {
    fleet: !!(status && status.fleet_configured),
    advisor: !!(status && status.advisor_enabled),
    audit: Array.isArray(audit) && audit.length > 0,
  };
}

function vendorKeyPromoteHTML(ids) {
  if (!ids || !ids.length) return '';
  const n = ids.length;
  return `<div class="fw-promote-vendor">
    <div class="fw-rule-main">
      <span class="fw-rule-id">Catch secrets</span>
      <div class="fw-metrics"><span class="fw-metric">${n} vendor-key rule${n === 1 ? '' : 's'} still in monitor — they report leaks but do not stop them</span></div>
    </div>
    <button class="btn btn-primary btn-sm" data-action="promote-vendor-keys"><svg class="icon"><use href="#i-arrow"/></svg><span>Promote vendor keys to block</span></button>
  </div>`;
}
// sseNeedsSnapshot: which EventSource kinds must refetch GET /snapshot.
// file/conn/transcript noise only bumps the sparkline — a 400ms snapshot
// after every ES file-open is the leftover hot-path tax.
function sseNeedsSnapshot(kind) {
  return kind === 'exec' || kind === 'guard-prompt' || kind === 'guard-resolved' || kind === 'proxy-hit';
}
