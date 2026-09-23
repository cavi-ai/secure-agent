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

// advisorAdviceHTML: the advisor's recommendation on a blocked guard prompt.
// Advisory only — it never resolves the prompt; it informs the human's choice.
// assessment (benign|suspicious|malicious) maps to allow|look|deny.
function advisorAdviceHTML(advice) {
  if (!advice || !advice.rationale) return '';
  const verdict = advice.assessment === 'benign' ? 'allow'
    : advice.assessment === 'malicious' ? 'deny' : 'look';
  const pct = Math.round((Number(advice.confidence) || 0) * 100);
  return `<span class="advisor-advice ${verdict}">`
    + `<b>Advisor suggests ${verdict === 'look' ? 'you look first' : verdict}</b>`
    + `${pct ? ` (${pct}% conf)` : ''} — ${escapeHTML(advice.rationale)}</span>`;
}

// eventClock: RFC3339 → local HH:MM:SS, '' when unparseable. Shared by the
// endpoint drill-down; the timeline's own helper is local to that builder.
function eventClock(s) {
  const d = Date.parse(s);
  return isNaN(d) ? '' : fmtTime(new Date(d));
}

// endpointIdentityLine: one plain sentence naming what an endpoint is, so an
// operator can decide whether an agent's connection is rightful. Pure.
function endpointIdentityLine(identity) {
  if (!identity) return 'Unknown endpoint';
  const org = identity.org || '';
  const name = identity.name || '';
  const isIP = identity.kind === 'ipv6' || identity.kind === 'ipv4';
  if (isIP && org && name) return `${org} address (${name})`;
  if (isIP && org) return `${org} address`;
  if (isIP && name) return `Resolves to ${name}`;
  if (isIP) return 'No owner identified — may be a private or unroutable address';
  if (org) return `${org} (${name})`;
  return name || 'Unknown endpoint';
}

// endpointDetailHTML: the endpoint evidence drawer. Pure function — the DOM
// tests drive it headless.
function endpointDetailHTML(detail, clickedAgent) {
  if (!detail || !detail.host) {
    return '<div class="empty"><span>No endpoint data</span></div>';
  }
  const id = detail.identity || {};
  const kindChip = id.kind === 'ipv6' ? 'IPv6' : id.kind === 'ipv4' ? 'IPv4' : 'hostname';
  const facts = [
    detail.count ? `<b>${detail.count}×</b> in 7d` : '',
    detail.last_seen ? `last ${fmtAge(detail.last_seen, Date.now())} ago` : '',
    detail.first_seen ? `first seen ${fmtAge(detail.first_seen, Date.now())} ago` : '',
  ].filter(Boolean).join(' · ');

  const agents = (detail.agents || []).map(a => {
    const isClicked = clickedAgent && a === clickedAgent;
    return `<button type="button" class="btn btn-ghost btn-sm${isClicked ? ' active' : ''}" data-action="allow-host" data-agent="${escapeHTML(a)}" data-host="${escapeHTML(detail.host)}">Allow for ${escapeHTML(a)}</button>`;
  }).join('');

  const sessions = (detail.sessions || []).map(s => `
    <div class="endpoint-session">
      <strong>${escapeHTML(s.harness || 'agent')}</strong>
      <span>${escapeHTML(s.repo ? `${s.repo}${s.branch ? '@' + s.branch : ''}` : (s.workspace || 'unknown workspace'))}</span>
      <span class="endpoint-session-id">${escapeHTML(String(s.id || '').slice(0, 8))}</span>
    </div>`).join('') || '<div class="resource-detail-empty">No session attribution on these connections.</div>';

  const events = (detail.events || []).slice(0, 20).map(e => `
    <div class="endpoint-event">
      <span class="endpoint-event-time">${escapeHTML(eventClock(e.ts))}</span>
      <span class="endpoint-event-port">:${escapeHTML(String(e.remote_port || ''))}</span>
      <span class="endpoint-event-agent">${escapeHTML(e.session_id ? 'session ' + String(e.session_id).slice(0, 8) : (e.exe_path ? String(e.exe_path).split('/').pop() : 'agent'))}</span>
    </div>`).join('') || '<div class="resource-detail-empty">No recorded connections.</div>';

  const allowed = (detail.allowed || []).length
    ? `<div class="endpoint-allowed">Already trusted for ${(detail.allowed || []).map(a => escapeHTML(a.agent)).join(', ')} — this endpoint stops being flagged for them.</div>`
    : '';

  return `
    <div class="endpoint-head">
      <div class="endpoint-host">${escapeHTML(detail.host)}</div>
      <span class="endpoint-kind">${escapeHTML(kindChip)}</span>
    </div>
    <p class="endpoint-identity">${escapeHTML(endpointIdentityLine(id))}</p>
    ${facts ? `<p class="endpoint-facts">${facts}</p>` : ''}
    ${allowed}
    <div class="endpoint-actions">${agents || ''}</div>
    <section class="endpoint-section"><h4>Reached by</h4>${sessions}</section>
    <section class="endpoint-section"><h4>Recent connections</h4>${events}</section>`;
}

// shared by the flag card chip and the timeline filter chip.
function sessionShort(id) {
  return String(id || '').slice(0, 8);
}

// harnessMeta: per-harness identity for the console — display name, brand
// color, and the sprite symbol of its mark (index.html, #logo-*). Needles
// match the harness names the daemon reports by substring, first match wins,
// so "cursor-ide" is listed before "cursor". Infra entries (IDEs, local model
// servers) are tracked but shown apart and never counted as agents. Known
// harnesses without a mark keep a text glyph. Colors must match the .hk-<key>
// rules in style.css. Pure: returns data, no DOM.
const HARNESS_TABLE = [
  { needle: 'claude', key: 'claude', label: 'Claude Code', color: '#D97757', logo: 'logo-claude' },
  { needle: 'cursor-ide', key: 'cursor-ide', label: 'Cursor', color: '#000000', logo: 'logo-cursor', tile: 'light', infra: true },
  { needle: 'cursor', key: 'cursor', label: 'Cursor', color: '#000000', logo: 'logo-cursor', tile: 'light' },
  { needle: 'codex', key: 'codex', label: 'Codex', color: '#10A37F', logo: 'logo-codex' },
  { needle: 'opencode', key: 'opencode', label: 'opencode', color: '#000000', logo: 'logo-opencode' },
  { needle: 'openclaw', key: 'openclaw', label: 'OpenClaw', color: 'hsl(342 62% 62%)', glyph: 'O' },
  { needle: 'antigravity', key: 'agy', label: 'Antigravity', color: '#8E75B2', logo: 'logo-gemini' },
  { needle: 'agy', key: 'agy', label: 'Antigravity', color: '#8E75B2', logo: 'logo-gemini' },
  { needle: 'gemini', key: 'gemini', label: 'Gemini', color: '#8E75B2', logo: 'logo-gemini' },
  { needle: 'windsurf', key: 'windsurf', label: 'Windsurf', color: '#0B100F', logo: 'logo-windsurf' },
  { needle: 'aider', key: 'aider', label: 'Aider', color: 'hsl(20 90% 58%)', glyph: '◉' },
  { needle: 'codeium', key: 'codeium', label: 'Codeium', color: 'hsl(201 88% 46%)', glyph: '◈' },
  { needle: 'copilot', key: 'copilot', label: 'GitHub Copilot', color: 'hsl(220 12% 60%)', glyph: '◍' },
  { needle: 'ollama', key: 'ollama', label: 'Ollama', color: '#000000', logo: 'logo-ollama', infra: true },
  { needle: 'lm-studio', key: 'lm-studio', label: 'LM Studio', color: '#000000', logo: 'logo-lm-studio', infra: true },
  { needle: 'lmstudio', key: 'lm-studio', label: 'LM Studio', color: '#000000', logo: 'logo-lm-studio', infra: true },
];

function harnessMeta(name) {
  const key = String(name || '').toLowerCase();
  for (const h of HARNESS_TABLE) {
    if (!key.includes(h.needle)) continue;
    return {
      key: h.key, label: h.label, color: h.color, logo: h.logo || '',
      glyph: h.glyph || '', tile: h.tile || '', infra: !!h.infra, known: true,
    };
  }
  // Unknown harness: deterministic hue from the name, first letter as glyph.
  let h = 2166136261;
  for (const b of key) h = (h ^ b.charCodeAt(0)) >>> 0, h = Math.imul(h, 16777619) >>> 0;
  return {
    key: key.trim() || 'agent', label: familyTitle(String(name || '').trim() || 'agent'),
    color: `hsl(${h % 360} 62% 62%)`, logo: '',
    glyph: (name || '?').trim().slice(0, 1).toUpperCase() || '?',
    tile: '', infra: false, known: false,
  };
}

// harnessChipHTML: the harness mark for list rows and group heads. A known
// mark renders white on its brand tile (Cursor dark on a light tile); the
// tile color comes from the .hk-<key> class because the console CSP
// (style-src 'self') drops inline style attributes. Unknown harnesses keep
// the hashed-hue initial. opts.label appends the display name as text.
function harnessChipHTML(name, opts) {
  const m = harnessMeta(name);
  let mark;
  if (m.logo) {
    mark = `<span class="harness-tile hk-${escapeHTML(m.key)}${m.tile === 'light' ? ' light' : ''}" aria-hidden="true">`
      + `<svg class="harness-logo" aria-hidden="true"><use href="#${escapeHTML(m.logo)}"/></svg></span>`;
  } else if (m.known) {
    mark = `<span class="harness-glyph hk-${escapeHTML(m.key)}" aria-hidden="true">${escapeHTML(m.glyph)}</span>`;
  } else {
    mark = `<span class="harness-glyph" style="--harness-color:${m.color}" aria-hidden="true">${escapeHTML(m.glyph)}</span>`;
  }
  const label = opts && opts.label ? `<span class="harness-label">${escapeHTML(m.label)}</span>` : '';
  return `<span class="harness-chip" title="${escapeHTML(m.known ? m.label : (name || 'agent'))}">${mark}${label}</span>`;
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

// groupSessionsByHarness: the Sessions rail, harness-first. One group per
// harness with its live families (active before idle, newest first) and an
// ended tail. A session whose parent_id names another listed session nests
// one level under its top-most listed ancestor, walking up only while the
// ancestor sits in the same group and the same live/ended half. Groups order
// by their most recent live activity; groups with nothing live sink to the
// bottom. Infra (by harness, or by the /status agent kind) never joins the
// rail: it folds into one trailing "Infrastructure" group of RSS totals.
// Pure; the console and the tests both consume it.
function groupSessionsByHarness(sessions, trees, agents) {
  const list = (sessions || []).filter(Boolean);
  const infraKeys = new Set();
  for (const a of agents || []) if (a && a.kind === 'infra') infraKeys.add(harnessMeta(a.name).key);
  const isInfra = (m) => m.infra || infraKeys.has(m.key);
  const statusOf = (s) => (s.status === 'ended' || s.status === 'idle' ? s.status : 'active');
  const isLive = (s) => statusOf(s) !== 'ended';
  const seenOf = (s) => String(s.last_seen_at || '');
  const keyOf = new Map(list.map(s => [s, harnessMeta(s.harness).key]));
  const byId = new Map(list.map(s => [s.id, s]));

  // A parent_id cycle has no top: its members stay top-level.
  const topOf = (s) => {
    let cur = s;
    const visited = new Set([s]);
    for (;;) {
      const p = cur.parent_id ? byId.get(cur.parent_id) : null;
      if (p && visited.has(p)) return s;
      if (!p || keyOf.get(p) !== keyOf.get(s) || isLive(p) !== isLive(s)) return cur;
      visited.add(p);
      cur = p;
    }
  };

  const groups = new Map();
  const families = new Map();
  for (const s of list) {
    const m = harnessMeta(s.harness);
    if (isInfra(m)) continue;
    if (!groups.has(m.key)) groups.set(m.key, { key: m.key, label: m.label, infra: false, live: [], ended: [], lastLive: '', lastSeen: '' });
    const g = groups.get(m.key);
    if (seenOf(s) > g.lastSeen) g.lastSeen = seenOf(s);
    if (isLive(s) && seenOf(s) > g.lastLive) g.lastLive = seenOf(s);
    const top = topOf(s);
    if (!families.has(top)) {
      const fam = { session: top, children: [] };
      families.set(top, fam);
      (isLive(top) ? g.live : g.ended).push(fam);
    }
    if (top !== s) families.get(top).children.push(s);
  }

  const byRecency = (a, b) => (seenOf(b) > seenOf(a) ? 1 : seenOf(b) < seenOf(a) ? -1 : 0);
  const famSeen = (f) => [f.session, ...f.children].map(seenOf).sort().pop();
  const famRank = (f) => ([f.session, ...f.children].some(s => statusOf(s) === 'active') ? 0 : 1);
  for (const g of groups.values()) {
    for (const f of [...g.live, ...g.ended]) f.children.sort(byRecency);
    g.live.sort((a, b) => famRank(a) - famRank(b) || (famSeen(b) > famSeen(a) ? 1 : famSeen(b) < famSeen(a) ? -1 : 0));
    g.ended.sort((a, b) => (famSeen(b) > famSeen(a) ? 1 : famSeen(b) < famSeen(a) ? -1 : 0));
  }
  const ordered = [...groups.values()].sort((a, b) => {
    if (!!a.lastLive !== !!b.lastLive) return a.lastLive ? -1 : 1;
    const ka = a.lastLive || a.lastSeen, kb = b.lastLive || b.lastSeen;
    if (ka !== kb) return kb > ka ? 1 : -1;
    return a.key.localeCompare(b.key);
  });

  // Infra totals: live process trees when the daemon sends them, else the
  // flat /status agent list.
  const infra = new Map();
  const bump = (m, rss) => {
    if (!infra.has(m.key)) infra.set(m.key, { key: m.key, label: m.label, rss: 0 });
    infra.get(m.key).rss += rss;
  };
  if (trees && trees.length) {
    for (const t of trees) {
      const r = (t && t.root) || {};
      const m = harnessMeta(r.name);
      if (isInfra(m) || r.kind === 'infra') bump(m, Number(t.rss_bytes || 0));
    }
  } else {
    for (const a of agents || []) {
      const m = harnessMeta(a && a.name);
      if (a && (isInfra(m) || a.kind === 'infra')) bump(m, Number(a.rss_bytes || 0));
    }
  }
  if (infra.size) {
    const items = [...infra.values()].sort((a, b) => b.rss - a.rss || a.key.localeCompare(b.key));
    ordered.push({
      key: 'infra', label: 'Infrastructure', infra: true, live: [], ended: [],
      items, rss: items.reduce((n, it) => n + it.rss, 0),
    });
  }
  return ordered;
}

// sessionMatchesText: the text filter's fields — repo, branch, repo@branch
// and workspace, case-insensitive. An empty query matches everything.
function sessionMatchesText(s, text) {
  const q = String(text || '').trim().toLowerCase();
  if (!q) return true;
  const repoBranch = s.repo ? `${s.repo}${s.branch ? '@' + s.branch : ''}` : '';
  return [s.repo, s.branch, repoBranch, s.workspace]
    .some(f => String(f || '').toLowerCase().includes(q));
}

// applySessionFilters: the rail's filter row over groupSessionsByHarness
// output. opts.harnesses maps a harness key to false when its pill is off;
// opts.text keeps a family when any member matches; opts.liveOnly drops
// groups with nothing live. The infra group carries totals, not sessions, and
// is never filtered. Pure; returns new group objects.
function applySessionFilters(groups, opts) {
  const o = opts || {};
  const off = o.harnesses || {};
  const keep = (fams) => fams.filter(f => [f.session, ...f.children].some(s => sessionMatchesText(s, o.text)));
  const out = [];
  for (const g of groups || []) {
    if (g.infra) { out.push(g); continue; }
    if (off[g.key] === false) continue;
    const live = keep(g.live);
    const ended = keep(g.ended);
    if (!live.length && !ended.length) continue;
    if (o.liveOnly && !live.length) continue;
    out.push({ ...g, live, ended });
  }
  return out;
}

// familySize: sessions in a list of families, sub-sessions included.
function familySize(fams) {
  return (fams || []).reduce((n, f) => n + 1 + f.children.length, 0);
}

// sessionGroupCounts: the group head's "3 active · 1 idle · 12 ended".
function sessionGroupCounts(g) {
  const c = { active: 0, idle: 0, ended: 0 };
  for (const f of [...(g.live || []), ...(g.ended || [])]) {
    for (const s of [f.session, ...f.children]) {
      c[s.status === 'ended' || s.status === 'idle' ? s.status : 'active']++;
    }
  }
  return ['active', 'idle', 'ended'].filter(k => c[k]).map(k => `${c[k]} ${k}`).join(' · ');
}

// sessionCountStrip: the rail's one-line census — live sessions, harnesses
// with live work, and the daemon's coverage (/status.coverage) when it has a
// live harness count.
function sessionCountStrip(groups, coverage) {
  let n = 0;
  let k = 0;
  for (const g of groups || []) {
    if (g.infra) continue;
    const live = familySize(g.live);
    n += live;
    if (live) k++;
  }
  const parts = [`Sessions ${n}`, `Harnesses ${k}`];
  if (coverage && coverage.harnesses_active > 0) parts.push(`seeing ${coverage.harnesses_seen}/${coverage.harnesses_active}`);
  return parts.join(' · ');
}

// harnessPillsHTML: one toggle pill per harness, shared by the Sessions and
// Agents filter rows. harnesses[key] === false renders the pill off.
function harnessPillsHTML(keys, harnesses) {
  const off = harnesses || {};
  return (keys || []).map(k => {
    const on = off[k] !== false;
    return `<button type="button" class="harness-pill${on ? '' : ' off'}" data-action="toggle-harness" data-harness="${escapeHTML(k)}" aria-pressed="${on}">${harnessChipHTML(k, { label: true })}</button>`;
  }).join('');
}

// middleTruncate: keep both ends of a long path — the root says where, the
// tail says which — and elide the middle.
function middleTruncate(str, max) {
  const s = String(str || '');
  if (s.length <= max) return s;
  const keep = max - 1;
  return s.slice(0, Math.ceil(keep / 2)) + '…' + s.slice(s.length - Math.floor(keep / 2));
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
// Structured items (kind "connect") carry it directly; legacy rows from
// older daemons arrive as {kind:"text"} and keep the string fallback.
function flagHost(flag) {
  for (const ev of (flag && flag.evidence) || []) {
    if (ev && ev.kind === 'connect' && ev.label) return String(ev.label).split(':')[0];
    const s = typeof ev === 'string' ? ev : (ev && ev.text) || '';
    const m = s.match(/connected to ([^:\s]+):\d+/) || s.match(/connecting to ([^:\s]+):\d+/);
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

// Render the flag's evidence items as causal nodes (sensitive read → egress
// connection → …) and append a severity-colored verdict node. Evidence is
// structured daemon-side; only legacy rows (kind "text") render as raw text.
// ---------- evidence chain ----------

const EVIDENCE_ICONS = {
  read:      { icon: 'i-key',    cls: 'cn-read' },
  connect:   { icon: 'i-globe',  cls: 'cn-egress' },
  keychain:  { icon: 'i-key',    cls: 'cn-read' },
  exec:      { icon: 'i-power',  cls: 'cn-read' },
  tcc:       { icon: 'i-alert',  cls: 'cn-read' },
  violation: { icon: 'i-shield', cls: 'cn-read' },
  text:      { icon: 'i-alert',  cls: '' },
};

function buildEvidenceChain(flag) {
  const nodes = [];
  const ts = (s) => {
    const d = Date.parse(s);
    return isNaN(d) ? '' : fmtTime(new Date(d));
  };
  for (const ev of (flag.evidence || [])) {
    if (typeof ev === 'string') { // pre-structured wire rows
      nodes.push({ icon: 'i-alert', cls: '', label: ev, sub: '' });
      continue;
    }
    const style = EVIDENCE_ICONS[ev.kind] || EVIDENCE_ICONS.text;
    const when = ev.ts ? ` · ${ts(ev.ts)}` : '';
    const sub = ev.kind === 'text' ? '' : (ev.sub || '') + when;
    nodes.push({ icon: style.icon, cls: style.cls, label: ev.label || ev.text || '', sub });
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

// Operator-facing rule titles come from the daemon (flag.title); this table
// is only the fallback for rows from older daemons.
var RULE_TITLES = {
  'proxy-secret-leak': 'Secret leaving in agent traffic',
  'sensitive-read-then-connect': 'Secret read, then connected out',
  'keychain-access': 'Keychain file access',
  'keychain-security-cli': 'Keychain CLI (security tool)',
  'tcc-tamper': 'Privacy permissions (TCC) tamper',
  'proxy-prompt-injection': 'Prompt injection in a response',
};

function ruleTitle(rule) {
  // Prefer the daemon-served title on any loaded flag carrying this rule.
  const flags = (window.SA && window.SA.t && window.SA.t.flags) || [];
  for (const f of flags) { if (f.rule === rule && f.title) return f.title; }
  return RULE_TITLES[rule] || String(rule || 'unknown');
}

// hbarsHTML renders a ranked horizontal-bar list — the readable chart for
// "which of these is biggest" without axes or a plotting dependency.
// rows: [{label, value, sub, cls}], value compared against the max.
function hbarsHTML(rows, opts) {
  opts = opts || {};
  const fmt = opts.format || (v => String(v));
  const max = Math.max(1, ...rows.map(r => r.value));
  return rows.map(r => {
    const pct = Math.max(2, (r.value / max) * 100);
    return `<div class="hbar-row">
      <span class="hbar-label" title="${escapeHTML(r.titleAttr || r.label)}">${escapeHTML(r.label)}</span>
      <span class="hbar-track"><span class="hbar-fill ${r.cls || ''}" style="width:${pct.toFixed(1)}%"></span></span>
      <span class="hbar-val">${escapeHTML(fmt(r.value))}</span>
      ${r.sub ? `<span class="hbar-sub">${escapeHTML(r.sub)}</span>` : ''}
    </div>`;
  }).join('');
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

// groupAgentsByHarness: the Agents tab, harness-first like the Sessions
// rail. One group per harness holding its instances (process-tree roots,
// most recent activity first) with their helper processes. Groups order by
// most recent activity. A group is infra when the harness is (IDEs, model
// servers) or the daemon tags a member kind=infra; callers show infra apart
// and never count it as agents. Pure.
function groupAgentsByHarness(agents) {
  const byKey = new Map();
  for (const a of agents || []) {
    if (!a) continue;
    const m = harnessMeta(a.name);
    if (!byKey.has(m.key)) byKey.set(m.key, { key: m.key, label: m.label, infra: m.infra, members: [], lastSeen: '' });
    const g = byKey.get(m.key);
    if (a.kind === 'infra') g.infra = true;
    if (a.last_seen_at && a.last_seen_at > g.lastSeen) g.lastSeen = a.last_seen_at;
    g.members.push(a);
  }
  const newest = (x, y) => (x > y ? -1 : x < y ? 1 : 0);
  const groups = [...byKey.values()].map(g => {
    const instances = g.members
      .filter(a => isFamilyRoot(a, g.members))
      .map(root => ({ root, children: childrenOf(root, g.members) }))
      .sort((x, y) => newest(String(x.root.last_seen_at || ''), String(y.root.last_seen_at || '')));
    return { key: g.key, label: g.label, infra: g.infra, lastSeen: g.lastSeen, instances };
  });
  return groups.sort((a, b) => newest(a.lastSeen, b.lastSeen) || a.key.localeCompare(b.key));
}

// agentGroupTotals: the group head's figures over the instances shown —
// instances, processes, RSS, CPU, last seen, leftovers.
function agentGroupTotals(g) {
  const t = { instances: g.instances.length, processes: 0, rss: 0, cpu: 0, lastSeen: '', orphans: 0 };
  for (const inst of g.instances) {
    for (const a of [inst.root, ...inst.children]) {
      t.processes++;
      t.rss += Number(a.rss_bytes || 0);
      t.cpu += Number(a.cpu_percent || 0);
      if (a.last_seen_at && a.last_seen_at > t.lastSeen) t.lastSeen = a.last_seen_at;
      if (a.is_orphan) t.orphans++;
    }
  }
  return t;
}

// applyAgentFilters: the Agents filter row, the same pill and text state as
// the Sessions rail. Text matches an instance's repo, branch, workspace or
// cwd; helpers ride along with their instance. Infra groups are never
// filtered. Pure; returns new group objects.
function applyAgentFilters(groups, opts) {
  const o = opts || {};
  const off = o.harnesses || {};
  const hit = a => sessionMatchesText(a, o.text) || sessionMatchesText({ workspace: a.cwd }, o.text);
  const out = [];
  for (const g of groups || []) {
    if (g.infra) { out.push(g); continue; }
    if (off[g.key] === false) continue;
    const instances = g.instances.filter(i => [i.root, ...i.children].some(hit));
    if (instances.length) out.push({ ...g, instances });
  }
  return out;
}

function cwdLabel(cwd) {
  if (!cwd) return '';
  const s = String(cwd).replace(/\/+$/, '');
  const i = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
  return i >= 0 ? s.slice(i + 1) : s;
}

// Session-first timeline: a waterfall of tool calls (bars spanning
// start→result), model calls (token rows), and file/network/guard dots on
// the same axis. Pure function — the DOM tests drive it headless.
function sessionWaterfallHTML(events) {
  const toolCalls = (events || []).filter(e => e.kind === 12);
  const modelCalls = (events || []).filter(e => e.kind === 14);
  const dots = (events || []).filter(e => e.kind !== 12 && e.kind !== 13 && e.kind !== 14);
  if (!events || events.length === 0) {
    return '<div class="empty"><span>No trace events for this session yet</span></div>';
  }
  const startOf = e => Date.parse(e.ts) || 0;
  const endOf = e => startOf(e) + (Number(e.duration_ms) || 0);
  let lo = Infinity, hi = -Infinity;
  for (const e of events) {
    lo = Math.min(lo, startOf(e));
    hi = Math.max(hi, endOf(e));
  }
  if (hi <= lo) hi = lo + 1000; // degenerate single-instant window
  const span = hi - lo;
  const pct = t => Math.max(0, Math.min(100, (t - lo) / span * 100));
  const wid = (a, b) => Math.max(0.4, (b - a) / span * 100);

  const fmtClock = t => {
    const d = new Date(t);
    return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0') + ':' + String(d.getSeconds()).padStart(2, '0');
  };

  const bars = toolCalls.map(e => {
    const err = e.tool_status === 'error' ? ' error' : '';
    const dur = e.duration_ms ? fmtDurationMs(e.duration_ms) : '';
    return `<div class="wf-row"><span class="wf-name">${escapeHTML(e.tool || 'tool')}<span class="wf-dur">${escapeHTML(dur)}</span></span><span class="wf-track"><span class="wf-bar${err}" style="left:${pct(startOf(e)).toFixed(2)}%;width:${wid(startOf(e), endOf(e)).toFixed(2)}%"></span></span></div>`;
  }).join('');

  const dotCls = e => {
    if (e.kind === 5 || e.kind === 6) return 'conn';
    if (e.kind === 10 || e.kind === 11) return 'guard';
    return '';
  };
  const dotRow = dots.length
    ? `<div class="wf-row"><span class="wf-name">file · net · guard</span><span class="wf-track">${dots.map(e => `<span class="wf-dot ${dotCls(e)}" style="left:${pct(startOf(e)).toFixed(2)}%"></span>`).join('')}</span></div>`
    : '';

  const modelRows = modelCalls.map(e => {
    const tok = `${fmtCompact(e.tokens_in || 0)} in · ${fmtCompact(e.tokens_out || 0)} out`;
    const cost = e.cost_usd ? `$${e.cost_usd.toFixed(4)}` : '';
    return `<div class="wf-model"><span><b>${escapeHTML(e.model || 'model')}</b> · ${escapeHTML(fmtClock(startOf(e)))}</span><span>${escapeHTML(tok)}${cost ? ' · ' + escapeHTML(cost) : ''}</span></div>`;
  }).join('');

  return `<div class="wf">
    <div class="wf-axis"><span>${escapeHTML(fmtClock(lo))}</span><span>${escapeHTML(fmtClock(hi))}</span></div>
    ${bars}${dotRow}${modelRows}
  </div>`;
}

function fmtDurationMs(ms) {
  ms = Number(ms) || 0;
  if (ms < 1000) return ms + 'ms';
  if (ms < 60000) return (ms / 1000).toFixed(1).replace(/\.0$/, '') + 's';
  return Math.floor(ms / 60000) + 'm ' + Math.round((ms % 60000) / 1000) + 's';
}

function fmtCompact(n) {
  n = Number(n) || 0;
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return String(n);
}

// sessionTitle: what a session is working on — repo@branch, else the
// workspace folder, else the live process tree's folder (a provisional
// session's workspace can be "/"), else the short id. No harness prefix: the
// rail group and the detail head name the harness beside it.
function sessionTitle(s, liveCwd) {
  if (s.repo) return `${s.repo}${s.branch ? '@' + s.branch : ''}`;
  return cwdLabel(s.workspace) || cwdLabel(liveCwd) || sessionShort(s.id);
}

// matchesSearch: the global-search lens. Free text (already lowercased by the
// caller) matched against the human-visible fields of any row kind — agent,
// rule, host, path, detail, evidence. A missing term matches everything.
function matchesSearch(term, ...fields) {
  if (!term) return true;
  for (const f of fields) {
    if (f == null) continue;
    const s = Array.isArray(f) ? f.join(' ') : String(f);
    if (s.toLowerCase().includes(term)) return true;
  }
  return false;
}

// hostSuffix groups endpoints for bulk decisions: the registrable-ish tail
// (last two labels) for names, the address itself for IPs/short hosts.
// Approximate by design — no public-suffix list ships with the console; the
// button always names exactly what it will allow.
function hostSuffix(host) {
  const h = String(host || '');
  if (!h || h.includes(':') || /^[\d.]+$/.test(h)) return h;
  const parts = h.split('.');
  return parts.length > 2 ? parts.slice(-2).join('.') : h;
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
