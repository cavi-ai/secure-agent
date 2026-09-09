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

// ---------- evidence chain ----------

// Parse the correlator's evidence sentences into the causal nodes they
// describe (sensitive read → egress connection → …) and append a
// severity-colored verdict node. Unrecognized sentences fall back to a raw
// node so the audit truth is never hidden by a parser gap.
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
