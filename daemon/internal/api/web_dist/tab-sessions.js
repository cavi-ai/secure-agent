// Sessions tab: session-first. A rail of durable sessions (the P1 spine)
// on the left; the selected session's trace waterfall on the right.
// renderSessionBoard (app.js's panel registry) delegates here when durable
// sessions exist; the legacy process-tree board remains the fallback.

// One rail card per session: name, repo@branch, state chip, last activity,
// live RSS when the tree is up. Kill stays on live cards only.
function sessionRailCardHTML(s, trees, selectedId) {
  const live = s.root_pid && (trees || []).some(t => t.root && Number(t.root.pid) === Number(s.root_pid));
  const tree = live ? (trees || []).find(t => t.root && Number(t.root.pid) === Number(s.root_pid)) : null;
  const rss = tree ? fmtRSS(tree.rss_bytes) : '';
  const status = s.status || 'active';
  const pulse = status === 'active' ? '<span class="sc-pulse active" aria-hidden="true"></span>' : '';
  const seen = s.last_seen_at ? fmtAge(s.last_seen_at, Date.now()) + ' ago' : '';
  return `<button type="button" class="session-card ${status}${s.id === selectedId ? ' selected' : ''}" data-action="select-session" data-id="${escapeHTML(s.id)}" aria-pressed="${s.id === selectedId}">
    <span class="sc-head">${harnessChipHTML(s.harness)}<span class="sc-label">${escapeHTML(sessionLabelDurable(s))}</span></span>
    <span class="sc-meta">${pulse}<span class="sc-state ${escapeHTML(status)}">${escapeHTML(status)}</span>${seen ? `<span>${escapeHTML(seen)}</span>` : ''}${rss ? `<span>${escapeHTML(rss)}</span>` : ''}</span>
  </button>`;
}

// The selected session's trace: waterfall of tool calls, model usage rows,
// and file/net/guard dots. data comes from GET /sessions/{id}/timeline.
function sessionDetailHTML(sess, events) {
  if (!sess) {
    return `<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>Select a session to see its trace</span></div>`;
  }
  const label = sessionLabelDurable(sess);
  const meta = [
    sess.workspace || '',
    sess.started_at ? 'started ' + fmtAge(sess.started_at, Date.now()) + ' ago' : '',
    sess.ended_at ? 'ended ' + fmtAge(sess.ended_at, Date.now()) + ' ago' : '',
    sess.confidence ? 'identity: ' + sess.confidence : '',
  ].filter(Boolean).map(escapeHTML).join(' · ');
  return `<div class="session-detail-head"><h3>${escapeHTML(label)}</h3><span class="sd-meta">${meta}</span></div>
    ${sessionWaterfallHTML(events)}`;
}
