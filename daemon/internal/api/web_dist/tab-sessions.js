// Sessions tab: session-first. A rail of durable sessions (the P1 spine)
// grouped by harness on the left; the selected session's trace waterfall on
// the right. renderSessionBoard (app.js's panel registry) delegates here when
// durable sessions exist; the legacy process-tree board remains the fallback.

// liveTreeFor: the live process tree rooted at a session's root pid, if up.
function liveTreeFor(s, trees) {
  if (!s.root_pid) return null;
  return (trees || []).find(t => t.root && Number(t.root.pid) === Number(s.root_pid)) || null;
}

// One rail card per session: title (the group head already names the
// harness), state chip, last activity, live RSS when the tree is up, a pulse
// while active. Kill stays on live cards only. nested indents a sub-session
// under its parent.
function sessionRailCardHTML(s, trees, selectedId, nested) {
  const tree = liveTreeFor(s, trees);
  const rss = tree ? fmtRSS(tree.rss_bytes) : '';
  const status = s.status || 'active';
  const pulse = status === 'active' ? '<span class="sc-pulse active" aria-hidden="true"></span>' : '';
  const seen = s.last_seen_at ? fmtAge(s.last_seen_at, Date.now()) + ' ago' : '';
  const selected = s.id === selectedId;
  const title = sessionTitle(s, tree && tree.root.cwd);
  const kill = tree && status !== 'ended'
    ? `<button type="button" class="btn btn-danger btn-sm sc-kill" data-action="kill" data-pid="${escapeHTML(tree.root.pid)}" data-started="${escapeHTML(tree.root.started_at || '')}" data-family="${escapeHTML(s.harness || '')}" title="Terminate" aria-label="Terminate ${escapeHTML(title)}"><svg class="icon"><use href="#i-power"/></svg></button>`
    : '';
  return `<div class="session-card ${escapeHTML(status)}${selected ? ' selected' : ''}${nested ? ' nested' : ''}">
    <button type="button" class="sc-main" data-action="select-session" data-id="${escapeHTML(s.id)}" aria-pressed="${selected}">
      <span class="sc-head">${pulse}<span class="sc-label">${escapeHTML(title)}</span></span>
      <span class="sc-meta"><span class="sc-state ${escapeHTML(status)}">${escapeHTML(status)}</span>${seen ? `<span>${escapeHTML(seen)}</span>` : ''}${rss ? `<span>${escapeHTML(rss)}</span>` : ''}</span>
    </button>${kill}
  </div>`;
}

// One harness group: mark + display name + counts in a collapsible head,
// live families (sub-sessions indented), then the collapsed ended tail.
function sessionGroupHTML(g, trees, selectedId, open, endedOpen) {
  const family = f => sessionRailCardHTML(f.session, trees, selectedId, false)
    + f.children.map(c => sessionRailCardHTML(c, trees, selectedId, true)).join('');
  const ended = g.ended.length
    ? `<div class="session-ended${endedOpen ? ' open' : ''}">
        <button type="button" class="session-ended-toggle" data-action="toggle-ended-sessions" data-harness="${escapeHTML(g.key)}" aria-expanded="${endedOpen}">Ended (${familySize(g.ended)}) <svg class="icon"><use href="#i-arrow"/></svg></button>
        <div class="session-ended-body">${g.ended.map(family).join('')}</div>
      </div>`
    : '';
  return `<details class="session-group" data-harness="${escapeHTML(g.key)}"${open ? ' open' : ''}>
    <summary class="session-group-head">${harnessChipHTML(g.key, { label: true })}<span class="session-group-counts">${escapeHTML(sessionGroupCounts(g))}</span></summary>
    <div class="session-group-body">${g.live.map(family).join('')}${ended}</div>
  </details>`;
}

// The trailing infra group: IDEs and model servers, RSS totals only.
function sessionInfraGroupHTML(g, open) {
  const rows = g.items.map(it => `<div class="infra-row">${harnessChipHTML(it.key, { label: true })}<span class="agent-meta-item">${escapeHTML(fmtRSS(it.rss) || '—')}</span></div>`).join('');
  return `<details class="session-group infra" data-harness="infra"${open ? ' open' : ''}>
    <summary class="session-group-head"><span class="session-group-title">Infrastructure</span><span class="session-group-counts">${escapeHTML(fmtRSS(g.rss) || '—')}</span></summary>
    <div class="session-group-body">${rows}</div>
  </details>`;
}

// The selected session's head and trace: mark, repo@branch, harness name,
// identity confidence, workspace path (click copies), Export (copies the
// markdown report from GET /sessions/{id}/report), then the waterfall of
// tool calls, model usage rows, and file/net/guard dots from
// GET /sessions/{id}/timeline.
function sessionDetailHTML(sess, events, trees) {
  if (!sess) {
    return `<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>Select a session to see its trace</span></div>`;
  }
  const tree = liveTreeFor(sess, trees);
  const title = sessionTitle(sess, tree && tree.root.cwd);
  const path = sess.workspace && sess.workspace !== '/' ? sess.workspace : '';
  const meta = [
    sess.started_at ? 'started ' + fmtAge(sess.started_at, Date.now()) + ' ago' : '',
    sess.ended_at ? 'ended ' + fmtAge(sess.ended_at, Date.now()) + ' ago' : '',
  ].filter(Boolean).map(escapeHTML).join(' · ');
  return `<div class="session-detail-head">
      ${harnessChipHTML(sess.harness)}
      <h3>${escapeHTML(title)}</h3>
      <span class="sd-harness">${escapeHTML(harnessMeta(sess.harness).label)}</span>
      ${sess.confidence ? `<span class="ss-chip sd-conf" title="How this session was identified">${escapeHTML(sess.confidence)}</span>` : ''}
      ${path ? `<button type="button" class="sd-path" data-action="copy-path" data-path="${escapeHTML(path)}" title="${escapeHTML(path)} — click to copy">${escapeHTML(middleTruncate(path, 48))}</button>` : ''}
      <button type="button" class="btn btn-sm btn-ghost sd-export" data-action="copy-report" data-id="${escapeHTML(sess.id)}" title="Copy this session's report as markdown"><svg class="icon"><use href="#i-copy"/></svg>Export</button>
      ${meta ? `<span class="sd-meta">${meta}</span>` : ''}
    </div>
    ${sessionWaterfallHTML(events)}`;
}
