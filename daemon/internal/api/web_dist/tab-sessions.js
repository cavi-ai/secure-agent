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
// under its parent; label, when set, replaces the title (a collapsed row's
// member reads by its start time).
function sessionRailCardHTML(s, trees, selectedId, nested, label) {
  const tree = liveTreeFor(s, trees);
  const rss = tree ? fmtRSS(tree.rss_bytes) : '';
  const status = s.status || 'active';
  const pulse = status === 'active' ? '<span class="sc-pulse active" aria-hidden="true"></span>' : '';
  const seen = s.last_seen_at ? fmtAge(s.last_seen_at, Date.now()) + ' ago' : '';
  const selected = s.id === selectedId;
  const title = label || sessionTitle(s, tree && tree.root.cwd);
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

// One harness group's shell: mark + display name + counts in a collapsible
// head, an empty live row list, then the collapsed ended tail's toggle and
// empty row list. sessionRailRows fills both lists through patchList;
// syncSessionGroupShell keeps the counts current on a kept shell.
function sessionGroupHTML(g, open, endedOpen) {
  const ended = g.ended.length
    ? `<div class="session-ended${endedOpen ? ' open' : ''}">
        <button type="button" class="session-ended-toggle" data-action="toggle-ended-sessions" data-harness="${escapeHTML(g.key)}" aria-expanded="${endedOpen}">Ended (${familySize(g.ended)}) <svg class="icon"><use href="#i-arrow"/></svg></button>
        <div class="session-ended-body"></div>
      </div>`
    : '';
  return `<details class="session-group" data-harness="${escapeHTML(g.key)}"${open ? ' open' : ''}>
    <summary class="session-group-head">${harnessChipHTML(g.key, { label: true })}<span class="session-group-counts">${escapeHTML(sessionGroupCounts(g))}</span></summary>
    <div class="session-group-body"><div class="session-rows"></div>${ended}</div>
  </details>`;
}

// syncSessionGroupShell: a kept group shell's volatile text — the head's
// counts, the ended toggle's count and open state — written in place, so a
// status change never rebuilds the group or its rows.
function syncSessionGroupShell(node, g, endedOpen) {
  const counts = node.querySelector('.session-group-counts');
  const text = sessionGroupCounts(g);
  if (counts && counts.textContent !== text) counts.textContent = text;
  const ended = node.querySelector('.session-ended');
  if (!ended) return;
  ended.classList.toggle('open', endedOpen);
  const toggle = ended.querySelector('.session-ended-toggle');
  if (!toggle) return;
  toggle.setAttribute('aria-expanded', String(endedOpen));
  const label = toggle.firstChild;
  const want = `Ended (${familySize(g.ended)}) `;
  if (label && label.nodeType === 3 && label.nodeValue !== want) label.nodeValue = want;
}

// sessionRailRows: one half (bucket: 'live' or 'ended') of a harness group as
// patchList items, keyed by session id, or by group:<harness>|<title> for
// sessions folded by collapseSessionFamilies. dupOpen maps '<bucket>|<key>'
// to a folded row's expanded state, so a live and an ended fold with one
// title open apart; unset, a row is open while it holds the selected session.
function sessionRailRows(fams, harness, trees, selectedId, dupOpen, bucket) {
  const titleOf = s => { const t = liveTreeFor(s, trees); return sessionTitle(s, t && t.root.cwd); };
  return collapseSessionFamilies(fams, harness, titleOf).map(r => {
    if (!r.dup) {
      const f = r.family;
      const cards = sessionRailCardHTML(f.session, trees, selectedId, false)
        + f.children.map(c => sessionRailCardHTML(c, trees, selectedId, true)).join('');
      return { key: r.key, html: f.children.length ? `<div class="session-family">${cards}</div>` : cards };
    }
    const state = bucket ? `${bucket}|${r.key}` : r.key;
    const set = dupOpen && Object.prototype.hasOwnProperty.call(dupOpen, state);
    const open = set ? !!dupOpen[state] : r.sessions.some(s => s.id === selectedId);
    return { key: r.key, html: sessionDupRowHTML(r, trees, selectedId, open, bucket) };
  });
}

// A folded row: "title ×N" with the most active member's status; open, it
// lists each member by start time (HH:MM) and status, selectable as a card.
function sessionDupRowHTML(r, trees, selectedId, open, bucket) {
  const status = r.status;
  const pulse = status === 'active' ? '<span class="sc-pulse active" aria-hidden="true"></span>' : '';
  const members = open
    ? `<div class="session-dup-body">${r.sessions.map(s => sessionRailCardHTML(s, trees, selectedId, true, fmtHHMM(s.started_at) || sessionShort(s.id))).join('')}</div>`
    : '';
  return `<div class="session-dup ${escapeHTML(status)}${open ? ' open' : ''}">
    <button type="button" class="session-dup-toggle" data-action="toggle-session-dup" data-key="${escapeHTML(r.key)}" aria-expanded="${open}"${bucket ? ` data-bucket="${escapeHTML(bucket)}"` : ''}>
      <span class="sc-head">${pulse}<span class="sc-label">${escapeHTML(r.title)}</span><span class="session-dup-count">×${r.sessions.length}</span><svg class="icon"><use href="#i-arrow"/></svg></span>
      <span class="sc-meta"><span class="sc-state ${escapeHTML(status)}">${escapeHTML(status)}</span></span>
    </button>${members}
  </div>`;
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
