function decisionPermissionReceipt(decision, reviewID, sessionID) {
  const ids = decision?.scope_ids;
  if (typeof reviewID !== 'string' || !reviewID || !Number.isSafeInteger(decision?.revision) || decision.revision < 1 || !Array.isArray(ids) ||
      !ids.length || ids.length > 128 || ids.some(id => typeof id !== 'string' || !id)) return null;
  return { sessionID, reviewID, revision: decision.revision, at: decision.at, ids: [...new Set(ids)] };
}

function sessionPermissionReceipt(data, reviewID, sessionID) {
  if (!sessionID || data?.session_id !== sessionID) return null;
  return decisionPermissionReceipt(data.history?.reviews?.find(r => r.id === reviewID)?.decision, reviewID, sessionID);
}

function reviewResultPermissionReceipt(result) {
  const decision = result?.receipt;
  if (!validReviewReceipt(decision, decision?.id, decision?.revision, 'expect')) return null;
  const session = result.review?.context?.session_id;
  return decisionPermissionReceipt(decision, decision.id, typeof session === 'string' ? session : '');
}

function validGuardReceipt(r, request) {
  return !!r && r.id === request.id && r.verdict === request.verdict && r.scope === request.scope &&
    typeof r.id === 'string' && !!r.id && ['allow','deny'].includes(r.verdict) &&
    ['once','always','session','exact'].includes(r.scope) && typeof r.rule_id === 'string' && !!r.rule_id &&
    typeof r.at === 'string' && Number.isFinite(Date.parse(r.at)) &&
    (r.session_id == null || typeof r.session_id === 'string') &&
    (r.scope_ids == null || (Array.isArray(r.scope_ids) && r.scope_ids.length <= 128 && r.scope_ids.every(id => typeof id === 'string' && !!id))) &&
    (!r.scope_ids?.length || (r.verdict === 'allow' && ['session','exact'].includes(r.scope)));
}

function guardPermissionReceipt(decision, sessionID) {
  if (!decision || decision.session_id !== sessionID || !validGuardReceipt(decision,decision) || !decision.scope_ids?.length) return null;
  return {kind:'guard',sessionID,reviewID:decision.id,at:decision.at,ids:[...new Set(decision.scope_ids)]};
}

function guardResultHTML(result) {
  const r = result.receipt;
  const title = result.expired ? 'Request no longer pending' : result.unconfirmed ? 'Answer not confirmed' : 'Answer submitted';
  const meaning = result.expired ? 'This answer was not submitted to a waiting request. Check session results for the recorded outcome.' : result.unconfirmed ? 'Check session results and permissions before deciding again. The answer may have reached the daemon.'
    : 'The daemon submitted this answer to the waiting request. This does not prove the tool received it, completed access, or saved request history.';
  const decision = r || result.request;
  return `<div class="panel-head"><h2 id="guard-result-title">${title}</h2><button type="button" class="btn btn-ghost btn-sm" data-action="guard-result-dismiss">Dismiss</button></div>
    <div class="panel-body"><p>${escapeHTML(decision.verdict)} · ${escapeHTML(decision.scope)}${r ? ` · ${escapeHTML(r.rule_id)} · ${escapeHTML(r.at)}` : ''}</p><p>${meaning}</p>
    ${!r && !result.unconfirmed && !result.expired ? '<p>Detailed receipt unavailable from this daemon.</p>' : ''}
    ${guardPermissionReceipt(r,r?.session_id) ? '<button type="button" class="btn btn-ghost btn-sm" data-action="guard-result-permissions">View permissions</button>' : ''}
    ${(r?.session_id || result.sessionID) ? '<button type="button" class="btn btn-ghost btn-sm" data-action="guard-result-history">Check session results</button>' : '<p>Session identity unavailable; inspect Rules &amp; permissions for current policy.</p>'}</div>`;
}

// No optimistic permission or receipt: only a matching daemon answer confirms
// submission. Failed responses are ambiguous and never replay automatically.
function guardScopeConfirmation(p, verdict, scope, expiry) {
  const effect = scope === 'always' ? `${verdict} every future path matched by rule ${p.rule_id || p.rule || 'unavailable'}`
    : `allow this file and tool ${scope === 'session' ? 'until this session ends' : `for ${expiry === '7d' ? '7 days' : '24 hours'}`}`;
  return `${effect}.\n\nAgent: ${p.agent || p.group?.agent || 'Unknown'}\nOperation: ${p.tool || 'Unknown'}\nResource: ${p.path || 'Unknown'}\nWorkspace: ${p.workspace || p.group?.workspace || 'Unknown'}\nExecutable path: ${p.reader_exe || 'Unknown'}\nSession: ${p.session_id || 'Unknown'}\n\nExecutable signatures are not verified. File approval does not authorize network access. Revoke under Protection → Rules & permissions.`;
}

function createGuardDecisionController({request,confirm,context,generation,ended,paint,announce,refetch,openPermissions,openResults,openInspection}) {
  let result = null, sequence = 0, resultGeneration = null;
  const pending = new Set();
  function clear() { sequence++; result=null; resultGeneration=null; paint(null); }
  async function resolve(id,verdict,scope,expiry) {
    if (ended() || pending.has(id) || !['allow','deny'].includes(verdict) || !['once','always','session','exact'].includes(scope)) return;
    pending.add(id);
    const auth = generation(), seq = ++sequence;
    const current = () => !ended() && generation() === auth;
    const p = context(id);
    const sessionID = p?.session_id || '';
    const body = {id,verdict,scope,...(expiry ? {expiry} : {})};
    try {
      if (!p || p.id !== id || (scope !== 'once' && !(p.available_scopes || []).some(s => s.kind === scope && (s.expiry || '') === (expiry || '')))) return;
      if(scope !== 'once' && !await confirm(guardScopeConfirmation(p,verdict,scope,expiry),{title:'Confirm future access',okLabel:'Allow future access',focusCancel:true})) return;
      if(!current() || context(id)?.id !== id) return;
      const response = await request('/guard/resolve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      const data = await response.json();
      if(!current()) return;
      if(response.ok && data.resolved === false) {
        if(seq === sequence) { result={request:body,sessionID,expired:true}; resultGeneration=auth; paint(result); announce('Request no longer pending.'); }
        return;
      }
      if(!response.ok || data.resolved !== true || (data.receipt != null && !validGuardReceipt(data.receipt,body))) throw new Error('Unconfirmed answer');
      if(seq === sequence) { result={request:body,receipt:data.receipt || null,sessionID}; resultGeneration=auth; paint(result); announce('Guard answer submitted.'); }
    } catch {
      if(current() && seq === sequence) { result={request:body,sessionID,unconfirmed:true}; resultGeneration=auth; paint(result); announce('Guard answer not confirmed. Check results before deciding again.'); }
    } finally {
      pending.delete(id);
      if(current()) refetch();
    }
  }
  return {resolve,clear,
    inspect(id, el) { const p=context(id); if(!ended() && p?.id === id && p.session_id) openInspection?.(p.session_id,el); },
    permissions() { const r=guardPermissionReceipt(result?.receipt,result?.receipt?.session_id); if(r && !ended() && resultGeneration===generation()) openPermissions(r); },
    history() { const id=result?.receipt?.session_id || result?.sessionID; if(id && !ended() && resultGeneration===generation()) openResults(id); },
  };
}

function validDecisionScopeRecords(records) {
  return Array.isArray(records) && records.length <= 10000 &&
    records.every(r => r && ['id', 'kind', 'agent', 'rule_id', 'operation', 'resource_path', 'created_at'].every(key => typeof r[key] === 'string' && r[key]) &&
      ['session_id', 'workspace', 'reader_exe', 'destination', 'expires_at', 'revoked_at'].every(key => r[key] == null || typeof r[key] === 'string')) &&
    new Set(records.map(r => r.id)).size === records.length;
}

function decisionScopeApplicability(record) {
  const a = record?.applicability;
  return a && typeof a.label === 'string' && a.label && typeof a.revoke === 'boolean'
    ? { label: a.label, revoke: a.revoke } : { label: 'Applicability unknown', revoke: false };
}

function validScopeRevocation(result, id) {
  return result?.revoked === true && result.id === id;
}

// Projects one saved decision into display rows. Applicability comes from the
// daemon's read response; it never authorizes a live request.
function decisionPermissionRows(receipt, records) {
  if (!validDecisionScopeRecords(records)) throw new Error('Invalid permission records');
  const byID = new Map(records.map(record => [record.id, record]));
  return receipt.ids.map(id => {
    const record = byID.get(id);
    if (!record) return { id, record: null, label: 'Current status unknown', revoke: false };
    const applicability = decisionScopeApplicability(record);
    const readConnect = record.operation === 'read-connect';
    const guarded = record.operation.startsWith('guard:');
    return {
      id, record,
      label: applicability.label,
      revoke: applicability.revoke,
      operation: readConnect ? 'Expected read/connect activity' : guarded ? 'Guarded ' + record.operation.slice(6) + ' access' : 'Operation unavailable',
      effect: readConnect ? 'Marks this matching read/connect pattern expected. It does not grant network access.' : guarded ? 'Allows matching guarded tool access when the daemon validates the recorded identity and scope.' : 'Permission effect unknown.',
      consequence: readConnect ? 'Future matching activity is evaluated under remaining expectations and policies.' : 'Future guard requests are evaluated under remaining permissions and policies.',
    };
  });
}

function sessionPermissionsHTML(receipt, state) {
  const st = state || {};
  const refresh = `<button type="button" class="link-btn" data-action="session-permissions-refresh"${st.loading || st.busy ? ' disabled' : ''}>Refresh permissions</button>`;
  const notice = st.error ? (st.rows ? 'Last known permission records. Current status unavailable.' : 'Permission records unavailable.')
    : st.loading ? 'Loading permission records…' : '';
  const head = `<header class="policy-row-main" data-session-part="permissions-head">
    <h4>Permissions from this decision</h4>
    <p>${receipt.sessionID ? `Session ${escapeHTML(receipt.sessionID)}` : 'Session unavailable'} · ${receipt.kind === 'guard' ? 'Guard decision' : `decision for revision ${receipt.revision}`}<br>Recorded ${escapeHTML(receipt.at || 'time unavailable')}</p>
    <p>The daemon rechecks live session and identity before applying a saved scope. These records do not establish that a request is currently allowed.</p>
    <p>Other permissions and legacy policies may still allow matching access. Revocation does not undo past access.</p>
    ${st.readAt ? `<p>Read at ${escapeHTML(st.readAt)}</p>` : ''}
    <p role="status">${notice}${st.mutationError ? ' Revocation confirmation unavailable. Refresh before retrying.' : ''}${st.busy ? ' Revocation awaiting confirmation or save.' : ''}</p>${refresh}
  </header>`;
  return head + (st.rows || decisionPermissionRows(receipt, [])).map(row => {
    const { id, record } = row;
    const saved = st.revoked?.has(id) ? '<p role="status">Revocation saved. Other permissions or expectations may still apply; past exposure and the saved decision remain.</p>' : '';
    if (!record) return `<section class="policy-row" data-session-part="permission:${escapeHTML(id)}"><div class="policy-row-main"><b>Current status unknown</b><p>Permission ${escapeHTML(id)}</p><p>The record is unavailable. This does not establish revocation or expiry.</p>${saved}</div></section>`;
    // Keep the action's height while a read/save is pending, so short drawers
    // do not clamp their reading position to zero. The action stays disabled.
    const revoke = row.revoke && !st.error && !st.mutationError && !st.revoked?.has(id);
    return `<section class="policy-row" data-session-part="permission:${escapeHTML(id)}"><div class="policy-row-main">
      <h5>${escapeHTML(row.label)}</h5><p>${escapeHTML(record.agent || 'Agent unavailable')} · ${escapeHTML(row.operation)}</p>
      <p>${escapeHTML(row.effect)}</p>
      <p>Resource <code>${escapeHTML(record.resource_path || 'unavailable')}</code>${record.destination ? ` → ${escapeHTML(record.destination)}` : ''}</p>
      <p>Workspace ${escapeHTML(record.workspace || 'unavailable')}<br>Executable path ${escapeHTML(record.reader_exe || 'unavailable')} (observed, not signature verified)</p>
      <p>Created ${escapeHTML(record.created_at || 'unavailable')}${record.expires_at ? `<br>Expires ${escapeHTML(record.expires_at)}` : ''}${record.revoked_at ? `<br>Revoked ${escapeHTML(record.revoked_at)}` : ''}</p>${saved}
      <details data-session-details><summary>Permission identifiers</summary><p>${escapeHTML(id)}<br>Rule ${escapeHTML(record.rule_id || 'unavailable')}<br>Originating session ${escapeHTML(record.session_id || 'unavailable')}</p></details>
      ${revoke ? `<button type="button" class="btn btn-ghost btn-sm" data-action="session-permission-revoke" data-id="${escapeHTML(id)}"${st.loading || st.busy ? ' disabled' : ''}>Revoke this permission</button>` : ''}
    </div></section>`;
  }).join('');
}
