import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Exact markup of the guard result and session permission renderers for a
// hostile served value in every text and attribute position.
const H = `<img src=x onerror=1>"'&amp;`;
const E = '&lt;img src=x onerror=1&gt;&quot;&#39;&amp;amp;';

const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const c = { Date };
vm.createContext(c);
for (const file of ['lib.js', 'decision-permissions.js']) vm.runInContext(readFileSync(new URL(file, web), 'utf8'), c);

const at = '2026-10-15T12:00:00Z';
const request = { verdict: H, scope: H };
const guardReceipt = { id: 'p', verdict: 'allow', scope: 'exact', rule_id: H, at, session_id: H, scope_ids: ['x'] };
const rows = [
  { id: H, record: null, label: 'Current status unknown', revoke: false },
  { id: 'b', record: { agent: H, category: 'mcp:' + H, destination: H, workspace: H, reader_exe: H, created_at: H, expires_at: H, revoked_at: H, rule_id: H, session_id: H },
    label: H, operation: H, effect: H, revoke: true },
  { id: 'c', record: { agent: '', resource_path: H }, label: H, operation: H, effect: H, revoke: false },
];
const guardKind = { sessionID: H, kind: 'guard', at: H, ids: ['a'] };

const cases = {
  'guard result expired': () => c.guardResultHTML({ expired: true, request }),
  'guard result unconfirmed with session': () => c.guardResultHTML({ unconfirmed: true, request, sessionID: H }),
  'guard result submitted without receipt': () => c.guardResultHTML({ request, sessionID: H }),
  'guard result submitted without session': () => c.guardResultHTML({ request }),
  'guard result receipt': () => c.guardResultHTML({ request, receipt: { ...guardReceipt, verdict: H, scope: H, at: H } }),
  'guard result receipt with permissions': () => c.guardResultHTML({ request, receipt: guardReceipt }),
  'permissions with records and saved revocation': () => c.sessionPermissionsHTML(guardKind, { rows, readAt: H, revoked: new Set([H]) }),
  'permissions with failed read': () => c.sessionPermissionsHTML(guardKind, { rows, error: true, loading: true, mutationError: true, busy: true }),
  'permissions loading unknown records': () => c.sessionPermissionsHTML({ sessionID: '', revision: 3, at: '', ids: [H] }, { loading: true }),
  'permissions without state': () => c.sessionPermissionsHTML({ sessionID: H, revision: 3, at: H, ids: [H] }),
};

const result = (title, line, meaning, a, b, tail) => `<div class="panel-head"><h2 id="guard-result-title">${title}</h2><button type="button" class="btn btn-ghost btn-sm" data-action="guard-result-dismiss">Dismiss</button></div>\n    <div class="panel-body"><p>${line}</p><p>${meaning}</p>\n    ${a}\n    ${b}\n    ${tail}</div>`;
const submitted = 'The daemon submitted this answer to the waiting request. This does not prove the tool received it, completed access, or saved request history.';
const noReceipt = '<p>Detailed receipt unavailable from this daemon.</p>';
const noSession = '<p>Session identity unavailable; inspect Rules &amp; permissions for current policy.</p>';
const history = '<button type="button" class="btn btn-ghost btn-sm" data-action="guard-result-history">Check session results</button>';
const viewPermissions = '<button type="button" class="btn btn-ghost btn-sm" data-action="guard-result-permissions">View permissions</button>';

const head = (session, recorded, readAt, notice, disabled) => `<header class="policy-row-main" data-session-part="permissions-head">\n    <h4>Permissions from this decision</h4>\n    <p>${session}<br>Recorded ${recorded}</p>\n    <p>The daemon rechecks live session and identity before applying a saved scope. These records do not establish that a request is currently allowed.</p>\n    <p>Other permissions and legacy policies may still allow matching access. Revocation does not undo past access.</p>\n    ${readAt}\n    <p role="status">${notice}</p><button type="button" class="link-btn" data-action="session-permissions-refresh"${disabled}>Refresh permissions</button>\n  </header>`;
const unknown = (id, saved = '') => `<section class="policy-row" data-session-part="permission:${id}"><div class="policy-row-main"><b>Current status unknown</b><p>Permission ${id}</p><p>The record is unavailable. This does not establish revocation or expiry.</p>${saved}</div></section>`;
const savedNotice = '<p role="status">Revocation saved. Other permissions or expectations may still apply; past exposure and the saved decision remain.</p>';
const revokeButton = '<button type="button" class="btn btn-ghost btn-sm" data-action="session-permission-revoke" data-id="b">Revoke this permission</button>';
const rowB = revoke => `<section class="policy-row" data-session-part="permission:b"><div class="policy-row-main">\n      <h5>${E}</h5><p>${E} · ${E}</p>\n      <p>${E}</p>\n      <p>Covers <b>all ${E} MCP sends</b> → ${E}</p>\n      <p>Workspace ${E}<br>Executable path ${E} (observed, not signature verified)</p>\n      <p>Created ${E}<br>Expires ${E}<br>Revoked ${E}</p>\n      <details data-session-details><summary>Permission identifiers</summary><p>b<br>Rule ${E}<br>Originating session ${E}</p></details>\n      ${revoke}\n    </div></section>`;
const rowC = `<section class="policy-row" data-session-part="permission:c"><div class="policy-row-main">\n      <h5>${E}</h5><p>Agent unavailable · ${E}</p>\n      <p>${E}</p>\n      <p>Resource <code>${E}</code></p>\n      <p>Workspace unavailable<br>Executable path unavailable (observed, not signature verified)</p>\n      <p>Created unavailable</p>\n      <details data-session-details><summary>Permission identifiers</summary><p>c<br>Rule unavailable<br>Originating session unavailable</p></details>\n      \n    </div></section>`;
const guardSession = `Session ${E} · Guard decision`;

const expected = {
  'guard result expired': result('Request no longer pending', `${E} · ${E}`,
    'This answer was not submitted to a waiting request. Check session results for the recorded outcome.', '', '', noSession),
  'guard result unconfirmed with session': result('Answer not confirmed', `${E} · ${E}`,
    'Check session results and permissions before deciding again. The answer may have reached the daemon.', '', '', history),
  'guard result submitted without receipt': result('Answer submitted', `${E} · ${E}`, submitted, noReceipt, '', history),
  'guard result submitted without session': result('Answer submitted', `${E} · ${E}`, submitted, noReceipt, '', noSession),
  'guard result receipt': result('Answer submitted', `${E} · ${E} · ${E} · ${E}`, submitted, '', '', history),
  'guard result receipt with permissions': result('Answer submitted', `allow · exact · ${E} · 2026-10-15T12:00:00Z`, submitted, '', viewPermissions, history),
  'permissions with records and saved revocation': head(guardSession, E, '<p>Read at Time unavailable</p>', '', '')
    + unknown(E, savedNotice) + rowB(revokeButton) + rowC,
  'permissions with failed read': head(guardSession, E, '',
    'Last known permission records. Current status unavailable. Revocation confirmation unavailable. Refresh before retrying. Revocation awaiting confirmation or save.', ' disabled')
    + unknown(E) + rowB('') + rowC,
  'permissions loading unknown records': head('Session unavailable · decision for revision 3', 'time unavailable', '', 'Loading permission records…', ' disabled') + unknown(E),
  'permissions without state': head(`Session ${E} · decision for revision 3`, E, '', '', '') + unknown(E),
};

for (const [name, run] of Object.entries(cases)) {
  test(name, async () => {
    assert.deepEqual(await run(), expected[name]);
  });
}
