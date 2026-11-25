import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Exact markup of the workspace permission review and its option list for a
// hostile served value in every text and attribute position.
const H = `<img src=x onerror=1>"'&amp;`;

const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const c = { Date };
vm.createContext(c);
for (const file of ['lib.js', 'decision-permissions.js', 'policy-controller.js']) vm.runInContext(readFileSync(new URL(file, web), 'utf8'), c);

const record = (id, extra = {}) => ({ id, kind: 'exact', agent: H, rule_id: H, operation: 'guard:' + H, resource_path: H, workspace: H,
  reader_exe: H, created_at: H, destination: H, applicability: { label: 'Timed permission', revoke: true }, ...extra });
const records = [record(H), record('b', { workspace: '/work' })];
const mine = { workspace: 'workspace:' + H, status: 'all' };

const cases = {
  'workspace options': () => c.permissionWorkspaceOptions(records, 'workspace:' + H),
  'review of one workspace': () => c.workspacePermissionsHTML(records, mine, {}),
  'review after a failed read': () => c.workspacePermissionsHTML(records, mine, { lastSuccessAt: 1, error: H }),
  'review while refreshing': () => c.workspacePermissionsHTML(records, mine, { loading: true }),
  'review with saved revocation under another status': () => c.workspacePermissionsHTML(records, { workspace: 'workspace:' + H, status: 'saved' },
    { scopeMutations: new Map([[H, { status: 'saved' }]]) }),
  'review without matches': () => c.workspacePermissionsHTML(records, { workspace: 'unassigned', status: 'all' }, {}),
  'review of no records': () => c.workspacePermissionsHTML([], { workspace: 'all', status: 'all' }, {}),
  'review of no records after a failed read': () => c.workspacePermissionsHTML([], { workspace: 'all', status: 'all' }, { error: H }),
  'review before the first read': () => c.workspacePermissionsHTML(null, mine, {}),
};

const E = '&lt;img src=x onerror=1&gt;&quot;&#39;&amp;amp;';
const context = (name, shown, readAt, extra = '') => `<div class="permission-read-context"><p><strong>${name}</strong> · ${shown} of 2 saved records</p><p>Last successful read: ${readAt}</p>${extra}</div>`;
const meta = disabled => `<span class="policy-row-meta"><button type="button" class="btn btn-ghost btn-sm" data-action="revoke-scope" data-id="${E}"${disabled}>Revoke</button></span>`;
const group = rowMeta => `<section class="permission-group" data-permission-status="saved"><h3>Session & timed permissions<span class="badge">1</span></h3><div class="policy-list" data-policy="scope"><section class="policy-harness-group"><div class="policy-harness-title"><span class="harness-chip" title="${E}"><span class="harness-glyph" data-harness-color="hsl(264 62% 62%)" aria-hidden="true">&lt;</span><span class="harness-label">${E}</span></span></div><div class="policy-row"><div class="policy-row-main"><b>${E}</b> · Guarded ${E} access <code>${E}</code> → ${E}</div><div class="policy-row-sub">${E} · executable path ${E} (observed, not signature verified) · Timed permission<br>Saved Time unavailable · Permission ${E}</div>${rowMeta}</div></section></div></section>`;
const refreshFailed = '<div class="policy-read-status" role="status"><p>Refresh failed. Showing last known records; current status is unavailable. Revocation is unavailable until a successful refresh.</p><button type="button" class="btn btn-ghost btn-sm" data-action="policy-refresh-report" data-kind="scope">Refresh saved permissions</button></div>';
const noMatch = '<div class="empty"><span>No saved permissions match this workspace and status. <button type="button" class="link-btn" data-action="permission-filter-clear">Clear filters</button></span></div>';

const expected = {
  'workspace options': `<option value="all">All workspaces</option><option value="unassigned">Workspace not recorded</option><option value="workspace:/work">/work</option><option value="workspace:${E}" selected>${E}</option>`,
  'review of one workspace': context(`${E}`, 1, 'Unavailable') + group(meta('')),
  'review after a failed read': context(E, 1, c.localTimestampHTML(1), refreshFailed) + group(''),
  'review while refreshing': context(E, 1, 'Unavailable', '<p role="status">Refreshing saved permissions… Showing the last successful read.</p>') + group(meta(' disabled')),
  'review with saved revocation under another status': context(E, 0, 'Unavailable',
    `<p role="status">Revocation saved for <code>${E}</code> (permission ${E}). Other permissions and policies may still apply.</p>`) + noMatch,
  'review without matches': context('Workspace not recorded', 0, 'Unavailable') + noMatch,
  'review of no records': context('All recorded workspaces', 0, 'Unavailable').replace('of 2', 'of 0') + '<div class="empty"><span>No saved permissions recorded in this read.</span></div>',
  'review of no records after a failed read': context('All recorded workspaces', 0, 'Unavailable', refreshFailed).replace('of 2', 'of 0') + '<p>Matching records are unavailable for the current read.</p>',
  'review before the first read': '<div class="loading">Loading…</div>',
};

for (const [name, run] of Object.entries(cases)) {
  test(name, async () => {
    assert.deepEqual(await run(), expected[name]);
  });
}
