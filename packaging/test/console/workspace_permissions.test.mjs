import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const web=new URL('../../../daemon/internal/api/web_dist/',import.meta.url);
const c={Date};vm.createContext(c);
for(const file of ['lib.js','decision-permissions.js','policy-controller.js']) vm.runInContext(readFileSync(new URL(file,web),'utf8'),c);
const scope=(id,workspace,label='Timed permission',extra={})=>({id,kind:'exact',agent:'claude',rule_id:'env',operation:'guard:Read',resource_path:'/work/.env',workspace,reader_exe:'/bin/claude',created_at:'2026-10-15T12:00:00Z',expires_at:'2099-01-01T00:00:00Z',applicability:{label,revoke:label==='Timed permission'},...extra});
const rows=[scope('one','/work/app'),scope('child','/work/app/sub'),scope('missing',''),scope('expired','/work/app','Expired'),scope('revoked','/work/app','Revoked'),scope('unknown','/work/app','Unrecognized future state')];
test('workspace review matches exact recorded paths and keeps missing identity separate',()=>{
 const result=c.workspacePermissionReview(rows,'workspace:/work/app','all');
 assert.deepEqual(Array.from(result.rows,r=>r.id).sort(),['expired','one','revoked','unknown']);
 assert.deepEqual(Array.from(c.workspacePermissionReview(rows,'unassigned','all').rows,r=>r.id),['missing']);
 assert.equal(c.workspacePermissionReview(rows,'workspace:/work/empty','all').rows.length,0);
 assert.ok(c.permissionWorkspaceOptions(rows,'workspace:/work/empty').includes('/work/empty'));
});
test('status grouping trusts daemon labels, preserves unknown and does not infer expiry from browser time',()=>{
 const result=c.workspacePermissionReview(rows,'workspace:/work/app','all');
 assert.deepEqual(Array.from(result.groups,g=>[g.key,Array.from(g.rows,r=>r.id)]),[['saved',['one']],['unknown',['unknown']],['expired',['expired']],['revoked',['revoked']]]);
 const past=scope('past','/work/app','Timed permission',{expires_at:'2001-01-01T00:00:00Z'});
 assert.equal(c.workspacePermissionReview([past],'all','saved').rows.length,1);
});
test('filtered review retains read health and unknown identity, withholds stale revocation',()=>{
 const html=c.workspacePermissionsHTML(rows,{workspace:'workspace:/work/app',status:'all'},{lastSuccessAt:1,error:'Read failed'});
 assert.match(html,/Last successful read/);assert.match(html,/current status is unavailable/);
 assert.match(html,/Unrecognized future state/);assert.doesNotMatch(html,/data-action="revoke-scope"/);
 assert.doesNotMatch(html,/all access blocked|fully protected/i);
 const empty=c.workspacePermissionsHTML(rows,{workspace:'workspace:/work/empty',status:'all'},{});
 assert.match(empty,/data-action="permission-filter-clear"/);
});
test('successful revocation moves only the saved record while retaining workspace selection',()=>{
 const mutations=new Map([['one',{status:'saved'}]]);
 const review=c.workspacePermissionReview(rows,'workspace:/work/app','revoked',mutations);
 assert.deepEqual(Array.from(review.rows,r=>r.id).sort(),['one','revoked']);
 const html=c.workspacePermissionsHTML(rows,{workspace:'workspace:/work/app',status:'all'},{scopeMutations:mutations});
 assert.match(html,/Revocation saved/);assert.doesNotMatch(html,/data-action="revoke-scope" data-id="one"/);
});
test('permission investigation identifies the workspace view instead of evidence filters',()=>{
 const html=c.scopeBarHTML({returnToSession:true,workspacePermissions:true});
 assert.match(html,/Saved permissions/);assert.match(html,/session-investigation-return/);
 assert.doesNotMatch(html,/Evidence filters cleared/);
});
test('authentication reset clears workspace and status along with permission records',()=>{
 const state={sessionEnded:false,handoffGeneration:1,policyState:{scopes:rows,scopeWorkspace:'workspace:/private/project',scopeStatus:'revoked'}};
 const controller=c.createConsolePolicy({state,actions:{markDirty:()=>{}}});
 controller.reset();
 assert.equal(state.policyState.scopes,null);
 assert.equal(state.policyState.scopeWorkspace,'all');
 assert.equal(state.policyState.scopeStatus,'all');
});
