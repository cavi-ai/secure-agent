import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const root = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const ctx = vm.createContext({window:{SA:{t:{}}},document:{},console});
vm.runInContext(fs.readFileSync(new URL('lib.js',root),'utf8'),ctx);
vm.runInContext(fs.readFileSync(new URL('tab-findings.js',root),'utf8'),ctx);
test('reported remediation remains unverified and later evidence stays visible',()=>{
 ctx.inc={id:'incident',summary:'Incident',workflow:{status:'resolved'},remediation:{revision:4,evidence_revision:'evidence',steps:[{id:'step',item:{name:'<key>',path:'/one/.env',action:'Rotate affected key'},status:'reported',verification:'unverified',reported_at:'2026-10-09T12:00:00Z',newer_evidence:true}]}};
 const html=vm.runInContext('incidentBodyHTML(inc, {advisor:false})',ctx);
 assert.match(html,/Reported completed/);
 assert.match(html,/Unverified/);
 assert.match(html,/New evidence since this report/);
 assert.match(html,/&lt;key&gt;/);
 assert.match(html,/Mark pending/);
 assert.doesNotMatch(html,/<key>|Verified remediation|Credential safe/);
});
test('report drawer actions carry the exact step and evidence revision',()=>{
 ctx.rem={revision:2,evidence_revision:'evidence',steps:[{id:'step',item:{name:'Key',action:'Revoke affected key'},status:'pending',verification:'unverified'}]};
 const html=vm.runInContext('incidentReportHTML("incident", {}, "# Report", rem)',ctx);
 assert.match(html,/Report step completed/);
 assert.match(html,/data-step-id="step"/);
 assert.match(html,/data-revision="2"/);
 assert.match(html,/data-evidence="evidence"/);
});
