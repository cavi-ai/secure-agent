import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const root = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const ctx=vm.createContext({window:{SA:{t:{}}},document:{},console});
vm.runInContext(fs.readFileSync(new URL('lib.js',root),'utf8'),ctx);
vm.runInContext(fs.readFileSync(new URL('tab-overview.js',root),'utf8'),ctx);

test('partial and missing receipts cannot render as successful recovery',()=>{
 for(const status of ['partial','unknown']) {
  ctx.receipt={id:'r',kind:'pause',status,verification:'unknown',after:[],limits:['Resume may be needed.'],error:'<bad>'};
  const html=vm.runInContext('resourceOutcomeHTML(receipt)',ctx);
  assert.match(html,status==='partial'?/Partially applied/:/Application unknown/);
  assert.match(html,/Verification unknown/);
  assert.doesNotMatch(html,/Recovered|<bad>/);
 }
});
test('resource samples and process absence have bounded labels',()=>{
 ctx.receipt={id:'r',kind:'terminate',status:'applied',verification:'verified',verified_by:'captured-family-absent',before:{rss_bytes:200},after:[{rss_bytes:100,host_capacity:'ample'}],limits:['Captured family only.']};
 const html=vm.runInContext('resourceOutcomeHTML(receipt)',ctx);
 assert.match(html,/Captured family absent/);
 assert.match(html,/Applied/);
 assert.match(html,/Captured family only/);
 assert.doesNotMatch(html,/Recovered/);
});
