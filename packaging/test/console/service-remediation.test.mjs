import {test} from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
const web=new URL('../../../daemon/internal/api/web_dist/',import.meta.url);
const preview={id:'review',preview_hash:'hash',label:'com.example.model',source:'/private/model.plist',endpoint:'http://127.0.0.1:19001',change:{runtime:'mlx',scope:'authenticated_inference',port:19001},client_fields:['advisor.api_key_file'],warnings:['Service restarts','Failure leaves original stopped']};
function setup(fixture=preview){
 const s={seq:0,generation:1,ended:false,posts:[],confirm:true};
 const ctx=vm.createContext({Date,URL,URLSearchParams,window:{}});
 for(const file of ['lib.js','service-remediation.js'])vm.runInContext(readFileSync(new URL(file,web),'utf8'),ctx);
 const api=ctx.createServiceRemediation({request:async(url,opts)=>{const input=opts?JSON.parse(opts.body):{};s.posts.push([url,input]);const value=input.action==='preview'?fixture:{...fixture,state:input.action==='rollback'?'restored_stopped':'verified',verified_at:'2026-11-09T18:00:00Z',checks:['authorized_one_token_inference']};return{ok:true,text:async()=>JSON.stringify(value)};},
 drawer:{seq:()=>s.seq,setMode(){},open(view){s.seq++;s.view=view;}},generation:()=>s.generation,ended:()=>s.ended,confirm:async()=>s.confirm});
 return{api,s};
}
test('apply uses the displayed identity only after review and rollback remains stopped',async()=>{
 const{api,s}=setup();api.open();await api.preview('/private/model.plist');
 assert.match(s.view.body,/advisor.api_key_file/);
 s.confirm=false;await api.apply();assert.equal(s.posts.length,1);
 s.confirm=true;await api.apply();assert.deepEqual(s.posts[1][1],{action:'apply',id:'review',preview_hash:'hash'});
 assert.match(s.view.body,/Last verified/);
 await api.rollback();assert.equal(s.posts[2][1].action,'rollback');assert.match(s.view.body,/restored_stopped/);
});
test('an old preview cannot mutate after drawer ownership changes',async()=>{
 const{api,s}=setup();api.open();await api.preview('/private/model.plist');s.seq++;await api.apply();assert.equal(s.posts.length,1);
});
test('browser-only receipts never claim authenticated protection',async()=>{
 const{api,s}=setup({...preview,change:{runtime:'ollama',scope:'browser_hardening'},client_fields:[]});api.open();await api.preview('/private/model.plist');
 assert.match(s.view.body,/browser hardening/);
 await api.apply();assert.match(s.view.body,/local API remains unauthenticated/);
 assert.doesNotMatch(s.view.body,/Authentication and direct-backend checks passed/);
 await api.lookup('com.example.model');assert.match(s.posts[2][0],/receipt\?label=com.example.model/);
});
