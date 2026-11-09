import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const report = () => ({generated_at:'2026-11-09T18:00:00Z',enforcement:'not_assessed',scope:'Metadata only',omitted_endpoints:3,
  managed:{state:'unloaded',transport:'inherited-unix-v1',enforcement:'private_transport'},
  inventory:{state:'partial',scope:'Visible listeners only',truncated:true,listeners:[{pid:42,command:'<img src=x>',address:'0.0.0.0:12345',binding:'wildcard',runtime_hint:'unknown'}]},
  services:[{endpoint:'http://127.0.0.1:12345',metadata:{state:'model_metadata',http_status:200},cross_origin:{state:'model_metadata',sharing:'advertised'},foreign_host:{state:'model_metadata'},findings:['<script>bad</script>'],enforcement:'not_assessed'}],
  hardening:[{runtime:'ollama',title:'Ollama',support:'browser_hardening_only',settings:'OLLAMA_HOST=127.0.0.1:11434',steps:['Review the service'],verification:['Recheck direct backend'],limitations:['Built-in origins remain allowed'],documentation:'https://docs.ollama.com/faq'}]});
function setup(respond) {
  const state = {seq:0,generation:1,ended:false,requests:[],copies:[],toasts:[]};
  const ctx=vm.createContext({Date,URL,window:{}});
  for (const file of ['lib.js','local-services.js']) vm.runInContext(readFileSync(new URL(file,web),'utf8'),ctx);
  const api=ctx.createLocalServices({request:async(url,options)=>{state.requests.push([url,options]);return respond?respond():{ok:true,json:async()=>report()};},
    drawer:{seq:()=>state.seq,setMode(){},open(view){state.seq++;state.view=view;}},generation:()=>state.generation,ended:()=>state.ended,
    copy:async text=>{state.copies.push(text);},toast:text=>state.toasts.push(text)});
  return {api,state};
}
test('on-demand assessment retains gaps and separates managed IPC from external observations',async()=>{
  const {api,state}=setup();
  assert.equal(state.requests.length,0);
  await api.open();
  assert.deepEqual(state.requests,[['/local-services',undefined]]);
  assert.match(state.view.body,/private connection/i);
  assert.match(state.view.body,/unloaded/);
  assert.match(state.view.body,/3.*not probed/i);
  assert.match(state.view.body,/partial/);
  assert.match(state.view.body,/Built-in origins remain allowed/);
  assert.match(state.view.body,/not applied/i);
  assert.doesNotMatch(state.view.body,/<script>|<img src=x>/);
  assert.match(state.view.body,/&lt;img/);
  await api.copySettings('ollama');
  assert.deepEqual(state.copies,['OLLAMA_HOST=127.0.0.1:11434']);
  state.seq++;
  await api.copySettings('ollama');
  assert.equal(state.copies.length,1);
});
test('failed and malformed reports keep retry available without a protection claim',async()=>{
  for(const response of [{ok:false},{ok:true,json:async()=>({...report(),services:null})},{ok:true,json:async()=>({...report(),inventory:{state:'available'}})}]){
    const {api,state}=setup(()=>response);
    await api.open();
    assert.match(state.view.body,/could not be loaded|incomplete/i);
    assert.match(state.view.foot,/local-services-refresh/);
    assert.doesNotMatch(state.view.body,/private connection/i);
  }
});
test('late responses cannot replace another drawer or a new console session',async()=>{
  for(const invalidate of [state=>state.seq++,state=>state.generation++,state=>state.ended=true]){
    let finish;
    const {api,state}=setup(()=>new Promise(resolve=>{finish=resolve;}));
    const pending=api.open();
    const initial=state.view;
    invalidate(state);
    finish({ok:true,json:async()=>report()});
    await pending;
    assert.equal(state.view,initial);
    assert.equal(state.copies.length,0);
  }
});
