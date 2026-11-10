import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const web=new URL('../../../daemon/internal/api/web_dist/',import.meta.url);
const report=()=>({generated_at:'2026-11-09T20:00:00Z',coverage:{discovery:'partial',connections:'available',requests:'routed_only',truncated:false,pending_endpoints:2},servers:[{endpoint:'http://127.0.0.1:11434',runtime:'ollama',metadata:'available',loaded_models:[{name:'<img src=x>'}]}],connections:[{pid:42,process:'Python',endpoint:'http://127.0.0.1:11434'}],requests:[],gateways:[]});
function setup(response){
 const state={seq:0,requests:0,timers:[]};
 const context=vm.createContext({Date,setTimeout:fn=>{state.timers.push(fn);return 1;},clearTimeout(){},window:{}});
 for(const file of ['lib.js','local-inference.js'])vm.runInContext(readFileSync(new URL(file,web),'utf8'),context);
 const api=context.createLocalInference({request:async()=>{state.requests++;return response?response():{ok:true,json:async()=>report()};},drawer:{seq:()=>state.seq,setMode(){},open(view){state.seq++;state.view=view;}},generation:()=>1,ended:()=>false});
 return{state,api};
}
test('loaded models and connected clients remain distinct from confirmed requests',async()=>{
 const {state,api}=setup();await api.open();
 assert.match(state.view.body,/Loaded models/);assert.match(state.view.body,/Connected clients/);
 assert.match(state.view.body,/No requests observed/);assert.match(state.view.body,/partial/);
 assert.match(state.view.body,/2.*await/i);assert.match(state.view.body,/&lt;img/);assert.doesNotMatch(state.view.body,/<img/);
 const count=state.requests;state.seq++;await state.timers[0]();assert.equal(state.requests,count);
});
test('unavailable observation never renders an empty active list as proof',async()=>{
 const {state,api}=setup(()=>({ok:false}));await api.open();
 assert.match(state.view.body,/unavailable/i);assert.doesNotMatch(state.view.body,/No requests observed/);
});
test('stale responses cannot replace a different drawer',async()=>{
 let finish;const {state,api}=setup(()=>new Promise(resolve=>finish=resolve));const pending=api.open();const view=state.view;state.seq++;finish({ok:true,json:async()=>report()});await pending;assert.equal(state.view,view);
});
