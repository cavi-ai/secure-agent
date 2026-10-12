import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const assets = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const app = readFileSync(new URL('app.js', assets), 'utf8');
import { controller } from './controllers.mjs';
function deferred() { let resolve; const promise = new Promise(r => {resolve=r;}); return {promise,resolve}; }
const response = rules => ({ok:true,json:async()=>({rules})});
function setup(rules = [], episodes = [{id:'origin',observed:{recurring:true}}]) {
  const calls = [], routes = [], focus = [], scroll = [], dirty = [];
  const ctx = {window:{}, URLSearchParams, sessionEnded:false, handoffGeneration:1, protectionContext:null, protectionContextGeneration:0,
    expectedEgressReadGen:0, telemetryData:{expectedEgress:rules,egressEpisodes:episodes},
    markDirty(...names){dirty.push(...names);},
    apiFetch(path, options){ calls.push({path,options}); return ctx.nextResponse ? ctx.nextResponse() : Promise.resolve(response([])); },
  };
  const nodes = new Map();
  const node = (kind,id) => {
    const key = kind + ':' + id;
    if (!nodes.has(key)) nodes.set(key, {dataset:{[kind]:id},
      focus(options){ ctx.document.activeElement=this;focus.push({key,options}); },
      scrollIntoView(options){scroll.push({key,options});},
    });
    return nodes.get(key);
  };
  const containers = {
    'expected-egress-container': {querySelectorAll(){return ctx.telemetryData.expectedEgress.filter(r=>!r.revoked_at).map(r=>node('expectedEgressRule',r.id));},querySelector(){return node('context','rules');}},
    'recurring-egress-container': {querySelectorAll(){return ctx.telemetryData.egressEpisodes.filter(e=>e.observed?.recurring).map(e=>node('egressEpisodeId',e.id));},querySelector(){return node('context','traffic');}},
  };
  ctx.document = {activeElement:{},getElementById:id=>containers[id]};
  ctx.renderNow = () => {};
  ctx.switchTab = (route, options = {}) => {if (ctx.protectionContext && !options.keepProtectionContext) ctx.clearProtectionContext();routes.push(route);};
  vm.createContext(ctx);
  vm.runInContext(readFileSync(new URL('lib.js',assets),'utf8'),ctx);
  vm.runInContext(readFileSync(new URL('telemetry-validation.js',assets),'utf8'),ctx);
  Object.assign(ctx, controller('console-lifecycle.js', 'createConsoleLifecycle', ctx));
  return {ctx,calls,routes,focus,scroll,dirty};
}

test('known exact rule opens canonical Rules and focuses the non-destructive row without reads or writes', async () => {
  const {ctx,calls,routes,focus} = setup([{id:'other',host:'same'},{id:'exact',host:'same'}]);
  await ctx.viewEgressExpectation('exact','origin');
  assert.deepEqual(routes,['protection/rules']);
  assert.equal(ctx.protectionContext.ruleId,'exact');
  assert.equal(ctx.document.activeElement.dataset.expectedEgressRule,'exact');
  assert.equal(focus[0].key,'expectedEgressRule:exact');
  assert.equal(calls.length,0);
});

test('absent exact ID gets one checked read, never a host-equivalent rule or a write', async () => {
  const {ctx,calls} = setup([{id:'other',host:'same'}]);
  ctx.nextResponse = async()=>response([{id:'other',host:'same'}]);
  await ctx.viewEgressExpectation('exact','origin');
  assert.equal(calls.length,1);
  assert.deepEqual(calls[0],{path:'/expected-egress',options:undefined});
  assert.equal(ctx.protectionContext.status,'ready');
  assert.equal(ctx.document.activeElement.dataset.context,'rules');
});

test('bounded read can find an exact rule and move initial fallback focus to it', async () => {
  const {ctx,calls} = setup();
  ctx.nextResponse = async()=>response([{id:'exact'}]);
  await ctx.viewEgressExpectation('exact','origin');
  assert.equal(calls.length,1);
  assert.equal(ctx.document.activeElement.dataset.expectedEgressRule,'exact');
});

for (const kind of ['http','invalid','network']) test('failed '+kind+' read retains cached rules and explicit error context', async () => {
  const cached = [{id:'other'}];
  const {ctx,calls} = setup(cached);
  ctx.nextResponse = async()=>kind === 'http' ? {ok:false} : kind === 'invalid' ? {ok:true,json:async()=>({rules:'invalid'})} : Promise.reject(new Error('offline'));
  await ctx.viewEgressExpectation('exact','origin');
  assert.equal(ctx.protectionContext.status,'error');
  assert.equal(ctx.telemetryData.expectedEgress,cached);
  assert.equal(calls.length,1);
});

for (const race of ['manual navigation','Back','auth generation','new context','new telemetry']) test('late expectation read cannot replace '+race, async () => {
  const {ctx} = setup();
  const pending = deferred();
  ctx.nextResponse = ()=>pending.promise;
  const work = ctx.viewEgressExpectation('exact','origin');
  if (race === 'manual navigation') ctx.switchTab('protection/audit');
  if (race === 'Back') ctx.backToEgressContext();
  if (race === 'auth generation') ctx.handoffGeneration++;
  if (race === 'new context') {
    ctx.nextResponse = async()=>response([{id:'new'}]);
    await ctx.viewEgressExpectation('new','another');
  }
  if (race === 'new telemetry') {ctx.expectedEgressReadGen++;ctx.telemetryData.expectedEgress=[{id:'fresh'}];}
  const expected = ctx.telemetryData.expectedEgress;
  const selected = ctx.document.activeElement;
  pending.resolve(response([{id:'obsolete'}]));
  await work;
  assert.equal(ctx.telemetryData.expectedEgress,expected);
  assert.equal(ctx.document.activeElement,selected);
  if (race === 'manual navigation') assert.equal(ctx.protectionContext,null);
  if (race === 'Back') assert.equal(ctx.protectionContext.phase,'traffic');
});

test('operator focus changes during the read are preserved', async () => {
  const {ctx,focus} = setup();
  const pending = deferred();ctx.nextResponse=()=>pending.promise;
  const work = ctx.viewEgressExpectation('exact','origin');
  const operatorControl = {};ctx.document.activeElement=operatorControl;
  pending.resolve(response([{id:'exact'}]));await work;
  assert.equal(ctx.document.activeElement,operatorControl);
  assert.equal(focus.length,1);
});

test('Back returns the exact origin and missing origins use the non-destructive context fallback', async () => {
  const {ctx,routes} = setup([{id:'exact'}]);
  await ctx.viewEgressExpectation('exact','origin');
  ctx.backToEgressContext();
  assert.equal(routes.at(-1),'protection/traffic');
  assert.equal(ctx.document.activeElement.dataset.egressEpisodeId,'origin');
  await ctx.viewEgressExpectation('exact','origin');
  ctx.telemetryData.egressEpisodes=[];ctx.backToEgressContext();
  assert.equal(ctx.document.activeElement.dataset.context,'traffic');
  ctx.switchTab('protection/rules');
  assert.equal(ctx.protectionContext,null);
});


test('valid credential-free hash navigation clears inspection context through existing routing; invalid or paused routes do nothing', async () => {
  const {ctx,routes} = setup([{id:'exact'}]);
  const start = app.indexOf("  window.addEventListener('hashchange'");
  const end = app.indexOf('\n  });',start) + 7;
  assert.ok(start >= 0 && end > start);
  let onHash;
  ctx.window.addEventListener = (_name,handler)=>{onHash=handler;};
  ctx.location = {hash:'#protection/audit'};
  vm.runInContext(app.slice(start,end),ctx);
  await ctx.viewEgressExpectation('exact','origin');
  await onHash();
  assert.equal(routes.at(-1),'#protection/audit');
  assert.equal(ctx.protectionContext,null);
  const count=routes.length;
  ctx.location.hash='#invalid-route';await onHash();
  assert.equal(routes.length,count);
  ctx.sessionEnded=true;ctx.location.hash='#protection/rules';await onHash();
  assert.equal(routes.length,count);
});


test('forward and Back center the exact target once, while rendering does not trigger controller scroll retries', async () => {
  const {ctx,scroll} = setup([{id:'exact'}]);
  await ctx.viewEgressExpectation('exact','origin');
  assert.equal(scroll.length,1);
  assert.equal(scroll[0].key,'expectedEgressRule:exact');
  assert.deepEqual({...scroll[0].options},{behavior:'auto',block:'center'});
  ctx.renderNow(['expected-egress']);
  assert.equal(scroll.length,1);
  ctx.backToEgressContext();
  assert.equal(scroll.length,2);
  assert.equal(scroll[1].key,'egressEpisodeId:origin');
  assert.deepEqual({...scroll[1].options},{behavior:'auto',block:'center'});
});
