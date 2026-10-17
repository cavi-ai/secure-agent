import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../daemon/internal/api/web_dist');

test('hidden or unavailable workbenches do not measure layout or read the selected view', () => {
  for (const panel of [null, {classList:{contains:()=>true},getClientRects:()=>[]}]) {
    const frames = [];
    const context = {
      window:{addEventListener(){}},
      document:{getElementById:()=>panel,querySelectorAll:()=>[]},
      requestAnimationFrame:callback=>{frames.push(callback);return frames.length;},
      getComputedStyle(){throw new Error('Hidden layout measured');},
    };
    vm.createContext(context);
    vm.runInContext(readFileSync(path.join(web,'session-layout.js'),'utf8'),context);
    const layout = context.createSessionLayout({getView(){throw new Error('Hidden selection read');}});
    layout.schedule();layout.schedule();
    assert.equal(frames.length,1);
    assert.doesNotThrow(()=>frames.shift()());
  }
});
test('workbench sizing reserves measured reading lines and rebinds chrome without observing height-driven panes', () => {
  const source = readFileSync(path.join(web, 'session-layout.js'), 'utf8');
  const frames = [], observed = new Set(), removed = [], writes = [];
  const rect = height => ({getClientRects:() => [1],getBoundingClientRect:() => ({height})});
  const text = {style:{lineHeight:'24px'}};
  const body = {...rect(240),style:{paddingTop:'0px',paddingBottom:'10px'},scrollHeight:1000,clientHeight:240,scrollTop:100,
    querySelector:() => text};
  let chrome = rect(220);
  const toolbar = rect(0), latest = {};
  const values = new Map();
  const panel = {getClientRects:() => [1],getBoundingClientRect:() => ({top:400}),
    classList:{contains:() => true,toggle(_name,on){panel.short=on;}},
    style:{getPropertyValue:name => values.get(name),setProperty(name,value){writes.push([name,value]);values.set(name,value);}},
    querySelector:selector => ({'.session-detail-body':body,'.session-detail-chrome':chrome,'.session-toolbar':toolbar,'[data-action="session-latest"]':latest})[selector]};
  const upstream = {};
  const context = {sessionView:'memory',window:{innerHeight:700,addEventListener(){}},
    document:{body:{},getElementById:() => panel,querySelector:() => upstream,querySelectorAll:() => [upstream]},
    getComputedStyle:node => node === panel ? {borderTopWidth:'1px',borderBottomWidth:'1px'} : node === upstream ? {paddingBottom:'16px'} : node.style || {},
    requestAnimationFrame:callback => {frames.push(callback);return frames.length;},
    ResizeObserver:class {constructor(callback){this.callback=callback;} observe(node){observed.add(node);} unobserve(node){observed.delete(node);removed.push(node);}},
  };
  vm.createContext(context);
  vm.runInContext(source, context);
  const layout = context.createSessionLayout({getView: () => context.sessionView});
  layout.schedule();layout.schedule();
  assert.equal(frames.length,1,'measurements coalesce');frames.shift()();
  assert.equal(values.get('--session-split-height'),'570px'); // 220 chrome + half the 700px viewport
  assert.equal(values.get('--session-workbench-height'),'572px');
  assert.equal(panel.short,true);
  assert.equal(body.scrollTop,100,'history position is preserved while sizing');
  assert.ok(observed.has(chrome) && observed.has(upstream));
  assert.ok(!observed.has(body) && !observed.has(panel));
  const count = writes.length;
  layout.schedule();frames.shift()();assert.equal(writes.length,count,'unchanged dimensions do not write styles');
  const previous = chrome;chrome=rect(180);context.window.innerHeight=1400;
  layout.schedule();frames.shift()();
  assert.ok(removed.includes(previous) && observed.has(chrome));
  assert.equal(panel.short,false);
  assert.equal(values.get('--session-workbench-height'),'984px');
  context.sessionView='hooks';
  layout.schedule();frames.shift()();
  assert.equal(latest.hidden,true,'hook summaries have no chronological tail to jump to');
});
