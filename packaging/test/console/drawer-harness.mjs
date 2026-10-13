import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const assets = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const libSource = readFileSync(new URL('lib.js', assets), 'utf8');
const drawerSource = readFileSync(new URL('drawer.js', assets), 'utf8');

function node(extra = {}) {
  const listeners = new Map();
  return {
    hidden: false, textContent: '', innerHTML: '', dataset: {}, children: [], focused: 0,
    addEventListener(type, fn) { listeners.set(type, fn); },
    fire(type, event) { return listeners.get(type)?.(event); },
    focus(options) { this.focused++; this.focusOptions = options; },
    setAttribute(key, value) { (this.attributes ||= new Map()).set(key, value); },
    removeAttribute(key) { this.attributes?.delete(key); },
    ...extra
  };
}

// The drawer's DOM, a document that serves it, and the collaborators the
// module takes. Overrides replace any collaborator or media query.
export function loadDrawer({ width = 1900, media = null, ended = false, deps = {} } = {}) {
  const classes = new Set();
  const app = node({ classList: { add: (...names) => names.forEach(n => classes.add(n)), remove: (...names) => names.forEach(n => classes.delete(n)),
    toggle: (name, on) => (on ? classes.add(name) : classes.delete(name)), contains: name => classes.has(name) } });
  const head = node({ children: [], ownerDocument: null,
    querySelector(selector) { return selector === '#btn-drawer-back' ? this.children.find(c => c.id === 'btn-drawer-back') || null : null; },
    insertBefore(child) { child.remove = () => { head.children = head.children.filter(c => c !== child); }; this.children.push(child); } });
  const drawer = node({ hidden: true, className: 'drawer', dataset: {},
    classList: { contains: name => drawer.className.split(' ').includes(name) },
    querySelector: selector => (selector === '.drawer-head' ? head : null), querySelectorAll: () => [] });
  const body = node(), foot = node({ hidden: true }), title = node(), titleIcon = node(), titleEl = node(), closeButton = node(), copyButton = node({ hidden: true });
  const attentionHead = node();
  const inertSiblings = [node({ inert: false, id: 'main', contains: () => false })];
  const documentListeners = new Map();
  const document = {
    activeElement: null, documentElement: { clientWidth: width },
    getElementById: id => ({ drawer, 'drawer-body': body, 'drawer-foot': foot, 'drawer-title-text': title, 'btn-drawer-close': closeButton,
      'btn-drawer-copy': copyButton, 'drawer-title': titleEl }[id] || null),
    querySelector: selector => ({ '#drawer-title use': titleIcon, '.app': app, '#attention-list .need-head': attentionHead }[selector] || null),
    querySelectorAll: () => inertSiblings,
    addEventListener: (type, fn) => documentListeners.set(type, fn),
    createElement: () => node()
  };
  head.ownerDocument = document;
  const windowListeners = new Map();
  const window = { innerWidth: width, addEventListener: (type, fn) => windowListeners.set(type, fn) };
  if (media) window.matchMedia = query => media.get(query);
  const toasts = [];
  const requests = [];
  const calls = { loadedPlans: [], cachedFlags: [], dirty: [], bumps: 0, closedDocks: 0, selected: [] };
  const state = { ended, generation: 0, sessions: new Map() };
  const ctx = {
    window, document, navigator: {}, URLSearchParams,
    fillUninspected: el => { el.innerHTML = 'uninspected rows'; },
    familyDrawerFootHTML: (fam, label) => `foot:${fam.key}:${label}`,
  };
  vm.createContext(ctx);
  vm.runInContext(libSource, ctx, { filename: 'lib.js' });
  vm.runInContext(drawerSource, ctx, { filename: 'drawer.js' });
  const families = new Map([['fam', { key: 'fam' }]]);
  const collaborators = {
    request: async (...args) => { requests.push(args); return deps.respond ? deps.respond(...args) : { ok: true, status: 200, text: async () => '', json: async () => ({}) }; },
    toast: (...args) => toasts.push(args),
    markDirty: (...names) => calls.dirty.push(names),
    closeAgentDock: () => { calls.closedDocks++; },
    auth: { ended: () => state.ended, generation: () => state.generation },
    attention: { select: key => calls.selected.push(key), bumpGeneration: () => { calls.bumps++; } },
    family: { byKey: key => families.get(key), label: fam => 'Family ' + fam.key, select() {}, sections: () => [] },
    plan: { load: subject => calls.loadedPlans.push(subject) },
    flag: { cache: f => calls.cachedFlags.push(f), advisorEnabled: () => false },
    session: { capture: () => null, restore() {} },
    ...(deps.collaborators || {})
  };
  const api = ctx.createDrawer(collaborators);
  return { api, ctx, state, calls, toasts, requests, collaborators,
    dom: { drawer, body, foot, title, titleIcon, titleEl, closeButton, copyButton, head, app, classes, attentionHead, inertSiblings, document, window, documentListeners, windowListeners } };
}
