import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const webDist = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../daemon/internal/api/web_dist'
);

test('event freshness marks only rows new since the last render', () => {
  const ctx = {};
  vm.runInNewContext(readFileSync(path.join(webDist, 'lib.js'), 'utf8'), ctx, { filename: 'lib.js' });
  const f = ctx.createEventFreshness();
  assert.equal(f.isFresh('a'), false, 'the first render animates nothing');
  f.rendered(['a']);
  assert.equal(f.isFresh('a'), false);
  assert.equal(f.isFresh('b'), true);
  f.suppressNext();
  assert.equal(f.isFresh('b'), false, 'a suppressed render animates nothing');
  f.rendered(['a', 'b']);
  assert.equal(f.isFresh('c'), true, 'rendering clears the suppression');
  f.reset();
  assert.equal(f.isFresh('c'), false, 'reset starts over as a first render');
});
