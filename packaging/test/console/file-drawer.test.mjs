// File drawer renderer and evidence-path links — lib.js in a fresh VM
// context, the way the browser loads the classic script.

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
const ctx = {};
vm.runInNewContext(readFileSync(path.join(webDist, 'lib.js'), 'utf8'), ctx, { filename: 'lib.js' });
const { fileDetailHTML, linkEvidencePaths, parseMarkdownToHTML } = ctx;

const now = Date.parse('2026-09-23T20:00:00Z');
const detail = {
  path: '/Users/dev/x"<y>.jsonl',
  display: '~/x"<y>.jsonl',
  exists: true, size: 2048, mod_time: '2026-09-23T19:50:00Z', owned_by_user: true,
  subject: { category_label: 'agent transcript', owner_label: 'Codex transcript' },
  findings: [{ kind: 'incident', id: 'inc-1', rule: 'secret-in-transcript', risk: 'high', ts: '2026-09-23T19:40:00Z' }],
  accesses: [{ kind: 'file-write', ts: '2026-09-23T19:45:00Z', exe_path: '/usr/local/bin/codex', session_id: 'sess-1234567890' }],
  hits: [{ flag_id: 'f1', rule: 'fp1', offset: 10 }],
  excerpt: 'TOKEN=[REDACTED:fp1] <b>ok</b>',
};

test('fileDetailHTML escapes every field and shows the masked excerpt', () => {
  const html = fileDetailHTML(detail, now);
  assert.ok(!html.includes('<y>') && !html.includes('<b>ok'), 'raw markup must not survive');
  assert.ok(html.includes('x&quot;&lt;y&gt;.jsonl'));
  assert.ok(html.includes('<pre class="file-excerpt">TOKEN=[REDACTED:fp1] &lt;b&gt;ok&lt;/b&gt;</pre>'));
  assert.ok(html.includes('data-action="file-reveal"') && html.includes('data-action="file-open"'));
  assert.ok(html.includes('data-action="open-incident" data-id="inc-1"'));
  assert.ok(html.includes('2 KB') && html.includes('modified 10m ago'));
  assert.ok(html.includes('codex · session sess-123'));
});

test('fileDetailHTML shows why an excerpt is withheld, and no actions for a deleted file', () => {
  const html = fileDetailHTML({ ...detail, exists: false, excerpt: '', excerpt_withheld: 'a secret appears encoded' }, now);
  assert.ok(html.includes('deleted since it was flagged'));
  assert.ok(html.includes('<p class="file-withheld">a secret appears encoded</p>'));
  assert.ok(!html.includes('data-action="file-reveal"') && !html.includes('data-action="file-open"'));
  assert.ok(!html.includes('file-excerpt'));
});

test('linkEvidencePaths links absolute paths in inline code only', () => {
  const md = '### Accessed Files\n- `/Users/dev/a "b".txt`\n\n### Egress Connections\n- `api.openai.com:443`\n';
  const html = linkEvidencePaths(parseMarkdownToHTML(md));
  assert.ok(html.includes('data-action="open-file" data-path="/Users/dev/a &quot;b&quot;.txt"'));
  assert.ok(html.includes('<code class="md-inline-code">api.openai.com:443</code>'));
  assert.equal(linkEvidencePaths(''), '');
});
