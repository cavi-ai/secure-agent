import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, copyFile, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

test('native OpenClaw callbacks enforce the real shared guard', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secure-agent-plugin-'));
  const prior = { HOME: process.env.HOME, SECURE_AGENT_ACTIVITY_LOG: process.env.SECURE_AGENT_ACTIVITY_LOG,
    SECURE_AGENT_GUARD_MODES: process.env.SECURE_AGENT_GUARD_MODES };
  try {
    process.env.HOME = root;
    process.env.SECURE_AGENT_ACTIVITY_LOG = join(root, 'activity.jsonl');
    process.env.SECURE_AGENT_GUARD_MODES = join(root, 'modes.json');
    await writeFile(join(root, 'modes.json'), JSON.stringify({ 'ssh-keys': 'deny' }));
    for (const name of ['harness_guard.py', 'secret_guard.py', 'activity_log.py', 'injection_scan.py', 'guard-rules.json']) {
      await copyFile(new URL('../' + name, import.meta.url), join(root, name));
    }
    await copyFile(new URL('./index.mjs', import.meta.url), join(root, 'index.mjs'));
    const { default: plugin } = await import(pathToFileURL(join(root, 'index.mjs')));
    const handlers = new Map();
    plugin.register({ on: (name, handler) => handlers.set(name, handler), logger: { warn() {} },
      config: {}, runtime: { agent: { resolveAgentWorkspaceDir: () => root } } });
    const ctx = { sessionId: 'openclaw-native-session', workspaceDir: root };
    const before = handlers.get('before_tool_call');
    const denied = await before({ toolName: 'read', params: { path: join(root, '.ssh/id_rsa') } }, ctx);
    assert.equal(denied.block, true);
    assert.equal(await before({ toolName: 'exec', params: { command: 'echo hello' } }, ctx), undefined);
    await handlers.get('after_tool_call')({ toolName: 'exec', params: { command: 'echo hello' }, result: 'hello' }, ctx);
    const rows = (await readFile(join(root, 'activity.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
    assert.ok(rows.some(row => row.session_id === ctx.sessionId));
    assert.ok(rows.filter(row => row.pid).every(row => row.pid === process.pid));
    await rm(join(root, 'harness_guard.py'));
    assert.equal((await before({ toolName: 'exec', params: { command: 'echo hello' } }, ctx)).block, true);
  } finally {
    for (const [key, value] of Object.entries(prior)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await rm(root, { recursive: true, force: true });
  }
});
