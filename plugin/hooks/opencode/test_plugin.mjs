import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, copyFile, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

test('OpenCode v2 callbacks check native tool input and block guard failures', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secure-agent-opencode-'));
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
    for (const name of ['index.js', 'package.json']) await copyFile(new URL('./' + name, import.meta.url), join(root, name));
    const { default: plugin } = await import(pathToFileURL(join(root, 'index.js')));
    const hooks = new Map();
    await plugin.setup({
      tool: { hook: async (name, handler) => hooks.set(name, handler) },
      session: { get: async ({ sessionID }) => {
        assert.equal(sessionID, 'opencode-native-session');
        return { location: { directory: root } };
      } },
    });
    const base = { sessionID: 'opencode-native-session' };
    await assert.rejects(hooks.get('execute.before')({ ...base, tool: 'read', input: { filePath: join(root, '.ssh/id_rsa') } }));
    await hooks.get('execute.before')({ ...base, tool: 'bash', input: { command: 'echo hello' } });
    await hooks.get('execute.after')({ ...base, tool: 'bash', input: { command: 'echo hello' }, result: { content: 'hello' } });
    const rows = (await readFile(join(root, 'activity.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
    assert.ok(rows.some(row => row.session_id === base.sessionID));
    assert.ok(rows.filter(row => row.pid).every(row => row.pid === process.pid));
    await rm(join(root, 'harness_guard.py'));
    await assert.rejects(hooks.get('execute.before')({ ...base, tool: 'bash', input: { command: 'echo hello' } }));
  } finally {
    for (const [key, value] of Object.entries(prior)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await rm(root, { recursive: true, force: true });
  }
});
