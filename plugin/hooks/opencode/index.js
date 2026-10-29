// secure-agent-managed-plugin: opencode-v2
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const guard = fileURLToPath(new URL('./harness_guard.py', import.meta.url));

function check(payload) {
  return new Promise((resolve, reject) => {
    const child = execFile('python3', [guard, 'opencode'], { timeout: 10000, maxBuffer: 1024 * 1024 }, (error, stdout) => {
      if (error) return reject(error);
      try { resolve(JSON.parse(stdout)); } catch (error) { reject(error); }
    });
    child.stdin.on('error', () => {});
    child.stdin.end(JSON.stringify(payload));
  });
}

export default {
  id: 'secure-agent',
  async setup(ctx) {
    const payload = async (event, hook) => {
      const session = await ctx.session.get({ sessionID: event.sessionID });
      const cwd = session.location?.directory;
      if (typeof cwd !== 'string' || !cwd.startsWith('/')) throw new Error('Session workspace is unavailable');
      return { hook_event_name: hook, tool_name: event.tool, tool_input: event.input,
        tool_response: event.result, session_id: event.sessionID, cwd };
    };
    await ctx.tool.hook('execute.before', async event => {
      let result;
      try { result = await check(await payload(event, 'PreToolUse')); }
      catch { throw new Error('Secure Agent could not check this tool request. Recheck the hook installation.'); }
      if (result?.permission !== 'allow') {
        throw new Error(result?.hookSpecificOutput?.permissionDecisionReason || 'Secure Agent denied the tool request.');
      }
    });
    await ctx.tool.hook('execute.after', async event => {
      try { await check(await payload(event, 'PostToolUse')); }
      catch { console.warn('Secure Agent could not record the completed tool call.'); }
    });
  },
};
