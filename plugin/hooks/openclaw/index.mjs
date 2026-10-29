import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const guard = fileURLToPath(new URL('./harness_guard.py', import.meta.url));

export function checkTool(event, ctx, hookEvent) {
  return new Promise((resolve, reject) => {
    const child = spawn('python3', [guard, 'openclaw'], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let bytes = 0;
    const timer = setTimeout(() => { child.kill(); reject(new Error('Guard timed out')); }, 10000);
    child.stdout.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > 1024 * 1024) { child.kill(); reject(new Error('Guard output exceeded limit')); }
      else stdout += chunk.toString();
    });
    child.stderr.resume();
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.stdin.on('error', () => {});
    child.on('close', code => {
      clearTimeout(timer);
      try {
        if (code !== 0) throw new Error('Guard exited unsuccessfully');
        const response = JSON.parse(stdout);
        if (!response || typeof response !== 'object') throw new Error('Invalid guard response');
        resolve(response);
      } catch (error) { reject(error); }
    });
    child.stdin.end(JSON.stringify({
      hook_event_name: hookEvent, tool_name: event.toolName, tool_input: event.params,
      tool_response: event.result, session_id: ctx.sessionId || ctx.sessionKey,
      cwd: ctx.workspaceDir,
    }));
  });
}

export default {
  id: 'secure-agent',
  register(api) {
    api.on('before_tool_call', async (event, ctx) => {
      try {
        const workspaceDir = api.runtime.agent.resolveAgentWorkspaceDir(api.config, ctx.agentId);
        const result = await checkTool(event, { ...ctx, workspaceDir }, 'PreToolUse');
        if (result.permission === 'allow') return;
        return { block: true, blockReason: result.hookSpecificOutput?.permissionDecisionReason || 'Secure Agent denied the tool request.' };
      } catch {
        return { block: true, blockReason: 'Secure Agent could not check this tool request. Recheck the hook installation.' };
      }
    });
    api.on('after_tool_call', async (event, ctx) => {
      try {
        const workspaceDir = api.runtime.agent.resolveAgentWorkspaceDir(api.config, ctx.agentId);
        await checkTool(event, { ...ctx, workspaceDir }, 'PostToolUse');
      }
      catch { api.logger.warn('Secure Agent could not record the completed tool call.'); }
    });
  },
};
