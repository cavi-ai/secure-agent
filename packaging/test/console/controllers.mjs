import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Load a complete controller in an isolated realm. Undeclared dependencies
// cannot accidentally resolve against the test fixture's global variables.
export function controller(file, factory, context) {
  const runtime = vm.createContext({ URLSearchParams });
  vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/' + file, import.meta.url), 'utf8'), runtime);
  return runtime[factory]({ store: context.telemetryStore, state: context, actions: context });
}
