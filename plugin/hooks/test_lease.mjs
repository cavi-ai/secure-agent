import { spawn } from 'node:child_process';
import { once } from 'node:events';

export async function holdLease(home) {
  const child = spawn('python3', ['-u', '-c', `import fcntl, pathlib, sys
p = pathlib.Path(sys.argv[1], '.config/secure-agent/menubar.lock')
p.parent.mkdir(parents=True, exist_ok=True)
f = p.open('a+')
fcntl.flock(f, fcntl.LOCK_EX)
print('ready', flush=True)
sys.stdin.read()`, home], { stdio: ['pipe', 'pipe', 'inherit'] });
  let timer;
  try {
    await Promise.race([
      once(child.stdout, 'data'),
      once(child, 'exit').then(([code]) => { throw new Error(`Lease process exited: ${code}`); }),
      once(child, 'error').then(([error]) => { throw error; }),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Lease setup timed out')), 3000); }),
    ]);
  } catch (error) {
    child.kill();
    throw error;
  } finally {
    clearTimeout(timer);
  }
  return async () => {
    const exited = once(child, 'exit');
    child.stdin.end();
    await exited;
  };
}
