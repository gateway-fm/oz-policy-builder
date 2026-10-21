import { spawn } from 'node:child_process';
import { isAbsolute } from 'node:path';

const ENVIRONMENT = ['PATH', 'HOME', 'RUSTUP_HOME', 'CARGO_HOME', 'TMPDIR', 'CARGO_NET_OFFLINE',
  'OZPB_BUILD_WORKER_LAUNCHER', 'OZPB_BUILD_CACHE_DIR', 'OZPB_BUILD_JOBS', 'OZPB_BUILD_TIMEOUT_SECS', 'OZPB_STELLAR_BINARY'];
const failure = () => new Error('wallet tool failed; no confidential diagnostics returned');

/** Fixed operator executable only. The API handler constructs arguments from a closed schema. */
export async function runTool(executable, args, options = {}) {
  const { maxOutput = 16 * 1024 * 1024, timeoutMs = 900_000, env = {}, signal } = options;
  if (process.platform === 'win32' || !isAbsolute(executable) || !Array.isArray(args)
    || !args.every((arg) => typeof arg === 'string') || !Number.isSafeInteger(maxOutput)
    || maxOutput < 1 || maxOutput > 16 * 1024 * 1024 || !Number.isSafeInteger(timeoutMs)
    || timeoutMs < 1 || timeoutMs > 900_000 || signal?.aborted) throw failure();
  const childEnv = {};
  for (const key of ENVIRONMENT) {
    const value = env[key] ?? (['PATH', 'HOME', 'RUSTUP_HOME', 'CARGO_HOME', 'TMPDIR'].includes(key) ? process.env[key] : undefined);
    if (typeof value === 'string') childEnv[key] = value;
  }
  childEnv.CARGO_NET_OFFLINE = 'true';
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd: '/', env: childEnv, detached: true, stdio: ['ignore', 'pipe', 'ignore'] });
    const out = [];
    let length = 0;
    let done = false;
    const fail = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', fail);
      if (child.pid) {
        try { process.kill(-child.pid, 'SIGKILL'); } catch { /* already gone */ }
      }
      child.stdout.destroy();
      child.unref();
      reject(failure());
    };
    const timer = setTimeout(fail, timeoutMs);
    // A caller that gives up (the HTTP client disconnected) stops the whole process group.
    signal?.addEventListener('abort', fail, { once: true });
    child.stdout.on('data', (chunk) => {
      length += chunk.length;
      if (length > maxOutput) fail();
      else if (!done) out.push(chunk);
    });
    child.stdout.on('error', fail);
    child.on('error', fail);
    child.on('close', (status) => {
      if (done) return;
      if (status !== 0) { fail(); return; }
      done = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', fail);
      resolve(Buffer.concat(out).toString('utf8'));
    });
  });
}
