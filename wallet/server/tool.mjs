import { spawn } from 'node:child_process';
import { isAbsolute } from 'node:path';

const ENVIRONMENT = ['PATH', 'HOME', 'RUSTUP_HOME', 'CARGO_HOME', 'TMPDIR', 'CARGO_NET_OFFLINE',
  'OZPB_BUILD_WORKER_LAUNCHER', 'OZPB_BUILD_CACHE_DIR', 'OZPB_BUILD_JOBS', 'OZPB_BUILD_TIMEOUT_SECS', 'OZPB_STELLAR_BINARY'];
const failure = (code) => Object.assign(new Error('wallet tool failed; no confidential diagnostics returned'),
  code ? { code } : {});
const CODE = /^[A-Z][A-Z_]*$/;
// The CLI reports a refusal as `Error: <CODE>: <message>` on stderr. Only that leading code is
// ever read, and only when the caller allowlisted it; the message, which can carry endpoint or
// input text, is discarded with the rest of stderr.
const STDERR_PREFIX = 256;

/** Fixed operator executable only. The API handler constructs arguments from a closed schema. */
export async function runTool(executable, args, options = {}) {
  const { maxOutput = 16 * 1024 * 1024, timeoutMs = 900_000, env = {}, signal, codes = [] } = options;
  if (process.platform === 'win32' || !isAbsolute(executable) || !Array.isArray(args)
    || !args.every((arg) => typeof arg === 'string') || !Number.isSafeInteger(maxOutput)
    || maxOutput < 1 || maxOutput > 16 * 1024 * 1024 || !Number.isSafeInteger(timeoutMs)
    || timeoutMs < 1 || timeoutMs > 900_000 || signal?.aborted || !Array.isArray(codes)
    || !codes.every((code) => typeof code === 'string' && CODE.test(code))) throw failure();
  const childEnv = {};
  for (const key of ENVIRONMENT) {
    const value = env[key] ?? (['PATH', 'HOME', 'RUSTUP_HOME', 'CARGO_HOME', 'TMPDIR'].includes(key) ? process.env[key] : undefined);
    if (typeof value === 'string') childEnv[key] = value;
  }
  childEnv.CARGO_NET_OFFLINE = 'true';
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd: '/', env: childEnv, detached: true,
      stdio: ['ignore', 'pipe', codes.length ? 'pipe' : 'ignore'] });
    const out = [];
    let length = 0;
    let done = false;
    let prefix = Buffer.alloc(0);
    // Read at most a bounded prefix; everything after it is drained and dropped.
    child.stderr?.on('data', (chunk) => {
      if (prefix.length < STDERR_PREFIX) prefix = Buffer.concat([prefix, chunk]).subarray(0, STDERR_PREFIX);
    });
    child.stderr?.on('error', () => {});
    const refusal = () => {
      const match = /^Error: ([A-Z][A-Z_]*): /.exec(prefix.toString('latin1'));
      return match && codes.includes(match[1]) ? match[1] : undefined;
    };
    const fail = (code) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      if (child.pid) {
        try { process.kill(-child.pid, 'SIGKILL'); } catch { /* already gone */ }
      }
      child.stdout.destroy();
      child.stderr?.destroy();
      child.unref();
      reject(failure(code));
    };
    const abort = () => fail();
    const timer = setTimeout(abort, timeoutMs);
    // A caller that gives up (the HTTP client disconnected) stops the whole process group.
    signal?.addEventListener('abort', abort, { once: true });
    child.stdout.on('data', (chunk) => {
      length += chunk.length;
      if (length > maxOutput) fail();
      else if (!done) out.push(chunk);
    });
    child.stdout.on('error', abort);
    child.on('error', abort);
    // A refusal code counts only from a process that exited by itself with status 1 or more;
    // a killed process, or one that overflowed its stdout, reports none.
    child.on('close', (status) => {
      if (done) return;
      if (status !== 0) { fail(Number.isSafeInteger(status) && status > 0 ? refusal() : undefined); return; }
      done = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      resolve(Buffer.concat(out).toString('utf8'));
    });
  });
}
