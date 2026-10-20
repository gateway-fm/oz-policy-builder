import { spawn } from 'node:child_process';
import { isAbsolute } from 'node:path';

const START = 16 * 1024 * 1024, FRAME = 256 * 1024, OUTPUT = 16 * 1024 * 1024;
const failure = () => new Error('native process refused; no execution evidence accepted');
function inspect(value, depth = 0, budget = { nodes: 0 }) {
  if (++budget.nodes > 65536 || depth > 64) throw failure();
  if (typeof value === 'number' && !Number.isSafeInteger(value)) throw failure();
  if (value && typeof value === 'object') for (const [key, part] of Object.entries(value)) {
    if (['__proto__', 'prototype', 'constructor'].includes(key)) throw failure();
    inspect(part, depth + 1, budget);
  }
}
function frame(bytes) {
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw failure();
  inspect(value);
  return value;
}

/** Fixed native modes only. Hooks belong to the trusted wallet controller, never HTTP input. */
export async function runNative(executable, jobText, {
  prepareOnly = false, validatePrepared, sign, validateResult, signal, timeoutMs = 120000,
} = {}) {
  if (process.platform === 'win32' || !isAbsolute(executable) || typeof jobText !== 'string'
    || Buffer.byteLength(jobText) >= START || typeof prepareOnly !== 'boolean'
    || typeof validatePrepared !== 'function' || !prepareOnly && (typeof sign !== 'function' || typeof validateResult !== 'function')
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000 || signal?.aborted) throw failure();
  let compact;
  try {
    const job = JSON.parse(jobText);
    if (!job || typeof job !== 'object' || Array.isArray(job)) throw failure();
    // Remove only insignificant whitespace. JSON numbers retain their original exact bytes.
    compact = jobText.replace(/"(?:\\.|[^"\\])*"|\s+/g, (token) => token[0] === '"' ? token : '');
    if (compact.includes('\n') || compact.includes('\r')) throw failure();
  } catch { throw failure(); }
  return new Promise((resolve, reject) => {
    let child, timer, grace, done = false, failed = false, prepared, result;
    let pending = Buffer.alloc(0), total = 0, stderr = 0, requests = 0, signPending = false;
    const finish = () => {
      if (done) return;
      done = true; clearTimeout(timer); clearTimeout(grace);
      signal?.removeEventListener('abort', fail);
      if (failed) reject(failure()); else resolve(prepareOnly ? prepared : result);
    };
    // Signal the worker itself first, so it cannot start more processes, then its group for any
    // descendants. Either signal can fail independently; neither failure skips the other.
    const terminate = () => {
      try { child.kill('SIGKILL'); } catch { /* close or the grace period decides */ }
      try { process.kill(-child.pid, 'SIGKILL'); } catch { /* group already gone or never formed */ }
    };
    const fail = () => {
      if (done || failed) return;
      failed = true;
      clearTimeout(timer);
      if (!child?.pid) { finish(); return; }
      terminate();
      child.stdin.destroy();
      grace = setTimeout(() => {
        terminate();
        child.stdout.destroy(); child.stderr.destroy(); child.unref(); finish();
      }, 5000);
    };
    const receive = (value) => {
      if (result !== undefined || signPending) throw failure();
      if (prepared === undefined) {
        if (value.type !== 'prepared') throw failure();
        if (validatePrepared(value)?.then) throw failure();
        prepared = structuredClone(value);
        return;
      }
      if (prepareOnly) throw failure();
      if (value.type === 'sign_request') {
        if (++requests > 10000) throw failure();
        const response = sign(value);
        if (!response || response.then) throw failure();
        const text = JSON.stringify(response) + '\n';
        if (Buffer.byteLength(text) > FRAME) throw failure();
        signPending = true;
        child.stdin.write(text, (error) => { signPending = false; if (error) fail(); });
      } else if (value.type === 'result') {
        const checked = validateResult(value);
        if (!checked || checked.then) throw failure();
        result = structuredClone(checked);
        child.stdin.end();
      } else throw failure();
    };
    try {
      child = spawn(executable, prepareOnly ? ['--prepare'] : [], {
        cwd: '/', env: { PATH: '/usr/bin:/bin', LANG: 'C' }, detached: true,
        stdio: ['pipe', 'pipe', 'pipe'], shell: false,
      });
      timer = setTimeout(fail, timeoutMs);
      signal?.addEventListener('abort', fail, { once: true });
      child.once('error', fail);
      child.stdin.on('error', fail); child.stdout.on('error', fail); child.stderr.on('error', fail);
      child.stderr.on('data', (chunk) => { stderr += chunk.length; if (stderr > 65536) fail(); });
      child.stdout.on('data', (chunk) => {
        if (done || failed) return;
        try {
          total += chunk.length;
          if (total > OUTPUT) throw failure();
          let remaining = chunk;
          while (remaining.length) {
            const at = remaining.indexOf(10), count = at < 0 ? remaining.length : at + 1;
            if (pending.length + count > FRAME) throw failure();
            pending = Buffer.concat([pending, remaining.subarray(0, count)]);
            remaining = remaining.subarray(count);
            if (at >= 0) {
              const line = pending.subarray(0, -1); pending = Buffer.alloc(0);
              receive(frame(line));
            }
          }
        } catch { fail(); }
      });
      child.once('close', (code, exitSignal) => {
        if (done) return;
        if (code !== 0 || exitSignal || pending.length || prepared === undefined || !prepareOnly && result === undefined) failed = true;
        // The worker must leave nothing running: `close` does not wait for a descendant with
        // ignored stdio. A surviving group member refuses even a complete report. The group is
        // signalled only while a probe finds a member, because only then can its ID not be
        // reused; a member forking during one signal is caught by the next probe. The existing
        // grace period caps the sweep, and the run settles only after it.
        clearTimeout(grace);
        const ends = performance.now() + 5000;
        const sweep = () => {
          let member;
          try { process.kill(-child.pid, 0); member = true; } catch (error) { member = error.code === 'EPERM'; }
          if (!member || performance.now() >= ends) { finish(); return; }
          failed = true;
          try { process.kill(-child.pid, 'SIGKILL'); } catch { /* re-probed below */ }
          grace = setTimeout(sweep, 20);
        };
        sweep();
      });
      if (prepareOnly) child.stdin.end(compact + '\n');
      else child.stdin.write(compact + '\n', (error) => { if (error) fail(); });
    } catch { fail(); }
  });
}
