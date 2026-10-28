// A bounded, one-shot attempt to remove the exact recorded grant while this run's keys exist.
// A missing confirmation is ambiguous: never send another removal automatically.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, constants, openSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { StrKey } from '@stellar/stellar-sdk';
import { isMainModule } from './cli-entry.mjs';
import { parseJsonExact } from './raw-json.mjs';
import { args, NETWORK_PASSPHRASE, PINNED_ACCOUNT_WASM, writeJson } from './rpc.mjs';

const hash = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const contract = (value) => typeof value === 'string' && StrKey.isValidContract(value);
const identity = (run) => ({
  network: run.network, account: run.account, account_code_hash: run.account_code_hash,
  rule_id: run.rule_id, installation: run.tx?.add_context_rule,
  policy: run.policy, policy_wasm_hash: run.policy_wasm_hash,
  // The revoke helper independently verifies the whole spec and both installed policies.
  subscription: run.subscription ?? null,
});
const sameIdentity = (left, right) => JSON.stringify(identity(left)) === JSON.stringify(identity(right));

/**
 * The cleanup child's stdout and stderr, in a new private file in the run directory. `wx`
 * semantics: an existing path (or symlink) is never opened, so earlier output is never truncated
 * and nothing is written through a link; the child then runs without a log. The child prints
 * transaction hashes and, on failure, its stage and a message with the run's secrets redacted.
 */
/**
 * The cleanup child's whole-process-group deadline. A child prepares a removal only with
 * REMOVAL_RESERVE_MS (240 s) left and polls a pending removal only with the rest, so it stops
 * itself before this kill: at worst one reconciliation (<= 180 s) and one fresh removal (240 s).
 */
export const CLEANUP_CHILD_DEADLINE_MS = 600_000;
/** The child's own deadline, measured from its start, keeps this margin before the kill. */
export const childDeadline = (start = Date.now()) => start + CLEANUP_CHILD_DEADLINE_MS - 30_000;

export function openCleanupLog(dir) {
  try {
    // `dir` is the run directory `run.sh` created, or one its operator names on the command
    // line; the basename is fixed. O_EXCL|O_NOFOLLOW: no existing file or link is followed.
    // nosec
    return openSync(join(dir, 'cleanup-child.log'),
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  } catch {
    console.error('Could not create a new cleanup-child.log; the cleanup child runs without a log.');
    return null;
  }
}
const childStdio = (fd) => fd === null ? 'ignore' : ['ignore', fd, fd];
const closeLog = (fd) => { if (fd !== null) try { closeSync(fd); } catch { /* the child holds its own copy */ } };
export { childStdio, closeLog };

export function runCleanupChild(dir, {
  expectedRunHash, spawnProcess = spawn, setTimer = setTimeout, clearTimer = clearTimeout,
  killGroup = (pid) => process.kill(-pid, 'SIGKILL'),
} = {}) {
  return new Promise((resolve) => {
    let timer, child, settled = false, timedOut = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimer(timer);
      resolve(result);
    };
    const terminate = () => {
      timedOut = true;
      if (timer !== undefined) clearTimer(timer);
      try {
        if (!Number.isSafeInteger(child.pid) || child.pid <= 0) throw new Error('missing child process');
        killGroup(child.pid);
      } catch { /* A failed kill is uncertainty, not proof that cleanup stopped. */ }
      if (!settled) timer = setTimer(() => {
        child.unref?.();
        finish({ status: 'termination_unconfirmed' });
      }, 5000);
    };
    try {
      if (!hash(expectedRunHash)) throw new Error('missing cleanup run snapshot');
      const log = openCleanupLog(dir);
      try {
        child = spawnProcess(process.execPath, [fileURLToPath(new URL('./lifecycle.mjs', import.meta.url)),
          '--run-dir', dir, '--expected-run-sha256', expectedRunHash],
        { detached: true, stdio: childStdio(log), env: process.env });
      } finally { closeLog(log); }
      child.once('error', () => Number.isSafeInteger(child.pid) && child.pid > 0 ? terminate() : finish({ status: 'failed' }));
      child.once('close', (code) => finish(timedOut ? { status: 'timed_out' } : { status: 'exited', code }));
      timer = setTimer(terminate, CLEANUP_CHILD_DEADLINE_MS);
    } catch { finish({ status: 'failed' }); }
  });
}

export async function cleanupAfterFailure(dir, { runRevoke = runCleanupChild } = {}) {
  const path = join(dir, 'run.json');
  const read = () => parseJsonExact(readFileSync(path, 'utf8'));
  let initial;
  // No journal means setup never recorded an installation. A journal that exists but cannot be
  // read may be one cut short after recording a live grant, so it is never "nothing to do".
  try { initial = read(); } catch (e) {
    return e?.code === 'ENOENT' ? { status: 'not_eligible' } : { status: 'incomplete', reason: 'unreadable_journal' };
  }
  if (initial === null || typeof initial !== 'object' || Array.isArray(initial)) {
    return { status: 'incomplete', reason: 'unreadable_journal' };
  }
  if (initial.failure_cleanup !== undefined) return { status: 'already_attempted' };
  if (initial.network !== NETWORK_PASSPHRASE || initial.account_code_hash !== PINNED_ACCOUNT_WASM
    || !contract(initial.account) || !contract(initial.policy) || !hash(initial.policy_wasm_hash)
    || !hash(initial.tx?.add_context_rule) || !Number.isSafeInteger(initial.rule_id)
    || initial.rule_id <= 0 || initial.rule_id > 0xffff_ffff) return { status: 'not_eligible' };
  const record = { status: 'attempting', ...identity(initial) };
  // A pending removal goes to the child, which reconciles it by its hash and never resends it.
  if (initial.lifecycle?.removals?.some((r) => r.rule_id === initial.rule_id)) {
    record.status = 'incomplete';
    record.reason = 'removal_already_recorded';
    initial.failure_cleanup = record;
    writeJson(path, initial);
    return record;
  }
  initial.failure_cleanup = record;
  writeJson(path, initial);
  // `dir` is the run directory `run.sh` created, or one its operator names on the command
  // line; no server or remote request reaches this script. Only a digest of the journal just
  // written leaves this read, to pin the revoke child to that exact file.
  // nosec
  const expectedRunHash = createHash('sha256').update(readFileSync(path)).digest('hex');
  let child;
  try { child = await runRevoke(dir, { expectedRunHash }); } catch { child = { status: 'failed' }; }
  if (child.status === 'termination_unconfirmed') {
    const result = { status: 'termination_unconfirmed', reason: 'cleanup_process_not_reaped' };
    // The child may still own run.json. Retain uncertainty in a separate file without
    // following an existing path or allowing a reporting failure to authorize finalization.
    try {
      writeFileSync(join(dir, 'cleanup-termination.json'), JSON.stringify({ ...result,
        expected_run_sha256: expectedRunHash }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    } catch { console.error('Could not create the separate cleanup termination marker.'); }
    return result;
  }
  const current = read();
  const removals = current.lifecycle?.removals;
  const removal = Array.isArray(removals) && removals.filter((r) => r.rule_id === initial.rule_id);
  const verified = sameIdentity(initial, current) && child.status === 'exited' && child.code === 0
    && current.lifecycle?.pending_removal === undefined && removal?.length === 1
    && hash(removal[0].transaction) && removal[0].event === 'verified' && removal[0].rule_readback === 'absent';
  record.status = verified ? 'removed' : 'incomplete';
  record.reason = verified ? 'verified_removal' : child.status === 'timed_out' ? 'deadline'
    : !sameIdentity(initial, current) ? 'identity_changed' : 'removal_unconfirmed';
  if (verified) record.transaction = removal[0].transaction;
  current.failure_cleanup = record;
  writeJson(path, current);
  return record;
}

if (isMainModule(import.meta.url)) {
  const opts = args();
  if (!opts['run-dir']) throw new Error('usage: failure-cleanup.mjs --run-dir DIRECTORY');
  const result = await cleanupAfterFailure(opts['run-dir']);
  console.error(`Failure cleanup: ${result.status}${result.reason ? ` (${result.reason})` : ''}.`);
  if (result.status === 'incomplete' || result.status === 'termination_unconfirmed') {
    console.error('The live grant may remain; inspect the retained journal and cleanup-child.log. Keys will still be discarded.');
  }
  if (result.status === 'termination_unconfirmed') {
    console.error('Cleanup termination is unconfirmed; do not rewrite or finalize its journal.');
    process.exitCode = 2;
  }
}
