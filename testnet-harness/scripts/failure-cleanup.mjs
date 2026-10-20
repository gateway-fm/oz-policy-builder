// A bounded, one-shot attempt to remove the exact recorded grant while this run's keys exist.
// A missing confirmation is ambiguous: never send another removal automatically.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
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
      child = spawnProcess(process.execPath, [fileURLToPath(new URL('./lifecycle.mjs', import.meta.url)),
        '--run-dir', dir, '--expected-run-sha256', expectedRunHash],
      { detached: true, stdio: 'ignore', env: process.env });
      child.once('error', () => Number.isSafeInteger(child.pid) && child.pid > 0 ? terminate() : finish({ status: 'failed' }));
      child.once('close', (code) => finish(timedOut ? { status: 'timed_out' } : { status: 'exited', code }));
      timer = setTimer(terminate, 180_000);
    } catch { finish({ status: 'failed' }); }
  });
}

export async function cleanupAfterFailure(dir, { runRevoke = runCleanupChild } = {}) {
  const path = join(dir, 'run.json');
  const read = () => parseJsonExact(readFileSync(path, 'utf8'));
  let initial;
  try { initial = read(); } catch { return { status: 'not_eligible' }; }
  if (initial.failure_cleanup !== undefined) return { status: 'already_attempted' };
  if (initial.network !== NETWORK_PASSPHRASE || initial.account_code_hash !== PINNED_ACCOUNT_WASM
    || !contract(initial.account) || !contract(initial.policy) || !hash(initial.policy_wasm_hash)
    || !hash(initial.tx?.add_context_rule) || !Number.isSafeInteger(initial.rule_id)
    || initial.rule_id <= 0 || initial.rule_id > 0xffff_ffff) return { status: 'not_eligible' };
  const record = { status: 'attempting', ...identity(initial) };
  if (initial.lifecycle?.pending_removal !== undefined || initial.lifecycle?.removals?.some((r) => r.rule_id === initial.rule_id)) {
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
    console.error('The live grant may remain; inspect the retained journal. Keys will still be discarded.');
  }
  if (result.status === 'termination_unconfirmed') {
    console.error('Cleanup termination is unconfirmed; do not rewrite or finalize its journal.');
    process.exitCode = 2;
  }
}
