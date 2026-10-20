// Called before fixture keys are discarded, on success or failure. The fixed cleanup child
// gets one 180-second deadline plus a five-second termination grace for its whole process group.
// If termination is unconfirmed, the caller must not reconcile/finalize the child-owned journal.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isMainModule } from './cli-entry.mjs';
import { args, NETWORK_PASSPHRASE, PINNED_ACCOUNT_WASM, writeJson } from './rpc.mjs';
const hash = (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const identity = (run) => {
  const bundle = run.walkthrough?.bundle;
  return { network: run.network, account: run.account, account_code_hash: run.account_code_hash,
    bundle: bundle && { network: bundle.network, account: bundle.account, account_code_hash: bundle.account_code_hash,
      spec_hash: bundle.spec_hash, registry_root: bundle.registry_root,
      entries: bundle.entries?.map((entry) => ({ rule_index: entry.rule_index, spec_hash: entry.spec_hash,
        policy: entry.policy, wasm_hash: entry.wasm_hash, installation: entry.installation ?? null,
        installation_transaction: entry.tx?.install ?? null, pending_installation: entry.pending?.operation === 'install' ? entry.pending : null })) } };
};
export function runProtocolCleanupChild(dir, {
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
      if (!hash(expectedRunHash)) throw new Error('missing expected protocol snapshot');
      child = spawnProcess(process.execPath, [fileURLToPath(new URL('./bundle-command.mjs', import.meta.url)),
        'cleanup', '--run-dir', dir, '--expected-run-sha256', expectedRunHash],
      { detached: true, stdio: 'ignore', env: process.env });
      child.once('error', () => Number.isSafeInteger(child.pid) && child.pid > 0 ? terminate() : finish({ status: 'failed' }));
      child.once('close', (code) => finish(timedOut ? { status: 'timed_out' } : { status: 'exited', code }));
      timer = setTimer(terminate, 180_000);
    } catch { finish({ status: 'failed' }); }
  });
}

export async function finishProtocolBundle(dir, { runChild = runProtocolCleanupChild } = {}) {
  const path = join(dir, 'run.json'), read = () => JSON.parse(readFileSync(path, 'utf8'));
  let initial;
  try { initial = read(); }
  catch (error) {
    // Only a missing journal is known to hold no grant; an unreadable one may.
    return error?.code === 'ENOENT' ? { status: 'not_applicable' } : { status: 'incomplete', reason: 'unreadable_journal' };
  }
  if (!initial.walkthrough?.bundle) return { status: 'not_applicable' };
  if (initial.walkthrough.final_cleanup !== undefined) return { status: 'already_attempted' };
  if (initial.network !== NETWORK_PASSPHRASE || initial.account_code_hash !== PINNED_ACCOUNT_WASM
    || !Array.isArray(initial.walkthrough.bundle.entries)) return { status: 'incomplete', reason: 'invalid_identity' };
  const before = JSON.stringify(identity(initial));
  initial.walkthrough.final_cleanup = { status: 'attempting' };
  writeJson(path, initial);
  const expectedRunHash = createHash('sha256').update(readFileSync(path)).digest('hex');
  let child;
  try { child = await runChild(dir, { expectedRunHash }); } catch { child = { status: 'failed' }; }
  if (child.status === 'termination_unconfirmed') {
    const result = { status: 'termination_unconfirmed', reason: 'cleanup_process_not_reaped' };
    try {
      // `dir` is the run directory `run.sh` created, or one its operator names on the command
      // line; no server or remote request reaches this script. `wx` refuses an existing path.
      // nosec
      writeFileSync(join(dir, 'cleanup-termination.json'), JSON.stringify({ ...result,
        expected_run_sha256: expectedRunHash }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    } catch { console.error('Could not create the separate cleanup termination marker.'); }
    return result;
  }
  let current;
  try { current = read(); } catch { return { status: 'incomplete', reason: 'unreadable_journal' }; }
  const entries = current.walkthrough?.bundle?.entries;
  const unchanged = before === JSON.stringify(identity(current));
  const known = entries?.filter((entry) => entry.installation?.rule_id > 0);
  const verified = unchanged && child.status === 'exited' && child.code === 0
    && Array.isArray(entries) && entries.every((entry) => entry.pending?.operation !== 'install'
      && entry.pending_removal === undefined && entry.installation?.rule_id !== null)
    && known.every((entry) => hash(entry.removal?.transaction) && entry.removal.event === 'verified'
      && entry.removal.rule_readback === 'absent' && entry.removal.policy_cleanup === 'not_installed')
    && current.walkthrough.bundle.cleanup?.status === (known.length ? 'removed' : 'no_installed_grants');
  const result = { status: verified ? known.length ? 'removed' : 'no_installed_grants' : 'incomplete',
    reason: verified ? 'verified_bundle_cleanup' : child.status === 'timed_out' ? 'deadline'
      : !unchanged ? 'identity_changed' : 'cleanup_unconfirmed' };
  if (current.walkthrough && typeof current.walkthrough === 'object') {
    current.walkthrough.final_cleanup = result;
    writeJson(path, current);
  }
  return result;
}
if (isMainModule(import.meta.url)) {
  const options = args();
  if (!options['run-dir']) throw new Error('usage: protocol-finish.mjs --run-dir DIRECTORY');
  const result = await finishProtocolBundle(options['run-dir']);
  console.error(`Protocol grant cleanup: ${result.status}.`);
  if (result.status === 'incomplete' || result.status === 'termination_unconfirmed') {
    console.error('One or more grants may remain; retain the journal. Fixture keys must still be discarded.');
    if (result.status === 'termination_unconfirmed') console.error('Cleanup termination is unconfirmed; do not rewrite or finalize its journal.');
    process.exitCode = result.status === 'termination_unconfirmed' ? 2 : 1;
  }
}
