import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { Networks, StrKey } from '@stellar/stellar-sdk';
import { cleanupAfterFailure, runCleanupChild } from './failure-cleanup.mjs';
import { PINNED_ACCOUNT_WASM } from './rpc.mjs';

const C = (n) => StrKey.encodeContract(Buffer.alloc(32, n));
function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'ozpb-failure-cleanup-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const run = { network: Networks.TESTNET, account: C(1), account_code_hash: PINNED_ACCOUNT_WASM,
    policy: C(2), policy_wasm_hash: 'ab'.repeat(32), rule_id: 7, tx: { add_context_rule: 'cd'.repeat(32) } };
  const save = (value = run) => writeFileSync(join(dir, 'run.json'), JSON.stringify(value));
  const read = () => JSON.parse(readFileSync(join(dir, 'run.json')));
  save();
  return { dir, run, save, read };
}
for (const mode of ['success', 'child failure', 'timeout', 'unverified', 'identity changed']) {
  test(`failed run cleanup preserves exact identity and outcome: ${mode}`, async (t) => {
    const f = fixture(t);
    const result = await cleanupAfterFailure(f.dir, { runRevoke: async () => {
      const state = f.read();
      assert.equal(state.failure_cleanup.status, 'attempting');
      if (mode === 'timeout') return { status: 'timed_out' };
      if (mode === 'child failure') return { status: 'failed' };
      state.lifecycle = { removals: [{ rule_id: 7, transaction: 'ef'.repeat(32),
        event: mode === 'unverified' ? 'not_verified' : 'verified', rule_readback: 'absent' }] };
      if (mode === 'identity changed') state.account = C(3);
      f.save(state);
      return { status: 'exited', code: 0 };
    } });
    assert.equal(result.status, mode === 'success' ? 'removed' : 'incomplete');
    assert.equal(f.read().failure_cleanup.status, result.status);
  });
}
for (const mode of ['owner rule', 'missing installation', 'pending removal', 'confirmed removal', 'attempted cleanup']) {
  test(`failure cleanup never retries or invents authority: ${mode}`, async (t) => {
    const f = fixture(t);
    if (mode === 'owner rule') f.run.rule_id = 0;
    if (mode === 'missing installation') delete f.run.tx.add_context_rule;
    if (mode === 'pending removal') f.run.lifecycle = { pending_removal: { rule_id: 7, transaction: 'ef'.repeat(32) } };
    if (mode === 'confirmed removal') f.run.lifecycle = { removals: [{ rule_id: 7, transaction: 'ef'.repeat(32) }] };
    if (mode === 'attempted cleanup') f.run.failure_cleanup = { status: 'incomplete' };
    f.save();
    const result = await cleanupAfterFailure(f.dir, { runRevoke: () => assert.fail('must not resubmit') });
    assert.notEqual(result.status, 'removed');
  });
}
test('cleanup child has a fixed whole-process-group deadline', async () => {
  const child = new EventEmitter(); child.pid = 123;
  let deadline; let killed; let options;
  const pending = runCleanupChild('/run', {
    expectedRunHash: 'ab'.repeat(32),
    spawnProcess: (_cmd, _args, opts) => { options = opts; return child; },
    setTimer: (fn, ms) => { assert.equal(ms, 180_000); deadline = fn; return 1; },
    clearTimer: () => {}, killGroup: (pid) => { killed = pid; child.emit('close', null, 'SIGKILL'); },
  });
  deadline();
  assert.equal((await pending).status, 'timed_out');
  assert.equal(options.detached, true);
  assert.equal(killed, 123);
});
