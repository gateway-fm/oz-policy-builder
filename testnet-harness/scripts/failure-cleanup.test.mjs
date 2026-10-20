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

test('cleanup deadline waits for child close before permitting journal reconciliation', async () => {
  const child = new EventEmitter(); child.pid = 123;
  const timers = new Map();
  let resolved = false, killed;
  const pending = runCleanupChild('/controlled', { expectedRunHash: 'ab'.repeat(32),
    spawnProcess: () => child,
    setTimer: (fn, ms) => { timers.set(ms, fn); return ms; },
    clearTimer: () => {}, killGroup: (pid) => { killed = pid; },
  }).then((result) => { resolved = true; return result; });
  timers.get(180_000)();
  await Promise.resolve();
  assert.equal(killed, 123);
  assert.equal(resolved, false, 'a requested SIGKILL is not a reaped child');
  child.emit('close', null, 'SIGKILL');
  assert.deepEqual(await pending, { status: 'timed_out' });
});
for (const mode of ['kill fails', 'close never arrives']) {
  test(`cleanup termination grace preserves uncertainty without reconciling: ${mode}`, async (t) => {
    const child = new EventEmitter(); child.pid = 123;
    const timers = new Map();
    const pending = runCleanupChild('/controlled', { expectedRunHash: 'ab'.repeat(32),
      spawnProcess: () => child, setTimer: (fn, ms) => { timers.set(ms, fn); return ms; }, clearTimer: () => {},
      killGroup: () => { if (mode === 'kill fails') throw new Error('permission denied'); },
    });
    timers.get(180_000)();
    assert.ok(timers.has(5000), 'termination grace is fixed and bounded');
    timers.get(5000)();
    assert.deepEqual(await pending, { status: 'termination_unconfirmed' });
    const f = fixture(t);
    const result = await cleanupAfterFailure(f.dir, { runRevoke: async () => {
      writeFileSync(join(f.dir, 'run.json'), '{child may still be writing');
      return { status: 'termination_unconfirmed' };
    } });
    assert.equal(result.status, 'termination_unconfirmed');
    assert.equal(readFileSync(join(f.dir, 'run.json'), 'utf8'), '{child may still be writing');
    const marker = JSON.parse(readFileSync(join(f.dir, 'cleanup-termination.json'), 'utf8'));
    assert.equal(marker.status, 'termination_unconfirmed');
    assert.match(marker.expected_run_sha256, /^[0-9a-f]{64}$/);
  });
}
