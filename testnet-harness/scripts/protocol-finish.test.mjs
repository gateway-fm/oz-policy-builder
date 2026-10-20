import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { Networks, StrKey } from '@stellar/stellar-sdk';
import { finishProtocolBundle, runProtocolCleanupChild } from './protocol-finish.mjs';
import { PINNED_ACCOUNT_WASM } from './rpc.mjs';
const C = (n) => StrKey.encodeContract(Buffer.alloc(32, n));
function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'ozpb-protocol-finish-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const run = { network: Networks.TESTNET, account: C(1), account_code_hash: PINNED_ACCOUNT_WASM,
    walkthrough: { bundle: { account: C(1), account_code_hash: PINNED_ACCOUNT_WASM, network: Networks.TESTNET,
      spec_hash: 'aa'.repeat(32), registry_root: 'bb'.repeat(32), entries: [0, 1].map((rule_index) => ({
        rule_index, policy: C(rule_index + 2), wasm_hash: 'cc'.repeat(32),
        installation: { rule_id: rule_index + 8, transaction: String(rule_index + 1).repeat(64) },
      })) } } };
  const save = (value = run) => writeFileSync(join(dir, 'run.json'), JSON.stringify(value));
  const read = () => JSON.parse(readFileSync(join(dir, 'run.json')));
  save();
  return { dir, run, save, read };
}
for (const mode of ['success', 'timeout', 'failed child', 'second rule remains', 'changed installation', 'changed policy', 'changed spec', 'pending install', 'pending removal', 'unreadable journal']) {
  test(`final protocol cleanup preserves all capability outcomes: ${mode}`, async (t) => {
    const f = fixture(t);
    const result = await finishProtocolBundle(f.dir, { runChild: async (_dir, options) => {
      const bytes = readFileSync(join(f.dir, 'run.json'));
      assert.equal(options.expectedRunHash, createHash('sha256').update(bytes).digest('hex'));
      const state = JSON.parse(bytes);
      assert.equal(state.walkthrough.final_cleanup.status, 'attempting');
      if (mode === 'timeout') return { status: 'timed_out' };
      if (mode === 'failed child') return { status: 'failed' };
      if (mode === 'unreadable journal') { writeFileSync(join(f.dir, 'run.json'), '{unreadable'); return { status: 'exited', code: 0 }; }
      for (const entry of state.walkthrough.bundle.entries) {
        entry.removal = { transaction: 'dd'.repeat(32), event: 'verified', rule_readback: 'absent', policy_cleanup: 'not_installed' };
      }
      const second = state.walkthrough.bundle.entries[1];
      if (mode === 'second rule remains') second.removal.rule_readback = 'still_present';
      if (mode === 'changed installation') second.installation.transaction = 'ee'.repeat(32);
      if (mode === 'changed policy') second.policy = C(9);
      if (mode === 'changed spec') state.walkthrough.bundle.spec_hash = 'ee'.repeat(32);
      if (mode === 'pending install') second.pending = { operation: 'install', transaction: 'ee'.repeat(32) };
      if (mode === 'pending removal') second.pending_removal = { transaction: 'ee'.repeat(32) };
      state.walkthrough.bundle.cleanup = { status: 'removed' };
      f.save(state);
      return { status: 'exited', code: 0 };
    } });
    assert.equal(result.status, mode === 'success' ? 'removed' : 'incomplete');
    if (mode === 'unreadable journal') assert.equal(readFileSync(join(f.dir, 'run.json'), 'utf8'), '{unreadable');
    else assert.equal(f.read().walkthrough.final_cleanup.status, result.status);
  });
}
test('final cleanup never repeats a previous attempt', async (t) => {
  const f = fixture(t);
  f.run.walkthrough.final_cleanup = { status: 'incomplete' }; f.save();
  assert.equal((await finishProtocolBundle(f.dir, { runChild: () => assert.fail('no retry') })).status, 'already_attempted');
});
test('protocol cleanup uses only its fixed command and a 180-second process-group deadline', async () => {
  const child = new EventEmitter(); child.pid = 123;
  let deadline, killed;
  const pending = runProtocolCleanupChild('/controlled run', { expectedRunHash: 'ab'.repeat(32),
    spawnProcess: (cmd, argv, options) => {
      assert.equal(cmd, process.execPath);
      assert.ok(argv[0].endsWith('/bundle-command.mjs'));
      assert.deepEqual(argv.slice(1), ['cleanup', '--run-dir', '/controlled run', '--expected-run-sha256', 'ab'.repeat(32)]);
      assert.equal(options.detached, true);
      return child;
    },
    setTimer: (fn, ms) => { assert.equal(ms, 180_000); deadline = fn; return 1; },
    clearTimer: () => {}, killGroup: (pid) => { killed = pid; child.emit('close', null, 'SIGKILL'); },
  });
  deadline();
  assert.deepEqual(await pending, { status: 'timed_out' });
  assert.equal(killed, 123);
});
test('cleanup deadline waits for child close before permitting journal reconciliation', async () => {
  const child = new EventEmitter(); child.pid = 123;
  const timers = new Map();
  let resolved = false, killed;
  const pending = runProtocolCleanupChild('/controlled', { expectedRunHash: 'ab'.repeat(32),
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
    const pending = runProtocolCleanupChild('/controlled', { expectedRunHash: 'ab'.repeat(32),
      spawnProcess: () => child, setTimer: (fn, ms) => { timers.set(ms, fn); return ms; }, clearTimer: () => {},
      killGroup: () => { if (mode === 'kill fails') throw new Error('permission denied'); },
    });
    timers.get(180_000)();
    assert.ok(timers.has(5000), 'termination grace is fixed and bounded');
    timers.get(5000)();
    assert.deepEqual(await pending, { status: 'termination_unconfirmed' });
    const f = fixture(t);
    const result = await finishProtocolBundle(f.dir, { runChild: async () => {
      writeFileSync(join(f.dir, 'run.json'), '{child may still be writing');
      return { status: 'termination_unconfirmed' };
    } });
    assert.equal(result.status, 'termination_unconfirmed');
    assert.equal(readFileSync(join(f.dir, 'run.json'), 'utf8'), '{child may still be writing');
  });
}
for (const mode of ['nonzero child exit', 'install still pending from the start', 'confirmed install without a rule ID']) {
  test(`final protocol cleanup stays incomplete when a grant may remain: ${mode}`, async (t) => {
    const f = fixture(t);
    const second = f.run.walkthrough.bundle.entries[1];
    if (mode === 'install still pending from the start') {
      delete second.installation;
      second.pending = { operation: 'install', transaction: 'ee'.repeat(32) };
    }
    if (mode === 'confirmed install without a rule ID') second.installation.rule_id = null;
    f.save();
    const result = await finishProtocolBundle(f.dir, { runChild: async () => {
      // A child that reports every known grant removed; the journal's own gaps must still count.
      const state = f.read();
      for (const entry of state.walkthrough.bundle.entries) {
        if (entry.installation?.rule_id > 0) {
          entry.removal = { transaction: 'dd'.repeat(32), event: 'verified', rule_readback: 'absent', policy_cleanup: 'not_installed' };
        }
      }
      state.walkthrough.bundle.cleanup = { status: 'removed' };
      f.save(state);
      return { status: 'exited', code: mode === 'nonzero child exit' ? 1 : 0 };
    } });
    assert.equal(result.status, 'incomplete');
    assert.equal(f.read().walkthrough.final_cleanup.status, 'incomplete');
  });
}

test('an unreadable journal before cleanup is incomplete, not inapplicable', async (t) => {
  const f = fixture(t);
  writeFileSync(join(f.dir, 'run.json'), '{"walkthrough": {"bundle"');
  const result = await finishProtocolBundle(f.dir, { runChild: () => assert.fail('nothing to bind a child to') });
  assert.equal(result.status, 'incomplete');
  assert.equal(result.reason, 'unreadable_journal');
});
test('a missing journal or one without a bundle is not applicable', async (t) => {
  const f = fixture(t);
  delete f.run.walkthrough.bundle; f.save();
  assert.equal((await finishProtocolBundle(f.dir, { runChild: () => assert.fail('no bundle') })).status, 'not_applicable');
  rmSync(join(f.dir, 'run.json'));
  assert.equal((await finishProtocolBundle(f.dir, { runChild: () => assert.fail('no journal') })).status, 'not_applicable');
});
