import assert from 'node:assert/strict';
import test from 'node:test';
import { StrKey } from '@stellar/stellar-sdk';
import { runProtocolControls } from './protocol-controls.mjs';
const C = (n) => StrKey.encodeContract(Buffer.alloc(32, n));
function fixture(kind = 'soroswap_swap') {
  const rules = kind === 'blend_claim' ? [0] : [0, 1];
  const run = { account: C(1), payer: StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 9)), valid_until_ledger: 280,
    walkthrough: { kind, grant_duration_ledgers: 180, ...(kind === 'blend_claim' ? { accrual_ledgers: 2,
      owner_transaction: { ledger: 276 } } : {}),
    bundle: { status: 'installed', entries: rules.map((rule_index) => ({ rule_index, policy: C(2 + rule_index),
      installation: { rule_id: 8 + rule_index, transaction: 'aa'.repeat(32) } })) } } };
  const calls = [], control = {};
  let now = 0, ledger = 279;
  const deps = {
    checkArtifacts: async () => {}, inspectGrant: async () => {},
    invoke: async (options) => {
      calls.push(options);
      if (control.failure === options.name) throw new Error('unexpected control outcome');
      const observed = { name: options.name, status: options.mode === 'execute' ? 'confirmed'
        : options.expected.permit ? 'verified_independent_permission' : 'verified_denial',
      ledger: control.lateLedger === options.name ? 281 : control.earlyLedger === options.name ? 280 : ledger,
      transaction: options.mode === 'execute' ? 'bb'.repeat(32) : undefined };
      (options.run.walkthrough.invocations ??= []).push(observed);
      return observed;
    },
    latestLedger: async () => ledger,
    now: () => now, delay: async () => { now += control.timeout ? 1_200_001 : 5000; if (!control.timeout) ledger++; },
    cleanup: async () => { calls.push({ name: 'cleanup' }); return { status: control.cleanupFailure ? 'incomplete' : 'removed' }; },
  };
  if (kind === 'blend_claim') ledger = 270;
  const execute = () => runProtocolControls({ run, spec: {}, artifacts: [], save: () => {} }, deps);
  return { run, calls, control, execute, setLedger: (value) => { ledger = value; } };
}
const expected = (f, name) => f.calls.find((call) => call.name === name).expected;
test('W3 controls prove bounded calls, independent token authority, actual expiry and removal in order', async () => {
  const f = fixture();
  assert.equal((await f.execute()).status, 'completed');
  assert.deepEqual(f.calls.map((call) => call.name), ['input_cap', 'output_floor', 'exact_deadline',
    'wrong_signer', 'zero_signers', 'independent_token', 'delegate_swap', 'count_cap', 'expired_rule', 'cleanup', 'post_revocation']);
  assert.equal(f.calls.filter((call) => call.mode === 'execute').length, 1);
  assert.deepEqual(expected(f, 'input_cap'), { enforcer: C(2), code: 6 });
  assert.deepEqual(expected(f, 'wrong_signer'), { enforcer: C(1), code: 3016 });
  assert.deepEqual(expected(f, 'independent_token'), { permit: true });
  assert.deepEqual(expected(f, 'count_cap'), { enforcer: C(2), code: 7 });
  assert.deepEqual(expected(f, 'expired_rule'), { enforcer: C(1), code: 3002 });
  assert.deepEqual(expected(f, 'post_revocation'), { enforcer: C(1), code: 3000 });
  assert.equal(f.run.walkthrough.controls.steps.find((step) => step.name === 'expiry_wait').ledger, 281);
});
test('W1 controls wait for accrual before the one delegated claim and keep its own denials', async () => {
  const f = fixture('blend_claim');
  assert.equal((await f.execute()).status, 'completed');
  assert.deepEqual(f.calls.map((call) => call.name), ['reserve_ids', 'claim_recipient', 'pool_function',
    'wrong_signer', 'zero_signers', 'delegate_claim', 'count_cap', 'expired_rule', 'cleanup', 'post_revocation']);
  assert.deepEqual(expected(f, 'reserve_ids'), { enforcer: C(2), code: 6 });
  assert.equal(f.calls.find((call) => call.name === 'delegate_claim').mode, 'execute');
  const steps = f.run.walkthrough.controls.steps.map((step) => step.name);
  assert.ok(steps.indexOf('accrual_wait') < steps.indexOf('delegate_claim'));
  assert.equal(f.run.walkthrough.controls.steps.find((step) => step.name === 'accrual_wait').ledger, 278);
});
test('W1 controls require an explicit bounded accrual wait', async () => {
  const f = fixture('blend_claim');
  delete f.run.walkthrough.accrual_ledgers;
  await assert.rejects(f.execute(), /accrual/);
  assert.equal(f.calls.length, 0);
});
for (const mode of ['negative failure', 'wait timeout', 'cleanup failure', 'denial after expiry', 'expiry not yet reached']) {
  test(`W3 controls preserve incomplete outcome: ${mode}`, async () => {
    const f = fixture();
    if (mode === 'negative failure') f.control.failure = 'input_cap';
    if (mode === 'wait timeout') f.control.timeout = true;
    if (mode === 'cleanup failure') f.control.cleanupFailure = true;
    if (mode === 'denial after expiry') f.control.lateLedger = 'output_floor';
    if (mode === 'expiry not yet reached') f.control.earlyLedger = 'expired_rule';
    await assert.rejects(f.execute());
    assert.equal(f.run.walkthrough.controls.status, 'incomplete');
    if (['negative failure', 'denial after expiry'].includes(mode)) assert.equal(f.calls.some((call) => call.mode === 'execute'), false);
    if (mode === 'wait timeout') assert.equal(f.calls.some((call) => call.name === 'expired_rule'), false);
    if (['cleanup failure', 'expiry not yet reached'].includes(mode)) {
      assert.equal(f.calls.some((call) => call.name === 'post_revocation'), false);
    }
    await assert.rejects(f.execute(), /already/);
  });
}
test('controls refuse an expired, incomplete or already exercised bundle before any call', async () => {
  for (const change of [(f) => f.setLedger(280), (f) => { f.run.walkthrough.bundle.status = 'incomplete'; },
    (f) => { f.run.walkthrough.invocations = [{ name: 'earlier', signer: 'delegate' }]; },
    (f) => { f.run.walkthrough.bundle.entries.pop(); }]) {
    const f = fixture();
    change(f);
    await assert.rejects(f.execute());
    assert.equal(f.calls.length, 0);
    assert.equal(f.run.walkthrough.controls, undefined);
  }
});
