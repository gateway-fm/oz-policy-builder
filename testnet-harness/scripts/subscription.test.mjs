import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { Address, Asset, Keypair, Networks, StrKey, scValToNative, xdr } from '@stellar/stellar-sdk';
import { contractCall, i128 } from './lib.mjs';
import { PINNED_ACCOUNT_WASM, NATIVE_SAC } from './rpc.mjs';
import { composedPolicies, configureSubscription, SPENDING_LIMIT_WASM, subscriptionConfig } from './subscription.mjs';
import { runSubscriptionControls, simulatedTransfer } from './subscription-controls.mjs';
import { setupSubscription } from './setup-subscription.mjs';

const C = (n) => StrKey.encodeContract(Buffer.alloc(32, n));
const key = (n) => Keypair.fromRawEd25519Seed(Buffer.alloc(32, n));
const hash = 'ab'.repeat(32);
function fixture() {
  const run = { network: Networks.TESTNET, account: C(1), account_code_hash: PINNED_ACCOUNT_WASM, sac: NATIVE_SAC,
    policy: C(2), policy_wasm_hash: hash, payer: key(6).publicKey(), delegate: key(5).publicKey(),
    recipient: key(7).publicKey(), owner: { kind: 'ed25519', address: key(4).publicKey() }, amount: '100',
    tx: {}, rule_id: 1, valid_until_ledger: 2000, authority_check: { rechecked_at_ledger: 490 }, invocations: [],
    subscription: { schema_version: 1, mode: 'short_test_window', policy_address: C(3), policy_code_hash: SPENDING_LIMIT_WASM,
      period_ledgers: 12, installation_readback: 'matched', other_token: C(8) } };
  const spec = JSON.parse(readFileSync(new URL('../native-sac-policy-spec.json', import.meta.url)));
  spec.rules[0].policies.unshift({ reviewed: { kind: 'oz:spending_limit', capability: SPENDING_LIMIT_WASM,
    params: { spending_limit: { limit: run.amount, period_ledgers: 12 } } } });
  return { run, spec };
}

test('subscription composition binds both policies in spec order and rejects broadened params', () => {
  const { run, spec } = fixture();
  const policies = composedPolicies(run, spec, run.policy);
  assert.deepEqual(policies.map((p) => p.address), [run.subscription.policy_address, run.policy]);
  assert.deepEqual(policies[0].install_params, { kind: 'spending_limit', spending_limit: '100', period_ledgers: 12 });
  spec.rules[0].policies[0].reviewed.params.spending_limit.limit = '101';
  assert.throws(() => composedPolicies(run, spec, run.policy), /parameters differ/);
  run.subscription.policy_address = run.policy;
  assert.throws(() => subscriptionConfig(run), /separate contract/);
});

test('configuration reads exact reviewed policy code before saving and refuses replay', async () => {
  let { run } = fixture(); delete run.subscription;
  let saved = 0;
  const deps = { readJson: () => structuredClone(run), writeJson: (_path, value) => { saved++; run = value; },
    assertTestnet: async () => {}, contractCodeObservation: async () => ({ value: hash, ledger: 500 }) };
  await assert.rejects(configureSubscription('/unused', { policy: C(3), period: 12 }, deps), /code differs/);
  assert.equal(saved, 0);
  deps.contractCodeObservation = async () => ({ value: SPENDING_LIMIT_WASM, ledger: 501 });
  await configureSubscription('/unused', { policy: C(3), period: 12 }, deps);
  assert.equal(run.subscription.code_observed_ledger, 501);
  await assert.rejects(configureSubscription('/unused', { policy: C(3), period: 12 }, deps), /already configured/);
});

for (const signer of ['delegate', 'payer', 'none', 'other_token']) for (const authV2 of [false, true]) {
  test(`negative control signs only the intended auth, never a fee transaction: ${signer}, authV2=${authV2}`, async () => {
    const { run } = fixture(); let simulated = 0;
    run.recipient = C(9);
    const token = signer === 'other_token' ? run.subscription.other_token : run.sac;
    const request = { signer: signer === 'other_token' ? 'delegate' : signer, token };
    const intended = contractCall(token, 'transfer', [new Address(run.account).toScVal(), new Address(run.recipient).toScVal(), i128(100n)]);
    const credentials = authV2 ? xdr.SorobanCredentials.sorobanCredentialsAddressV2 : xdr.SorobanCredentials.sorobanCredentialsAddress;
    const entry = new xdr.SorobanAuthorizationEntry({ credentials: credentials(
      new xdr.SorobanAddressCredentials({ address: new Address(run.account).toScAddress(), nonce: 1n,
        signatureExpirationLedger: 600, signature: xdr.ScVal.scvVoid() })), rootInvocation: intended });
    const deps = { loadKey: (name) => key(name === 'payer' ? 6 : 5), latestLedger: async () => 500,
      recordAuth: async () => [entry], enforceSimulation: async (_payer, operation) => {
        simulated++;
        // Exercise the actual SDK wire boundary: inspecting in-memory fields misses a
        // Buffer accidentally supplied where a ScVal is required.
        const decoded = xdr.Operation.fromXDR(operation.toXDR());
        const call = decoded.body.invokeHostFunctionOp.hostFunction.invokeContract;
        assert.equal(Address.fromScAddress(call.contractAddress).toString(), token);
        assert.equal(scValToNative(call.args[1]), C(9), 'wrong-token control keeps the recorded merchant');
        const auth = decoded.body.invokeHostFunctionOp.auth;
        assert.equal(auth.length, signer === 'none' ? 1 : 2);
        const accountCredentials = auth[0].credentials.address ?? auth[0].credentials.addressV2;
        const payload = accountCredentials.signature;
        assert.deepEqual(scValToNative(payload.map.find((p) => p.key.sym.toString() === 'context_rule_ids').val), [run.rule_id]);
        const signers = payload.map.find((p) => p.key.sym.toString() === 'signers').val.map;
        assert.equal(signers.length, signer === 'none' ? 0 : 1);
        assert.equal(accountCredentials.signatureExpirationLedger, 600);
        return { result: 'permit', ledger: 500 };
      }, submit: () => assert.fail('negative controls cannot submit') };
    const observed = await simulatedTransfer(run, request, deps);
    assert.equal(observed.result, 'permit', 'unexpected permission stays a simulation observation');
    assert.equal(simulated, 1);
    entry.rootInvocation = contractCall(run.sac, 'burn', []);
    await assert.rejects(simulatedTransfer(run, request, deps), /authorization tree/);
    assert.equal(simulated, 1);
  });
}

function controlFixture(mode = '') {
  let { run } = fixture(); let ledger = 500; let clock = 0; let charges = 0; let controls = 0;
  const deps = {
    readJson: () => structuredClone(run), writeJson: (_path, value) => { run = structuredClone(value); },
    assertTestnet: async () => {}, viewCall: async () => i128(mode === 'unfunded token' ? 0n : 100n),
    latestLedger: async () => ledger, now: () => clock,
    delay: async () => { clock += mode === 'timeout' ? 1_000_000 : 5000; if (mode !== 'timeout') ledger += 12; },
    invokePermit: async () => {
      charges++; ledger++;
      run.invocations.push({ signer: 'delegate', rule: 1, amount: run.amount, to: run.recipient,
        result: 'permit', hash: String(charges).repeat(64), ledger });
    },
    simulatedTransfer: async (_run, request) => {
      controls++;
      let enforcer = run.policy; let code = 6;
      if (request.token) { enforcer = run.account; code = 3002; }
      else if (request.signer === 'payer') { enforcer = run.account; code = 3016; }
      else if (request.signer === 'none') code = 1;
      else if (charges === 1) { enforcer = run.subscription.policy_address; code = 3221; }
      else if (charges === 2) code = 7;
      if (mode === 'late repeat' && charges === 1) ledger += 12;
      if (mode === 'wrong enforcer' && charges === 1) enforcer = run.policy;
      return { result: mode === 'unexpected permit' ? 'permit' : 'deny', ledger,
        error: `topics:[error, Error(Auth, InvalidAction)], data:["failed account authentication with error", ${run.account}, Error(Contract, #${code})]\n`
          + `contract:${enforcer}, topics:[error, Error(Contract, #${code})], data:["failing with contract error", ${code}]` };
    },
  };
  return { deps, state: () => run, charges: () => charges, controls: () => controls };
}

test('subscription controls prove exact tuple, early repeat, next window and unmasked total cap', async () => {
  const f = controlFixture();
  const journal = await runSubscriptionControls('/unused', f.deps);
  assert.equal(journal.status, 'completed');
  assert.equal(f.charges(), 2);
  assert.equal(f.controls(), 8);
  const early = journal.steps.find((s) => s.name === 'early_repeat');
  assert.ok(early.ledger < early.before_ledger);
  assert.equal(early.code, 3221);
  const charges = journal.steps.filter((s) => s.result === 'confirmed_charge');
  assert.ok(charges[1].ledger >= charges[0].ledger + 12);
  assert.ok(journal.steps.at(-1).ledger >= charges[1].ledger + 12);
  assert.equal(journal.steps.at(-1).code, 7);
  await assert.rejects(runSubscriptionControls('/unused', f.deps), /already started/);
});
for (const mode of ['late repeat', 'wrong enforcer', 'unexpected permit', 'unfunded token', 'timeout']) {
  test(`subscription controls refuse incomplete evidence: ${mode}`, async () => {
    const f = controlFixture(mode);
    await assert.rejects(runSubscriptionControls('/unused', f.deps));
    if (mode !== 'unfunded token') assert.equal(f.state().subscription.controls.status, 'incomplete');
    if (mode === 'late repeat') assert.equal(f.state().subscription.controls.steps.at(-1).result, 'inconclusive_window_elapsed');
    assert.ok(f.charges() <= 1);
  });
}

for (const wrongMerchant of [false, true]) {
test(`subscription fixture setup isolates the merchant and journals confirmed steps: wrongMerchant=${wrongMerchant}`, async () => {
  let { run } = fixture(); delete run.subscription;
  const token = new Asset('W2TEST', run.payer).contractId(Networks.TESTNET);
  const stages = [];
  const deps = { readJson: () => structuredClone(run), writeJson: (_path, value) => { run = structuredClone(value); },
    assertTestnet: async () => {}, loadKey: () => key(6), contractIdOf: (value) => scValToNative(value),
    contractCodeObservation: async () => ({ value: SPENDING_LIMIT_WASM, ledger: 499 }),
    contractCodeHash: async () => PINNED_ACCOUNT_WASM,
    viewCall: async () => i128(100n),
    submit: async (_payer, operation, { stage }) => {
      stages.push(stage);
      if (stage === 'create subscription merchant') {
        const constructor = operation.body.invokeHostFunctionOp.hostFunction.createContractV2.constructorArgs;
        assert.equal(constructor[0].vec.length, 1);
        assert.deepEqual(scValToNative(constructor[0].vec[0]), ['Delegated', run.owner.address]);
        assert.equal(constructor[1].map.length, 0);
      }
      if (stage === 'mint control token') {
        assert.ok(run.tx.create_control_token);
        const call = operation.body.invokeHostFunctionOp.hostFunction.invokeContract;
        assert.equal(Address.fromScAddress(call.contractAddress).toString(), token);
        assert.equal(scValToNative(call.args[0]), run.account);
        assert.equal(scValToNative(call.args[1]), 100n);
      }
      return { hash, returnValue: new Address(stage === 'create subscription policy' ? C(3)
        : stage === 'create subscription merchant' ? (wrongMerchant ? run.account : C(9)) : token).toScVal() };
    } };
  if (wrongMerchant) {
    await assert.rejects(setupSubscription('/unused', { policy: 'deploy', period: 12 }, deps), /separate contract/);
    assert.equal(run.tx.create_subscription_merchant, hash, 'confirmed deployment identity is retained');
    assert.deepEqual(stages, ['create subscription policy', 'create subscription merchant']);
    return;
  }
  await setupSubscription('/unused', { policy: 'deploy', period: 12 }, deps);
  assert.deepEqual(stages, ['create subscription policy', 'create subscription merchant', 'create control token', 'mint control token']);
  assert.equal(run.recipient, C(9));
  assert.equal(run.subscription.other_token, token);
  assert.equal(run.subscription.control_token_funding, 'matched');
});
}
