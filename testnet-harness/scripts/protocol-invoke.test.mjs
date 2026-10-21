import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, Keypair, StrKey, scValToNative, xdr } from '@stellar/stellar-sdk';
import { invokeProtocol } from './protocol-invoke.mjs';
import { protocolInvocation, PROTOCOL_TARGETS } from './protocol-calls.mjs';
import { i128 } from './lib.mjs';
import { BLEND_FEE_CEILING } from './blend-preflight.mjs';
import { NETWORK_PASSPHRASE, PINNED_ACCOUNT_WASM } from './rpc.mjs';
const C = (n) => StrKey.encodeContract(Buffer.alloc(32, n));
function fixture(kind = 'soroswap_swap') {
  const payer = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 1)), delegate = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 2));
  const account = C(3), policy = C(4);
  const plan = { kind, account, amount_in: '1000000', minimum_out: '100000', deadline: 2_000_000_000 };
  const run = { network: NETWORK_PASSPHRASE, account, account_code_hash: PINNED_ACCOUNT_WASM,
    payer: payer.publicKey(), delegate: delegate.publicKey(), walkthrough: { ...plan, bundle: {
      status: 'installed', entries: (kind === 'blend_claim' ? [0] : [0, 1]).map((rule_index) => ({
        rule_index, policy: rule_index ? C(5) : policy, installation: { rule_id: 8 + rule_index, transaction: 'aa'.repeat(32) },
      })),
    } } };
  const controls = {}, sends = [], saved = [], signatures = [], simulated = [];
  let balanceCalls = 0;
  const deps = {
    assertTestnet: async () => {}, latestLedger: async () => 100,
    recheckSoroswapTargets: async () => { if (controls.pairDrift) throw new Error('unexpected Soroswap pair code'); },
    contractCodeHash: async (address) => address === account ? PINNED_ACCOUNT_WASM
      : kind === 'blend_claim' ? PROTOCOL_TARGETS.blend_code : PROTOCOL_TARGETS.router_code,
    loadKey: (name) => name === 'payer' || controls.wrongDelegate ? payer : delegate,
    ownerSigner: async () => ({ verifier: C(6), keyData: Buffer.alloc(66, 1), sign: async (digest) => {
      signatures.push(digest); return Buffer.alloc(64, 2);
    } }),
    viewCall: async () => i128(balanceCalls++ === 0 ? 1000 : controls.badBalance ? 1000 : 151000),
    recordAuth: async (_payer, op) => {
      const host = op.body.invokeHostFunctionOp.hostFunction.invokeContract;
      const root = host.functionName.toString() === 'transfer' ? protocolInvocation(plan).subInvocations[0] : protocolInvocation(plan);
      root.function.contractFn.args = host.args;
      if (kind === 'soroswap_swap' && root.subInvocations.length) root.subInvocations[0].function.contractFn.args[2] = host.args[0];
      if (controls.missingChild) root.subInvocations = [];
      return [new xdr.SorobanAuthorizationEntry({
        credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
          address: new Address(account).toScAddress(), nonce: 1n, signatureExpirationLedger: 0, signature: xdr.ScVal.scvVoid(),
        })), rootInvocation: root,
      })];
    },
    enforceSimulation: async (_payer, op) => {
      xdr.Operation.fromXDR(op.toXDR());
      simulated.push(op);
      if (controls.permit) return { result: 'permit', ledger: 101 };
      if (controls.error !== undefined) return { result: 'deny', ledger: 101, error: controls.error };
      const { policy: raiser = policy, code = 6 } = controls.deny ?? {};
      return { result: 'deny', ledger: 101, error: `topics:[error, Error(Auth, InvalidAction)], data:["failed account authentication with error", ${account}, Error(Contract, #${code})]\ncontract:${raiser}, topics:[error, Error(Contract, #${code})], data:["failing with contract error", ${code}]` };
    },
    submit: async (_payer, op, options) => {
      await options.onSubmitting('bb'.repeat(32));
      assert.equal(saved.at(-1).walkthrough.invocations.at(-1).transaction, 'bb'.repeat(32));
      sends.push(op);
      controls.fees = [...(controls.fees ?? []), options.maxFee];
      if (controls.ambiguous) throw new Error('send unconfirmed');
      return { hash: 'bb'.repeat(32), receipt: { ledger: 101 },
        returnValue: kind === 'blend_claim' ? i128(controls.zeroOutput ? 0 : 150000) : xdr.ScVal.scvVec([i128(1000000), i128(150000)]) };
    },
  };
  const execute = ({ deny, ...options } = {}) => {
    if (deny) controls.deny = deny;
    return invokeProtocol({ run, name: options.name ?? 'control', mode: 'simulate',
      signer: 'delegate', expected: { enforcer: policy, code: 6 }, control: 'baseline', ...options,
      save: () => saved.push(structuredClone(run)) }, deps);
  };
  return { run, sends, saved, signatures, controls, simulated, execute };
}
for (const kind of ['soroswap_swap', 'blend_claim']) {
  test(`owner ${kind} records confirmed nonzero output and balance change`, async () => {
    const f = fixture(kind);
    const result = await f.execute({ name: 'owner', signer: 'owner', mode: 'execute', expected: undefined });
    assert.equal(f.sends.length, 1);
    assert.equal(result.status, 'confirmed');
    assert.equal(f.run.walkthrough.owner_transaction.returned_amount, '150000');
    assert.equal(f.run.walkthrough.owner_transaction.balance_after, '151000');
  });
}
for (const control of ['baseline', 'input_cap', 'output_floor', 'deadline']) {
  test(`protocol negative ${control} stays simulation-only even on an unexpected permit`, async () => {
    const f = fixture(); f.controls.permit = true;
    await assert.rejects(f.execute({ control }), /unexpected simulation result/);
    assert.equal(f.sends.length, 0);
    assert.equal(f.run.walkthrough.invocations[0].observation, 'enforcing_simulation');
    assert.equal(f.run.walkthrough.invocations[0].status, 'unexpected_permit');
  });
}
test('negative control cannot opt into execution', async () => {
  const f = fixture();
  await assert.rejects(f.execute({ mode: 'execute', control: 'input_cap' }), /only simulated/);
  assert.equal(f.sends.length, 0);
});
test('missing nested authorization is refused before an owner proof is produced', async () => {
  const f = fixture(); f.controls.missingChild = true;
  await assert.rejects(f.execute({ signer: 'owner', mode: 'execute', expected: undefined }), /intended invocation/);
  assert.equal(f.signatures.length, 0);
  assert.equal(f.sends.length, 0);
});
test('an unconfirmed send retains the known hash and is never automatically repeated', async () => {
  const f = fixture(); f.controls.ambiguous = true;
  const options = { name: 'owner', signer: 'owner', mode: 'execute', expected: undefined };
  await assert.rejects(f.execute(options), /unconfirmed/);
  assert.equal(f.run.walkthrough.invocations[0].status, 'pending');
  assert.equal(f.run.walkthrough.invocations[0].transaction, 'bb'.repeat(32));
  await assert.rejects(f.execute(options), /already/);
  assert.equal(f.sends.length, 1);
});
test('confirmed output without matching balance effect stays incomplete', async () => {
  const f = fixture(); f.controls.badBalance = true;
  await assert.rejects(f.execute({ signer: 'owner', mode: 'execute', expected: undefined }), /balance/);
  assert.equal(f.run.walkthrough.invocations[0].status, 'confirmed_unverified');
  assert.equal(f.run.walkthrough.invocations[0].transaction, 'bb'.repeat(32));
  assert.equal(f.run.walkthrough.owner_transaction, undefined);
});
test('empty signer payload uses real ScVals and never submits', async () => {
  const f = fixture();
  assert.equal((await f.execute({ signer: 'none' })).status, 'verified_denial');
  assert.equal(f.sends.length, 0);
});
test('the independent child capability can be observed only through simulation and its own rule', async () => {
  const f = fixture(); f.controls.permit = true;
  const result = await f.execute({ control: 'direct_token', expected: { permit: true } });
  assert.equal(result.status, 'verified_independent_permission');
  assert.deepEqual(result.rule_ids, [9]);
  assert.equal(f.sends.length, 0);
});
test('permit observation cannot disguise an ordinary negative control', async () => {
  const f = fixture();
  await assert.rejects(f.execute({ control: 'output_floor', expected: { permit: true } }), /expected denial/);
  assert.equal(f.sends.length, 0);
});
const signedRuleIds = (op) => {
  const entry = op.body.invokeHostFunctionOp.auth[0];
  const map = entry.credentials.address.signature.map;
  return map.find((item) => item.key.sym.toString() === 'context_rule_ids').val.vec.map((id) => id.u32);
};
for (const [kind, ids] of [['soroswap_swap', [0, 0]], ['blend_claim', [0]]]) {
  test(`owner ${kind} names the owner rule once per authorization context`, async () => {
    const f = fixture(kind);
    await f.execute({ name: 'owner', signer: 'owner', mode: 'execute', expected: undefined });
    assert.deepEqual(signedRuleIds(f.sends[0]), ids);
  });
}
test('delegate rule IDs follow the root-first context order of the full tree', async () => {
  const f = fixture();
  await f.execute({ name: 'denied' });
  assert.deepEqual(f.run.walkthrough.invocations[0].rule_ids, [8, 9]);
});
test('a direct transfer above the cap is simulated under the transfer rule alone', async () => {
  const f = fixture();
  const result = await f.execute({ control: 'direct_token_cap', expected: { enforcer: C(5), code: 6 },
    deny: { policy: C(5), code: 6 } });
  assert.equal(result.status, 'verified_denial');
  assert.deepEqual(result.rule_ids, [9]);
  assert.equal(f.sends.length, 0);
  const call = f.simulated[0].body.invokeHostFunctionOp.hostFunction.invokeContract;
  assert.equal(call.functionName.toString(), 'transfer');
  assert.equal(scValToNative(call.args[2]), 1_000_001n, 'one unit above the recorded input');
});

const ROUTER_ERROR = (account) => `contract:${PROTOCOL_TARGETS.router}, topics:[error, Error(Contract, #6)], data:["failing with contract error", 6]`;
for (const mode of ['raised by another contract', 'different code', 'protocol error without account failure', 'no error text']) {
  test(`a denial is verified only when the expected policy refused the account: ${mode}`, async () => {
    const f = fixture();
    if (mode === 'raised by another contract') f.controls.deny = { policy: C(7), code: 6 };
    if (mode === 'different code') f.controls.deny = { code: 7 };
    if (mode === 'protocol error without account failure') f.controls.error = ROUTER_ERROR(f.run.account);
    if (mode === 'no error text') f.controls.error = '';
    await assert.rejects(f.execute(), /unexpected simulation result/);
    assert.equal(f.run.walkthrough.invocations[0].status, 'unattributed_denial');
    assert.equal(f.run.walkthrough.invocations[0].code, undefined);
    assert.equal(f.sends.length, 0);
  });
}
test('a changed Soroswap pair stops a call before any authorization is recorded', async () => {
  const f = fixture(); f.controls.pairDrift = true;
  await assert.rejects(f.execute(), /pair code/);
  assert.equal(f.run.walkthrough.invocations, undefined);
  assert.equal(f.signatures.length, 0);
});
test('a delegate call refuses a key that is not the run delegate', async () => {
  const f = fixture(); f.controls.wrongDelegate = true;
  await assert.rejects(f.execute(), /delegate key/);
  assert.equal(f.run.walkthrough.invocations[0].status, 'started');
  assert.equal(f.sends.length, 0);
});

test('a delegated Blend claim that pays zero BLND fails the run instead of counting as the positive', async () => {
  const f = fixture('blend_claim'); f.controls.zeroOutput = true;
  await assert.rejects(f.execute({ name: 'delegate_claim', mode: 'execute', expected: undefined }), /no nonzero amount/);
  assert.equal(f.sends.length, 1);
  const observed = f.run.walkthrough.invocations[0];
  assert.equal(observed.signer, 'delegate');
  assert.equal(observed.status, 'confirmed_unverified');
  assert.equal(observed.returned_amount, undefined);
});

test('a Blend claim names the Blend fee ceiling; a swap keeps the default', async () => {
  for (const [kind, fee] of [['blend_claim', BLEND_FEE_CEILING], ['soroswap_swap', undefined]]) {
    const f = fixture(kind);
    await f.execute({ name: 'owner', signer: 'owner', mode: 'execute', expected: undefined });
    assert.deepEqual(f.controls.fees, [fee]);
  }
});
