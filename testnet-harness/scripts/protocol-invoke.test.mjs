import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, Keypair, StrKey, scValToNative, xdr } from '@stellar/stellar-sdk';
import { SOROSWAP_FOREIGN_RECIPIENT, invokeProtocol } from './protocol-invoke.mjs';
import { negatives } from './protocol-controls.mjs';
import { protocolInvocation, PROTOCOL_TARGETS } from './protocol-calls.mjs';
import { i128 } from './lib.mjs';
import { BLEND_FEE_CEILING } from './blend-preflight.mjs';
import { NETWORK_PASSPHRASE, PINNED_ACCOUNT_WASM } from './rpc.mjs';
const C = (n) => StrKey.encodeContract(Buffer.alloc(32, n));
function fixture(kind = 'soroswap_swap') {
  const payer = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 1)), delegate = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 2));
  const account = C(3), policy = C(4);
  const plan = { kind, account, amount_in: '1000000', minimum_out: '100000', deadline: 2_000_000_000,
    ...(kind === 'soroswap_swap' ? { operator_decisions: { schema: 'ozpb-soroswap-operator-decisions/v1',
      output_floor: { min: '100000', intent: 'floor' }, transfer_cap: { max: '1000000', intent: 'cap' },
      adapter_deadline: 'accept_any_value_high_blast_radius', source_sha256: 'cd'.repeat(32) } } : {}) };
  const run = { network: NETWORK_PASSPHRASE, account, account_code_hash: PINNED_ACCOUNT_WASM,
    payer: payer.publicKey(), delegate: delegate.publicKey(), walkthrough: { ...plan, bundle: {
      status: 'installed', entries: (kind === 'blend_claim' ? [0] : [0, 1]).map((rule_index) => ({
        rule_index, policy: rule_index ? C(5) : policy, installation: { rule_id: 8 + rule_index, transaction: 'aa'.repeat(32) },
      })),
    } } };
  const controls = {}, sends = [], saved = [], signatures = [], simulated = [], recordings = [];
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
      recordings.push(op);
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
  return { run, sends, saved, signatures, controls, simulated, recordings, execute };
}
const simulatedCall = (f) => f.simulated[0].body.invokeHostFunctionOp.hostFunction.invokeContract;
const signedTree = (f) => f.simulated[0].body.invokeHostFunctionOp.auth[0].rootInvocation;
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
for (const control of ['baseline', 'input_cap', 'output_floor', 'path_reordered', 'path_extended', 'path_truncated', 'router_function']) {
  test(`protocol negative ${control} stays simulation-only even on an unexpected permit`, async () => {
    const f = fixture(); f.controls.permit = true;
    await assert.rejects(f.execute({ control }), /unexpected simulation result/);
    assert.equal(f.sends.length, 0);
    assert.equal(f.run.walkthrough.invocations[0].observation, 'enforcing_simulation');
    assert.equal(f.run.walkthrough.invocations[0].status, 'unexpected_permit');
  });
}
const NATIVE = PROTOCOL_TARGETS.native, OUTPUT = PROTOCOL_TARGETS.swap_output;
for (const [control, route] of [['path_reordered', [OUTPUT, NATIVE]], ['path_extended', [NATIVE, OUTPUT, NATIVE]],
  ['path_truncated', [NATIVE]]]) {
  test(`a tampered route (${control}) is signed for both rules without a recording and refused by the router rule`, async () => {
    const f = fixture();
    const result = await f.execute({ name: control, control });
    assert.equal(result.status, 'verified_denial');
    // The router would fail such a route before returning an authorization to record, so the
    // delegate signs the intended tree directly; the account decides it before the route is read.
    assert.equal(f.recordings.length, 0);
    assert.deepEqual(scValToNative(simulatedCall(f).args[2]), route);
    assert.deepEqual(result.rule_ids, [8, 9]);
    const child = signedTree(f).subInvocations[0].function.contractFn;
    assert.equal(Address.fromScAddress(child.contractAddress).toString(), NATIVE, 'the recorded transfer child is kept');
    assert.equal(f.sends.length, 0);
  });
}
test('another router function is signed for the router rule alone and refused by name (#5)', async () => {
  const f = fixture();
  const result = await f.execute({ name: 'router_function', control: 'router_function', expected: { enforcer: C(4), code: 5 },
    deny: { code: 5 } });
  assert.equal(result.status, 'verified_denial');
  assert.equal(simulatedCall(f).functionName.toString(), 'swap_tokens_for_exact_tokens');
  assert.deepEqual(scValToNative(simulatedCall(f).args[3]), f.run.account, 'the account still pays and receives');
  assert.deepEqual(result.rule_ids, [8]);
  assert.equal(signedTree(f).subInvocations.length, 0);
});
const RECIPIENT_REFUSAL = `topics:[error, Error(Auth, InvalidAction)], data:["Unauthorized function call for address", ${SOROSWAP_FOREIGN_RECIPIENT}]`;
test('a foreign recipient is refused before the account is asked: the router authorizes and debits `to`', async () => {
  const f = fixture(); f.controls.error = RECIPIENT_REFUSAL;
  const result = await f.execute({ name: 'foreign_recipient', control: 'foreign_recipient', expected: { recipient_refusal: true } });
  assert.equal(result.status, 'verified_recipient_refusal');
  assert.equal(result.code, undefined);
  assert.equal(scValToNative(simulatedCall(f).args[3]), SOROSWAP_FOREIGN_RECIPIENT);
  assert.ok(StrKey.isValidContract(SOROSWAP_FOREIGN_RECIPIENT) && SOROSWAP_FOREIGN_RECIPIENT !== f.run.payer);
  assert.equal(f.recordings.length, 0);
  assert.equal(f.sends.length, 0);
});
for (const mode of ['the account was asked', 'permitted', 'another address refused', 'error and subject in different events']) {
  test(`a foreign-recipient observation is not verified when ${mode}`, async () => {
    const f = fixture();
    if (mode === 'permitted') f.controls.permit = true;
    if (mode === 'the account was asked') f.controls.error = `${RECIPIENT_REFUSAL}\ntopics:[error, Error(Auth, InvalidAction)], data:["failed account authentication with error", ${f.run.account}, Error(Contract, #6)]`;
    if (mode === 'another address refused') f.controls.error = RECIPIENT_REFUSAL.replace(SOROSWAP_FOREIGN_RECIPIENT, f.run.payer);
    if (mode === 'error and subject in different events') f.controls.error = `topics:[error, Error(Auth, InvalidAction)], data:"other"\n`
      + `topics:[error, Error(Context, InvalidAction)], data:["Unauthorized function call for address", ${SOROSWAP_FOREIGN_RECIPIENT}]`;
    await assert.rejects(f.execute({ control: 'foreign_recipient', expected: { recipient_refusal: true } }), /unexpected simulation result/);
    assert.notEqual(f.run.walkthrough.invocations[0].status, 'verified_recipient_refusal');
    assert.equal(f.sends.length, 0);
  });
}
test('any deadline is a disclosed permit, observed only by simulation with a short-lived signature', async () => {
  const f = fixture(); f.controls.permit = true;
  const result = await f.execute({ name: 'any_deadline', control: 'any_deadline', expected: { permit: true } });
  assert.equal(result.status, 'verified_disclosed_permission');
  assert.equal(scValToNative(simulatedCall(f).args[4]), (1n << 64n) - 1n);
  assert.equal(f.recordings.length, 1, 'the network asks for exactly this tree');
  assert.equal(f.simulated[0].body.invokeHostFunctionOp.auth[0].credentials.address.signatureExpirationLedger, 105);
  assert.equal(f.sends.length, 0);
  f.controls.permit = false;
  const g = fixture();
  await assert.rejects(g.execute({ name: 'any_deadline', control: 'any_deadline', expected: { permit: true } }), /not observed/);
  assert.equal(g.run.walkthrough.invocations[0].status, 'disclosed_permission_not_observed');
});
test('the floor and transfer-cap controls step just past the operator\'s decisions', async () => {
  const f = fixture();
  Object.assign(f.run.walkthrough, { minimum_out: '150000' });
  Object.assign(f.run.walkthrough.operator_decisions, { output_floor: { min: '150000', intent: 'floor' },
    transfer_cap: { max: '2000000', intent: 'cap' } });
  await f.execute({ name: 'output_floor', control: 'output_floor' });
  assert.equal(scValToNative(simulatedCall(f).args[1]), 149_999n);
  const g = fixture();
  g.run.walkthrough.operator_decisions.transfer_cap.max = '2000000';
  await g.execute({ name: 'token_cap', control: 'direct_token_cap', expected: { enforcer: C(5), code: 6 }, deny: { policy: C(5), code: 6 } });
  assert.equal(scValToNative(simulatedCall(g).args[2]), 2_000_001n);
});
for (const [control, expected] of [['any_deadline', { enforcer: C(4), code: 6 }], ['foreign_recipient', { permit: true }],
  ['input_cap', { recipient_refusal: true }]]) {
  test(`an expectation of the wrong kind is refused before anything is signed: ${control}`, async () => {
    const f = fixture();
    await assert.rejects(f.execute({ control, expected }), /expected denial/);
    assert.equal(f.simulated.length, 0);
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
  assert.equal(scValToNative(call.args[2]), 1_000_001n, 'one unit above the decided transfer cap');
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

test('the foreign-recipient claim control names a contract, which needs no BLND trustline to be recorded', async () => {
  const f = fixture('blend_claim');
  const result = await f.execute({ name: 'claim_recipient', control: 'claim_recipient' });
  assert.equal(result.status, 'verified_denial');
  const call = f.simulated[0].body.invokeHostFunctionOp.hostFunction.invokeContract;
  const recipient = scValToNative(call.args[2]);
  assert.ok(StrKey.isValidContract(recipient), 'a classic account without a trustline would fail the recording first');
  assert.notEqual(recipient, f.run.account);
  assert.notEqual(recipient, f.run.payer);
  assert.equal(f.sends.length, 0);
});

test('every W3 control the runner sends passes the invoke guard and verifies as the runner expects', async () => {
  // protocol-controls.test.mjs mocks invoke; this drives the same option objects through the real guard.
  const account = C(3), root = C(4), transfer = C(5);
  const calls = [...negatives('soroswap_swap', account, root, transfer),
    ['count_cap', { expected: { enforcer: root, code: 7 } }],
    ['token_count_cap', { control: 'direct_token', expected: { enforcer: transfer, code: 7 } }]];
  for (const [name, options] of calls) {
    const f = fixture();
    const { expected } = options;
    if (expected.permit) f.controls.permit = true;
    else if (expected.recipient_refusal) f.controls.error = RECIPIENT_REFUSAL;
    else f.controls.deny = { policy: expected.enforcer, code: expected.code };
    const result = await f.execute({ name, mode: 'simulate', ...options });
    assert.equal(result.status, expected.permit ? (options.control === 'direct_token' ? 'verified_independent_permission'
      : 'verified_disclosed_permission') : expected.recipient_refusal ? 'verified_recipient_refusal' : 'verified_denial', name);
    assert.equal(f.sends.length, 0, name);
  }
});
