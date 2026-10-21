import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { Account, Address, Keypair, Networks, Operation, StrKey, TransactionBuilder, nativeToScVal, xdr } from '@stellar/stellar-sdk';
import { addContextRuleArgs, contractCall } from './lib.mjs';
import { removalEvent, revokePolicy } from './lifecycle.mjs';
import { monitorGrant } from './monitor.mjs';
import { PINNED_ACCOUNT_WASM, SimulationError } from './rpc.mjs';
import { composedPolicies, SPENDING_LIMIT_WASM } from './subscription.mjs';

const account = StrKey.encodeContract(Buffer.alloc(32, 1));
const policy = StrKey.encodeContract(Buffer.alloc(32, 2));
const spending = StrKey.encodeContract(Buffer.alloc(32, 8));
const target = StrKey.encodeContract(Buffer.alloc(32, 3));
const key = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 4));
const delegate = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 5)).publicKey();
const hash = 'ab'.repeat(32);
const ruleId = 1;
const asHex = (value) => Buffer.from(value.toXDR()).toString('hex');

function event(contract = account, id = ruleId, data = xdr.ScVal.scvMap([])) {
  return new xdr.ContractEvent({ ext: xdr.ExtensionPoint.v0(),
    contractId: new xdr.ContractId(StrKey.decodeContract(contract)), type: xdr.ContractEventType.contract,
    body: xdr.ContractEventBody.v0(new xdr.ContractEventV0({
      topics: [xdr.ScVal.scvSymbol('context_rule_removed'), xdr.ScVal.scvU32(id)], data,
    })),
  });
}
function receipt(events = [event()]) {
  const tx = new TransactionBuilder(new Account(key.publicKey(), '1'), { fee: '100', networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.invokeContractFunction({ contract: account, function: 'remove_context_rule', args: [xdr.ScVal.scvU32(ruleId)] }))
    .setTimeout(100).build();
  return { status: 'SUCCESS', txHash: createHash('sha256').update(tx.signatureBase()).digest('hex'), ledger: 500, envelopeXdr: tx.toEnvelope(),
    resultXdr: new xdr.TransactionResult({ feeCharged: 100n, ext: xdr.TransactionResultExt.v0(),
      result: xdr.TransactionResultResult.txSuccess([
        xdr.OperationResult.opInner(xdr.OperationResultTr.invokeHostFunction(xdr.InvokeHostFunctionResult.invokeHostFunctionSuccess(Buffer.alloc(32)))),
      ]),
    }), events: { contractEventsXdr: [events] } };
}

test('the pinned deployed account event spec uses an empty map, despite the function comment saying []', () => {
  const recorded = JSON.parse(readFileSync(new URL('./fixtures/context-rule-removed-spec.json', import.meta.url)));
  assert.equal(recorded.account_wasm_hash, PINNED_ACCOUNT_WASM);
  const spec = xdr.ScSpecEntry.fromXDR(recorded.event_spec_xdr_base64, 'base64').toJson().event_v0;
  assert.equal(spec.name, 'ContextRuleRemoved');
  assert.deepEqual(spec.prefix_topics, ['context_rule_removed']);
  assert.equal(spec.data_format, 'map');
  assert.deepEqual(spec.params, [{ doc: '', name: 'context_rule_id', type: 'u32', location: 'topic_list' }]);
});

test('recognizes only the pinned removal event in the successful requested transaction', () => {
  const done = receipt();
  assert.deepEqual(removalEvent(done, { hash: done.txHash, account, ruleId }), { contract: account, rule_id: ruleId, ledger: 500 });
});
for (const [name, change] of Object.entries({
  'missing event': (d) => { d.events.contractEventsXdr = [[]]; },
  'duplicate event': (d) => { d.events.contractEventsXdr[0].push(event()); },
  'other rule removal': (d) => { d.events.contractEventsXdr[0].push(event(account, 2)); },
  'other event account': (d) => { d.events.contractEventsXdr = [[event(policy)]]; },
  'wrong event data': (d) => { d.events.contractEventsXdr = [[event(account, ruleId, xdr.ScVal.scvBool(true))]]; },
  'failed transaction': (d) => { d.status = 'FAILED'; },
  'failed result': (d) => { d.resultXdr = { result: { type: 'txFailed' } }; },
  'wrong transaction id': (d) => { d.txHash = hash; },
  'missing envelope': (d) => { delete d.envelopeXdr; },
})) {
  test(`rejects ${name} as removal evidence`, () => {
    const d = receipt(); const expected = d.txHash; change(d);
    assert.throws(() => removalEvent(d, { hash: expected, account, ruleId }));
  });
}

function fixture(t, mode = '') {
  const dir = mkdtempSync(join(tmpdir(), 'ozpb-revoke-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const spec = JSON.parse(readFileSync(new URL('../native-sac-policy-spec.json', import.meta.url)));
  spec.name = 'native-sub'; spec.smart_account.address = account; spec.smart_account.observed_code_hash = PINNED_ACCOUNT_WASM;
  const rule = spec.rules[0]; rule.context.contract = target; rule.authorization.signers[0].delegated.address = delegate;
  const run = { network: Networks.TESTNET, account, account_code_hash: PINNED_ACCOUNT_WASM, sac: target,
    owner: { kind: 'ed25519', address: key.publicKey() }, delegate, policy, policy_wasm_hash: hash,
    rule_id: ruleId, tx: { add_context_rule: hash }, payer: key.publicKey() };
  if (mode.startsWith('subscription')) {
    run.amount = '100';
    run.subscription = { schema_version: 1, mode: 'short_test_window', period_ledgers: 12,
      policy_address: spending, policy_code_hash: SPENDING_LIMIT_WASM };
    rule.policies.unshift({ reviewed: { kind: 'oz:spending_limit', capability: SPENDING_LIMIT_WASM,
      params: { spending_limit: { limit: '100', period_ledgers: 12 } } } });
  }
  writeFileSync(join(dir, 'spec.json'), JSON.stringify(spec)); writeFileSync(join(dir, 'run.json'), JSON.stringify(run));
  const args = addContextRuleArgs({ context: target, name: spec.name, validUntil: rule.valid_until.ledger,
    signers: [{ kind: 'delegated', address: delegate }], policies: composedPolicies(run, spec, policy) });
  const fields = { id: xdr.ScVal.scvU32(ruleId), context_type: args[0], name: args[1], valid_until: args[2],
    signers: args[3], policies: xdr.ScVal.scvVec(args[4].map.map((p) => p.key)) };
  if (mode === 'changed rule') fields.valid_until = xdr.ScVal.scvU32(1);
  const liveRule = xdr.ScVal.scvMap(Object.entries(fields).sort(([a], [b]) => a.localeCompare(b))
    .map(([name, value]) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(name), val: value })));
  let sent = 0; let keyLoads = 0;
  const done = receipt(mode === 'missing event' ? [] : [event()]);
  const deps = {
    assertTestnet: async () => {}, latestLedger: async () => 500,
    contractCodeHash: async (address) => address === account ? (mode === 'changed code' ? hash : PINNED_ACCOUNT_WASM) : hash,
    contractCodeObservation: async (address) => ({
      value: address === account ? (mode === 'changed code' ? hash : PINNED_ACCOUNT_WASM)
        : address === spending ? (mode === 'subscription wrong code' ? hash : SPENDING_LIMIT_WASM) : hash,
      ledger: address === account ? 497 : 498,
    }),
    viewCallObservation: async (_payer, _address, fn) => ({ value: fn === 'get_spending_limit_data'
      ? nativeToScVal({ spending_limit: 100n, period_ledgers: mode === 'subscription wrong params' ? 13 : 12 },
        { type: { spending_limit: ['symbol', 'i128'], period_ledgers: ['symbol', 'u32'] } }) : liveRule, ledger: 499 }),
    loadKey: () => { keyLoads++; return key; }, ownerSigner: async () => key,
    viewCall: async (_payer, address, fn) => {
      if (fn === 'get_context_rule' && sent === 0) return liveRule;
      if (fn === 'get_context_rule') {
        if (mode === 'rule remains') return liveRule;
        throw new SimulationError(fn, `contract:${account}, topics:[error, Error(Contract, #3000)], data:["failing with contract error", 3000]`);
      }
      if (fn === 'is_installed' && address === policy) {
        if (mode === 'readback fails') throw new Error('endpoint unavailable');
        return xdr.ScVal.scvBool(mode === 'cleanup remains');
      }
      if (fn === 'get_spending_limit_data' && address === spending) {
        if (mode === 'subscription cleanup remains') return nativeToScVal({ spending_limit: 100n, period_ledgers: 12 });
        throw new SimulationError(fn, `contract:${spending}, topics:[error, Error(Contract, #3220)], data:["failing with contract error", 3220]`);
      }
      assert.fail(`unexpected read ${fn}`);
    },
    recordAuth: async () => [new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
        address: new Address(account).toScAddress(), nonce: 1n, signatureExpirationLedger: 600, signature: xdr.ScVal.scvVoid(),
      })), rootInvocation: contractCall(account, mode === 'wrong auth' ? 'remove_signer' : 'remove_context_rule', [xdr.ScVal.scvU32(ruleId)]),
    })],
    submit: async (_payer, op) => {
      sent++;
      assert.equal(asHex(op.body.invokeHostFunctionOp.hostFunction), asHex(Operation.invokeContractFunction({
        contract: account, function: 'remove_context_rule', args: [xdr.ScVal.scvU32(ruleId)],
      }).body.invokeHostFunctionOp.hostFunction));
      return { hash: done.txHash, returnValue: xdr.ScVal.scvVoid(), receipt: done };
    },
  };
  return { dir, deps, done, sent: () => sent, keyLoads: () => keyLoads,
    state: () => JSON.parse(readFileSync(join(dir, 'run.json'))) };
}

test('owner revocation preserves installation history and records independent removal/cleanup observations', async (t) => {
  const f = fixture(t);
  await revokePolicy(f.dir, f.deps);
  const state = f.state();
  assert.equal(state.tx.add_context_rule, hash);
  assert.equal(state.rule_id, ruleId);
  const removal = state.lifecycle.removals[0];
  assert.equal(removal.transaction, f.done.txHash);
  assert.equal(removal.event, 'verified');
  assert.equal(removal.rule_readback, 'absent');
  assert.equal(removal.policy_cleanup, 'not_installed');
});
for (const mode of ['changed code', 'changed rule', 'wrong auth']) {
  test(`refuses ${mode} before submitting removal`, async (t) => {
    const f = fixture(t, mode);
    await assert.rejects(revokePolicy(f.dir, f.deps));
    assert.equal(f.sent(), 0);
  });
}
for (const mode of ['missing event', 'readback fails', 'rule remains']) {
  test(`retains the confirmed removal transaction when ${mode}`, async (t) => {
    const f = fixture(t, mode);
    await assert.rejects(revokePolicy(f.dir, f.deps));
    assert.equal(f.state().lifecycle.removals[0].transaction, f.done.txHash);
    assert.equal(f.state().tx.add_context_rule, hash);
  });
}
test('best-effort policy cleanup failure does not erase confirmed rule removal', async (t) => {
  const f = fixture(t, 'cleanup remains');
  const removal = await revokePolicy(f.dir, f.deps);
  assert.equal(removal.rule_readback, 'absent');
  assert.equal(removal.policy_cleanup, 'still_installed');
});

test('an ambiguous removal keeps its pre-submission identity and is never resubmitted', async (t) => {
  const f = fixture(t);
  let attempts = 0;
  f.deps.submit = async (_payer, _op, { onSubmitting }) => {
    attempts++;
    await onSubmitting(hash);
    assert.equal(f.state().lifecycle.pending_removal.transaction, hash);
    throw new Error('confirmation unavailable');
  };
  await assert.rejects(revokePolicy(f.dir, f.deps), /confirmation unavailable/);
  assert.equal(f.state().lifecycle.pending_removal.rule_id, ruleId);
  await assert.rejects(revokePolicy(f.dir, f.deps), /already recorded|pending/);
  assert.equal(attempts, 1);
});

for (const mode of ['subscription', 'subscription cleanup remains']) {
  test(`composed removal preserves both independent cleanup results: ${mode}`, async (t) => {
    const f = fixture(t, mode);
    const removal = await revokePolicy(f.dir, f.deps);
    assert.equal(removal.policy_cleanup, 'not_installed');
    assert.equal(removal.reviewed_policy_cleanup, mode.endsWith('remains') ? 'still_installed' : 'not_installed');
    assert.equal(removal.before.reviewed_policy.address, spending);
  });
}
for (const mode of ['subscription wrong code', 'subscription wrong params']) {
  test(`composed removal refuses changed reviewed policy before loading keys: ${mode}`, async (t) => {
    const f = fixture(t, mode);
    await assert.rejects(revokePolicy(f.dir, f.deps));
    assert.equal(f.sent(), 0);
    assert.equal(f.keyLoads(), 0);
  });
}

test('one-shot configuration observation reads no signing keys and records drift separately', async (t) => {
  const f = fixture(t);
  const result = await monitorGrant(f.dir, f.deps);
  assert.equal(result.configuration, 'matched');
  assert.equal(result.observation, 'non_atomic');
  assert.deepEqual(result.read_ledgers, { account_code: 497, policy_code: 498, rule: 499 });
  assert.equal(Object.hasOwn(result, 'ledger'), false);
  assert.equal(f.keyLoads(), 0);
  assert.equal(f.sent(), 0);
  const changed = fixture(t, 'changed rule');
  await assert.rejects(monitorGrant(changed.dir, changed.deps));
  assert.equal(changed.keyLoads(), 0);
  assert.equal(changed.state().lifecycle.configuration_checks[0].configuration, 'drift_or_unavailable');
});

for (const mode of ['account refusal', 'exhausted policy', 'unrelated policy code', 'permit', 'unrecorded removal', 'scope refusal', 'scope permit', 'wrong challenge refusal', 'wrong challenge permit', 'wrong challenge implicit refusal', 'wrong challenge implicit permit', 'wrong challenge conflicting expectation']) {
  test(`post-revocation invocation control: ${mode}`, () => {
    execFileSync(process.execPath, ['--experimental-vm-modules', fileURLToPath(new URL('./fixtures/post-revoke-invoke.mjs', import.meta.url)), mode], { stdio: 'pipe' });
  });
}


test('failure cleanup refuses a changed run snapshot before loading owner keys', async (t) => {
  const f = fixture(t);
  await assert.rejects(revokePolicy(f.dir, { ...f.deps, expectedRunHash: '00'.repeat(32) }), /cleanup run snapshot/);
  assert.equal(f.keyLoads(), 0);
  assert.equal(f.sent(), 0);
});
