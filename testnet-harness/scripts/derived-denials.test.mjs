import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Address, Keypair, StrKey, scValToNative, xdr } from '@stellar/stellar-sdk';
import {
  MIN_DERIVED_DENIALS, OFFLINE_CLASSES, liveRules, liveStandIns, planDerivedDenials, predictEnforcer,
  runDerivedDenials, suiteHash, verifySuite,
} from './derived-denials.mjs';
import { PROTOCOL_TARGETS } from './protocol-calls.mjs';
import { parseJsonExact } from './raw-json.mjs';
import { SPENDING_LIMIT_WASM } from './subscription.mjs';
import { NATIVE_SAC, NETWORK_PASSPHRASE, PINNED_ACCOUNT_WASM } from './rpc.mjs';

const C = (n) => StrKey.encodeContract(Buffer.alloc(32, n));
const G = (n) => Keypair.fromRawEd25519Seed(Buffer.alloc(32, n)).publicKey();
const fixture = (name) => readFileSync(new URL(`./fixtures/derived/${name}`, import.meta.url), 'utf8');
const ACCOUNT = C(1), DELEGATE = G(2), MERCHANT = C(4);
const delegateKey = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 2));
const GENERATED = C(5), SPENDING = C(6), OTHER_TOKEN = C(7), TRANSFER_POLICY = C(8);

function runFor(walkthrough) {
  const common = { network: NETWORK_PASSPHRASE, account: ACCOUNT, account_code_hash: PINNED_ACCOUNT_WASM,
    delegate: DELEGATE, payer: G(9), sac: NATIVE_SAC, recipient: MERCHANT, amount: '10000000' };
  if (walkthrough === 'w2') {
    return { ...common, rule_id: 3, policy: GENERATED, policy_wasm_hash: 'ab'.repeat(32),
      authority_check: { checked_at_ledger: 9, rechecked_at_ledger: 10 },
      subscription: { schema_version: 1, mode: 'short_test_window', period_ledgers: 24, policy_address: SPENDING,
        policy_code_hash: SPENDING_LIMIT_WASM, other_token: OTHER_TOKEN, installation_readback: 'matched' } };
  }
  const kind = walkthrough === 'w1' ? 'blend_claim' : 'soroswap_swap';
  const spec = parseJsonExact(fixture(`${walkthrough}-spec.json`));
  const plan = { kind, account: ACCOUNT };
  if (kind === 'soroswap_swap') Object.assign(plan, { amount_in: '1000000', minimum_out: '100000', deadline: 1792505380 });
  plan.bundle = { status: 'installed', spec_hash: 'cd'.repeat(32), entries: spec.rules.map((_rule, index) => ({
    rule_index: index, policy: index ? TRANSFER_POLICY : GENERATED, wasm_hash: `${index}e`.repeat(32),
    installation: { rule_id: 8 + index, transaction: 'aa'.repeat(32) } })) };
  return { ...common, walkthrough: plan };
}

function suiteFor(walkthrough) {
  const emitted = parseJsonExact(fixture(`${walkthrough}-cases.json`));
  const reference = parseJsonExact(fixture(`${walkthrough}-reference.json`));
  return { emitted, reference, spec: parseJsonExact(fixture(`${walkthrough}-spec.json`)) };
}

function plan(walkthrough, standIns) {
  const run = runFor(walkthrough);
  const { emitted, spec } = suiteFor(walkthrough);
  const rules = liveRules(run, spec);
  return planDerivedDenials({ cases: emitted.cases, rules, account: run.account, delegate: run.delegate,
    standIns: standIns ?? ((rule) => liveStandIns(run, rule)) });
}

const denialText = (account, contract, code) => `topics:[error, Error(Auth, InvalidAction)], data:["failed account authentication with error", ${account}, Error(Contract, #${code})]\n`
  + `contract:${contract}, topics:[error, Error(Contract, #${code})], data:["failing with contract error", ${code}]`;

/** A run directory with the pre-install artifacts derived-denials reads, plus network doubles. */
function harness(walkthrough, { policyOrder, observe, emittedText, specHash, standIns } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'ozpb-derived-'));
  const run = runFor(walkthrough);
  const { emitted, reference } = suiteFor(walkthrough);
  run.spec = join(dir, 'spec.json');
  writeFileSync(join(dir, 'spec.json'), fixture(`${walkthrough}-spec.json`));
  writeFileSync(join(dir, 'reference-suite.json'), fixture(`${walkthrough}-reference.json`));
  const pipeline = walkthrough === 'w2' ? 'pipeline.json' : 'protocol-pipeline.json';
  writeFileSync(join(dir, pipeline), JSON.stringify({ schema_version: 1, spec_hash: specHash ?? emitted.spec_hash }));
  if (run.walkthrough) run.walkthrough.bundle.spec_hash = specHash ?? emitted.spec_hash;
  writeFileSync(join(dir, 'run.json'), JSON.stringify(run, null, 2));
  const calls = { network: 0, simulations: [], cli: [] };
  const order = policyOrder ?? (walkthrough === 'w2' ? [GENERATED, SPENDING] : null);
  const deps = {
    runCli: (args) => { calls.cli.push(args); return emittedText ?? fixture(`${walkthrough}-cases.json`); },
    assertTestnet: async () => { calls.network++; },
    contractCodeHash: async (address) => {
      calls.network++;
      if (address === ACCOUNT) return PINNED_ACCOUNT_WASM;
      if (address === SPENDING) return SPENDING_LIMIT_WASM;
      if (address === GENERATED) return walkthrough === 'w2' ? run.policy_wasm_hash : '0e'.repeat(32);
      return '1e'.repeat(32);
    },
    viewCallObservation: async (_source, contract, fn, args) => {
      calls.network++;
      if (fn === 'get_context_rule') {
        const id = scValToNative(args[0]);
        const policies = walkthrough === 'w2' ? order : [id === 8 ? GENERATED : TRANSFER_POLICY];
        return { ledger: 100, value: xdr.ScVal.scvMap([new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('policies'),
          val: xdr.ScVal.scvVec(policies.map((p) => new Address(p).toScVal())) })]) };
      }
      assert.equal(fn, 'get_spending_limit_data');
      assert.equal(contract, SPENDING);
      return { ledger: 100, value: xdr.ScVal.scvMap([
        new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('cached_total_spent'), val: xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: 0n })) }),
        new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('period_ledgers'), val: xdr.ScVal.scvU32(24) }),
        new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('spending_history'), val: xdr.ScVal.scvVec([]) }),
        new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('spending_limit'), val: xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: 10000000n })) }),
      ]) };
    },
    latestLedger: async () => { calls.network++; return 100; },
    loadKey: (name) => { assert.equal(name, 'delegate'); return delegateKey; },
    enforceSimulation: async (source, operation) => {
      calls.network++;
      assert.equal(source.publicKey(), run.payer);
      xdr.Operation.fromXDR(operation.toXDR());
      calls.simulations.push(operation);
      const outcome = observe(operation, calls.simulations.length);
      return { ledger: 101, ...outcome };
    },
    ...(standIns ? { standIns } : {}),
  };
  const read = () => JSON.parse(readFileSync(join(dir, 'run.json'), 'utf8'));
  return { dir, run, deps, calls, read, emitted };
}

/** The network double: the account and policies decide exactly as the plan predicts. */
function faithful(account, predicted) {
  return (operation) => {
    const p = predicted(operation);
    return p.permit ? { result: 'permit' } : { result: 'deny', error: denialText(account, p.enforcer, p.code) };
  };
}

// --- the three properties the report's claim rests on ---------------------------------------------

test('derived denials refuse fewer than five realizable cases', async () => {
  // W1's suite reaches exactly five only with the pool's other function as the live stand-in for
  // the generated absent name; without it the run must refuse rather than report four.
  assert.equal(plan('w1').denials.length, MIN_DERIVED_DENIALS);
  assert.throws(() => plan('w1', () => ({})), /4 live-realizable deny cases; at least 5 are required/);
  // And the refusal comes before anything touches the network or the journal.
  const h = harness('w1', { standIns: () => ({}), observe: () => assert.fail('nothing may be simulated') });
  await assert.rejects(runDerivedDenials(h.dir, h.deps), /at least 5 are required/);
  assert.equal(h.calls.network, 0);
  assert.equal(h.read().derived_denials, undefined);
  // Nothing is left behind that would make the refusal look like a replay, or block a rerun.
  assert.ok(!existsSync(join(h.dir, 'derived-cases.json')));
});

test('a denial attributed to the wrong enforcer fails the run', async () => {
  // The spending policy refuses the larger amount first only if it is first in the live order;
  // here the generated policy is first, so a 3221 from the spending policy is misattributed.
  const h = harness('w2', { observe: (operation) => {
    const args = operation.body.invokeHostFunctionOp.hostFunction.invokeContract.args;
    if (args.length === 3 && args[2].type === 'scvI128' && scValToNative(args[2]) === 10000001n) {
      return { result: 'deny', error: denialText(ACCOUNT, SPENDING, 3221) };
    }
    return faithful(ACCOUNT, predictFromOperation)(operation);
  } });
  await assert.rejects(runDerivedDenials(h.dir, h.deps), /case-7: unattributed_denial/);
  const journal = h.read().derived_denials;
  assert.equal(journal.status, 'incomplete');
  const failed = journal.cases.find((c) => c.id === 'case-7');
  assert.deepEqual(failed.expected, { enforcer: GENERATED, code: 6 });
  assert.deepEqual(failed.observed, { result: 'deny', enforcer: SPENDING, code: 3221 });
  assert.equal(failed.status, 'unattributed_denial');

  // An unexpected permit is a failure too, and never becomes a submission.
  const p = harness('w2', { observe: () => ({ result: 'permit' }) });
  await assert.rejects(runDerivedDenials(p.dir, p.deps), /unexpected_permit/);
  assert.equal(p.read().derived_denials.cases[0].status, 'unexpected_permit');
  assert.ok(!('submit' in p.deps));
});

test('cases are drawn from this spec\'s suite hash, not hand-picked', async () => {
  const { emitted, reference } = suiteFor('w2');
  const cases = verifySuite(emitted, { specHash: emitted.spec_hash, reference });
  assert.equal(cases.length, emitted.total);
  assert.equal(suiteHash(emitted.spec_hash, emitted.cases), emitted.suite_hash);
  // A subset, an edited case or another spec's list does not recompute to the hash it claims.
  const subset = { ...emitted, cases: emitted.cases.filter((c) => c.class !== 'arg_equality') };
  subset.total = subset.cases.length;
  assert.throws(() => verifySuite(subset, { specHash: emitted.spec_hash, reference }), /suite hash/);
  const edited = structuredClone(emitted);
  edited.cases[7].invocation.args[2] = { i128: '1' };
  assert.throws(() => verifySuite(edited, { specHash: emitted.spec_hash, reference }), /suite hash/);
  assert.throws(() => verifySuite(emitted, { specHash: 'ee'.repeat(32), reference }), /installed spec/);
  // A list that recomputes but is not the suite the pre-install reference report evaluated.
  const relabeled = structuredClone(emitted);
  relabeled.cases[7].label = 'hand-written control';
  relabeled.suite_hash = suiteHash(relabeled.spec_hash, relabeled.cases);
  assert.throws(() => verifySuite(relabeled, { specHash: emitted.spec_hash, reference }), /reference report/);

  // End to end: the CLI is asked for this run's spec, and the replayed denials are every
  // live-realizable deny case of that suite, in suite order — none chosen by name.
  const live = harness('w2', { observe: faithful(ACCOUNT, predictFromOperation) });
  await runDerivedDenials(live.dir, live.deps);
  assert.deepEqual(live.calls.cli, [['reference-suite', '--spec', join(live.dir, 'spec.json'), '--emit-cases']]);
  const journal = live.read().derived_denials;
  assert.equal(journal.status, 'completed');
  assert.deepEqual(journal.suite, { spec_hash: emitted.spec_hash, suite_hash: emitted.suite_hash, total: emitted.total,
    minimum_denials: MIN_DERIVED_DENIALS });
  const expectedIds = plan('w2').denials.map((d) => d.id);
  assert.deepEqual(journal.cases.map((c) => c.id), expectedIds);
  assert.deepEqual(expectedIds, ['case-1', 'case-5', 'case-7', 'case-8', 'case-9', 'case-10', 'case-11', 'case-15', 'case-16', 'case-18']);
  assert.ok(existsSync(join(live.dir, 'derived-cases.json')));
});

// --- realization and prediction ---------------------------------------------------------------------

/** Re-derive the expected decision from the operation alone, as the live network would. */
function predictFromOperation(operation) {
  const call = operation.body.invokeHostFunctionOp.hostFunction.invokeContract;
  const contract = Address.fromScAddress(call.contractAddress).toString();
  const auth = operation.body.invokeHostFunctionOp.auth;
  const payload = auth[0].credentials.address.signature;
  const signers = payload.map.find((e) => e.key.sym.toString() === 'signers').val.map;
  const addresses = signers.map((e) => Address.fromScAddress(e.key.vec[1].address).toString());
  if (contract !== NATIVE_SAC) return { enforcer: ACCOUNT, code: 3002 };
  if (addresses.some((a) => a !== DELEGATE)) return { enforcer: ACCOUNT, code: 3016 };
  if (addresses.length === 0) return { enforcer: GENERATED, code: 1 };
  const [from, to, amount] = call.args;
  const exact = Address.fromScVal(from).toString() === ACCOUNT && Address.fromScVal(to).toString() === MERCHANT
    && scValToNative(amount) === 10000000n;
  return exact ? { permit: true } : { enforcer: GENERATED, code: 6 };
}

test('W2 replays its ten live denials and lists every offline class with its reason', () => {
  const p = plan('w2');
  assert.equal(p.originals.length, 1);
  assert.deepEqual(p.denials.map((d) => [d.id, d.class, d.realization]), [
    ['case-1', 'different_contract', 'live_stand_in'],
    ['case-5', 'different_address_arg', 'mutation_on_recorded_call'],
    ['case-7', 'arg_equality', 'mutation_on_recorded_call'],
    ['case-8', 'arg_equality', 'mutation_on_recorded_call'],
    ['case-9', 'arg_equality', 'mutation_on_recorded_call'],
    ['case-10', 'numeric_boundary', 'mutation_on_recorded_call'],
    ['case-11', 'numeric_boundary', 'mutation_on_recorded_call'],
    ['case-15', 'zero_signers', 'mutation_on_recorded_call'],
    ['case-16', 'wrong_signer', 'mutation_on_recorded_call'],
    ['case-18', 'signer_boundary', 'mutation_on_recorded_call'],
  ]);
  // The other token is the existing funded control token, with the recorded call's arguments.
  assert.equal(p.denials[0].contract, OTHER_TOKEN);
  assert.equal(p.denials[0].stand_in, 'w2_control_token');
  const byReason = Object.fromEntries(p.offline.map((o) => [`${o.class}:${o.reason}`, o.cases]));
  assert.deepEqual(byReason, {
    'different_function:no_live_stand_in': 1,
    'different_address_arg:authorizer_replaced': 1,
    'type_confusion:host_rejects_before_authorization': 3,
    'arg_arity:host_rejects_before_authorization': 2,
    'strict_set_mutation:installation_state': 2,
    'time_boundary:ledger_time': 1,
    'call_count_boundary:installation_state': 3,
    'missing_state:installation_state': 1,
  });
  for (const o of p.offline) if (OFFLINE_CLASSES[o.class]) assert.equal(o.reason, OFFLINE_CLASSES[o.class]);
});

test('W2 predictions follow the live policy order, including the spending policy deciding first', () => {
  const p = plan('w2');
  const run = runFor('w2');
  const [rule] = liveRules(run, suiteFor('w2').spec);
  const generated = { address: GENERATED, kind: 'generated' };
  const spending = { address: SPENDING, kind: 'spending_limit', limit: 10000000n, spent: 0n };
  const expect = (order) => Object.fromEntries(p.denials.map((d) => [d.id, predictEnforcer(d, rule, order, ACCOUNT)]));
  const g = (code) => ({ enforcer: GENERATED, code }), s = (code) => ({ enforcer: SPENDING, code });
  const a = (code) => ({ enforcer: ACCOUNT, code });
  assert.deepEqual(expect([generated, spending]), { 'case-1': a(3002), 'case-5': g(6), 'case-7': g(6), 'case-8': g(6),
    'case-9': g(6), 'case-10': g(6), 'case-11': g(6), 'case-15': g(1), 'case-16': a(3016), 'case-18': a(3016) });
  // Spending first: amounts above its limit and the empty signer set are its own refusals; a
  // smaller amount or another recipient passes it and reaches the generated policy.
  assert.deepEqual(expect([spending, generated]), { 'case-1': a(3002), 'case-5': g(6), 'case-7': s(3221), 'case-8': g(6),
    'case-9': s(3221), 'case-10': g(6), 'case-11': s(3221), 'case-15': s(3223), 'case-16': a(3016), 'case-18': a(3016) });
  assert.deepEqual(predictEnforcer(p.originals[0], rule, [spending, generated], ACCOUNT), { permit: true });
});

test('W3 replays both rules with their recorded trees and keeps type-changing mutations offline', () => {
  const p = plan('w3');
  assert.equal(p.originals.length, 2);
  // The router original carries the recorded transfer child and both rule IDs, root first.
  const [router, transfer] = p.originals;
  assert.deepEqual(router.rule_ids, [8, 9]);
  assert.equal(router.tree.subInvocations.length, 1);
  assert.deepEqual(transfer.rule_ids, [9]);
  assert.equal(p.denials.length, 10);
  assert.deepEqual(p.denials.map((d) => `${d.rule_index}:${d.class}`), [
    '0:numeric_boundary', '0:numeric_boundary', '0:zero_signers', '0:wrong_signer', '0:signer_boundary',
    '1:different_address_arg', '1:numeric_boundary', '1:zero_signers', '1:wrong_signer', '1:signer_boundary',
  ]);
  // A router mutation keeps the recorded transfer child, so it needs both rule IDs; a transfer-rule
  // case is the direct transfer alone.
  for (const d of p.denials) {
    assert.equal(d.tree.subInvocations.length, d.rule_index === 0 ? 1 : 0);
    assert.deepEqual(d.rule_ids, d.rule_index === 0 ? [8, 9] : [9]);
  }
  // Above the input cap and below the output floor, each on the recorded call.
  const [cap, floor] = p.denials;
  assert.equal(scValToNative(cap.args[0]), 1000001n);
  assert.equal(scValToNative(floor.args[1]), 99999n);
  assert.equal(cap.args[4].type, 'scvU64');
  // A bool where the route or deadline is would be refused by the router before authorization.
  const reasons = p.offline.filter((o) => o.rule_index === 0).map((o) => `${o.class}:${o.reason}`);
  assert.ok(reasons.includes('arg_equality:host_rejects_before_authorization'));
  assert.ok(reasons.includes('different_address_arg:authorizer_replaced'));
  assert.ok(reasons.includes('different_function:no_live_stand_in'));
  assert.ok(reasons.includes('different_contract:no_live_stand_in'));
});

test('W1 realizes the other pool function as its stand-in and predicts FunctionNotAllowed', () => {
  const p = plan('w1');
  const run = runFor('w1');
  const [rule] = liveRules(run, suiteFor('w1').spec);
  const fn = p.denials.find((d) => d.class === 'different_function');
  assert.equal(fn.stand_in, 'blend_pool_submit');
  assert.equal(fn.fn, 'submit');
  assert.equal(fn.contract, PROTOCOL_TARGETS.blend_pool);
  const order = [{ address: GENERATED, kind: 'generated' }];
  assert.deepEqual(predictEnforcer(fn, rule, order, ACCOUNT), { enforcer: GENERATED, code: 5 });
  const recipient = p.denials.find((d) => d.class === 'different_address_arg');
  // The claim's `to`, not its authorizing `from`, is replaced.
  assert.equal(Address.fromScVal(recipient.args[0]).toString(), ACCOUNT);
  assert.notEqual(Address.fromScVal(recipient.args[2]).toString(), ACCOUNT);
  assert.deepEqual(predictEnforcer(recipient, rule, order, ACCOUNT), { enforcer: GENERATED, code: 6 });
});

test('signer payloads name only what each case authenticates, in host key order', async () => {
  const h = harness('w2', { observe: faithful(ACCOUNT, predictFromOperation) });
  await runDerivedDenials(h.dir, h.deps);
  const signersOf = (operation) => {
    const auth = operation.body.invokeHostFunctionOp.auth;
    const payload = auth[0].credentials.address.signature;
    return { entries: auth.length, signers: payload.map.find((e) => e.key.sym.toString() === 'signers').val.map
      .map((e) => Address.fromScAddress(e.key.vec[1].address).toString()) };
  };
  const byId = Object.fromEntries(h.read().derived_denials.cases.map((c, i) => [c.id, h.calls.simulations[i + 1]]));
  assert.deepEqual(signersOf(byId['case-15']), { entries: 1, signers: [] });
  const wrong = signersOf(byId['case-16']);
  assert.equal(wrong.entries, 1);
  assert.equal(wrong.signers.length, 1);
  assert.notEqual(wrong.signers[0], DELEGATE);
  const plus = signersOf(byId['case-18']);
  assert.equal(plus.entries, 2);
  assert.deepEqual([...plus.signers].sort(), [DELEGATE, wrong.signers[0]].sort());
  const keys = plus.signers.map((a) => Buffer.from(xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Delegated'), new Address(a).toScVal()]).toXDR()));
  assert.ok(Buffer.compare(keys[0], keys[1]) < 0);
  // Every simulation's authorization expires within a few ledgers of the run.
  // The signed original is a live authorization of the real call while it lasts, and it reaches
  // the RPC endpoint, so it lasts only long enough to be simulated.
  for (const op of h.calls.simulations) assert.ok(op.body.invokeHostFunctionOp.auth[0].credentials.address.signatureExpirationLedger <= 105);
});

test('a completed journal labels the evidence and never records a transaction', async () => {
  const h = harness('w2', { observe: faithful(ACCOUNT, predictFromOperation) });
  const journal = await runDerivedDenials(h.dir, h.deps);
  assert.equal(journal.status, 'completed');
  assert.deepEqual(journal.labels, { post_install: true, state_dependent: true, simulation_only: true, submitted: false });
  assert.deepEqual(journal.originals.map((o) => [o.id, o.status]), [['case-0', 'permitted']]);
  assert.ok(journal.cases.every((c) => c.status === 'verified_denial' && c.ledger === 101 && !('transaction' in c)));
  assert.deepEqual(journal.policy_order, [GENERATED, SPENDING]);
  // A second attempt on the same grant is refused.
  await assert.rejects(runDerivedDenials(h.dir, h.deps), /already/);
});

test('a recorded call that is not the suite original is refused before replaying', () => {
  // Mutations are applied to the recorded call, so it must be the call the suite's original
  // describes: equal at every exact position, and within every bound.
  const run = runFor('w2');
  const { emitted, spec } = suiteFor('w2');
  const plan = (r) => planDerivedDenials({ cases: emitted.cases, rules: liveRules(r, spec), account: r.account,
    delegate: r.delegate, standIns: (rule) => liveStandIns(r, rule) });
  assert.equal(plan(run).denials.length, 10);
  assert.throws(() => plan({ ...run, amount: '10000001' }), /recorded call differs from the suite original at arg\[2\]/);
  assert.throws(() => plan({ ...run, recipient: C(12) }), /recorded call differs from the suite original at arg\[1\]/);
  const w3 = runFor('w3');
  const protocol = suiteFor('w3');
  const over = { ...w3, walkthrough: { ...w3.walkthrough, amount_in: '1000001' } };
  assert.throws(() => planDerivedDenials({ cases: protocol.emitted.cases, rules: liveRules(over, protocol.spec), account: over.account,
    delegate: over.delegate }), /recorded call differs from the suite original at arg\[0\]/);
});
