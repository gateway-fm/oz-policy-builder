import assert from 'node:assert/strict';
import test from 'node:test';
import { Keypair } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM, NETWORK_ID } from '../shared/approval.mjs';
import { deploymentFixture, setup } from './actions-fixture.mjs';
import { nativeFixture, signRequest } from './native-execution-fixture.mjs';

const LEDGER = { protocol_version: 29, sequence: 1000, timestamp: '1760000000', base_reserve: 5000000,
  min_temp_entry_ttl: 720, min_persistent_entry_ttl: 120960, max_entry_ttl: 3110400 };

/** A deployed, reviewed grant whose delegate is a backend-created capability; the worker is faked. */
async function reviewed({ maxCalls = 2, runFails = false, intentChange = () => {}, prepareFails = false, sourceFails = false } = {}) {
  const runs = [];
  const prepares = [];
  let frames;
  const native = { executable: '/fixed/ozpb-execution-runtime', run: async (executable, jobText, options) => {
    runs.push({ executable, jobText, prepareOnly: options.prepareOnly === true });
    if (runFails) throw new Error('native process refused; no execution evidence accepted');
    options.validatePrepared(structuredClone(frames.prepared));
    if (options.prepareOnly) return structuredClone(frames.prepared);
    const answer = options.sign(signRequest(frames.prepared));
    assert.ok(Keypair.fromPublicKey(frames.prepared.binding.delegate_address).verify(
      Buffer.from(signRequest(frames.prepared).digest_hex, 'hex'), Buffer.from(answer.signature_hex, 'hex')));
    return options.validateResult(structuredClone(frames.result));
  } };
  const f = deploymentFixture(() => {}, { native });
  const delegate = await f.actions['create-delegate']({});
  f.artifact.spec.rules[0].authorization = { signers: [{ delegated: { address: delegate.address } }] };
  f.artifact.spec.rules[0].state = [{ call_count_per_installation: { max_calls: maxCalls } }];
  const preview = await f.actions['prepare-deploy']({ artifactId: f.artifactId });
  const deployed = await f.actions['confirm-deploy']({ id: preview.action.id });
  intentChange(f.f.intent.authority.verdict.evidence);
  const review = await f.actions.review({ deploymentId: deployed.deploymentId, wallet: f.f.wallet });
  frames = nativeFixture({ maxCalls, accountAddress: f.f.wallet.contractId, delegateAddress: delegate.address,
    policyAddress: f.policy, policyCodeHash: f.artifact.wasmHash, candidateContextRuleId: 1 });
  f.toolchain.prepareDryRun = async (input) => {
    prepares.push(input);
    if (prepareFails) throw new Error('wallet pipeline refused; refresh and review again');
    return { request: { candidate: input.candidate, run_nonce: 'e'.repeat(64) }, output: {
      schema: 'ozpb:dry-run:v1', run_hash: frames.expected.runHash, binding: { spec_hash: f.artifact.specHash,
        binding_set_hash: f.f.expected.bindingSetHash, registry_snapshot_root: 'c'.repeat(64), account_address: f.f.wallet.contractId,
        account_code_hash: ACCOUNT_WASM, network_id: NETWORK_ID, rule_index: 0, candidate_context_rule_id: input.candidateContextRuleId,
        suite_hash: frames.expected.suiteHash, policy_code_hashes: { [f.policy]: f.artifact.wasmHash } },
      artifact_verification: { matches: true }, reference_report: { total: 3, disagreements: 0,
        outcomes: frames.reference.outcomes, expected_classes: { 0: frames.reference.requiredClasses } },
      layers: [{ id: 'reference', status: 'passed', cases: 3 }, { id: 'account_wasm', status: 'unavailable' },
        { id: 'captured_target', status: 'unavailable' }, { id: 'live_enforcement', status: 'unavailable' }],
      complete: false, disclaimer: 'x' } };
  };
  f.network.nativeSource = async (hash) => { assert.equal(hash, ACCOUNT_WASM);
    if (sourceFails) throw new Error('wallet network operation refused; inspect the local journal before retrying');
    return { ledger: LEDGER, accountWasmBase64: 'AGFzbQEAAAA=' }; };
  return { ...f, delegate, deployed, review, runs, prepares, native };
}

test('without an operator worker, delegate creation and account checks are unavailable', async () => {
  const { actions } = setup();
  const status = await actions.status({});
  assert.equal(status.capabilities.accountCheck, false);
  await assert.rejects(() => actions['create-delegate']({}), /refused/);
  await assert.rejects(() => actions['check-account']({ reviewId: 'a'.repeat(64), capabilityId: 'b'.repeat(64) }), /refused/);
});

test('a backend-held delegate drives a validated account-Wasm layer while installation stays disabled', async () => {
  const f = await reviewed();
  assert.deepEqual(Object.keys(f.delegate).sort(), ['address', 'capabilityId']);
  assert.equal((await f.actions.status({})).capabilities.accountCheck, true);
  const result = await f.actions['check-account']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  const layers = Object.fromEntries(result.verification.layers.map((layer) => [layer.layer, layer.status]));
  assert.deepEqual(layers, { reference: 'passed', account_wasm: 'passed', captured_target: 'unavailable', live_enforcement: 'unavailable' });
  assert.equal(result.verification.complete, false);
  assert.equal(result.verification.specHash, f.artifact.specHash);
  assert.equal(result.verification.layers[1].evidence.candidateContextRuleId, 1);
  assert.equal(f.prepares[0].candidateContextRuleId, 1, 'bounded next ID from the reviewed authority evidence');
  assert.equal(f.prepares[0].artifactId, f.artifactId);
  assert.deepEqual(f.runs.map((run) => [run.executable, run.prepareOnly]),
    [['/fixed/ozpb-execution-runtime', true], ['/fixed/ozpb-execution-runtime', false]]);
  assert.equal(f.runs[0].jobText, f.runs[1].jobText);
  assert.ok(!f.runs[0].jobText.includes(f.delegate.capabilityId), 'the worker never receives the capability ID');
  assert.equal((await f.actions.status({})).capabilities.install, false);
  await assert.rejects(() => f.actions.assemble({ reviewId: f.review.reviewId }), /refused/);
});

test('a capability for another delegate is refused before any preparation or worker', async () => {
  const f = await reviewed();
  const other = await f.actions['create-delegate']({});
  await assert.rejects(() => f.actions['check-account']({ reviewId: f.review.reviewId, capabilityId: other.capabilityId }), /refused/);
  assert.equal(f.prepares.length, 0);
  assert.equal(f.runs.length, 0);
});

test('a refused worker records a failed layer and accepts no evidence', async () => {
  const f = await reviewed({ runFails: true });
  const result = await f.actions['check-account']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  assert.equal(result.verification.layers[1].status, 'failed');
  assert.equal(result.verification.layers[1].evidence, undefined);
});

test('call caps beyond the worker scope are unsupported and never run', async () => {
  const f = await reviewed({ maxCalls: 513 });
  const result = await f.actions['check-account']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  assert.equal(result.verification.layers[1].status, 'unsupported');
  assert.equal(f.prepares.length + f.runs.length, 0);
});

test('a fresh review starts without earlier account evidence and callers cannot inject evidence', async () => {
  const f = await reviewed();
  await f.actions['check-account']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  const again = await f.actions.review({ deploymentId: f.deployed.deploymentId, wallet: f.f.wallet });
  assert.equal(again.verification.layers[1].status, 'unavailable');
  await assert.rejects(() => f.actions['check-account']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId,
    verification: { complete: true } }), /refused/);
  await assert.rejects(() => f.actions['check-account']({ reviewId: 'f'.repeat(64), capabilityId: f.delegate.capabilityId }), /refused/);
});

for (const [name, change] of [['an on-chain list enumeration', (evidence) => { evidence.enumeration_evidence.method = 'onchain_list'; }],
  ['a missing next ID', (evidence) => { delete evidence.enumeration_evidence.next_id; }],
  ['a fractional next ID', (evidence) => { evidence.enumeration_evidence.next_id = 1.5; }],
  ['a string next ID', (evidence) => { evidence.enumeration_evidence.next_id = '1'; }],
  ['an out-of-range next ID', (evidence) => { evidence.enumeration_evidence.next_id = 4294967296; }],
  ['no enumeration evidence', (evidence) => { delete evidence.enumeration_evidence; }]]) {
  test(`${name} leaves the proposed rule ID unestablished, so the layer is unavailable and nothing runs`, async () => {
    const f = await reviewed({ intentChange: change });
    const result = await f.actions['check-account']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
    assert.equal(result.verification.layers[1].status, 'unavailable');
    assert.match(result.verification.layers[1].detail, /next context rule ID/);
    assert.equal(f.prepares.length + f.runs.length, 0);
  });
}

for (const failure of ['prepareFails', 'sourceFails']) {
  test(`an infrastructure error before the worker (${failure}) is unavailable, not a failed candidate`, async () => {
    const f = await reviewed({ [failure]: true });
    const result = await f.actions['check-account']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
    assert.equal(result.verification.layers[1].status, 'unavailable');
    assert.match(result.verification.layers[1].detail, /did not run/);
    assert.equal(f.runs.length, 0);
  });
}

test('refused preparation evidence is a failed check, distinct from an infrastructure error', async () => {
  const f = await reviewed();
  const prepare = f.toolchain.prepareDryRun;
  f.toolchain.prepareDryRun = async (input) => {
    const value = await prepare(input);
    return { ...value, output: { ...value.output, complete: true } };
  };
  const result = await f.actions['check-account']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  assert.equal(result.verification.layers[1].status, 'failed');
  assert.equal(f.runs.length, 0);
});
