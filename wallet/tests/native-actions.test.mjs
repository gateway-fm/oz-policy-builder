import assert from 'node:assert/strict';
import test from 'node:test';
import { setup } from './actions-fixture.mjs';
import { reviewed } from './native-actions-fixture.mjs';

test('without an operator worker, delegate creation and account checks are unavailable', async () => {
  const { actions } = setup();
  const status = await actions.status({});
  assert.equal(status.capabilities.accountCheck, false);
  await assert.rejects(() => actions['create-delegate']({}), /refused/);
  await assert.rejects(() => actions['check-account']({ reviewId: 'a'.repeat(64), capabilityId: 'b'.repeat(64) }), /refused/);
});

test('a backend-held delegate drives a validated account-Wasm layer while installation stays unavailable without the live layer', async () => {
  const f = await reviewed();
  assert.deepEqual(Object.keys(f.delegate).sort(), ['address', 'capabilityId']);
  assert.equal((await f.actions.status({})).capabilities.accountCheck, true);
  const result = await f.actions['check-account']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  const layers = Object.fromEntries(result.verification.layers.map((layer) => [layer.layer, layer.status]));
  assert.deepEqual(layers, { reference: 'passed', account_wasm: 'passed', captured_target: 'passed', live_enforcement: 'unavailable' });
  assert.equal(result.verification.complete, false);
  assert.equal(result.verification.specHash, f.artifact.specHash);
  assert.equal(result.verification.layers[1].evidence.candidateContextRuleId, 1);
  assert.equal(f.prepares[0].candidateContextRuleId, 1, 'bounded next ID from the reviewed authority evidence');
  assert.equal(f.prepares[0].artifactId, f.artifactId);
  assert.deepEqual(f.runs.map((run) => [run.executable, run.prepareOnly, run.captured]),
    [['/fixed/ozpb-execution-runtime', true, false], ['/fixed/ozpb-execution-runtime', false, false],
      ['/fixed/ozpb-execution-runtime', true, true], ['/fixed/ozpb-execution-runtime', false, true]]);
  assert.equal(f.runs[0].jobText, f.runs[1].jobText);
  assert.equal(f.runs[2].jobText, f.runs[3].jobText);
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
  assert.equal(result.verification.layers[2].status, 'unsupported');
  assert.equal(f.prepares.length + f.runs.length + f.captures.length, 0);
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
    assert.equal(result.verification.layers[2].status, 'unavailable');
    assert.equal(f.prepares.length + f.runs.length + f.captures.length, 0);
  });
}

for (const failure of ['prepareFails', 'sourceFails']) {
  test(`an infrastructure error before the worker (${failure}) is unavailable, not a failed candidate`, async () => {
    const f = await reviewed({ [failure]: true });
    const result = await f.actions['check-account']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
    assert.equal(result.verification.layers[1].status, 'unavailable');
    assert.match(result.verification.layers[1].detail, /did not run/);
    assert.equal(result.verification.layers[2].status, 'unavailable');
    assert.equal(f.runs.length + f.captures.length, 0);
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
  assert.equal(result.verification.layers[2].status, 'failed');
  assert.equal(f.runs.length, 0);
});
