import assert from 'node:assert/strict';
import test from 'node:test';
import { xdr } from '@stellar/stellar-sdk';
import { LIVE_CONSENT_MIN_LEDGERS, LIVE_HELPER_WASM, LIVE_SIGNATURE_LEDGERS, consentDisplay, liveCases, statementHash } from '../shared/live-consent.mjs';
import { requireNoReplay } from '../server/live-check.mjs';
import { setup } from './actions-fixture.mjs';
import { HELPER, START_LEDGER, consented, liveReviewed } from './live-check-fixture.mjs';
import { denialSimulation, permitChanges, permitSimulation, withProbe } from './live-enforcement-fixture.mjs';

const layerOf = (result) => result.verification.layers.find((layer) => layer.layer === 'live_enforcement');
const base64Entries = (text) => /AAAA[A-Za-z0-9+/]{200,}/.test(text);

test('without a configured helper, the live layer is not offered', async () => {
  const { actions } = setup();
  assert.equal((await actions.status({})).capabilities.liveCheck, false);
  await assert.rejects(() => actions['prepare-live']({ reviewId: 'a'.repeat(64), capabilityId: 'b'.repeat(64) }), /refused/);
  await assert.rejects(() => actions['check-replay']({}), /refused/);
});

test('the live check passes when the candidate permits the exact transfer and refuses the adjacent amount', async () => {
  const f = await liveReviewed();
  assert.equal((await f.actions.status({})).capabilities.liveCheck, true);
  assert.equal((await f.actions.status({})).capabilities.install, false);
  const { prepared, consent, input } = await consented(f);
  const display = prepared.live.display;
  const n = START_LEDGER + LIVE_SIGNATURE_LEDGERS;
  assert.equal(display.signature_expiration_ledger, n);
  assert.equal(display.current_ledger, START_LEDGER);
  assert.deepEqual(display.cases.map((c) => [c.case, c.delegate_signs.amount_stroops, c.simulated_call.contract]),
    [['target:original:0', '1000000', HELPER], ['target:argument-denial:0', '1000001', HELPER]]);
  assert.equal(display.owner_signs.function, 'add_context_rule');
  assert.match(display.warning, new RegExp(`^Until ledger ${n}, these signatures are real and submittable`));
  assert.match(display.warning, /complete installation/);
  assert.match(display.warning, /operator's testnet RPC endpoint/);
  assert.deepEqual(display.labels, ['state_dependent', 'simulation_only', `signatures_valid_until_ledger:${n}`,
    'delegate_is_wallet_in_memory_automation_key']);
  assert.equal(prepared.live.statementSha256, statementHash(display));
  assert.deepEqual(f.funded, [f.delegate.address], 'the delegate exists on testnet before anything is signed');
  assert.equal(consent.signatureExpirationLedger, n);
  assert.equal(f.records.length, 1, 'the replay obligation is journaled at consent');
  const result = await f.actions['run-live'](input);
  const live = layerOf(result);
  assert.equal(live.status, 'passed', JSON.stringify(live));
  assert.deepEqual(live.evidence.cases.map((c) => [c.case, c.outcome, c.code]),
    [['target:original:0', 'permit', undefined], ['target:argument-denial:0', 'deny', 6]]);
  assert.equal(live.evidence.helper, HELPER);
  assert.equal(live.evidence.helperCodeHash, LIVE_HELPER_WASM);
  assert.equal(live.evidence.signatureExpirationLedger, n);
  assert.deepEqual(live.evidence.owner, { authentication: 'webauthn_user_verified', human_approval_attested: false });
  assert.equal(live.evidence.delegate, 'wallet_in_memory_automation_key');
  assert.equal(live.evidence.submitted, false);
  assert.equal(f.simulations.length, 2);
  assert.equal(f.delegates.liveSignatures, 2);
  // Simulation only: the envelopes are unsigned, never returned, and the fee payer submits nothing.
  for (const envelope of f.simulations) assert.equal(xdr.TransactionEnvelope.fromXDR(envelope, 'base64').v1.signatures.length, 0);
  assert.ok(!base64Entries(JSON.stringify(result)), 'no signed entry or envelope leaves the backend');
  assert.equal(result.verification.complete, false, 'the local layers have not run here');
  await assert.rejects(() => f.actions.assemble({ reviewId: f.review.reviewId }), /refused/);
});

test('consent required before any live signature', async () => {
  const f = await liveReviewed();
  const prepared = await f.actions['prepare-live']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  assert.ok(!JSON.stringify(prepared).includes('ownerEntryXdr') && !base64Entries(JSON.stringify(prepared)),
    'preparation releases nothing a passkey could sign');
  // A run cannot start from the unconsented statement, and a consent to another statement is refused.
  await assert.rejects(() => f.actions['run-live']({ id: prepared.live.action.id, signedAuthEntriesXdr: ['AAAA'] }), /unavailable|refused/);
  const again = await f.actions['prepare-live']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  await assert.rejects(() => f.actions['consent-live']({ id: again.live.action.id, statementSha256: 'f'.repeat(64) }), /refused/);
  await assert.rejects(() => f.actions['consent-live']({ id: again.live.action.id, statementSha256: again.live.statementSha256 }),
    /unavailable/, 'a refused consent consumes the statement');
  assert.equal(f.records.length, 0);
  assert.equal(f.delegates.liveMints + f.delegates.liveSignatures + f.simulations.length, 0);
  // Consenting is not signing either: the owner's signature must verify before the delegate's key is reached.
  const third = await f.actions['prepare-live']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  const consent = await f.actions['consent-live']({ id: third.live.action.id, statementSha256: third.live.statementSha256 });
  const forged = await f.sign(consent.ownerEntryXdr, (client) => { client.origin = 'http://localhost:3001'; });
  await assert.rejects(() => f.actions['run-live']({ id: consent.action.id, signedAuthEntriesXdr: forged }), /refused/);
  assert.equal(f.delegates.liveMints + f.delegates.liveSignatures + f.simulations.length, 0);
});

test('consent is refused when too little of the signatures\' validity remains', async () => {
  const f = await liveReviewed();
  const prepared = await f.actions['prepare-live']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  f.state.ledger = START_LEDGER + LIVE_SIGNATURE_LEDGERS - LIVE_CONSENT_MIN_LEDGERS + 1;
  await assert.rejects(() => f.actions['consent-live']({ id: prepared.live.action.id, statementSha256: prepared.live.statementSha256 }), /refused/);
  assert.equal(f.records.length, 0, 'no obligation and no owner entry');
});

test('abort on disconnect', async () => {
  const controller = new AbortController();
  const f = await liveReviewed({ onSimulate: (count) => { if (count === 1) controller.abort(); } });
  const { input } = await consented(f);
  await assert.rejects(() => f.actions['run-live'](input, { signal: controller.signal }), /refused/);
  assert.equal(f.simulations.length, 1, 'nothing starts after the disconnect');
  assert.equal(f.delegates.liveSignatures, 1);
  const review = await f.actions['prepare-live']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId }).catch((e) => e);
  assert.match(String(review), /refused/, 'a new check waits until the aborted one\'s signatures have expired');
  assert.equal(f.records.length, 1, 'the aborted check\'s replay obligation stays');
  f.state.ledger = START_LEDGER + LIVE_SIGNATURE_LEDGERS + 1;
  const replay = await f.actions['check-replay']({});
  assert.equal(replay.replay.status, 'unchanged');
});

test('install refused when NextId moved after the live check', async () => {
  const f = await liveReviewed();
  const { input } = await consented(f);
  assert.equal(layerOf(await f.actions['run-live'](input)).status, 'passed');
  const records = f.records;
  const n = START_LEDGER + LIVE_SIGNATURE_LEDGERS;
  // While the signatures are valid, an installation must wait.
  assert.equal((await f.actions['check-replay']({})).replay.status, 'waiting');
  await assert.rejects(() => requireNoReplay({ network: f.network, records }), /refused/);
  f.state.ledger = n + 1;
  assert.equal((await f.actions['check-replay']({})).replay.status, 'unchanged');
  assert.equal((await requireNoReplay({ network: f.network, records })).status, 'unchanged');
  f.state.nextId = 2;
  const replay = (await f.actions['check-replay']({})).replay;
  assert.equal(replay.status, 'changed');
  assert.deepEqual(replay.changes, ['NextId 1 -> 2']);
  assert.match(replay.alert, /Do not install/);
  await assert.rejects(() => requireNoReplay({ network: f.network, records }), /refused/);
  f.state.nextId = 1;
  f.state.installed = true;
  assert.deepEqual((await f.actions['check-replay']({})).replay.changes, ['candidate installation marker for rule 1']);
  f.state.installed = false;
  f.state.rules = [{ id: 0, xdr: 'another owner rule' }];
  assert.deepEqual((await f.actions['check-replay']({})).replay.changes, ['context rules']);
});

test('uncapped policies are unsupported and nothing is signed', async () => {
  const f = await liveReviewed({ maxCalls: null });
  const result = await f.actions['prepare-live']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  assert.equal(result.live, null);
  assert.equal(layerOf(result).status, 'unsupported');
  assert.match(layerOf(result).detail, /call-capped/);
  assert.equal(f.funded.length + f.records.length + f.simulations.length, 0);
});

test('an expired or archived helper is unavailable, with how to extend or redeploy it', async () => {
  for (const liveUntil of [START_LEDGER - 5, START_LEDGER + LIVE_SIGNATURE_LEDGERS]) {
    const f = await liveReviewed({ liveUntil });
    const result = await f.actions['prepare-live']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
    assert.equal(layerOf(result).status, 'unavailable');
    assert.match(layerOf(result).detail, /Extend its TTL or deploy it again \(docs\/ATOMIC-LIVE-HELPER\.md#keeping-the-helper-live\)/);
    assert.equal(result.live, null);
  }
  const missing = await liveReviewed({ helperState: { found: false, ledger: START_LEDGER } });
  const result = await missing.actions['prepare-live']({ reviewId: missing.review.reviewId, capabilityId: missing.delegate.capabilityId });
  assert.match(layerOf(result).detail, /does not exist on testnet/);
});

test('the helper must read back with the reviewed code hash, and the candidate with its reviewed Wasm', async () => {
  const f = await liveReviewed({ helperState: { found: true, wasmHash: 'e'.repeat(64), instanceLiveUntil: 9e6, codeLiveUntil: 9e6, ledger: START_LEDGER } });
  const result = await f.actions['prepare-live']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  assert.equal(layerOf(result).status, 'unavailable');
  assert.match(layerOf(result).detail, new RegExp(`not the reviewed helper ${LIVE_HELPER_WASM}`));
  const g = await liveReviewed({ policyHash: 'e'.repeat(64) });
  assert.equal(layerOf(await g.actions['prepare-live']({ reviewId: g.review.reviewId, capabilityId: g.delegate.capabilityId })).status, 'failed');
});

test('state the transfer cannot run against, or a moved NextId, is unavailable rather than a policy outcome', async () => {
  const f = await liveReviewed({ readiness: { ledger: START_LEDGER, recipientExists: false, covered: true } });
  assert.equal(layerOf(await f.actions['prepare-live']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId })).status, 'unavailable');
  const g = await liveReviewed({ nextId: 2 });
  const moved = layerOf(await g.actions['prepare-live']({ reviewId: g.review.reviewId, capabilityId: g.delegate.capabilityId }));
  assert.equal(moved.status, 'unavailable');
  assert.match(moved.detail, /review again/);
});

// The validator's refusals, through the wallet: a response that is not the candidate's own decision
// on exactly these entries fails the layer.
for (const [name, respond] of [
  ['refuses transfer entry with an unexecuted sub-invocation', (kind, entries, P) => {
    if (kind !== 'permit') return null;
    // The response of an envelope whose transfer entry carries an unexecuted sub-invocation.
    const altered = entries.map((e) => xdr.SorobanAuthorizationEntry.fromXDR(e.toXDR()));
    altered[1].rootInvocation.subInvocations = [xdr.SorobanAuthorizedInvocation.fromXDR(altered[1].rootInvocation.toXDR())];
    return withProbe(P, () => permitSimulation(permitChanges(altered), { entries: altered }));
  }],
  ['denial requires code 6 from the policy contract id', (kind, entries, P) => (kind === 'denial'
    ? withProbe(P, () => denialSimulation(entries, { raisedBy: P.helper })) : null)],
  ['a denial with another policy code fails', (kind, entries, P) => (kind === 'denial'
    ? withProbe(P, () => denialSimulation(entries, { code: 5 })) : null)],
  ['a permitted adjacent amount fails', (kind, entries, P) => (kind === 'denial'
    ? withProbe({ ...P, permitAmount: 1000001n }, () => permitSimulation(permitChanges(entries, { amount: 1000001n }), { entries, amount: 1000001n })) : null)],
]) {
  test(`through the wallet: ${name}`, async () => {
    const f = await liveReviewed({ respond });
    const { input } = await consented(f);
    const live = layerOf(await f.actions['run-live'](input));
    assert.equal(live.status, 'failed', JSON.stringify(live.evidence?.cases));
    // Either the validator refused a response, or it is the policy's decision but not the expected one.
    assert.ok(live.evidence.cases.some((c) => c.outcome === 'failed') || live.evidence.cases[1].outcome === 'permit');
  });
}

test('a response that needs restoration, or comes after the signatures expired, is unavailable', async () => {
  const f = await liveReviewed({ respond: (kind, entries, P) => (kind === 'permit'
    ? withProbe(P, () => ({ ...permitSimulation(permitChanges(entries), { entries }), restorePreamble: { minResourceFee: '1' } })) : null) });
  const { input } = await consented(f);
  assert.equal(layerOf(await f.actions['run-live'](input)).status, 'unavailable');
});

test('the browser and backend derive the same statement; it binds the expiry, the calls and the warning', async () => {
  const f = await liveReviewed();
  const prepared = await f.actions['prepare-live']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  const inputs = prepared.live.inputs;
  const review = (await f.actions.review({ deploymentId: f.deployed.deploymentId, wallet: f.f.wallet }));
  const { reviewIntent } = await import('../shared/approval.mjs');
  const approval = reviewIntent(review);
  const cases = liveCases({ approval, spec: f.artifact.spec, helper: inputs.helper, policyCodeHash: inputs.policyCodeHash,
    expectedRuleId: inputs.expectedRuleId, signatureExpirationLedger: inputs.signatureExpirationLedger });
  const display = consentDisplay(cases, { currentLedger: inputs.currentLedger });
  assert.equal(statementHash(display), prepared.live.statementSha256);
  for (const change of [{ signatureExpirationLedger: inputs.signatureExpirationLedger + 1 }, { helper: f.policy }, { expectedRuleId: 2 }]) {
    let other;
    try {
      other = statementHash(consentDisplay(liveCases({ approval, spec: f.artifact.spec, helper: inputs.helper, policyCodeHash: inputs.policyCodeHash,
        expectedRuleId: inputs.expectedRuleId, signatureExpirationLedger: inputs.signatureExpirationLedger, ...change }),
      { currentLedger: inputs.currentLedger }));
    } catch { other = null; }
    assert.notEqual(other, prepared.live.statementSha256);
  }
  assert.equal(HELPER, inputs.helper);
});

test('the wallet pins the helper hash the real-Wasm host tests assert', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../../execution-runtime/tests/atomic_helper.rs', import.meta.url), 'utf8');
  const [, pinned] = /const EXPECTED_HELPER_HASH: &str =\s*"([0-9a-f]{64})";/.exec(source);
  assert.equal(LIVE_HELPER_WASM, pinned);
});

test('a policy decision is never masked as unavailable by the other case needing restoration', async () => {
  const restoring = (entries, P) => withProbe(P, () => ({ ...permitSimulation(permitChanges(entries), { entries }), restorePreamble: { minResourceFee: '1' } }));
  const f = await liveReviewed({ respond: (kind, entries, P) => (kind === 'permit' ? restoring(entries, P)
    : withProbe({ ...P, permitAmount: 1000001n }, () => permitSimulation(permitChanges(entries, { amount: 1000001n }), { entries, amount: 1000001n }))) });
  const { input } = await consented(f);
  const live = layerOf(await f.actions['run-live'](input));
  assert.equal(live.status, 'failed', 'a permitted adjacent amount is the candidate\'s own wrong decision');
  assert.deepEqual(live.evidence.cases.map((c) => c.outcome), ['failed', 'permit']);
});

test('a candidate missing on testnet is unavailable, not a failed candidate', async () => {
  const f = await liveReviewed();
  const liveness = f.network.contractLiveness;
  f.network.contractLiveness = async (contract) => (contract === f.policy ? { found: false, ledger: START_LEDGER } : liveness(contract));
  const result = await f.actions['prepare-live']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  assert.equal(layerOf(result).status, 'unavailable');
});

test('the installation guard fails closed without a live check record', async () => {
  const f = await liveReviewed();
  await assert.rejects(() => requireNoReplay({ network: f.network, records: [] }), /refused/);
  await assert.rejects(() => requireNoReplay({ network: f.network }), /refused/);
});

test('the delegate signs nothing when the fee payer cannot be read for the envelope', async () => {
  const f = await liveReviewed();
  const { input } = await consented(f);
  f.network.source = async () => { throw new Error('wallet network operation refused'); };
  assert.equal(layerOf(await f.actions['run-live'](input)).status, 'unavailable');
  assert.equal(f.delegates.liveSignatures, 0);
});
