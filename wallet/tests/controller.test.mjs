import test from 'node:test';
import assert from 'node:assert/strict';
import { WalletController } from '../overlay/files/src/policy-builder/client/controller.mjs';

const hash = (c) => c.repeat(64);
const pins = { networkId: hash('1'), accountWasm: hash('2'), verifierWasm: hash('3') };
const wallet = { contractId: 'account', credentialId: 'AQ', publicKey: '04key', verifier: 'verifier' };
function fixture() {
  const verification = { complete: true, runId: hash('9'), specHash: hash('a'), wasmHash: hash('b'),
    bindingSetHash: hash('c'), layers: ['reference', 'account_wasm', 'captured_target', 'live_enforcement']
      .map((layer) => ({ layer, status: 'passed' })) };
  const replies = {
    status: { ...pins, network: 'testnet', capabilities: { record: true, generate: true, deploy: true, install: true } },
    record: { recordId: 'record1', accountAddress: wallet.contractId, transactionHash: hash('d') },
    generate: { artifactId: 'artifact1', specHash: hash('a'), wasmHash: hash('b'), spec: {
      name: 'grant', network_id: pins.networkId, smart_account: { address: wallet.contractId },
      rules: [{ valid_until: { ledger: 123 }, authorization: { signers: [{ delegated: { address: 'delegate' } }] },
        state: [{ call_count_per_installation: { max_calls: 2 } }], allowed_calls: [{ fn: 'transfer', args: [] }] },
    ] }, files: [] },
    'prepare-deploy': { action: { id: 'deploy1' }, summary: { specHash: hash('a'), wasmHash: hash('b') } },
    'confirm-deploy': { deploymentId: 'deployment1', policyAddress: 'policy1', wasmHash: hash('b'), bindingSetHash: hash('c') },
    review: { reviewId: 'review1', wallet, verification, expected: { specHash: hash('a'), bindingSetHash: hash('c') },
      intent: { policies: [{ address: 'policy1', wasm_hash: hash('b') }] }, ownerRuleXdr: 'owner' },
    assemble: { pendingId: 'pending1', verification, assembly: {}, ownerRuleXdr: 'owner', limits: {} },
    submit: { receipt: { hash: hash('e') }, installation: { installationId: 'install1' } },
  };
  const calls = [];
  const validators = {
    reviewIntent: (value) => ({ ...value, ownerRuleId: 7 }),
    validateAssembly: () => ({ authEntriesXdr: ['unsigned'], ownerRuleId: 7, expirationLedger: 123 }),
    validateSignedAuthorization: async ({ signedAuthEntriesXdr }) => ({ signedAuthEntriesXdr }),
  };
  const controller = new WalletController({
    pins, request: async (name, data) => { calls.push([name, data]); return replies[name]; },
    validators, sign: async () => { calls.push(['sign']); return ['signed']; }, origin: 'http://localhost:3000',
  });
  return { controller, replies, calls, validators };
}
async function prepared(f) {
  await f.controller.connect();
  f.controller.attachWallet(wallet);
  await f.controller.record(hash('d'));
  await f.controller.generate({ delegateAddress: 'delegate', maxCalls: 2, validUntilLedger: 123, grantName: 'grant' });
  await f.controller.prepareDeploy();
  await f.controller.confirmDeploy();
  await f.controller.review();
}

test('deploy consent is separate and install validates before requesting a passkey', async () => {
  const f = fixture();
  await prepared(f);
  assert.equal(f.calls.some(([name]) => name === 'sign'), false);
  await f.controller.install();
  assert.deepEqual(f.calls.slice(-3).map(([name]) => name), ['assemble', 'sign', 'submit']);
  assert.equal(f.controller.state.installation.installationId, 'install1');
  await assert.rejects(f.controller.install(), /wallet action refused/);
});
test('missing real layer4 blocks signing even when the service advertises install capability', async () => {
  const f = fixture();
  f.replies.review.verification.layers[3].status = 'unavailable';
  await prepared(f);
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit'), false);
});
test('changed report identity or assembly refusal consumes the review before signing', async () => {
  for (const kind of ['run', 'validation']) {
    const f = fixture();
    await prepared(f);
    if (kind === 'run') f.replies.assemble = { ...f.replies.assemble, verification: { ...f.replies.assemble.verification, runId: hash('8') } };
    else f.validators.validateAssembly = () => { throw new Error('secret diagnostic'); };
    await assert.rejects(f.controller.install(), /wallet action refused/);
    await assert.rejects(f.controller.install(), /wallet action refused/);
    assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit'), false);
  }
});
test('new account or recording invalidates the immutable prior artifact and review', async () => {
  const f = fixture();
  await prepared(f);
  f.replies.generate.spec.rules.push({ changed: true });
  assert.equal(f.controller.state.artifact.spec.rules.length, 1);
  f.controller.attachWallet({ ...wallet, contractId: 'different' });
  assert.equal(f.controller.state.artifact, null);
  assert.equal(f.controller.state.review, null);
  await assert.rejects(f.controller.install(), /wallet action refused/);
});
test('generation refuses a grant that differs from the user-selected limits or identity', async () => {
  for (const mutate of [
    (s) => { s.rules[0].valid_until.ledger++; },
    (s) => { s.rules[0].state[0].call_count_per_installation.max_calls++; },
    (s) => { s.rules[0].authorization.signers[0].delegated.address = 'other'; },
    (s) => { s.smart_account.address = 'other'; },
    (s) => { s.network_id = hash('f'); },
  ]) {
    const f = fixture(); mutate(f.replies.generate.spec);
    await assert.rejects(prepared(f), /wallet action refused/);
    assert.equal(f.calls.some(([name]) => name === 'prepare-deploy' || name === 'sign'), false);
  }
});
test('review refuses a substituted policy, binding or grant artifact', async () => {
  for (const change of [
    (r) => { r.expected.specHash = hash('f'); },
    (r) => { r.expected.bindingSetHash = hash('f'); },
    (r) => { r.intent.policies[0].address = 'other'; },
    (r) => { r.wallet = { ...wallet, credentialId: 'Ag' }; },
  ]) {
    const f = fixture(); change(f.replies.review);
    await assert.rejects(prepared(f), /wallet action refused/);
    assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit'), false);
  }
});

function sampleFixture() {
  const f = fixture();
  const descriptor = { recipient: 'payer', amountStroops: '1000000', ownerRuleXdr: 'created-owner' };
  const approval = { wallet, ownerRuleId: 0, commitment: hash('8') };
  const checked = { authEntriesXdr: ['sample-auth'], ownerRuleId: 0, expirationLedger: 123 };
  f.replies.status.capabilities.sampleTransfer = true;
  f.replies['prepare-account'] = { action: { id: 'create1' }, summary: { ...wallet,
    accountWasm: pins.accountWasm, verifierWasm: pins.verifierWasm } };
  f.replies['confirm-account'] = { wallet, sample: descriptor, receipts: [] };
  f.replies['prepare-sample'] = { action: { id: hash('4'), expires_in_seconds: 120 },
    ownerRuleXdr: descriptor.ownerRuleXdr, assembly: { exact: 'sample-envelope' }, limits: { feePayer: 'payer' },
    approval: { wallet: { contractId: 'forged' } }, checked: { authEntriesXdr: ['forged-auth'] } };
  f.replies['submit-sample'] = { transactionHash: hash('e'), receipt: { hash: hash('e') } };
  f.validators.reviewSample = (input) => {
    assert.deepEqual(input, { wallet, descriptor: { recipient: 'payer', amountStroops: '1000000',
      ownerRuleXdr: 'created-owner' }, ownerRuleXdr: 'created-owner' });
    f.calls.push(['reviewSample', input]);
    return approval;
  };
  f.validators.validateSampleAssembly = (input) => {
    assert.deepEqual(input, { approval, ownerRuleXdr: 'created-owner',
      assembly: { exact: 'sample-envelope' }, limits: { feePayer: 'payer' } });
    f.calls.push(['validateSampleAssembly', input]);
    return checked;
  };
  const validateSignature = f.validators.validateSignedAuthorization;
  f.validators.validateSignedAuthorization = async (input) => {
    assert.equal(input.approval, approval);
    assert.equal(input.checked, checked);
    return validateSignature(input);
  };
  return f;
}
async function created(f) {
  await f.controller.connect();
  await f.controller.prepareAccount({ credentialId: wallet.credentialId, publicKey: wallet.publicKey });
  await f.controller.confirmAccount();
}
test('sample transfer uses retained creation evidence and local validators before explicit signing', async () => {
  const f = sampleFixture();
  await created(f);
  await f.controller.prepareSample();
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit-sample'), false);
  assert.deepEqual(f.controller.state.sample, f.replies['confirm-account'].sample);
  f.replies['confirm-account'].sample.recipient = 'changed-after-creation';
  await f.controller.approveSample();
  assert.deepEqual(f.calls.slice(-4).map(([name]) => name),
    ['reviewSample', 'validateSampleAssembly', 'sign', 'submit-sample']);
  assert.deepEqual(f.calls.at(-1)[1], { id: hash('4'), signedAuthEntriesXdr: ['signed'] });
  assert.equal(f.controller.state.sampleTransactionHash, hash('e'));
  assert.equal(f.controller.state.samplePreview, null);
  await assert.rejects(f.controller.approveSample(), /wallet action refused/);
  await assert.rejects(f.controller.prepareSample(), /wallet action refused/);
});
test('sample descriptor survives recording but attach or new credential clears eligibility', async () => {
  for (const reset of ['attach', 'credential']) {
    const f = sampleFixture();
    await created(f);
    await f.controller.prepareSample();
    await f.controller.record(hash('d'));
    assert.equal(f.controller.state.sample.recipient, 'payer');
    assert.equal(f.controller.state.samplePreview, null);
    if (reset === 'attach') f.controller.attachWallet(wallet);
    else await f.controller.prepareAccount({ credentialId: wallet.credentialId, publicKey: wallet.publicKey });
    assert.equal(f.controller.state.sample, null);
    await assert.rejects(f.controller.prepareSample(), /wallet action refused/);
  }
});
test('sample validator refusal consumes preview without signing and requires preparation again', async () => {
  const f = sampleFixture();
  await created(f);
  await f.controller.prepareSample();
  f.validators.validateSampleAssembly = () => { throw new Error('mismatched sample envelope'); };
  await assert.rejects(f.controller.approveSample(), /wallet action refused/);
  await assert.rejects(f.controller.approveSample(), /wallet action refused/);
  assert.equal(f.controller.state.samplePreview, null);
  assert.equal(f.controller.state.sampleAttempted, false);
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit-sample'), false);
});
test('a lost sample submission response cannot cause an automatic or manual retry', async () => {
  const f = sampleFixture();
  await created(f);
  await f.controller.prepareSample();
  f.replies['submit-sample'] = null;
  await assert.rejects(f.controller.approveSample(), /wallet action refused/);
  assert.equal(f.controller.state.sampleAttempted, true);
  await assert.rejects(f.controller.prepareSample(), /wallet action refused/);
  await assert.rejects(f.controller.approveSample(), /wallet action refused/);
  assert.equal(f.calls.filter(([name]) => name === 'submit-sample').length, 1);
});
test('cancelling sample review requires a new preparation and does not sign or submit', async () => {
  const f = sampleFixture();
  await created(f);
  await f.controller.prepareSample();
  f.controller.cancelSample();
  assert.equal(f.controller.state.samplePreview, null);
  await assert.rejects(f.controller.approveSample(), /wallet action refused/);
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit-sample'), false);
  await f.controller.prepareSample();
  await f.controller.approveSample();
  assert.equal(f.calls.filter(([name]) => name === 'submit-sample').length, 1);
});

const DELEGATE = `G${'A'.repeat(55)}`;
async function accountChecked(change = () => {}) {
  const f = fixture();
  f.replies.status.capabilities.accountCheck = true;
  f.replies['create-delegate'] = { capabilityId: hash('5'), address: DELEGATE };
  f.replies.generate.spec.rules[0].authorization.signers = [{ delegated: { address: DELEGATE } }];
  f.replies.review.verification = { ...f.replies.review.verification, complete: false,
    layers: f.replies.review.verification.layers.map((layer) => ({ ...layer, status: layer.layer === 'reference' ? 'passed' : 'unavailable' })) };
  f.replies['check-account'] = { reviewId: 'review1', verification: { ...f.replies.review.verification, runId: hash('6'),
    layers: f.replies.review.verification.layers.map((layer) => layer.layer === 'account_wasm' ? { ...layer, status: 'passed' } : layer) } };
  change(f);
  await f.controller.connect();
  await f.controller.createDelegate();
  f.controller.attachWallet(wallet);
  await f.controller.record(hash('d'));
  await f.controller.generate({ delegateAddress: DELEGATE, maxCalls: 2, validUntilLedger: 123, grantName: 'grant' });
  await f.controller.prepareDeploy();
  await f.controller.confirmDeploy();
  await f.controller.review();
  return f;
}
test('account check uses the explicit backend delegate and updates only the matching review evidence', async () => {
  const f = await accountChecked();
  assert.deepEqual(f.controller.state.delegate, { capabilityId: hash('5'), address: DELEGATE });
  await f.controller.checkAccount();
  assert.deepEqual(f.calls.at(-1), ['check-account', { reviewId: 'review1', capabilityId: hash('5') }]);
  assert.equal(f.controller.state.review.verification.layers[1].status, 'passed');
  assert.equal(f.controller.state.review.approval.ownerRuleId, 7, 'the reviewed approval is retained');
  assert.equal(f.calls.some(([name]) => name === 'sign'), false);
  await assert.rejects(f.controller.install(), /wallet action refused/, 'three local layers do not enable installation');
});
for (const change of ['other review', 'other spec', 'other binding set', 'missing layers']) {
  test(`account check refuses a response for ${change} and keeps the earlier evidence`, async () => {
    const f = await accountChecked((value) => {
      const reply = value.replies['check-account'];
      if (change === 'other review') reply.reviewId = 'review2';
      if (change === 'other spec') reply.verification = { ...reply.verification, specHash: hash('f') };
      if (change === 'other binding set') reply.verification = { ...reply.verification, bindingSetHash: hash('f') };
      if (change === 'missing layers') reply.verification = { ...reply.verification, layers: reply.verification.layers.slice(0, 2) };
    });
    await assert.rejects(f.controller.checkAccount(), /wallet action refused/);
    assert.equal(f.controller.state.review.verification.layers[1].status, 'unavailable');
  });
}
test('account check is unavailable without the capability or for a grant naming another delegate', async () => {
  const f = fixture();
  await f.controller.connect();
  await assert.rejects(f.controller.createDelegate(), /wallet action refused/);
  assert.equal(f.calls.some(([name]) => name === 'create-delegate'), false);
  const g = await accountChecked((value) => {
    value.replies.generate.spec.rules[0].authorization.signers = [{ delegated: { address: `G${'B'.repeat(55)}` } }];
  }).catch(() => null);
  assert.equal(g, null, 'generation refuses a grant whose delegate differs from the selected address');
  const h = await accountChecked();
  h.controller.attachWallet(wallet);
  await assert.rejects(h.controller.checkAccount(), /wallet action refused/, 'no review after the wallet changes');
  assert.equal(h.calls.some(([name]) => name === 'check-account'), false);
});

function liveFixture() {
  const f = fixture();
  f.replies.status.capabilities.liveCheck = true;
  f.replies['create-delegate'] = { capabilityId: hash('5'), address: `G${'A'.repeat(55)}` };
  f.replies.generate.spec.rules[0].authorization.signers[0].delegated.address = f.replies['create-delegate'].address;
  const display = { signature_expiration_ledger: 130, warning: 'Until ledger 130, these signatures are real and submittable.' };
  f.replies['prepare-live'] = { reviewId: 'review1', live: { action: { id: hash('6') }, display, statementSha256: hash('7'),
    inputs: { helper: 'helper', policyCodeHash: hash('b'), expectedRuleId: 1, currentLedger: 100, signatureExpirationLedger: 130 } } };
  f.replies['consent-live'] = { action: { id: hash('8') }, ownerEntryXdr: 'unsigned owner entry', signatureExpirationLedger: 130 };
  f.replies['run-live'] = { reviewId: 'review1', verification: f.replies.review.verification };
  f.replies['check-replay'] = { replay: { status: 'waiting', latestLedger: 120, signaturesValidUntil: 130 } };
  Object.assign(f.validators, {
    liveCases: (input) => { f.calls.push(['liveCases', input]); return ['permit', 'denial']; },
    consentDisplay: () => display,
    statementHash: () => hash('7'),
    checkLiveOwnerEntry: ({ ownerEntryXdr }) => { f.calls.push(['checkLiveOwnerEntry', ownerEntryXdr]);
      return { authEntriesXdr: [ownerEntryXdr], ownerRuleId: 7, expirationLedger: 130 }; },
    validateLiveOwnerSignature: async ({ signedAuthEntriesXdr }) => ({ signedEntryXdr: signedAuthEntriesXdr[0] }),
  });
  return f;
}
async function livePrepared(f) {
  await f.controller.connect();
  f.controller.attachWallet(wallet);
  await f.controller.createDelegate();
  await f.controller.record(hash('d'));
  await f.controller.generate({ delegateAddress: f.replies['create-delegate'].address, maxCalls: 2, validUntilLedger: 123, grantName: 'grant' });
  await f.controller.prepareDeploy();
  await f.controller.confirmDeploy();
  await f.controller.review();
}

test('the live check shows the browser\'s own statement, then consent, then the passkey, then the simulations', async () => {
  const f = liveFixture();
  await livePrepared(f);
  await f.controller.prepareLive();
  assert.equal(f.controller.state.livePreview.statementSha256, hash('7'));
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'consent-live'), false, 'preparing signs and consents to nothing');
  await f.controller.consentLive();
  const names = f.calls.map(([name]) => name);
  assert.deepEqual(names.slice(names.indexOf('consent-live')), ['consent-live', 'checkLiveOwnerEntry', 'sign', 'run-live']);
  assert.deepEqual(f.calls.find(([name]) => name === 'run-live')[1], { id: hash('8'), signedAuthEntriesXdr: ['signed'] });
  assert.equal(f.controller.state.livePreview, null);
  await f.controller.checkReplay();
  assert.equal(f.controller.state.replay.status, 'waiting');
});

test('consent required before any live signature: no preview, a different statement or a changed entry asks no passkey', async () => {
  const noPreview = liveFixture();
  await livePrepared(noPreview);
  await assert.rejects(noPreview.controller.consentLive(), /wallet action refused/);
  for (const change of [
    (f) => { f.validators.statementHash = () => hash('0'); },
    (f) => { f.replies['prepare-live'].live.inputs.policyCodeHash = hash('0'); },
    (f) => { f.replies['consent-live'].signatureExpirationLedger = 131; },
    (f) => { f.validators.checkLiveOwnerEntry = () => { throw new Error('not the reviewed installation'); }; },
  ]) {
    const f = liveFixture();
    change(f);
    await livePrepared(f);
    await f.controller.prepareLive().then(() => f.controller.consentLive()).catch(() => {});
    assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'run-live'), false);
    await assert.rejects(f.controller.consentLive(), /wallet action refused/, 'a refused attempt consumes the preview');
  }
});

test('wallet and grant resets discard the previous live preview and replay assurance', async () => {
  for (const reset of ['attach', 'record', 'generate']) {
    const f = liveFixture();
    await livePrepared(f);
    await f.controller.prepareLive();
    f.replies['check-replay'] = { replay: { status: 'unchanged' } };
    await f.controller.checkReplay();
    if (reset === 'attach') f.controller.attachWallet({ ...wallet, contractId: 'other-account' });
    if (reset === 'record') await f.controller.record(hash('d'));
    if (reset === 'generate') await f.controller.generate({ delegateAddress: f.replies['create-delegate'].address,
      maxCalls: 2, validUntilLedger: 123, grantName: 'grant' });
    assert.equal(f.controller.state.replay, null, reset);
    assert.equal(f.controller.state.livePreview, null, reset);
    await assert.rejects(f.controller.consentLive(), /wallet action refused/);
    assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'consent-live'), false);
  }
});

test('refreshing authority invalidates the live preview before success or failure', async () => {
  for (const valid of [true, false]) {
    const f = liveFixture();
    await livePrepared(f);
    await f.controller.prepareLive();
    f.replies['check-replay'] = { replay: { status: 'unchanged' } };
    await f.controller.checkReplay();
    f.replies.review = { ...f.replies.review, reviewId: 'review2', ...(valid ? {} : { wallet: null }) };
    if (valid) await f.controller.review();
    else await assert.rejects(f.controller.review(), /wallet action refused/);
    assert.equal(f.controller.state.livePreview, null);
    assert.equal(f.controller.state.replay, null);
    await assert.rejects(f.controller.consentLive(), /wallet action refused/);
    assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'consent-live'), false);
  }
});

test('a new live consent clears earlier replay assurance even if consent fails', async () => {
  for (const valid of [true, false]) {
    const f = liveFixture();
    await livePrepared(f);
    f.replies['check-replay'] = { replay: { status: 'unchanged' } };
    await f.controller.checkReplay();
    await f.controller.prepareLive();
    const check = f.validators.checkLiveOwnerEntry;
    f.validators.checkLiveOwnerEntry = (args) => { assert.equal(f.controller.state.replay, null); return check(args); };
    if (valid) await f.controller.consentLive();
    else {
      f.replies['consent-live'].signatureExpirationLedger++;
      await assert.rejects(f.controller.consentLive(), /wallet action refused/);
    }
    assert.equal(f.controller.state.replay, null);
  }
});

test('the automation delegate is available for the live check without the native worker', async () => {
  const f = liveFixture();
  await f.controller.connect();
  await f.controller.createDelegate();
  assert.equal(f.controller.state.delegate.capabilityId, hash('5'));
  const g = fixture();
  g.replies['create-delegate'] = { capabilityId: hash('5'), address: `G${'A'.repeat(55)}` };
  await g.controller.connect();
  await assert.rejects(g.controller.createDelegate(), /wallet action refused/);
});
