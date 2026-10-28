import test from 'node:test';
import assert from 'node:assert/strict';
import { WalletController } from '../overlay/files/src/policy-builder/client/controller.mjs';

const hash = (c) => c.repeat(64);
const pins = { networkId: hash('1'), accountWasm: hash('2'), verifierWasm: hash('3') };
const wallet = { contractId: 'account', credentialId: 'AQ', publicKey: '04key', verifier: 'verifier' };
const INSTALL_DISPLAY = { owner_signs: { function: 'add_context_rule' }, grant: { rule_id: 1, delegate: 'delegate' },
  fee: { prepared_fee_stroops: 1100, max_fee_stroops: 10000000 }, warning: 'Once installed, the delegate can act without your passkey.' };
const REVOKE_DISPLAY = { owner_signs: { function: 'remove_context_rule', args: [1] }, warning: 'Policy cleanup is best effort.' };
const INSTALLATION = { installationId: hash('6'), status: 'installed', transactionHash: hash('e'), ruleId: 1, account: 'account' };
function fixture() {
  const verification = { complete: true, acceptance: { requiredRevertedDenials: 5, originalPermitted: true, meetsMinimum: true,
    executedLayers: [{ layer: 'account_wasm', status: 'passed', originalPermitted: true, revertedDenials: 5 },
      { layer: 'captured_target', status: 'passed', originalPermitted: true, revertedDenials: 2 }] }, runId: hash('9'), specHash: hash('a'), wasmHash: hash('b'),
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
    assemble: { action: { id: hash('5'), expires_in_seconds: 120 }, verification, assembly: {}, ownerRuleXdr: 'owner', limits: {},
      display: INSTALL_DISPLAY },
    submit: { receipt: { hash: hash('e') }, installation: INSTALLATION },
    'prepare-revoke': { action: { id: hash('7'), expires_in_seconds: 120 }, assembly: {}, ownerRuleXdr: 'owner', limits: {},
      display: REVOKE_DISPLAY, installation: INSTALLATION },
    'confirm-revoke': { receipt: { hash: hash('f') }, removal: { status: 'removed', ruleId: 1, transactionHash: hash('f'),
      event: 'verified', ruleReadback: 'absent', policyCleanup: 'not_installed' } },
  };
  const calls = [];
  const pauses = [];
  const validators = {
    reviewIntent: (value) => ({ ...value, ownerRuleId: 7 }),
    validateAssembly: () => ({ authEntriesXdr: ['unsigned'], ownerRuleId: 7, expirationLedger: 123 }),
    validateSignedAuthorization: async ({ signedAuthEntriesXdr }) => ({ signedAuthEntriesXdr }),
    installConsent: () => INSTALL_DISPLAY,
    reviewRemoval: ({ wallet: owner, ownerRuleId, ownerRuleXdr }) => ({ wallet: owner, ownerRuleId, ownerRuleXdr, commitment: hash('9') }),
    validateRemovalAssembly: () => ({ authEntriesXdr: ['unsigned-removal'], ownerRuleId: 7, expirationLedger: 200 }),
    revokeConsent: () => REVOKE_DISPLAY,
  };
  const controller = new WalletController({
    pins, request: async (name, data) => {
      calls.push([name, data]);
      const reply = typeof replies[name] === 'function' ? replies[name]() : replies[name];
      if (reply instanceof Error) throw reply;
      return reply;
    }, pause: async (ms) => { pauses.push(ms); },
    validators, sign: async () => { calls.push(['sign']); return ['signed']; }, origin: 'http://localhost:3000',
  });
  return { controller, replies, calls, validators, pauses };
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

test('deploy consent is separate and install validates and shows its consent before requesting a passkey', async () => {
  const f = fixture();
  await prepared(f);
  assert.equal(f.calls.some(([name]) => name === 'sign'), false);
  await f.controller.prepareInstall();
  assert.deepEqual(f.calls.slice(-2).map(([name]) => name), ['status', 'assemble']);
  assert.deepEqual(f.calls.at(-1)[1], { reviewId: 'review1' });
  assert.deepEqual(f.controller.state.installPreview.display, INSTALL_DISPLAY);
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit'), false, 'preparing signs nothing');
  await f.controller.install();
  assert.deepEqual(f.calls.slice(-3).map(([name]) => name), ['sign', 'submit', 'status']);
  assert.deepEqual(f.calls.find(([name]) => name === 'submit')[1], { id: hash('5'), signedAuthEntriesXdr: ['signed'] });
  assert.equal(f.controller.state.installation.installationId, hash('6'));
  assert.equal(f.controller.state.installPreview, null);
  await assert.rejects(f.controller.install(), /wallet action refused/);
  await assert.rejects(f.controller.prepareInstall(), /wallet action refused/, 'one installation attempt per review');
});
test('install consent the browser derives must equal the backend display, or no passkey is asked', async () => {
  for (const change of [
    (f) => { f.validators.installConsent = () => ({ ...INSTALL_DISPLAY, grant: { rule_id: 2, delegate: 'delegate' } }); },
    (f) => { f.replies.assemble = { ...f.replies.assemble, action: { id: 'short' } }; },
    (f) => { f.replies.status = { ...f.replies.status, capabilities: { ...f.replies.status.capabilities, install: false } }; },
    (f) => { f.replies.assemble = { ...f.replies.assemble, limits: { maxFeeStroops: 100_000_000 } }; },
  ]) {
    const f = fixture();
    await prepared(f);
    change(f);
    await assert.rejects(f.controller.prepareInstall(), /wallet action refused/);
    await assert.rejects(f.controller.install(), /wallet action refused/);
    assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit'), false);
  }
});
test('a lost install response cannot cause an automatic or manual retry', async () => {
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  f.replies.submit = null;
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.equal(f.controller.state.installAttempted, true);
  await assert.rejects(f.controller.prepareInstall(), /wallet action refused/);
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.equal(f.calls.filter(([name]) => name === 'submit').length, 1);
});
test('cancelling the install consent asks no passkey and keeps the review', async () => {
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  f.controller.cancelInstall();
  assert.equal(f.controller.state.installPreview, null);
  assert.notEqual(f.controller.state.review, null);
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit'), false);
});
test('revoke shows the removal consent, then the passkey, then confirms only an absent readback', async () => {
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  await f.controller.install();
  f.replies.status = { ...f.replies.status, capabilities: { ...f.replies.status.capabilities, lifecycle: true } };
  await f.controller.prepareRevoke();
  assert.deepEqual(f.calls.slice(-2).map(([name]) => name), ['status', 'prepare-revoke']);
  assert.deepEqual(f.calls.at(-1)[1], { installationId: hash('6') });
  assert.deepEqual(f.controller.state.revokePreview.display, REVOKE_DISPLAY);
  await f.controller.revoke();
  assert.deepEqual(f.calls.slice(-3).map(([name]) => name), ['sign', 'confirm-revoke', 'status']);
  assert.equal(f.controller.state.removal.ruleReadback, 'absent');
  await assert.rejects(f.controller.prepareRevoke(), /wallet action refused/, 'one removal attempt');
  for (const change of [{ ruleReadback: 'still_present' }, { status: 'unverified' }, { ruleId: 2 }]) {
    const g = fixture();
    await prepared(g);
    await g.controller.prepareInstall();
    await g.controller.install();
    g.replies.status = { ...g.replies.status, capabilities: { ...g.replies.status.capabilities, lifecycle: true } };
    g.replies['confirm-revoke'] = { ...g.replies['confirm-revoke'], removal: { ...g.replies['confirm-revoke'].removal, ...change } };
    await g.controller.prepareRevoke();
    await assert.rejects(g.controller.revoke(), /wallet action refused/, JSON.stringify(change));
    assert.equal(g.controller.state.removal, null);
  }
});
test('revoke needs the lifecycle capability and an installation from this session', async () => {
  const f = fixture();
  await prepared(f);
  await assert.rejects(f.controller.prepareRevoke(), /wallet action refused/);
  await f.controller.prepareInstall();
  await f.controller.install();
  await assert.rejects(f.controller.prepareRevoke(), /wallet action refused/, 'status says no lifecycle');
  assert.equal(f.calls.some(([name]) => name === 'prepare-revoke'), false);
});
test('missing real layer4 blocks signing even when the service advertises install capability', async () => {
  const f = fixture();
  f.replies.review.verification.layers[3].status = 'unavailable';
  await prepared(f);
  await assert.rejects(f.controller.prepareInstall(), /wallet action refused/);
  assert.equal(f.calls.some(([name]) => name === 'assemble' || name === 'sign' || name === 'submit'), false);
});
test('changed report identity or assembly refusal consumes the review before signing', async () => {
  for (const kind of ['run', 'validation']) {
    const f = fixture();
    await prepared(f);
    if (kind === 'run') f.replies.assemble = { ...f.replies.assemble, verification: { ...f.replies.assemble.verification, runId: hash('8') } };
    else f.validators.validateAssembly = () => { throw new Error('secret diagnostic'); };
    await assert.rejects(f.controller.prepareInstall(), /wallet action refused/);
    await assert.rejects(f.controller.prepareInstall(), /wallet action refused/);
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
  await assert.rejects(f.controller.prepareInstall(), /wallet action refused/);
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
  await assert.rejects(f.controller.prepareInstall(), /wallet action refused/, 'three local layers do not enable installation');
  assert.equal(f.calls.some(([name]) => name === 'assemble'), false);
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
  assert.equal(f.calls.at(-1)[0], 'status', 'the replay answer refreshes the backend capabilities');
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

test('a backend refusal to assemble keeps the review; only a refused validation consumes it', async () => {
  const f = fixture();
  await prepared(f);
  f.replies.assemble = new Error('wallet action unavailable');
  await assert.rejects(f.controller.prepareInstall(), /wallet action refused/);
  assert.notEqual(f.controller.state.review, null, 'the backend released nothing; the layers need not run again');
  f.replies.assemble = fixture().replies.assemble;
  await f.controller.prepareInstall();
  assert.deepEqual(f.controller.state.installPreview.display, INSTALL_DISPLAY);
});
test('after a failed submission the browser adopts the installation the backend confirmed, so it can be revoked', async () => {
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  const unverified = { installationId: hash('6'), status: 'confirmed_unverified', account: wallet.contractId, ruleId: 1,
    transactionHash: hash('e'), ledger: 9, removal: null };
  f.replies.submit = new Error('wallet action unavailable');
  f.replies.status = { ...f.replies.status, installations: [unverified],
    capabilities: { ...f.replies.status.capabilities, lifecycle: true } };
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.deepEqual(f.controller.state.installation, unverified);
  f.replies['prepare-revoke'] = { ...f.replies['prepare-revoke'], installation: unverified };
  await f.controller.prepareRevoke();
  await f.controller.revoke();
  assert.equal(f.controller.state.removal.ruleReadback, 'absent');
});
test('a removal the backend refused before submitting can be prepared again; a submitted one cannot', async () => {
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  await f.controller.install();
  f.replies.status = { ...f.replies.status, capabilities: { ...f.replies.status.capabilities, lifecycle: true },
    installations: [{ ...INSTALLATION, ledger: 9, removalAttempted: false, removal: null }] };
  await f.controller.prepareRevoke();
  f.replies['confirm-revoke'] = new Error('wallet action unavailable');
  await assert.rejects(f.controller.revoke(), /wallet action refused/);
  assert.equal(f.controller.state.revokeAttempted, false, 'the backend lists no removal');
  await f.controller.prepareRevoke();
  // Attempted but not yet listed as a removal: the send may have happened, so no second attempt.
  f.replies.status = { ...f.replies.status, installations: [{ ...INSTALLATION, ledger: 9, removalAttempted: true, removal: null }] };
  await assert.rejects(f.controller.revoke(), /wallet action refused/);
  assert.equal(f.controller.state.revokeAttempted, true);
  await assert.rejects(f.controller.prepareRevoke(), /wallet action refused/);
  const g2 = fixture();
  await prepared(g2);
  await g2.controller.prepareInstall();
  await g2.controller.install();
  g2.replies.status = { ...g2.replies.status, capabilities: { ...g2.replies.status.capabilities, lifecycle: true },
    installations: [{ ...INSTALLATION, ledger: 9, removalAttempted: false, removal: null }] };
  await g2.controller.prepareRevoke();
  g2.replies['confirm-revoke'] = new Error('wallet action unavailable');
  g2.replies.status = { ...g2.replies.status, installations: [{ ...INSTALLATION, ledger: 9, removalAttempted: true,
    removal: { status: 'confirmed_unverified', transactionHash: hash('f') } }] };
  await assert.rejects(g2.controller.revoke(), /wallet action refused/);
  assert.equal(g2.controller.state.revokeAttempted, true);
  await assert.rejects(g2.controller.prepareRevoke(), /wallet action refused/);
});

test('the browser re-derives each consent before the passkey and checks the installed rule ID', async () => {
  // Installation: the display at signing time must still be the one shown.
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  f.validators.installConsent = () => ({ ...INSTALL_DISPLAY, warning: 'changed' });
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit'), false);
  // The backend's record must be for the rule the consent named.
  const g = fixture();
  await prepared(g);
  await g.controller.prepareInstall();
  g.replies.submit = { ...g.replies.submit, installation: { ...INSTALLATION, ruleId: 2 } };
  await assert.rejects(g.controller.install(), /wallet action refused/);
  assert.equal(g.controller.state.installation, null);
  // Revocation: preparation and signing both re-derive the removal display, owner rule and installation.
  for (const change of [
    (h) => { h.validators.revokeConsent = () => ({ ...REVOKE_DISPLAY, warning: 'changed' }); },
    (h) => { h.replies['prepare-revoke'] = { ...h.replies['prepare-revoke'], ownerRuleXdr: 'other owner' }; },
    (h) => { h.replies['prepare-revoke'] = { ...h.replies['prepare-revoke'], installation: { ...INSTALLATION, ruleId: 2 } }; },
  ]) {
    const h = fixture();
    await prepared(h);
    await h.controller.prepareInstall();
    await h.controller.install();
    h.replies.status = { ...h.replies.status, capabilities: { ...h.replies.status.capabilities, lifecycle: true } };
    change(h);
    await assert.rejects(h.controller.prepareRevoke(), /wallet action refused/);
    assert.equal(h.controller.state.revokePreview, null);
  }
  const k = fixture();
  await prepared(k);
  await k.controller.prepareInstall();
  await k.controller.install();
  k.replies.status = { ...k.replies.status, capabilities: { ...k.replies.status.capabilities, lifecycle: true } };
  await k.controller.prepareRevoke();
  k.validators.revokeConsent = () => ({ ...REVOKE_DISPLAY, warning: 'changed' });
  await assert.rejects(k.controller.revoke(), /wallet action refused/);
  assert.equal(k.calls.some(([name]) => name === 'confirm-revoke'), false);
});
test('after a lost submit response the browser waits while the backend is busy, then adopts what it confirmed', async () => {
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  const confirmed = { installationId: hash('6'), status: 'installed', account: wallet.contractId, ruleId: 1,
    transactionHash: hash('e'), ledger: 9, removal: null };
  const ready = { ...f.replies.status, installations: [confirmed], capabilities: { ...f.replies.status.capabilities, lifecycle: true } };
  let busy = 3;
  f.replies.submit = new Error('wallet action refused');
  f.replies.status = () => (busy-- > 0 ? new Error('wallet session busy') : ready);
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.deepEqual(f.controller.state.installation, confirmed);
  // Still busy beyond the bound: nothing adopted yet, but a later status refresh adopts it.
  const g = fixture();
  await prepared(g);
  await g.controller.prepareInstall();
  g.replies.submit = new Error('wallet action refused');
  g.replies.status = new Error('wallet session busy');
  await assert.rejects(g.controller.install(), /wallet action refused/);
  assert.equal(g.controller.state.installation, null);
  g.replies.status = ready;
  await g.controller.refreshStatus();
  assert.deepEqual(g.controller.state.installation, confirmed);
});

test('a lost submit response adopts only this wallet\'s confirmed, unremoved installation of the expected rule', async () => {
  const good = { installationId: hash('6'), status: 'installed', account: wallet.contractId, ruleId: 1,
    transactionHash: hash('e'), ledger: 9, removalAttempted: false, removal: null };
  for (const [name, listed] of [['another account', { ...good, account: 'other' }], ['another rule', { ...good, ruleId: 2 }],
    ['removed', { ...good, removal: { status: 'removed', transactionHash: hash('f') } }], ['failed status', { ...good, status: 'failed' }]]) {
    const f = fixture();
    await prepared(f);
    await f.controller.prepareInstall();
    f.replies.submit = new Error('wallet action refused');
    f.replies.status = { ...f.replies.status, installations: [listed] };
    await assert.rejects(f.controller.install(), /wallet action refused/);
    assert.equal(f.controller.state.installation, null, name);
  }
});
test('the browser asks a busy backend for its status at most 40 times after a lost response', async () => {
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  const before = f.calls.filter(([name]) => name === 'status').length;
  f.replies.submit = new Error('wallet action refused');
  f.replies.status = new Error('wallet session busy');
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.equal(f.calls.filter(([name]) => name === 'status').length - before, 40);
  assert.equal(f.pauses.length, 40);
  assert.ok(f.pauses.every((ms) => ms === 3000));
});


test('new recording and generation retain confirmed and uncertain installation recovery for the same wallet', async () => {
  for (const uncertain of [false, true]) {
    for (const reset of ['record', 'generate', 'attach']) {
      const f = fixture();
      await prepared(f);
      await f.controller.prepareInstall();
      if (uncertain) {
        f.replies.submit = new Error('lost response');
        await assert.rejects(f.controller.install(), /refused/);
      } else await f.controller.install();
      const owner = f.controller.state.installOwner;
      if (reset === 'record') await f.controller.record(hash('d'));
      if (reset === 'generate') await f.controller.generate({ grantName: 'grant', delegateAddress: 'delegate', validUntilLedger: 123, maxCalls: 2 });
      if (reset === 'attach') f.controller.attachWallet({ ...wallet });
      assert.equal(f.controller.state.installAttempted, true, reset);
      assert.equal(f.controller.state.installRuleId, 1, reset);
      assert.deepEqual(f.controller.state.installOwner, owner, reset);
      f.replies.status = { ...f.replies.status, installations: [{ ...INSTALLATION, removal: null }],
        capabilities: { ...f.replies.status.capabilities, lifecycle: true } };
      await f.controller.refreshStatus();
      assert.equal(f.controller.state.installation.installationId, INSTALLATION.installationId, reset);
      await f.controller.prepareRevoke();
      await f.controller.revoke();
      assert.equal(f.controller.state.removal.status, 'removed', reset);
      f.controller.attachWallet({ ...wallet, contractId: 'different-wallet' });
      assert.equal(f.controller.state.installation, null);
      assert.equal(f.controller.state.installOwner, null);
      assert.equal(f.controller.state.installAttempted, false);
    }
  }
});

const REPLACEMENT_DISPLAY = { schema: 'wallet-revoke-first-replacement/v1', account: wallet.contractId,
  previousInstallationId: INSTALLATION.installationId, previousRuleId: 1, installationTransactionHash: hash('e'),
  removalTransactionHash: hash('f'), budget: 'previously_used_authority_plus_new_cap', warning: 'Fresh budget' };
async function removedForReplacement() {
  const f = fixture();
  f.replies.status.capabilities.lifecycle = true;
  f.replies.status.capabilities.replacement = true;
  f.replies['prepare-revoke'].limits.maxFeeStroops = f.replies.status.maxFeeStroops;
  f.validators.replacementConsent = () => REPLACEMENT_DISPLAY;
  f.replies['prepare-replacement'] = { action: { id: hash('8') }, display: REPLACEMENT_DISPLAY };
  f.replies['confirm-replacement'] = { replacementReady: true, actionId: hash('8'), display: REPLACEMENT_DISPLAY };
  await prepared(f); await f.controller.prepareInstall(); await f.controller.install();
  await f.controller.prepareRevoke(); await f.controller.revoke();
  return f;
}
test('replacement has separate consent, signs nothing, discards the old review and resets lifecycle only on success', async () => {
  const f = await removedForReplacement();
  const signed = f.calls.filter(([name]) => name === 'sign').length;
  await f.controller.prepareReplacement();
  assert.deepEqual(f.controller.state.replacementPreview.display, REPLACEMENT_DISPLAY);
  assert.equal(f.controller.state.installAttempted, true);
  await f.controller.confirmReplacement();
  assert.equal(f.calls.filter(([name]) => name === 'sign').length, signed);
  assert.equal(f.controller.state.review, null); assert.equal(f.controller.state.artifact, null);
  assert.equal(f.controller.state.installAttempted, false); assert.equal(f.controller.state.revokeAttempted, false);
  assert.equal(f.controller.state.installation, null); assert.deepEqual(f.controller.state.replacement, REPLACEMENT_DISPLAY);
  await assert.rejects(f.controller.prepareInstall(), /refused/, 'new candidate and checks required');
});
test('cancelled or refused replacement retains the removed grant and spent installation state', async () => {
  const f = await removedForReplacement();
  await f.controller.prepareReplacement(); f.controller.cancelReplacement();
  await assert.rejects(f.controller.confirmReplacement(), /refused/);
  assert.equal(f.controller.state.installAttempted, true); assert.ok(f.controller.state.removal);
  await f.controller.prepareReplacement();
  f.replies['confirm-replacement'] = new Error('refused');
  await assert.rejects(f.controller.confirmReplacement(), /refused/);
  assert.equal(f.controller.state.installAttempted, true); assert.ok(f.controller.state.installation);
});
test('substituted replacement consent cannot reset the browser installation guard', async () => {
  const f = await removedForReplacement();
  f.replies['prepare-replacement'] = { action: { id: hash('8') }, display: { ...REPLACEMENT_DISPLAY, previousRuleId: 9 } };
  await assert.rejects(f.controller.prepareReplacement(), /refused/);
  assert.equal(f.controller.state.replacementPreview, null); assert.equal(f.controller.state.installAttempted, true);
});

test('lost replacement confirmation recovers only its exact action-bound acknowledgement', async () => {
  const f = await removedForReplacement();
  await f.controller.prepareReplacement();
  f.replies['confirm-replacement'] = () => {
    f.replies.status.replacement = { replacementReady: true, actionId: hash('8'), display: REPLACEMENT_DISPLAY };
    f.replies.status.capabilities.replacement = false;
    throw new Error('lost response after backend commit');
  };
  await f.controller.confirmReplacement();
  assert.equal(f.controller.state.installAttempted, false);
  assert.equal(f.controller.state.replacementPending, null);
  assert.deepEqual(f.controller.state.replacement, REPLACEMENT_DISPLAY);
  assert.equal(f.calls.filter(([name]) => name === 'confirm-replacement').length, 1, 'no automatic retry');
});
for (const kind of ['different action', 'different display', 'not committed']) test(`replacement recovery refuses ${kind}`, async () => {
  const f = await removedForReplacement(); await f.controller.prepareReplacement();
  f.replies['confirm-replacement'] = () => {
    f.replies.status.replacement = { replacementReady: kind !== 'not committed',
      actionId: kind === 'different action' ? hash('9') : hash('8'),
      display: kind === 'different display' ? { ...REPLACEMENT_DISPLAY, previousRuleId: 2 } : REPLACEMENT_DISPLAY };
    throw new Error('lost response');
  };
  await assert.rejects(f.controller.confirmReplacement(), /refused/);
  assert.equal(f.controller.state.installAttempted, true); assert.ok(f.controller.state.installation);
  assert.ok(f.controller.state.replacementPending);
});
test('later status refresh recovers a replacement after transient status failures', async () => {
  const f = await removedForReplacement(); await f.controller.prepareReplacement();
  f.replies['confirm-replacement'] = () => { f.replies.status = new Error('disconnected'); throw new Error('lost response'); };
  await assert.rejects(f.controller.confirmReplacement(), /refused/);
  const pending = f.controller.state.replacementPending;
  f.replies.status = { ...pins, network: 'testnet', capabilities: {}, replacement: { replacementReady: true,
    actionId: pending.actionId, display: REPLACEMENT_DISPLAY } };
  await f.controller.refreshStatus();
  assert.equal(f.controller.state.installAttempted, false); assert.equal(f.controller.state.replacementPending, null);
});

for (const change of ['rederived display', 'wallet account']) test(`lost replacement acknowledgement rejects changed ${change}`, async () => {
  const f = await removedForReplacement();
  await f.controller.prepareReplacement();
  f.replies['confirm-replacement'] = () => {
    f.replies.status.replacement = { replacementReady: true, actionId: hash('8'), display: REPLACEMENT_DISPLAY };
    f.validators.replacementConsent = () => ({ ...REPLACEMENT_DISPLAY,
      ...(change === 'wallet account' ? { account: 'another-account' } : { previousRuleId: 9 }) });
    throw new Error('lost response');
  };
  await assert.rejects(f.controller.confirmReplacement(), /refused/);
  assert.equal(f.controller.state.installAttempted, true);
  assert.ok(f.controller.state.replacementPending);
  assert.equal(f.controller.state.replacement, null);
});
