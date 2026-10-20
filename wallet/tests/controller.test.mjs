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
