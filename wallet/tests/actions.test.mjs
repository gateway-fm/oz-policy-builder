import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, Asset, Networks, StrKey, xdr } from '@stellar/stellar-sdk';
import { WalletSession } from '../server/session.mjs';
import { createWalletActions } from '../server/actions.mjs';
import { ACCOUNT_WASM, NETWORK_ID, WEBAUTHN_WASM } from '../shared/approval.mjs';
import { fixture } from './approval-fixture.mjs';

function setup() {
  const calls = [];
  const f = fixture();
  const session = new WalletSession({ origin: 'http://127.0.0.1:3000', host: '127.0.0.1:3000', secret: 'ab'.repeat(32) });
  let creates = 0;
  const network = {
    payerAddress: StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 9)),
    assertTestnet: async () => { calls.push('network'); },
    requireCode: async (hash) => { calls.push(['code', hash]); },
    fundPayer: async () => { calls.push('fund'); },
    latestLedger: async () => 123,
    requireInstance: async (address, hash) => { calls.push(['instance', address, hash]); },
    create: async (_hash, _args, stage) => {
      calls.push(stage); creates++;
      return { contractId: creates === 1 ? f.wallet.verifier : f.wallet.contractId,
        receipt: { hash: String(creates).repeat(64), ledger: 124, trust: 'rpc_reported' } };
    },
    view: async () => ({ value: xdr.ScVal.fromXDR(f.ruleXdr({ id: xdr.ScVal.scvU32(0) }), 'base64'), ledger: 124 }),
    submitOperation: async (operation, stage) => {
      calls.push(stage);
      const invoke = xdr.Operation.fromXDR(operation.toXDR()).body.invokeHostFunctionOp.hostFunction.invokeContract;
      assert.equal(Address.fromScAddress(invoke.contractAddress).toString(), Asset.native().contractId(Networks.TESTNET));
      assert.equal(invoke.functionName.toString(), 'transfer');
      assert.equal(invoke.args[2].i128.lo, 10_000_000n);
      return { hash: '3'.repeat(64), ledger: 125, trust: 'rpc_reported' };
    },
  };
  const toolchain = {
    record: async (request) => { calls.push(['record', request]); return { recordId: '4'.repeat(64) }; },
    generate: async (request) => { calls.push(['generate', request]); return { artifactId: '5'.repeat(64) }; },
  };
  return { actions: createWalletActions({ session, toolchain, network }), calls, f, network, toolchain };
}
test('account preview performs no writes and separately discloses funding and fees', async () => {
  const { actions, calls, f } = setup();
  const preview = await actions['prepare-account']({ credentialId: f.wallet.credentialId, publicKey: f.wallet.publicKey });
  assert.deepEqual(calls, []);
  assert.equal(preview.summary.accountWasm, ACCOUNT_WASM);
  assert.equal(preview.summary.verifierWasm, WEBAUTHN_WASM);
  assert.equal(preview.summary.sampleFundingStroops, '10000000');
  assert.equal(preview.summary.maxTotalFeeStroops, 30_000_000);
  const result = await actions['confirm-account']({ id: preview.action.id });
  assert.deepEqual(result.wallet, f.wallet);
  assert.equal(result.receipts.length, 3);
  await assert.rejects(() => actions['confirm-account']({ id: preview.action.id }), /unavailable|refused/);
  assert.equal(calls.filter((call) => call === 'deploy-account').length, 1);
});
test('wrong fresh owner getter never triggers sample funding or returns a wallet', async () => {
  const { actions, network, calls, f } = setup();
  network.view = async () => ({ value: xdr.ScVal.fromXDR(f.ruleXdr({ id: xdr.ScVal.scvU32(8) }), 'base64'), ledger: 124 });
  const preview = await actions['prepare-account']({ credentialId: f.wallet.credentialId, publicKey: f.wallet.publicKey });
  await assert.rejects(() => actions['confirm-account']({ id: preview.action.id }), /refused/);
  assert.ok(!calls.includes('fund-account'));
});
test('recording and synthesis accept no caller RPC, paths, current ledger, or invented runtime result', async () => {
  const { actions, calls, f } = setup();
  await actions.record({ wallet: f.wallet, transactionHash: 'a'.repeat(64) });
  await assert.rejects(() => actions.record({ wallet: f.wallet, transactionHash: 'a'.repeat(64), rpcUrl: 'http://attacker' }), /refused/);
  await actions.generate({ recordId: '4'.repeat(64), delegateAddress: StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 1)),
    grantName: 'test', maxCalls: 1, validUntilLedger: 150 });
  assert.equal(calls.find((call) => Array.isArray(call) && call[0] === 'generate')[1].currentLedger, 123);
  await assert.rejects(() => actions.generate({ recordId: '4'.repeat(64), currentLedger: 1 }), /refused/);
});
test('missing runtime layers keep installation unavailable even if the caller supplies passed evidence', async () => {
  const { actions, calls } = setup();
  const status = await actions.status({});
  assert.equal(status.networkId, NETWORK_ID);
  assert.equal(status.capabilities.install, false);
  assert.equal(status.verification.complete, false);
  await assert.rejects(() => actions.assemble({ reviewId: 'f'.repeat(64), verification: { complete: true } }), /unavailable|refused/);
  await assert.rejects(() => actions.submit({ pendingId: 'f'.repeat(64), signedAuthEntriesXdr: [], complete: true }), /unavailable|refused/);
  assert.deepEqual(calls, []);
});

function deploymentFixture(change = () => {}) {
  const f = setup();
  const artifactId = 'a'.repeat(64);
  const policy = f.f.expected.boundPolicies[0];
  const artifact = { artifactId, specHash: f.f.expected.specHash, wasmHash: 'b'.repeat(64), spec: {
    registry_snapshot: f.f.expected.registrySnapshotRoot, smart_account: { address: f.f.wallet.contractId },
    rules: [{ context: { contract: f.f.expected.target } }],
  } };
  f.toolchain.artifact = (selected) => {
    assert.equal(selected, artifactId);
    return { response: artifact, wasmBase64: Buffer.from('retained artifact').toString('base64') };
  };
  f.toolchain.bindingRequest = (selected, address) => {
    assert.equal(selected, artifactId); assert.equal(address, policy);
    return { binding_set: { spec_hash: artifact.specHash }, spec: artifact.spec };
  };
  f.toolchain.authority = async (command) => {
    if (command === 'check-policy-call-surface') return f.f.intent.authority;
    if (command === 'prepare-install-intent') return f.f.intent;
    assert.fail('unexpected authority command');
  };
  f.network.upload = async (bytes, hash) => {
    assert.equal(bytes.toString(), 'retained artifact'); assert.equal(hash, artifact.wasmHash);
    f.calls.push('upload');
    return { hash: 'c'.repeat(64), ledger: 123456, trust: 'rpc_reported' };
  };
  f.network.create = async (hash, args, stage) => {
    assert.equal(hash, artifact.wasmHash); assert.deepEqual(args, []); assert.equal(stage, 'deploy-policy');
    f.calls.push('deploy-policy');
    return { contractId: policy, receipt: { hash: 'd'.repeat(64), ledger: 123456, trust: 'rpc_reported' } };
  };
  f.network.view = async (_account, method, args) => {
    assert.equal(method, 'get_context_rule'); assert.equal(args[0].u32, 7);
    return { value: xdr.ScVal.fromXDR(f.f.ownerRuleXdr, 'base64'), ledger: f.f.intent.authority.verdict.observed_ledger };
  };
  change(f);
  return { ...f, artifactId, artifact, policy };
}
test('deployment consent retains exact artifact and a review selects the actual nonzero owner rule', async () => {
  const f = deploymentFixture();
  const preview = await f.actions['prepare-deploy']({ artifactId: f.artifactId });
  assert.equal(preview.summary.wasmHash, f.artifact.wasmHash);
  assert.equal(preview.summary.maxTotalFeeStroops, 110_000_000);
  assert.deepEqual(f.calls, []);
  const deployed = await f.actions['confirm-deploy']({ id: preview.action.id });
  assert.equal(deployed.policyAddress, f.policy);
  assert.equal(deployed.bindingSetHash, f.f.expected.bindingSetHash);
  const review = await f.actions.review({ deploymentId: deployed.deploymentId, wallet: f.f.wallet });
  assert.equal(review.ownerRuleXdr, f.f.ownerRuleXdr);
  assert.equal(review.verification.complete, false);
  assert.equal(review.verification.layers[0].status, 'passed');
  assert.equal(review.verification.layers[3].status, 'unavailable');
  await assert.rejects(() => f.actions['prepare-deploy']({ artifactId: f.artifactId }), /refused/);
});
test('failed deployment cannot become an implicit upload retry', async () => {
  const f = deploymentFixture((value) => { value.network.upload = async () => { value.calls.push('upload'); throw new Error('ambiguous'); }; });
  const preview = await f.actions['prepare-deploy']({ artifactId: f.artifactId });
  await assert.rejects(() => f.actions['confirm-deploy']({ id: preview.action.id }));
  await assert.rejects(() => f.actions['prepare-deploy']({ artifactId: f.artifactId }), /refused/);
  assert.deepEqual(f.calls.filter((call) => call === 'upload'), ['upload']);
});
test('authority intent cannot substitute a policy after the browser has retained the deployment', async () => {
  const f = deploymentFixture();
  const preview = await f.actions['prepare-deploy']({ artifactId: f.artifactId });
  const deployed = await f.actions['confirm-deploy']({ id: preview.action.id });
  f.f.intent.policies[0].address = f.f.wallet.verifier;
  await assert.rejects(() => f.actions.review({ deploymentId: deployed.deploymentId, wallet: f.f.wallet }), /refused/);
});
