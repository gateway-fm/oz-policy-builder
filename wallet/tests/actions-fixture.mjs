import assert from 'node:assert/strict';
import { Address, Asset, Networks, StrKey, xdr } from '@stellar/stellar-sdk';
import { WalletSession } from '../server/session.mjs';
import { createWalletActions } from '../server/actions.mjs';
import { fixture } from './approval-fixture.mjs';
export function setup({ native = null } = {}) {
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
  return { actions: createWalletActions({ session, toolchain, network, native }), calls, f, network, toolchain };
}

export function deploymentFixture(change = () => {}, options = {}) {
  const f = setup(options);
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
