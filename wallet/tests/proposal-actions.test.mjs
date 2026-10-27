import test from 'node:test';
import assert from 'node:assert/strict';
import { setup } from './actions-fixture.mjs';
import { proposalFixture } from './proposal-fixture.mjs';
import { parseGrantProposal, checkProposalArtifact } from '../shared/proposal.mjs';
import { WalletController } from '../overlay/files/src/policy-builder/client/controller.mjs';
import { ACCOUNT_WASM, NETWORK_ID, WEBAUTHN_WASM } from '../shared/approval.mjs';

function backend() {
  const f = setup(), p = proposalFixture();
  f.toolchain.record = async input => { f.calls.push(['record', input]); return p.record; };
  f.toolchain.generate = async input => { f.calls.push(['generate', input]); return p.artifact; };
  return { ...f, ...p };
}
test('import re-records and generates through wallet tools without submitting or signing', async () => {
  const f = backend();
  const result = await f.actions['import-proposal']({ proposal: JSON.stringify(f.proposal), wallet: f.wallet });
  assert.deepEqual(f.calls.map(c => Array.isArray(c) ? c[0] : c), ['network', 'instance', 'instance', 'record', 'generate']);
  assert.deepEqual(f.calls[3][1], { transactionHash: f.proposal.transaction_hash, accountAddress: f.wallet.contractId });
  assert.equal(f.calls[4][1].recordId, f.record.recordId);
  assert.equal(f.calls[4][1].currentLedger, 123);
  assert.equal(f.calls[4][1].proposal.expected_grant.account, f.wallet.contractId);
  assert.equal(result.proposalReview.hashesMatch, false);
  assert.equal(result.proposalReview.grantsMatch, true);
  assert.deepEqual(result.artifact, f.artifact);
});
test('invalid import makes no RPC or tool call; regenerated mismatch releases no artifact', async () => {
  const f = backend();
  await assert.rejects(() => f.actions['import-proposal']({ proposal: '{}', wallet: f.wallet }));
  assert.deepEqual(f.calls, []);
  f.spec.rules[0].allowed_calls[0].args[2].c.eq_i128.value = '1000001';
  await assert.rejects(() => f.actions['import-proposal']({ proposal: JSON.stringify(f.proposal), wallet: f.wallet }));
});

function browser() {
  const f = proposalFixture(), calls = [], pins = { networkId: NETWORK_ID, accountWasm: ACCOUNT_WASM, verifierWasm: WEBAUTHN_WASM };
  const result = { record: f.record, artifact: f.artifact,
    proposalReview: checkProposalArtifact(parseGrantProposal(JSON.stringify(f.proposal), f.wallet.contractId), f.artifact) };
  const controller = new WalletController({ validators: { parseGrantProposal, checkProposalArtifact }, pins,
    sign: async () => assert.fail('import must never sign'), origin: 'http://localhost:3000',
    request: async (name, body) => { calls.push([name, body]);
      if (name === 'status') return { ...pins, network: 'testnet', capabilities: { importProposal: true } };
      assert.equal(name, 'import-proposal'); return result;
    } });
  return { ...f, calls, result, controller };
}
test('browser accepts an independently matched import and clears it on a failed retry', async () => {
  const f = browser(); await f.controller.connect(); f.controller.attachWallet(f.wallet);
  await f.controller.importProposal(JSON.stringify(f.proposal));
  assert.equal(f.controller.state.artifact.specHash, f.artifact.specHash);
  assert.equal(f.controller.state.proposalReview.agentSpecHash, f.proposal.spec_hash);
  assert.equal(f.controller.state.deployment, null);
  assert.equal(f.controller.state.review, null);
  await assert.rejects(() => f.controller.importProposal('{}'));
  assert.equal(f.controller.state.artifact, null);
  assert.equal(f.controller.state.proposalReview, null);
  assert.equal(f.calls.filter(([name]) => name === 'import-proposal').length, 1);
});
for (const change of ['permission', 'record', 'recordId', 'receipt']) test(`browser rejects a mismatched import ${change}`, async () => {
  const f = browser(); await f.controller.connect(); f.controller.attachWallet(f.wallet);
  if (change === 'permission') f.spec.rules[0].authorization.strict_signer_set = false;
  if (change === 'record') f.record.transactionHash = 'a'.repeat(64);
  if (change === 'recordId') f.record.recordId = [f.record.recordId];
  if (change === 'receipt') f.result.proposalReview = { ...f.result.proposalReview, grantsMatch: false };
  await assert.rejects(() => f.controller.importProposal(JSON.stringify(f.proposal)));
  assert.equal(f.controller.state.artifact, null);
});
