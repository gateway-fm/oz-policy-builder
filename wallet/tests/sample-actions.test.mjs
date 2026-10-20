import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { Address, Networks, buildAuthorizationEntryPreimage, hash, xdr } from '@stellar/stellar-sdk';
import { createWalletActions } from '../server/actions.mjs';
import { WalletSession } from '../server/session.mjs';
import { reviewSample, validateSampleAssembly } from '../shared/sample.mjs';
import { fixture } from './approval-fixture.mjs';
import { sampleTransfer } from './sample-fixture.mjs';

function setup() {
  const calls = [];
  const f = fixture();
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  f.wallet.publicKey = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]).toString('hex');
  const ownerRuleXdr = f.ruleXdr({ id: xdr.ScVal.scvU32(0) });
  const draft = sampleTransfer();
  draft.wallet = f.wallet;
  draft.ownerRuleXdr = ownerRuleXdr;
  draft.descriptor.ownerRuleXdr = ownerRuleXdr;
  const network = {
    payerAddress: draft.descriptor.recipient,
    assertTestnet: async () => {}, requireCode: async () => {}, fundPayer: async () => { calls.push('fund'); },
    requireInstance: async () => ({ ledger: 100 }),
    latestLedger: async () => 101,
    sourceCapture: async () => ({ sourceSequence: '100', ledger: 101 }),
    create: async (_hash, _args, stage) => {
      calls.push(stage);
      return { contractId: stage === 'deploy-verifier' ? f.wallet.verifier : f.wallet.contractId,
        receipt: { hash: 'a'.repeat(64), ledger: 100, trust: 'rpc_reported' } };
    },
    view: async () => ({ value: xdr.ScVal.fromXDR(ownerRuleXdr, 'base64'), ledger: 100 }),
    submitOperation: async () => { calls.push('fund-account'); return { hash: 'b'.repeat(64), ledger: 100, trust: 'rpc_reported' }; },
    prepareSample: async (request) => {
      calls.push('prepare-sample');
      assert.equal(request.wallet.publicKey, f.wallet.publicKey);
      assert.equal(request.descriptor.recipient, network.payerAddress);
      assert.equal(request.ownerRuleXdr, ownerRuleXdr);
      return { assembly: draft.assembly, limits: draft.limits };
    },
    submitEnvelope: async (raw, stage) => {
      calls.push('submit-sample');
      assert.equal(stage, 'sample-transfer');
      const op = xdr.TransactionEnvelope.fromXDR(raw, 'base64').v1.tx.operations[0].body.invokeHostFunctionOp;
      assert.equal(op.auth[0].credentials.address.signature.type, 'scvMap');
      return { hash: 'c'.repeat(64), ledger: 102, trust: 'rpc_reported', returnValue: xdr.ScVal.scvVoid(), events: [] };
    },
  };
  const actions = createWalletActions({ session: new WalletSession({ origin: 'http://localhost:3000', host: 'localhost:3000', secret: 'ab'.repeat(32) }),
    toolchain: {}, network });
  return { actions, network, calls, wallet: f.wallet, draft, pair, ownerRuleXdr };
}
async function create(f) {
  const preview = await f.actions['prepare-account']({ credentialId: f.wallet.credentialId, publicKey: f.wallet.publicKey });
  return f.actions['confirm-account']({ id: preview.action.id });
}
function signed(f, prepared) {
  const approval = reviewSample({ wallet: f.wallet, descriptor: f.draft.descriptor, ownerRuleXdr: prepared.ownerRuleXdr });
  const checked = validateSampleAssembly({ ...prepared, approval });
  const entry = xdr.SorobanAuthorizationEntry.fromXDR(checked.authEntriesXdr[0], 'base64');
  const rules = xdr.ScVal.scvVec([xdr.ScVal.scvU32(0)]);
  const payload = Buffer.from(hash(buildAuthorizationEntryPreimage(entry, checked.expirationLedger, Networks.TESTNET).toXDR()));
  const challenge = createHash('sha256').update(Buffer.concat([payload, rules.toXDR()])).digest('base64url');
  const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'http://localhost:3000', crossOrigin: false }));
  const auth = Buffer.concat([createHash('sha256').update('localhost').digest(), Buffer.from([5, 0, 0, 0, 0])]);
  const signature = sign('sha256', Buffer.concat([auth, createHash('sha256').update(client).digest()]), { key: f.pair.privateKey, dsaEncoding: 'ieee-p1363' });
  const field = (key, val) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val });
  const proof = xdr.ScVal.scvMap([field('authenticator_data', xdr.ScVal.scvBytes(auth)),
    field('client_data', xdr.ScVal.scvBytes(client)), field('signature', xdr.ScVal.scvBytes(signature))]);
  entry.credentials.address.signature = xdr.ScVal.scvMap([field('context_rule_ids', rules), field('signers',
    xdr.ScVal.scvMap([new xdr.ScMapEntry({ key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('External'),
      new Address(f.wallet.verifier).toScVal(), xdr.ScVal.scvBytes(Buffer.concat([Buffer.from(f.wallet.publicKey, 'hex'), Buffer.from([1])]))]),
      val: xdr.ScVal.scvBytes(proof.toXDR()) })]))]);
  return [entry.toXDR('base64')];
}
test('only a freshly created retained account can prepare a sample without implicit signing or sending', async () => {
  const f = setup();
  await assert.rejects(() => f.actions['prepare-sample']({ wallet: f.wallet }), /refused/);
  const created = await create(f);
  assert.deepEqual(created.sample, f.draft.descriptor);
  assert.equal((await f.actions.status({})).capabilities.sampleTransfer, true);
  const prepared = await f.actions['prepare-sample']({ wallet: f.wallet });
  assert.ok(prepared.action.id);
  assert.equal(prepared.ownerRuleXdr, f.ownerRuleXdr);
  assert.ok(!f.calls.includes('submit-sample'));
  await assert.rejects(() => f.actions['prepare-sample']({ wallet: { ...f.wallet, credentialId: 'Ag' } }), /refused/);
  await assert.rejects(() => f.actions['prepare-sample']({ wallet: f.wallet, amount: '10000000' }), /refused/);
});
test('real passkey proof submits the retained sample exactly once and yields a recording hash', async () => {
  const f = setup();
  await create(f);
  const prepared = await f.actions['prepare-sample']({ wallet: f.wallet });
  const input = { id: prepared.action.id, signedAuthEntriesXdr: signed(f, prepared) };
  const result = await f.actions['submit-sample'](input);
  assert.equal(result.transactionHash, 'c'.repeat(64));
  assert.equal(result.receipt.ledger, 102);
  await assert.rejects(() => f.actions['submit-sample'](input), /refused|unavailable/);
  await assert.rejects(() => f.actions['prepare-sample']({ wallet: f.wallet }), /refused/);
  assert.equal(f.calls.filter((x) => x === 'submit-sample').length, 1);
});
test('a new preparation invalidates the previous authorization token', async () => {
  const f = setup(); await create(f);
  const first = await f.actions['prepare-sample']({ wallet: f.wallet });
  const second = await f.actions['prepare-sample']({ wallet: f.wallet });
  await assert.rejects(() => f.actions['submit-sample']({ id: first.action.id, signedAuthEntriesXdr: signed(f, first) }), /refused|unavailable/);
  await f.actions['submit-sample']({ id: second.action.id, signedAuthEntriesXdr: signed(f, second) });
});
for (const mutation of ['owner', 'sequence', 'ledger', 'proof']) {
  test(`a changed ${mutation} after preparation refuses before send and consumes approval`, async () => {
    const f = setup(); await create(f);
    const prepared = await f.actions['prepare-sample']({ wallet: f.wallet });
    const input = { id: prepared.action.id, signedAuthEntriesXdr: signed(f, prepared) };
    if (mutation === 'owner') f.network.view = async () => ({ value: xdr.ScVal.scvVoid(), ledger: 100 });
    if (mutation === 'sequence') f.network.sourceCapture = async () => ({ sourceSequence: '101', ledger: 101 });
    if (mutation === 'ledger') f.network.latestLedger = async () => 219;
    if (mutation === 'proof') input.signedAuthEntriesXdr = prepared.assembly ? ['AAAA'] : [];
    await assert.rejects(() => f.actions['submit-sample'](input), /refused|unavailable/);
    await assert.rejects(() => f.actions['submit-sample'](input), /refused|unavailable/);
    assert.ok(!f.calls.includes('submit-sample'));
  });
}
test('ambiguous sample send cannot become another implicit attempt', async () => {
  const f = setup(); await create(f);
  const prepared = await f.actions['prepare-sample']({ wallet: f.wallet });
  f.network.submitEnvelope = async () => { f.calls.push('submit-sample'); throw new Error('unknown receipt'); };
  await assert.rejects(() => f.actions['submit-sample']({ id: prepared.action.id, signedAuthEntriesXdr: signed(f, prepared) }));
  await assert.rejects(() => f.actions['prepare-sample']({ wallet: f.wallet }), /refused/);
  assert.equal(f.calls.filter((x) => x === 'submit-sample').length, 1);
});
