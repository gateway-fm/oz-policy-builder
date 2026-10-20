import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, Keypair, xdr } from '@stellar/stellar-sdk';
import { reviewSample, validateSampleAssembly } from '../shared/sample.mjs';
import { sampleTransfer } from './sample-fixture.mjs';

function checked(f) { return validateSampleAssembly({ ...f, approval: reviewSample(f) }); }
test('fresh-account sample binds the fixed transfer, exact owner0 credential and retained payer', () => {
  const f = sampleTransfer();
  const approval = reviewSample(f);
  const result = checked(f);
  assert.equal(approval.ownerRuleId, 0);
  assert.equal(result.envelopeXdr, f.assembly.envelope_xdr_base64);
  assert.equal(result.expirationLedger, 219);
  assert.equal(result.authorityCommitment, approval.commitment);
  assert.equal(result.feeStroops, 1100);
  assert.ok(Object.isFrozen(approval));
});
for (const field of ['policy_ids', 'signer_ids']) {
  test(`fresh owner refuses changed ${field} even if the descriptor repeats it`, () => {
    const f = sampleTransfer();
    const raw = xdr.ScVal.fromXDR(f.ownerRuleXdr, 'base64');
    raw.map.find((entry) => entry.key.sym.toString() === field).val = xdr.ScVal.scvVec([xdr.ScVal.scvU32(9)]);
    f.ownerRuleXdr = f.descriptor.ownerRuleXdr = raw.toXDR('base64');
    assert.throws(() => checked(f), /refused/);
  });
}
for (const field of ['owner getter', 'amount', 'owner credential', 'fee ceiling', 'recipient as source', 'source sequence', 'expired', 'stale owner', 'source before owner']) {
  test(`sample refuses changed ${field}`, () => {
    const f = sampleTransfer();
    if (field === 'owner getter') f.ownerRuleXdr = f.ownerRuleXdr.replace(/.$/, 'A');
    if (field === 'amount') f.descriptor.amountStroops = '10000000';
    if (field === 'owner credential') f.wallet.credentialId = 'Ag';
    if (field === 'fee ceiling') f.limits.maxFeeStroops = 100_000_000;
    if (field === 'recipient as source') f.limits.feePayer = Keypair.random().publicKey();
    if (field === 'source sequence') f.limits.sourceSequence = '101';
    if (field === 'expired') f.limits.currentLedger = 219;
    if (field === 'stale owner') f.limits.currentLedger = 113;
    if (field === 'source before owner') f.limits.ownerReadLedger = 101;
    assert.throws(() => checked(f), /refused/);
  });
}
for (const field of ['amount', 'recipient', 'token', 'function', 'nested auth', 'auth account', 'auth expiration', 'signed auth', 'payer signature', 'fee', 'fee resources', 'memo', 'max ledger', 'operation source']) {
  test(`raw sample envelope refuses substituted ${field}`, () => {
    const f = sampleTransfer((tx, envelope) => {
      const op = tx.operations[0].body.invokeHostFunctionOp;
      const call = op.hostFunction.invokeContract;
      const auth = op.auth[0];
      if (field === 'amount') call.args[2] = xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: 2_000_000n }));
      if (field === 'recipient') call.args[1] = new Address(Keypair.random().publicKey()).toScVal();
      if (field === 'token') call.contractAddress = call.args[0].address;
      if (field === 'function') call.functionName = 'burn';
      if (field === 'nested auth') auth.rootInvocation.subInvocations.push(xdr.SorobanAuthorizedInvocation.fromXDR(auth.rootInvocation.toXDR()));
      if (field === 'auth account') auth.credentials.address.address = new Address(Keypair.random().publicKey()).toScAddress();
      if (field === 'auth expiration') auth.credentials.address.signatureExpirationLedger--;
      if (field === 'signed auth') auth.credentials.address.signature = xdr.ScVal.scvU32(1);
      if (field === 'payer signature') envelope.v1.signatures.push(new xdr.DecoratedSignature({ hint: Buffer.alloc(4), signature: Buffer.alloc(64) }));
      if (field === 'fee') tx.fee = 10_000_001;
      if (field === 'fee resources') tx.ext.sorobanData.resourceFee = 1101n;
      if (field === 'memo') tx.memo = xdr.Memo.memoText('sample');
      if (field === 'max ledger') tx.cond.v2.ledgerBounds.maxLedger++;
      if (field === 'operation source') tx.operations[0].sourceAccount = xdr.MuxedAccount.keyTypeEd25519(Keypair.random().rawPublicKey());
    });
    assert.throws(() => checked(f), /refused/);
  });
}

test('sample preserves the address-bound V2 credential and rejects unsupported credential arms', () => {
  const f = sampleTransfer(() => {}, 'v2');
  const accepted = checked(f);
  assert.equal(xdr.SorobanAuthorizationEntry.fromXDR(accepted.authEntriesXdr[0], 'base64').credentials.type, 'sorobanCredentialsAddressV2');
  const source = sampleTransfer((tx) => {
    tx.operations[0].body.invokeHostFunctionOp.auth[0].credentials = xdr.SorobanCredentials.sorobanCredentialsSourceAccount();
  });
  assert.throws(() => checked(source), /refused/);
});
