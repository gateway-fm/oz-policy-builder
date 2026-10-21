import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { Address, Networks, buildAuthorizationEntryPreimage, hash, xdr } from '@stellar/stellar-sdk';
import { sample } from './assembly-fixture.mjs';
import { validateAssembly } from '../shared/assembly.mjs';
import { validateSignedAuthorization } from '../shared/signature.mjs';

function signatureInput(change = () => {}) {
  const source = sample();
  const checked = validateAssembly(source);
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const publicKey = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]).toString('hex');
  // The signed-entry checker trusts the already reviewed display; use a real signing key here.
  const approval = { ...source.approval, wallet: { ...source.approval.wallet, publicKey } };
  const entry = xdr.SorobanAuthorizationEntry.fromXDR(checked.authEntriesXdr[0], 'base64');
  const ruleIds = xdr.ScVal.scvVec([xdr.ScVal.scvU32(checked.ownerRuleId)]);
  const payload = Buffer.from(hash(buildAuthorizationEntryPreimage(entry, checked.expirationLedger, Networks.TESTNET).toXDR()));
  const challenge = createHash('sha256').update(Buffer.concat([payload, ruleIds.toXDR()])).digest('base64url');
  const client = { type: 'webauthn.get', challenge, origin: 'http://localhost:3000', crossOrigin: false };
  const auth = Buffer.concat([createHash('sha256').update('localhost').digest(), Buffer.from([5, 0, 0, 0, 0])]);
  const state = { client, auth, entry, ruleIds, signerKey: Buffer.concat([Buffer.from(publicKey, 'hex'), Buffer.from([1])]), verifier: approval.wallet.verifier };
  change(state);
  const clientBytes = Buffer.from(JSON.stringify(client));
  const sigBytes = sign('sha256', Buffer.concat([auth, createHash('sha256').update(clientBytes).digest()]), { key: pair.privateKey, dsaEncoding: 'ieee-p1363' });
  const field = (name, val) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(name), val });
  const proof = xdr.ScVal.scvMap([
    field('authenticator_data', xdr.ScVal.scvBytes(auth)), field('client_data', xdr.ScVal.scvBytes(clientBytes)),
    field('signature', xdr.ScVal.scvBytes(state.badCrypto ? Buffer.alloc(64) : sigBytes)),
  ]).toXDR();
  entry.credentials.address.signature = xdr.ScVal.scvMap([
    field('context_rule_ids', state.ruleIds), field('signers', xdr.ScVal.scvMap([new xdr.ScMapEntry({
      key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('External'), new Address(state.verifier).toScVal(), xdr.ScVal.scvBytes(state.signerKey)]),
      val: xdr.ScVal.scvBytes(proof),
    })])),
  ]);
  return { approval, checked, signedAuthEntriesXdr: [entry.toXDR('base64')], origin: 'http://localhost:3000' };
}

test('valid fresh passkey proof is bound to the exact reviewed authorization and origin', async () => {
  const value = await validateSignedAuthorization(signatureInput());
  assert.equal(xdr.TransactionEnvelope.fromXDR(value.envelopeXdr, 'base64').v1.signatures.length, 0);
  assert.equal(value.authentication, 'webauthn_user_verified');
  assert.equal(value.human_approval_attested, false);
});

for (const mutation of ['challenge', 'origin', 'cross origin', 'UV', 'UP', 'RP ID', 'rule', 'credential', 'nonce', 'expiration', 'crypto']) {
  test(`signed entry refuses changed ${mutation}`, async () => {
    const input = signatureInput((s) => {
      switch (mutation) {
        case 'challenge': s.client.challenge = 'wrong'; break;
        case 'origin': s.client.origin = 'https://evil.invalid'; break;
        case 'cross origin': s.client.crossOrigin = true; break;
        case 'UV': s.auth[32] = 1; break;
        case 'UP': s.auth[32] = 4; break;
        case 'RP ID': s.auth[0] ^= 1; break;
        case 'rule': s.ruleIds = xdr.ScVal.scvVec([xdr.ScVal.scvU32(0)]); break;
        case 'credential': s.signerKey[s.signerKey.length - 1] = 2; break;
        case 'nonce': s.entry.credentials.address.nonce += 1n; break;
        case 'expiration': s.entry.credentials.address.signatureExpirationLedger += 1; break;
        case 'crypto': s.badCrypto = true; break;
      }
    });
    await assert.rejects(() => validateSignedAuthorization(input), /refused/);
  });
}

test('extra, replay-substituted, or malformed signed entries cannot become a generic relayer request', async () => {
  const input = signatureInput();
  for (const signedAuthEntriesXdr of [[], [...input.signedAuthEntriesXdr, ...input.signedAuthEntriesXdr], ['AAAA'], ['A'.repeat(50000)]]) {
    await assert.rejects(() => validateSignedAuthorization({ ...input, signedAuthEntriesXdr }), /refused/);
  }
});
