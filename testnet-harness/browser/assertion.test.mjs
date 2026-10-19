// Offline checks for the WebAuthn assertion verifier webauthn.mjs relies on. The assertions here
// are built with node's own P-256 implementation, so the verifier is tested against a signer it
// shares no code with.
//
//   node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';

import { verifyAssertion } from './assertion.mjs';

const sha256 = (b) => createHash('sha256').update(b).digest();
const b64url = (b) => Buffer.from(b).toString('base64url');

const RP_ID = 'localhost';
const ORIGIN = 'http://localhost:5177';

/** An honest assertion over `challenge`, with knobs to make each field wrong. */
function assertion({
  challenge = Buffer.alloc(32, 7), type = 'webauthn.get', origin = ORIGIN, rpId = RP_ID, flags = 0x05,
  curve = 'P-256',
} = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: curve });
  // rpIdHash (32) ‖ flags (1) ‖ signCount (4)
  const authenticatorData = Buffer.concat([sha256(rpId), Buffer.from([flags]), Buffer.from([0, 0, 0, 1])]);
  const clientDataJSON = Buffer.from(JSON.stringify({ type, challenge: b64url(challenge), origin }));
  const signature = sign('sha256', Buffer.concat([authenticatorData, sha256(clientDataJSON)]), privateKey);
  return {
    publicKeySpki: publicKey.export({ format: 'der', type: 'spki' }),
    authenticatorData, clientDataJSON, signature, challenge: Buffer.alloc(32, 7), origin: ORIGIN, rpId: RP_ID,
  };
}

test('an honest ES256 assertion verifies', () => {
  assert.deepEqual(verifyAssertion(assertion()), { userPresent: true, userVerified: true, signCount: 1 });
});

test('a flipped signature bit is refused', () => {
  const a = assertion();
  a.signature = Buffer.from(a.signature);
  a.signature[a.signature.length - 1] ^= 1;
  assert.throws(() => verifyAssertion(a), /signature/);
});

test('the signature must be over this challenge', () => {
  assert.throws(() => verifyAssertion(assertion({ challenge: Buffer.alloc(32, 8) })), /challenge/);
});

test('a registration response is not an assertion', () => {
  assert.throws(() => verifyAssertion(assertion({ type: 'webauthn.create' })), /type/);
});

test('origin and relying party are both bound', () => {
  assert.throws(() => verifyAssertion(assertion({ origin: 'http://evil.test' })), /origin/);
  assert.throws(() => verifyAssertion(assertion({ rpId: 'evil.test' })), /rpId/);
});

test('user verification was required, so its flag must be set', () => {
  assert.throws(() => verifyAssertion(assertion({ flags: 0x01 })), /user verification/);
  assert.throws(() => verifyAssertion(assertion({ flags: 0x04 })), /presen/);
});

test('only a P-256 credential key is accepted, even with a valid signature', () => {
  // ES256 is P-256 with SHA-256; a P-384 key signing correctly is still the wrong algorithm.
  assert.throws(() => verifyAssertion(assertion({ curve: 'P-384' })), /P-256/);
});

test('authenticatorData shorter than its 37-byte header is refused', () => {
  const a = assertion();
  a.authenticatorData = a.authenticatorData.subarray(0, 36);
  assert.throws(() => verifyAssertion(a), /shorter/);
});
