// Verify a WebAuthn assertion the way a relying party must, using node's own crypto: the
// browser saying "signed" is not evidence that a valid signature exists.
//
// An ES256 (alg −7, secp256r1) assertion signs `authenticatorData ‖ sha256(clientDataJSON)`.
// Valid means all of: the signature verifies under the credential's public key; clientDataJSON
// is a `webauthn.get` over exactly our challenge from exactly our origin; authenticatorData is
// for our relying party; and the flags say the user was present and verified, since the request
// required verification.
//
// Not checked here, because nothing in this harness depends on them: the sign counter against a
// stored value (webauthn.mjs compares it with the authenticator's instead), `tokenBinding`,
// `crossOrigin`, and the registration ceremony's attestation, which is not verified at all.
// A Soroban contract verifying this signature would also need it as 64-byte r‖s, not DER.
import { createHash, createPublicKey, verify } from 'node:crypto';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest();

const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;

/**
 * @param {object} a
 * @param {Buffer} a.publicKeySpki      DER SubjectPublicKeyInfo, from `response.getPublicKey()` at creation
 * @param {Buffer} a.authenticatorData
 * @param {Buffer} a.clientDataJSON
 * @param {Buffer} a.signature          DER-encoded ECDSA signature, as WebAuthn returns it
 * @param {Buffer} a.challenge          the bytes the page asked the authenticator to sign
 * @param {string} a.origin
 * @param {string} a.rpId
 * @returns {{userPresent: boolean, userVerified: boolean, signCount: number}}
 */
export function verifyAssertion({ publicKeySpki, authenticatorData, clientDataJSON, signature, challenge, origin, rpId }) {
  const client = JSON.parse(Buffer.from(clientDataJSON).toString('utf8'));
  if (client.type !== 'webauthn.get') throw new Error(`clientData type is ${client.type}, not webauthn.get`);
  if (client.challenge !== Buffer.from(challenge).toString('base64url')) {
    throw new Error('clientData challenge is not the challenge that was asked for');
  }
  if (client.origin !== origin) throw new Error(`clientData origin is ${client.origin}, expected ${origin}`);

  const data = Buffer.from(authenticatorData);
  if (data.length < 37) throw new Error(`authenticatorData is ${data.length} bytes, shorter than its header`);
  if (!data.subarray(0, 32).equals(sha256(rpId))) throw new Error(`authenticatorData is not for rpId ${rpId}`);
  const flags = data[32];
  if (!(flags & FLAG_USER_PRESENT)) throw new Error('authenticator did not report user presence');
  if (!(flags & FLAG_USER_VERIFIED)) throw new Error('authenticator did not report user verification');

  const key = createPublicKey({ key: Buffer.from(publicKeySpki), format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new Error('credential key is not a P-256 (secp256r1) key');
  }
  const signed = Buffer.concat([data, sha256(clientDataJSON)]);
  if (!verify('sha256', signed, { key, dsaEncoding: 'der' }, Buffer.from(signature))) {
    throw new Error('signature does not verify under the credential public key');
  }
  return { userPresent: true, userVerified: true, signCount: data.readUInt32BE(33) };
}
