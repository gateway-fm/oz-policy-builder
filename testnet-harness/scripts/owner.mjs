// The account owner as a signer for `signForSmartAccount`, whichever kind setup.mjs created:
//
//   ed25519  a `Delegated` Stellar account; its seed is in the secrets file.
//   passkey  an `External` signer: the pinned OpenZeppelin WebAuthn verifier and the passkey's
//            key data. Each signature is a WebAuthn assertion made by Chrome's virtual
//            authenticator (`../browser/passkey.mjs`), from the credential in the secrets file.
//
// The browser module is imported only for a passkey owner, so the ed25519 path needs no
// `npm ci` in `browser/`.
//
// `{ wrongChallenge: true }` is a negative control for the passkey: it signs 32 random bytes
// instead of the account's digest, a well-formed assertion over the wrong message, which the
// verifier must refuse (`ChallengeInvalid`, #3114).
import { randomBytes } from 'node:crypto';

import { derToLowS, p256PublicKeyRaw, passkeyKeyData, webAuthnSigData } from './lib.mjs';
import { loadKey, loadSecret, log, updateSecret } from './rpc.mjs';

export async function ownerSigner(run, { wrongChallenge = false } = {}) {
  const owner = run.owner;
  if (wrongChallenge && owner?.kind !== 'passkey') throw new Error('the wrong-challenge control is for a passkey owner');
  if (owner?.kind === 'ed25519') {
    const key = loadKey('owner');
    if (key.publicKey() !== owner.address) throw new Error('the owner seed is not the run\'s owner');
    return key;
  }
  if (owner?.kind !== 'passkey') throw new Error(`run.json has no owner this script can sign as (${owner?.kind})`);

  const { signChallenge } = await import('../browser/passkey.mjs');
  const fromHex = (h) => Buffer.from(h, 'hex');
  const stored = loadSecret('passkey');
  const credentialId = Buffer.from(stored.credentialId, 'base64url');
  const publicKeySpki = Buffer.from(stored.publicKeySpki, 'base64url');
  // The key data the account holds (run.json) must be this passkey's, or every signature would be
  // checked against another key.
  const keyData = passkeyKeyData(p256PublicKeyRaw(publicKeySpki), credentialId);
  if (!keyData.equals(fromHex(owner.key_data))) throw new Error('the stored passkey is not the run\'s owner');

  return {
    verifier: owner.verifier,
    keyData,
    async sign(digest) {
      const current = loadSecret('passkey');
      const challenge = wrongChallenge ? randomBytes(32) : Buffer.from(digest);
      const assertion = await signChallenge({ credential: current.credential, credentialId, publicKeySpki }, challenge);
      updateSecret('passkey', { ...current, credential: assertion.credential });
      const what = wrongChallenge
        ? `random challenge ${challenge.toString('hex')} instead of auth_digest ${Buffer.from(digest).toString('hex')}`
        : `auth_digest ${challenge.toString('hex')}`;
      log(`          passkey signed ${what} (sign count ${assertion.signCount}), verified off chain`);
      return webAuthnSigData({
        authenticatorData: assertion.authenticatorData,
        clientDataJSON: assertion.clientDataJSON,
        signature: derToLowS(assertion.signature),
      });
    },
  };
}
