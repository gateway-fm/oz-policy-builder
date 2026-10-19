// A passkey that outlives one browser, for the testnet harness: created in Chrome's virtual
// authenticator, and used again by later scripts to sign a smart account's `auth_digest`.
//
// Each call launches headless Chromium, serves `app.html` on loopback, attaches the virtual
// authenticator (`authenticator.mjs`) and drives the page's own `navigator.credentials` calls, so
// every signature is a real WebAuthn assertion made by the browser's authenticator. Nothing here
// signs with node's crypto.
//
// The harness runs as separate scripts, with cargo steps between them, and the virtual
// authenticator dies with its browser. So the credential, private key included, is exported
// through the DevTools Protocol after creation and imported again before each signature. The
// caller keeps it with the other throwaway secrets. A real authenticator never lets its key out;
// this is the one place the headless harness differs from a device.
//
// Every assertion is checked outside the browser (`assertion.mjs`) before it is returned: the
// signature verifies under the credential key, over exactly the challenge asked for, from this
// origin, with the user present and verified.
import { createPrivateKey, createPublicKey } from 'node:crypto';

import { verifyAssertion } from './assertion.mjs';

// Playwright's `pw:protocol` and `pw:channel` debug logs print every DevTools call and reply in
// full, and two of them carry the credential's private key (`WebAuthn.getCredentials`,
// `WebAuthn.addCredential`). Refuse to run at all rather than hope nobody turned them on.
if (/pw:|\*/.test(process.env.DEBUG ?? '')) {
  throw new Error('DEBUG would make Playwright log the passkey\'s private key; unset it to use a passkey owner');
}
import { addVirtualAuthenticator, launch } from './authenticator.mjs';
import { serve } from './server.mjs';

const RP_ID = 'localhost';
const b = (s) => Buffer.from(s, 'base64url'); // also accepts the standard alphabet CDP uses

/** The fields of a CDP `WebAuthn.Credential` that `addCredential` takes back. */
function portable(c) {
  const out = {
    credentialId: c.credentialId,
    isResidentCredential: c.isResidentCredential,
    rpId: c.rpId,
    privateKey: c.privateKey,
    userHandle: c.userHandle,
    signCount: c.signCount,
  };
  for (const k of ['backupEligibility', 'backupState']) if (k in c) out[k] = c[k];
  return out;
}

async function withPage(credential, fn) {
  const server = await serve(0);
  const origin = `http://localhost:${server.address().port}`;
  let browser;
  try {
    browser = await launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    const authenticator = await addVirtualAuthenticator(context, page);
    if (credential) {
      await authenticator.client.send('WebAuthn.addCredential', {
        authenticatorId: authenticator.authenticatorId, credential,
      });
    }
    await page.goto(origin);
    const settled = async (step) => {
      await page.waitForFunction((s) => window.__passkey[s] || window.__passkey.error, step, { timeout: 20_000 });
      const value = await page.evaluate((s) => window.__passkey[s], step);
      if (!value) throw new Error(await page.evaluate(() => window.__passkey.error));
      return value;
    };
    return await fn({ page, authenticator, origin, settled });
  } finally {
    await browser?.close();
    server.close();
  }
}

/** The one credential the authenticator holds, checked to be the expected one. */
async function soleCredential(authenticator, credentialId) {
  const held = await authenticator.credentials();
  if (held.length !== 1 || !held[0].isResidentCredential || !b(held[0].credentialId).equals(credentialId)) {
    throw new Error(`authenticator holds ${held.length} credential(s), expected exactly the one resident passkey`);
  }
  return held[0];
}

/**
 * Register a new ES256 passkey. Returns its raw credential id, its public key as DER SPKI, and
 * `credential`: the exported CDP credential, private key included, for `signChallenge`. Treat
 * `credential` as a secret.
 */
export async function createPasskey() {
  return withPage(null, async ({ page, authenticator, settled }) => {
    await page.click('#create');
    const created = await settled('created');
    if (created.algorithm !== -7) throw new Error(`expected an ES256 credential, got COSE alg ${created.algorithm}`);
    const credentialId = b(created.credentialId);
    const publicKeySpki = b(created.publicKeySpki);
    const held = await soleCredential(authenticator, credentialId);
    const heldPublic = createPublicKey(createPrivateKey({ key: b(held.privateKey), format: 'der', type: 'pkcs8' }))
      .export({ format: 'der', type: 'spki' });
    if (!heldPublic.equals(publicKeySpki)) throw new Error('the held private key is not the credential key');
    return { credentialId, publicKeySpki, credential: portable(held) };
  });
}

/**
 * Sign `challenge` (the account's 32-byte `auth_digest`) with the stored passkey. Returns the
 * assertion's `authenticatorData`, `clientDataJSON` and DER `signature`, and the credential with
 * its advanced sign count, for the caller to store in place of the old one.
 */
export async function signChallenge({ credential, credentialId, publicKeySpki }, challenge) {
  const id = Buffer.from(credentialId);
  return withPage(credential, async ({ page, authenticator, origin, settled }) => {
    // The page offers exactly this credential (`allowCredentials`), and signs the challenge given
    // here: the page does not choose what it signs.
    await page.evaluate((cid) => { window.__passkey.created = { credentialId: cid }; }, id.toString('base64url'));
    await page.fill('#challenge', Buffer.from(challenge).toString('hex'));
    await page.click('#sign');
    const signed = await settled('signed');
    if (!b(signed.credentialId).equals(id)) throw new Error('signed with a different credential');
    const assertion = {
      authenticatorData: b(signed.authenticatorData),
      clientDataJSON: b(signed.clientDataJSON),
      signature: b(signed.signature),
    };
    const verdict = verifyAssertion({
      ...assertion, publicKeySpki: Buffer.from(publicKeySpki), challenge: Buffer.from(challenge), origin, rpId: RP_ID,
    });
    const held = await soleCredential(authenticator, id);
    if (held.signCount !== verdict.signCount) {
      throw new Error(`assertion sign count ${verdict.signCount}, authenticator holds ${held.signCount}`);
    }
    return { ...assertion, signCount: verdict.signCount, credential: portable(held) };
  });
}
