// Headless passkey: create a secp256r1 credential and sign a 32-byte challenge with it, in a
// browser with no display and no authenticator hardware — then verify the signature outside the
// browser. This is the technique a CI job or a demo recording would use to drive a passkey
// wallet's UI.
//
//   OZPB_BROWSER_CHANNEL=chrome node webauthn.mjs     # or `npx playwright install chromium` first
//
// Exits 0 only if the assertion verifies (assertion.mjs) under the public key the authenticator
// returned at creation, over the challenge this script chose, and the virtual authenticator holds
// exactly one resident credential: the same id, a private key matching that public key, and the
// sign counter the assertion reports. Writes out/passkey.png.
import { createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { verifyAssertion } from './assertion.mjs';
import { addVirtualAuthenticator, launch } from './authenticator.mjs';
import { serve } from './server.mjs';

const OUT = new URL('./out/', import.meta.url);
mkdirSync(OUT, { recursive: true });

// Port 0: any free port. The origin is built from whatever the OS assigned.
const server = await serve(0);
const origin = `http://localhost:${server.address().port}`;
const browser = await launch();
let failure = null;
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  const authenticator = await addVirtualAuthenticator(context, page);
  await page.goto(origin);

  const settled = (step) => page.waitForFunction(
    (s) => window.__passkey[s] || window.__passkey.error, step, { timeout: 20_000 },
  );

  await page.click('#create');
  await settled('created');
  const created = await page.evaluate(() => window.__passkey.created);
  if (!created) throw new Error(await page.evaluate(() => window.__passkey.error));
  console.log(`created   credential ${created.credentialId} (COSE alg ${created.algorithm})`);

  // The challenge comes from here, not from the page, so the page cannot choose what it signs.
  const challenge = randomBytes(32);
  await page.fill('#challenge', challenge.toString('hex'));
  await page.click('#sign');
  await settled('signed');
  const signed = await page.evaluate(() => window.__passkey.signed);
  if (!signed) throw new Error(await page.evaluate(() => window.__passkey.error));
  await page.screenshot({ path: fileURLToPath(new URL('passkey.png', OUT)), fullPage: true });

  const b = (s) => Buffer.from(s, 'base64url');
  const verdict = verifyAssertion({
    publicKeySpki: b(created.publicKeySpki),
    authenticatorData: b(signed.authenticatorData),
    clientDataJSON: b(signed.clientDataJSON),
    signature: b(signed.signature),
    challenge,
    origin,
    rpId: 'localhost',
  });
  console.log(`signed    challenge ${challenge.toString('hex')}`);
  console.log(`verified  ES256 signature under the credential key; user present ${verdict.userPresent}, verified ${verdict.userVerified}`);

  // CDP returns ids and keys as standard base64; node's base64url decoder accepts both alphabets.
  const held = await authenticator.credentials();
  if (held.length !== 1 || !held[0].isResidentCredential || b(held[0].credentialId).toString('base64url') !== created.credentialId) {
    throw new Error(`authenticator holds ${held.length} credential(s), expected the one resident key created`);
  }
  if (created.credentialId !== signed.credentialId) throw new Error('signed with a different credential');
  const heldPublic = createPublicKey(createPrivateKey({ key: b(held[0].privateKey), format: 'der', type: 'pkcs8' }))
    .export({ format: 'der', type: 'spki' });
  if (!heldPublic.equals(b(created.publicKeySpki))) throw new Error('the held private key is not the credential key');
  if (held[0].signCount !== verdict.signCount) {
    throw new Error(`assertion sign count ${verdict.signCount}, authenticator holds ${held[0].signCount}`);
  }
  console.log(`held      one resident credential: same id, private key matching the public key, sign count ${verdict.signCount}`);
} catch (e) {
  failure = e;
} finally {
  await browser.close();
  server.close();
}
console.log(failure ? `RESULT: FAILED: ${failure.message}` : 'RESULT: passkey created, signed and verified headless');
process.exit(failure ? 1 : 0);
