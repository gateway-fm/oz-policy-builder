// Drive pollywallet's real "Create Smart Wallet" button headless, with the virtual authenticator
// standing in for the user's passkey, and report what happened on both sides.
//
//   OZPB_BROWSER_CHANNEL=chrome node drive-pollywallet.mjs [url]   # default http://localhost:3000/
//
// pollywallet (github.com/kalepail/pollywallet) is a passkey smart-wallet demo on Stellar testnet.
// Its own code makes the WebAuthn call, so a credential appearing on the virtual authenticator
// shows that its real passkey registration ran under automation. Whether a wallet then exists is a
// separate question, answered by its backend, and reported separately: deploying the account
// goes through pollywallet's server and relayer, which this script neither controls nor needs.
//
// Every run that gets that far deploys a testnet contract whose only signer is a passkey that
// dies with this browser. Run it by hand, not in a loop or in CI against someone else's server.
//
// Exit status 0 means the passkey registered.
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { addVirtualAuthenticator, launch } from './authenticator.mjs';

const url = process.argv[2] ?? process.env.POLLYWALLET_URL ?? 'http://localhost:3000/';
const OUT = new URL('./out/', import.meta.url);
mkdirSync(OUT, { recursive: true });
const CONTRACT = /\bC[A-Z2-7]{55}\b/g;

const browser = await launch();
let registered = false;
let failure = null;
try {
  const context = await browser.newContext({ viewport: { width: 1000, height: 720 } });
  const page = await context.newPage();
  const consoleLines = [];
  page.on('console', (m) => consoleLines.push(`${m.type()}: ${m.text().slice(0, 200)}`));
  const authenticator = await addVirtualAuthenticator(context, page);

  try {
    await page.goto(url, { waitUntil: 'networkidle', timeout: 30_000 });
    // Anything address-shaped already on the page is not the new wallet.
    const before = new Set((await page.innerText('body')).match(CONTRACT) ?? []);
    console.log(`clicking "Create Smart Wallet" on ${page.url()}`);
    await page.getByRole('button', { name: 'Create Smart Wallet' }).click();

    // Settled means a contract address that was not there before, or an error message.
    let outcome = 'no change within 60 s';
    try {
      await page.waitForFunction((known) => {
        const text = document.body.innerText;
        return (text.match(/\bC[A-Z2-7]{55}\b/g) ?? []).some((c) => !known.includes(c)) || /error|failed/i.test(text);
      }, [...before], { timeout: 60_000 });
      outcome = 'settled';
    } catch { /* reported below as no change */ }
    await page.waitForTimeout(1500);

    const body = (await page.innerText('body')).replace(/\s*\n\s*/g, ' | ');
    const fresh = (body.match(CONTRACT) ?? []).filter((c) => !before.has(c));
    console.log(`wallet    ${fresh.length === 1 ? `new contract address on screen: ${fresh[0]}` : `no single new contract address on screen (${outcome}, ${fresh.length} new)`}`);
    console.log(`page      ${body.slice(0, 400)}`);
  } catch (e) {
    failure = e;
  }

  // Reported whatever happened above: the passkey is the part this script can vouch for.
  const held = await authenticator.credentials();
  registered = held.length === 1 && held[0].isResidentCredential;
  console.log(`passkey   ${held.length} credential(s) on the virtual authenticator, resident: ${held.map((c) => c.isResidentCredential)}`);
  const relevant = consoleLines.filter((l) => /passkey|wallet|deploy|error|credential|contract|relayer/i.test(l));
  if (relevant.length) console.log(`console   ${relevant.slice(-8).join('\n          ')}`);
  await page.screenshot({ path: fileURLToPath(new URL('pollywallet-after-create.png', OUT)), fullPage: true });
  console.log('SCREENSHOT: out/pollywallet-after-create.png');
} catch (e) {
  failure ??= e;
} finally {
  await browser.close();
}
if (failure) console.log(`FAILED:   ${failure.message.split('\n')[0]}`);
console.log(`PASSKEY_REGISTERED_IN_POLLYWALLET_UI: ${registered}`);
process.exit(registered ? 0 : 1);
