// A CTAP2 platform authenticator that exists only inside the browser, through the Chrome DevTools
// Protocol's WebAuthn domain: no hardware, no display, and every request is approved as if a
// verified user had touched it. Shared by the scripts in this directory.
import { chromium } from 'playwright';

/**
 * Launch headless Chromium. `OZPB_BROWSER_CHANNEL=chrome` uses an installed Google Chrome instead
 * of Playwright's own build, which then needs no `npx playwright install`.
 */
export function launch() {
  const channel = process.env.OZPB_BROWSER_CHANNEL;
  return chromium.launch({ headless: true, ...(channel ? { channel } : {}) });
}

export async function addVirtualAuthenticator(context, page) {
  const client = await context.newCDPSession(page);
  await client.send('WebAuthn.enable');
  const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  const credentials = async () => (await client.send('WebAuthn.getCredentials', { authenticatorId })).credentials;
  return { client, authenticatorId, credentials };
}
