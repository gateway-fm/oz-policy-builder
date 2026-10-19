// Read a wallet UI without touching it: title, headings, what can be clicked, and a screenshot.
// Run it before drive-pollywallet.mjs to see whether the UI still has the control that script
// clicks — a deployed demo changes without notice.
//
//   OZPB_BROWSER_CHANNEL=chrome node recon.mjs [url]     # default http://localhost:3000/
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { launch } from './authenticator.mjs';

const url = process.argv[2] ?? process.env.POLLYWALLET_URL ?? 'http://localhost:3000/';
const OUT = new URL('./out/', import.meta.url);
mkdirSync(OUT, { recursive: true });

const browser = await launch();
try {
  const page = await (await browser.newContext()).newPage();
  await page.goto(url, { waitUntil: 'networkidle', timeout: 30_000 });
  console.log('URL:       ', page.url());
  console.log('TITLE:     ', await page.title());
  const text = (sel) => page.$$eval(sel, (els) => els.map((e) => (e.innerText || e.textContent || '').trim()).filter(Boolean).slice(0, 25));
  console.log('HEADINGS:  ', JSON.stringify(await text('h1, h2, h3')));
  console.log('CLICKABLE: ', JSON.stringify(await text('button, a, [role="button"]')));
  await page.screenshot({ path: fileURLToPath(new URL('recon.png', OUT)), fullPage: true });
  console.log('SCREENSHOT: out/recon.png');
} finally {
  await browser.close();
}
