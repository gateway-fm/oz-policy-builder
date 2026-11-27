import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from '../testnet-harness/browser/node_modules/playwright/index.mjs';
import { ACCOUNT_WASM, WEBAUTHN_WASM } from '../wallet/shared/approval.mjs';
import { WALLET_NETWORKS } from '../wallet/shared/networks.mjs';

const [checkout, builtFor] = process.argv.slice(2);
assert.ok(checkout && ['mainnet', 'testnet'].includes(builtFor));
const token = 'a'.repeat(64);
const backendCalls = [];
const backend = createServer((request, response) => {
  backendCalls.push({ method: request.method, url: request.url, authorization: request.headers.authorization });
  response.writeHead(200, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify({
    network: 'mainnet', networkId: WALLET_NETWORKS.mainnet.networkId,
    accountWasm: ACCOUNT_WASM, verifierWasm: WEBAUTHN_WASM, capabilities: { agentHandoff: false },
  }));
});
await new Promise((resolve, reject) => {
  backend.once('error', reject);
  backend.listen(4318, '127.0.0.1', resolve);
});
let browser, server;
try {
  process.chdir(checkout);
  // The compiled marker must control the proxy regardless of what the preview shell says.
  process.env.VITE_OZPB_NETWORK = builtFor === 'mainnet' ? 'testnet' : 'mainnet';
  const { preview } = await import(pathToFileURL(join(checkout, 'node_modules/vite/dist/node/index.js')));
  server = await preview({ root: checkout });
  browser = await chromium.launch({ args: ['--host-resolver-rules=MAP localhost 127.0.0.1'] });
  const page = await browser.newPage();
  await page.route('**/*', (route) => new URL(route.request().url()).hostname === 'localhost'
    ? route.continue() : route.abort());
  const origin = 'http://localhost:3000';
  await page.goto(`${origin}/policy-builder#session=${token}&network=mainnet`);
  if (builtFor === 'mainnet') {
    await page.getByText('Connected to the local mainnet wallet backend.', { exact: true }).waitFor();
    assert.deepEqual(backendCalls, [{ method: 'POST', url: '/api/policy-builder/status', authorization: `Bearer ${token}` }]);
    assert.equal(new URL(page.url()).hash, '');
    await page.goto(origin);
    await page.getByText('This upstream testnet prototype feature is disabled in a mainnet build of the wallet.').waitFor();
  } else {
    await page.getByText(/A mainnet session runs only from a production build made for mainnet/).waitFor();
    await page.request.post(`${origin}/api/policy-builder/status`, { data: {}, timeout: 5000 });
    assert.deepEqual(backendCalls, []);
  }
  console.log(`Applied Pollywallet ${builtFor} production preview passed the mainnet boundary smoke test.`);
} finally {
  await browser?.close();
  await server?.close();
  await new Promise((resolve) => backend.close(resolve));
}
