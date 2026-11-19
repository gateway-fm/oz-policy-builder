// What the applied app inherits from the upstream testnet prototype, and how a mainnet session is
// kept away from each: it runs only from a production build made for mainnet, which serves the
// Policy Builder alone and refuses the upstream server functions that sign, relay or store; the
// Policy Builder itself uses neither the public deployer seed, nor browser storage, nor a testnet
// constant. The patch is checked as text here and applied to the pinned upstream revision by
// scripts/apply-pollywallet.py; the behaviour of the guard it calls is checked directly.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import test from 'node:test';
import { UPSTREAM_DISABLED, assertUpstreamEnabled, buildNetwork, sessionAllowed, sessionRefusal, upstreamAllowed }
  from '../overlay/files/src/policy-builder/client/build-guard.mjs';
import { BACKEND_PORTS } from '../server/main.mjs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const PATCH = read('../overlay/upstream.patch');
const ROUTE = read('../overlay/files/src/routes/policy-builder.tsx');
/** The patch's added lines for one upstream file. */
function added(file) {
  const start = PATCH.indexOf(`+++ b/${file}\n`);
  assert.ok(start >= 0, `the patch edits ${file}`);
  const end = PATCH.indexOf('\ndiff --git', start);
  return PATCH.slice(start, end < 0 ? undefined : end).split('\n').filter((line) => line.startsWith('+') && !line.startsWith('+++'))
    .map((line) => line.slice(1)).join('\n');
}

const DEV = { DEV: true, PROD: false };
const PROD = { DEV: false, PROD: true };
const MAINNET_BUILD = { ...PROD, VITE_OZPB_NETWORK: 'mainnet' };

test('a mainnet session runs only from a production build made for mainnet, never the development server', () => {
  assert.equal(sessionAllowed('mainnet', MAINNET_BUILD), true);
  for (const env of [DEV, PROD, { ...DEV, VITE_OZPB_NETWORK: 'mainnet' }, { ...MAINNET_BUILD, DEV: true }, { VITE_OZPB_NETWORK: 'mainnet' }, undefined]) {
    assert.equal(sessionAllowed('mainnet', env), false, JSON.stringify(env));
    assert.match(sessionRefusal('mainnet', env), /production build made for mainnet/);
  }
  // Testnet keeps the development server; a mainnet build runs no testnet session.
  assert.equal(sessionAllowed('testnet', DEV), true);
  assert.equal(sessionAllowed('testnet', PROD), true);
  assert.equal(sessionAllowed('testnet', MAINNET_BUILD), false);
  assert.equal(sessionAllowed('pubnet', MAINNET_BUILD), false);
  assert.equal(buildNetwork({ VITE_OZPB_NETWORK: 'Mainnet' }), 'testnet', 'only the exact name makes a mainnet build');
  // The page asks before it connects or takes the network.
  const refusal = ROUTE.indexOf('const refusal = sessionRefusal(session.network, import.meta.env);');
  assert.ok(refusal > 0 && refusal < ROUTE.indexOf('NETWORK = walletNetwork(session.network);'));
});

test('the mainnet backend is reachable only through the production preview server', () => {
  assert.deepEqual({ ...BACKEND_PORTS }, { testnet: 4317, mainnet: 4318 });
  const vite = added('vite.config.ts');
  // The development server's proxy reaches the testnet backend alone.
  const server = vite.slice(vite.indexOf('  server: {'), vite.indexOf('  preview: {'));
  assert.match(server, /'\/api\/policy-builder': \{ target: 'http:\/\/127\.0\.0\.1:4317'/);
  assert.doesNotMatch(server, /4318/, 'the development server never proxies to the mainnet backend');
  // `vite preview` reaches the mainnet backend through a preview-only hook, registered before the
  // Cloudflare plugin, which otherwise answers every preview request itself (Vite's preview.proxy never runs).
  const plugin = vite.slice(vite.indexOf('const mainnetBackendProxy'), vite.indexOf('export default defineConfig'));
  assert.match(plugin, /configurePreviewServer\(server\) \{\n {4}server\.middlewares\.use\('\/api\/policy-builder'/);
  assert.match(plugin, /host: '127\.0\.0\.1', port: 4318, method: req\.method, path: `\/api\/policy-builder\$\{req\.url\}`/);
  assert.doesNotMatch(plugin, /configureServer/, 'the development server never gets it');
  assert.match(vite, /preview: \{ host: '127\.0\.0\.1', port: 3000, strictPort: true \}/);
  assert.ok(PATCH.includes('+    mainnetBackendProxy,\n     cloudflare({'), 'before the Cloudflare plugin');
});

test('a mainnet build serves the Policy Builder alone: upstream routes and navigation are refused', () => {
  assert.equal(upstreamAllowed(MAINNET_BUILD), false);
  assert.equal(upstreamAllowed(DEV), true);
  assert.equal(upstreamAllowed(PROD), true);
  const root = added('src/routes/__root.tsx');
  assert.match(root, /const upstream = upstreamAllowed\(import\.meta\.env\)/);
  assert.match(root, /\{upstream && <Header \/>\}/);
  assert.match(root, /\{upstream \|\| pathname === '\/policy-builder' \? children : <p role="alert">\{UPSTREAM_DISABLED\}<\/p>\}/);
});

test('every upstream server function that signs, relays, deploys or stores refuses in a mainnet build first', () => {
  assert.throws(() => assertUpstreamEnabled(MAINNET_BUILD), new RegExp(UPSTREAM_DISABLED));
  assert.doesNotThrow(() => assertUpstreamEnabled(DEV));
  // signAndSubmitDeploy signs with the public deployer seed and relays through Channels; submitPolicyTransaction
  // relays with the operator's Channels key; deployPolicyWasm drives the sandbox; savePolicy writes shared KV.
  for (const [file, count] of [['src/lib/relayer.ts', 1], ['src/lib/policy-deploy.ts', 2], ['src/lib/policy-store.ts', 1]]) {
    const lines = added(file);
    assert.equal(lines.split('assertUpstreamEnabled(import.meta.env);').length - 1, count, file);
    assert.match(lines, /import \{ assertUpstreamEnabled \} from "\.\.\/policy-builder\/client\/build-guard\.mjs";/);
  }
  // Each call is the handler's first statement.
  for (const handler of ['  .handler(async ({ data }) => {\n+    assertUpstreamEnabled(import.meta.env);\n     try {',
    '  .handler(async ({ data }): Promise<DeployResult> => {\n+    assertUpstreamEnabled(import.meta.env);',
    '  }> => {\n+    assertUpstreamEnabled(import.meta.env);\n     try {',
    '  .handler(async ({ data }) => {\n+    assertUpstreamEnabled(import.meta.env);\n     const kv = env.POLICIES_KV;']) {
    assert.ok(PATCH.includes(handler), handler);
  }
});

test('the Policy Builder takes nothing unsafe from upstream: no deployer seed, no relayer, no browser storage, no testnet default', () => {
  const imports = [...ROUTE.matchAll(/^import .* from "\.\.\/lib\/([^"]+)";$/gm)];
  assert.deepEqual(imports.map((m) => m[0]), ['import { createPasskey, signWalletAuthEntries } from "../lib/passkey";']);
  for (const name of ['DEPLOYER', 'relayer', 'policy-deploy', 'policy-store', 'Networks.TESTNET', 'TESTNET_']) {
    assert.equal(ROUTE.includes(name), false, name);
  }
  // The passkey signs for the launched network with the account's own verifier, never upstream's testnet defaults.
  assert.match(ROUTE, /verifier: approval\.wallet\.verifier, networkPassphrase: NETWORK\.passphrase \}\)/);
  const client = new URL('../overlay/files/src/policy-builder/client/', import.meta.url);
  const sources = [ROUTE, ...readdirSync(client).filter((name) => name.endsWith('.mjs')).map((name) => readFileSync(new URL(name, client), 'utf8'))];
  for (const source of sources) {
    assert.doesNotMatch(source.replace(/^\s*(\/\/|\*).*$/gm, ''), /localStorage|sessionStorage|indexedDB/, 'no browser storage');
  }
});
