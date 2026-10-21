import assert from 'node:assert/strict';
import { request } from 'node:http';
import test from 'node:test';
import { WalletSession } from '../server/session.mjs';
import { createWalletServer } from '../server/http.mjs';

const token = 'a'.repeat(64);
async function fixture(t, actions = { status: async () => ({ ready: true }) }) {
  const session = new WalletSession({ origin: 'http://localhost:3000', host: 'localhost:3000', secret: token });
  const server = createWalletServer({ session, actions });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  return (options = {}) => new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port: server.address().port,
      method: options.method ?? 'POST', path: options.path ?? '/api/policy-builder/status', headers: {
        host: 'localhost:3000', origin: 'http://localhost:3000', authorization: `Bearer ${token}`, 'content-type': 'application/json',
        ...options.headers,
      } }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject); req.end(options.body ?? '{}');
  });
}

test('same-origin authenticated JSON actions return uncached data without credential echo', async (t) => {
  const send = await fixture(t);
  const response = await send();
  assert.equal(response.status, 200);
  assert.deepEqual(JSON.parse(response.body), { ready: true });
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(response.headers['access-control-allow-origin'], undefined);
  assert.ok(!response.body.includes(token));
});

test('foreign/missing Origin, rebinding Host, and incorrect credentials never execute an action', async (t) => {
  let calls = 0;
  const send = await fixture(t, { status: async () => { calls++; return {}; } });
  for (const headers of [{ origin: '' }, { origin: 'http://evil.invalid' }, { host: 'evil.invalid' },
    { authorization: '' }, { authorization: `Bearer ${'b'.repeat(64)}` }]) {
    assert.equal((await send({ headers })).status, 403);
  }
  assert.equal(calls, 0);
});

test('closed paths, methods, content type and bounded JSON refuse before execution', async (t) => {
  let calls = 0;
  const send = await fixture(t, { status: async () => { calls++; return {}; } });
  for (const value of [{ method: 'GET' }, { method: 'OPTIONS' }, { path: '/api/policy-builder/status?token=x' },
    { path: '/api/policy-builder/unknown' }, { headers: { 'content-type': 'text/plain' } },
    { body: '[]' }, { body: '{"__proto__":{}}' }, { body: '{' }, { body: '{"x":' + '['.repeat(40) + '0' + ']'.repeat(40) + '}' },
    { body: JSON.stringify({ value: 'x'.repeat(65536) }) }]) assert.ok((await send(value)).status >= 400);
  assert.equal(calls, 0);
});

test('backend errors and oversized output cannot reveal confidential diagnostics', async (t) => {
  const send = await fixture(t, { status: async () => { throw new Error('secret diagnostic canary'); } });
  const response = await send();
  assert.equal(response.status, 422);
  assert.ok(!response.body.includes('canary'));
});

test('only one long operation occupies the local wallet backend at a time', async (t) => {
  let release; let started;
  const begun = new Promise((resolve) => { started = resolve; });
  const send = await fixture(t, { status: async () => { started(); await new Promise((resolve) => { release = resolve; }); return {}; } });
  const first = send(); await begun;
  assert.equal((await send()).status, 409);
  release(); assert.equal((await first).status, 200);
});
