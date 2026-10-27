import assert from 'node:assert/strict';
import test from 'node:test';
import { WalletSession } from '../server/session.mjs';

const secret = 'a'.repeat(64);
const headers = { host: 'localhost:3000', origin: 'http://localhost:3000', authorization: `Bearer ${secret}` };
const session = (options = {}) => new WalletSession({ origin: headers.origin, host: headers.host, secret, ...options });

test('wallet API requires exact origin, host and a non-URL session credential', () => {
  const s = session();
  assert.equal(s.authenticate(headers), true);
  for (const change of [{ origin: undefined }, { origin: 'null' }, { origin: 'https://evil.example' },
    { host: 'evil.example' }, { host: 'localhost:3000.evil.example' }, { authorization: undefined },
    { authorization: `Bearer ${'b'.repeat(64)}` }, { authorization: [`Bearer ${secret}`] }]) {
    assert.throws(() => s.authenticate({ ...headers, ...change }), /unauthorized/);
  }
});

test('session configuration refuses public, wildcard, path-bearing or inconsistent origins', () => {
  for (const origin of ['http://0.0.0.0:3000', 'http://example.com', 'http://localhost:3000/path', 'http://user@localhost:3000']) {
    assert.throws(() => session({ origin }), /configuration/);
  }
  assert.throws(() => session({ secret: 'short' }), /configuration/);
});

test('pending actions are unguessable, immutable, bounded and session-bound', () => {
  const s = session();
  const value = { commitment: 'approved', nested: { fee: 100 } };
  const first = s.issue('install', value);
  const second = s.issue('revoke', value);
  assert.match(first.id, /^[0-9a-f]{64}$/);
  assert.notEqual(first.id, second.id);
  assert.equal(Object.hasOwn(first, 'value'), false);
  value.nested.fee = 900;
  return s.consume(first.id, 'install', async (held) => assert.equal(held.nested.fee, 100));
});

test('action is consumed before side effects and cannot be reused after failure', async () => {
  const s = session();
  const { id } = s.issue('install', { commitment: 'approved' });
  let executions = 0;
  await assert.rejects(s.consume(id, 'install', async () => {
    executions++;
    await assert.rejects(s.consume(id, 'install', async () => { executions++; }), /unavailable/);
    throw new Error('execution failed');
  }), /execution failed/);
  await assert.rejects(s.consume(id, 'install', async () => { executions++; }), /unavailable/);
  assert.equal(executions, 1);
});

test('expired, foreign-session and wrong-kind actions cannot run', async () => {
  let now = 1000;
  const s = session({ now: () => now });
  const action = s.issue('install', {});
  await assert.rejects(session().consume(action.id, 'install', async () => assert.fail()), /unavailable/);
  await assert.rejects(s.consume(action.id, 'revoke', async () => assert.fail()), /unavailable/);
  now += 121_000;
  await assert.rejects(s.consume(action.id, 'install', async () => assert.fail()), /unavailable/);
});

test('one wallet session cannot execute concurrent state transitions', async () => {
  const s = session();
  const a = s.issue('install', {});
  const b = s.issue('revoke', {});
  let release;
  const running = s.consume(a.id, 'install', () => new Promise((resolve) => { release = resolve; }));
  await assert.rejects(s.consume(b.id, 'revoke', async () => assert.fail()), /busy/);
  release();
  await running;
  await s.consume(b.id, 'revoke', async () => {});
});
