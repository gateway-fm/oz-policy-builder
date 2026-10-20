import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { loadWalletConfig } from '../server/config.mjs';
import { createWalletRuntime } from '../server/main.mjs';

function fixture(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'wallet-config-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const executable = join(root, 'ozpb');
  const workRoot = join(root, 'work');
  const registrySnapshotPath = join(root, 'registry.json');
  const registryRootsPath = join(root, 'roots.json');
  mkdirSync(workRoot, { mode: 0o700 });
  writeFileSync(executable, '#!/bin/sh\nexit 99\n', { mode: 0o700 });
  writeFileSync(registrySnapshotPath, '{"valid_until":9223372036854775807}', { mode: 0o600 });
  writeFileSync(registryRootsPath, '{}', { mode: 0o600 });
  const value = { executable, workRoot, rpcUrl: 'https://rpc.example/testnet',
    registrySnapshotPath, registryRootsPath, registryMinimumVersion: 3 };
  const path = join(root, 'operator.json');
  const save = (data = value) => writeFileSync(path, JSON.stringify(data), { mode: 0o600 });
  save();
  return { root, path, value, save };
}

test('operator configuration retains exact registry bytes and has a closed build environment', (t) => {
  const { path, value, save } = fixture(t);
  save({ ...value, stellarBinary: value.executable, buildJobs: 2, buildTimeoutSecs: 300,
    buildCacheDir: value.workRoot });
  const config = loadWalletConfig(path);
  assert.equal(config.registrySnapshot, '{"valid_until":9223372036854775807}');
  assert.equal(config.registryRoots, '{}');
  assert.equal(config.registryMinimumVersion, 3);
  assert.deepEqual(config.buildEnvironment, { CARGO_NET_OFFLINE: 'true',
    OZPB_STELLAR_BINARY: value.executable, OZPB_BUILD_CACHE_DIR: value.workRoot,
    OZPB_BUILD_JOBS: '2', OZPB_BUILD_TIMEOUT_SECS: '300' });
  assert.equal(Object.isFrozen(config.buildEnvironment), true);
});

for (const invalid of ['unknown field', 'environment', 'http rpc', 'rpc secret', 'relative executable',
  'symlink executable', 'non-executable', 'shared workspace', 'oversized config', 'oversized registry', 'jobs', 'timeout']) {
  test(`operator configuration refuses ${invalid}`, (t) => {
    const { root, path, value, save } = fixture(t);
    if (invalid === 'unknown field') value.listen = '0.0.0.0';
    if (invalid === 'environment') value.buildEnvironment = { NODE_OPTIONS: '--require /tmp/inject' };
    if (invalid === 'http rpc') value.rpcUrl = 'http://rpc.example/';
    if (invalid === 'rpc secret') value.rpcUrl = 'https://secret@rpc.example/';
    if (invalid === 'relative executable') value.executable = './ozpb';
    if (invalid === 'symlink executable') {
      symlinkSync(value.executable, join(root, 'link'));
      value.executable = join(root, 'link');
    }
    if (invalid === 'non-executable') chmodSync(value.executable, 0o600);
    if (invalid === 'shared workspace') chmodSync(value.workRoot, 0o755);
    if (invalid === 'jobs') value.buildJobs = 0;
    if (invalid === 'timeout') value.buildTimeoutSecs = 901;
    if (invalid === 'oversized registry') writeFileSync(value.registrySnapshotPath, ' '.repeat(2 * 1024 * 1024 + 1));
    save();
    if (invalid === 'oversized config') writeFileSync(path, ' '.repeat(16 * 1024 + 1));
    assert.throws(() => loadWalletConfig(path), /^Error: invalid wallet operator configuration$/);
  });
}

test('launcher creates private retained state without startup network writes or invoking tools', async (t) => {
  const { path } = fixture(t);
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls++; throw new Error('unexpected network call'); };
  t.after(() => { globalThis.fetch = originalFetch; });
  let captured;
  const runtime = await createWalletRuntime(path, {
    actionsFactory: (parts) => { captured = parts; return { status: async () => ({ network: 'testnet' }) }; },
  });
  assert.equal(calls, 0);
  assert.equal(runtime.server.listening, false);
  assert.match(runtime.launchUrl, /^http:\/\/localhost:3000\/policy-builder#session=[a-f0-9]{64}$/);
  assert.equal(statSync(captured.toolchain.sessionRoot).mode & 0o777, 0o700);
  assert.equal(statSync(join(captured.toolchain.sessionRoot, 'journal')).mode & 0o777, 0o700);
  assert.equal(readFileSync(join(captured.toolchain.sessionRoot, 'registry.signed.json'), 'utf8'),
    '{"valid_until":9223372036854775807}');
  assert.ok(captured.network.payerAddress.startsWith('G'));
  assert.equal(captured.session.authenticate({ host: 'localhost:3000', origin: 'http://localhost:3000',
    authorization: `Bearer ${new URL(runtime.launchUrl).hash.slice('#session='.length)}` }), true);
  assert.throws(() => captured.session.authenticate({ host: '127.0.0.1:3000', origin: 'http://127.0.0.1:3000',
    authorization: `Bearer ${new URL(runtime.launchUrl).hash.slice('#session='.length)}` }), /unauthorized/);
});
