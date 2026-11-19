// The on-demand monitor also runs `ozpb registry monitor` against the operator's published registry
// log and the persisted checkpoint, watching the installed grant's account and owner-verifier Wasm,
// and shows what its exit status means (docs/REGISTRY-GOVERNANCE.md#monitoring). The CLI here is a
// stub executable that prints the report and exits as the real one does.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { WalletToolchain, REGISTRY_MONITOR, MONITOR_UNAVAILABLE } from '../server/toolchain.mjs';
import { WALLET_NETWORKS } from '../shared/networks.mjs';
import { ACCOUNT_WASM, WEBAUTHN_WASM } from '../shared/approval.mjs';

function stub(t, { status, exit, report = {}, stderr = '', executable: missing = false }) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'wallet-registry-monitor-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const body = JSON.stringify({ schema: 'registry-monitor/v1', status, checked_at_unix: '1795000000', checkpoint_version: '6',
    head: { version: '7', log_index: '7', root: 'ef'.repeat(32), revocations: {} }, newer_version_available: status === 'newer_version',
    validity: 'valid', valid_from_unix: '1790000000', expires_at_unix: '1800000000',
    revoked: status === 'revoked' ? [{ wasm_hash: ACCOUNT_WASM, capability: `account/${ACCOUNT_WASM}`, reason: 'advisory', effective_version: '7' }] : [],
    ...report });
  const executable = join(root, 'ozpb');
  writeFileSync(join(root, 'report.json'), body);
  writeFileSync(join(root, 'stderr'), stderr);
  if (!missing) writeFileSync(executable, `#!/bin/sh\necho "$@" > "${join(root, 'args')}"\ncat "${join(root, 'report.json')}"\n`
    + `cat "${join(root, 'stderr')}" >&2\nexit ${exit}\n`, { mode: 0o700 });
  const workRoot = join(root, 'work');
  mkdirSync(workRoot, { mode: 0o700 });
  const published = join(root, 'published');
  mkdirSync(published, { mode: 0o700 });
  const toolchain = new WalletToolchain({ executable, workRoot, rpcUrl: 'https://rpc.example/', registrySnapshot: '{}', registryRoots: '{}',
    registryMinimumVersion: 6, network: WALLET_NETWORKS.mainnet, registryPublishedPath: published });
  return { toolchain, args: () => readFileSync(join(root, 'args'), 'utf8').trim().split(' '), published };
}

test('each exit status is read with its meaning, as the governance guide tabulates it', async (t) => {
  for (const [status, exit] of [['current', 0], ['newer_version', 3], ['not_yet_valid', 7], ['expires_soon', 4], ['expired', 5], ['revoked', 6]]) {
    const { toolchain, args, published } = stub(t, { status, exit });
    const result = await toolchain.registryMonitor({ wasmHashes: [ACCOUNT_WASM, WEBAUTHN_WASM] });
    assert.equal(result.status, status, status);
    assert.equal(result.exit, exit);
    assert.equal(result.meaning, REGISTRY_MONITOR[exit].meaning);
    assert.equal(result.action, REGISTRY_MONITOR[exit].action);
    assert.equal(result.headVersion, '7');
    if (status === 'revoked') assert.deepEqual(result.revoked.map((r) => r.wasm_hash), [ACCOUNT_WASM]);
    const a = args();
    assert.deepEqual(a.slice(0, 2), ['registry', 'monitor']);
    assert.equal(a[a.indexOf('--published') + 1], published);
    assert.equal(a.filter((x) => x === '--wasm-hash').length, 2);
    assert.ok(a.includes(ACCOUNT_WASM) && a.includes(WEBAUTHN_WASM));
  }
});

test('an unverifiable log, or a report that contradicts its exit status, is an incident, never "current"', async (t) => {
  // The CLI's own verdict: it exited 1 naming a registry verification fault.
  for (const code of ['E_REGISTRY_SIGNATURE', 'E_REGISTRY_TRANSPARENCY', 'E_REGISTRY_ROLLBACK', 'E_REGISTRY_PARSE', 'E_REGISTRY_SCHEMA',
    'E_REGISTRY_NETWORK']) {
    const unverifiable = stub(t, { status: 'current', exit: 1, stderr: `Error: ${code}: the published log forks\n` });
    assert.equal((await unverifiable.toolchain.registryMonitor({ wasmHashes: [ACCOUNT_WASM] })).status, 'log_unverifiable', code);
  }
  const contradicting = stub(t, { status: 'current', exit: 6 });
  assert.equal((await contradicting.toolchain.registryMonitor({ wasmHashes: [ACCOUNT_WASM] })).status, 'log_unverifiable');
  const malformed = stub(t, { status: 'current', exit: 0, report: { schema: 'something else' } });
  assert.equal((await malformed.toolchain.registryMonitor({ wasmHashes: [ACCOUNT_WASM] })).status, 'log_unverifiable');
});

test('a monitor that could not run to a verdict is monitor_unavailable, not an incident', async (t) => {
  const expected = { status: MONITOR_UNAVAILABLE.status, meaning: MONITOR_UNAVAILABLE.meaning, action: MONITOR_UNAVAILABLE.action };
  for (const [label, given] of [
    ['a missing executable', { status: 'current', exit: 0, executable: true }],
    ['the toolkit refusing the root policy', { status: 'current', exit: 1, stderr: 'Error: E_REGISTRY_ROOT_POLICY: the development root\n' }],
    ['an error naming no registry fault (an unreadable published path)', { status: 'current', exit: 1, stderr: 'Error: reading /published\n' }],
    ['a usage error', { status: 'current', exit: 2, stderr: 'error: unexpected argument\n' }],
  ]) {
    const { toolchain } = stub(t, given);
    assert.deepEqual({ ...(await toolchain.registryMonitor({ wasmHashes: [ACCOUNT_WASM] })) }, expected, label);
  }
  // A runner that timed out or was stopped reports no exit status at all.
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'wallet-registry-monitor-timeout-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const toolchain = new WalletToolchain({ executable: '/fixed/ozpb', workRoot: root, rpcUrl: 'https://rpc.example/', registrySnapshot: '{}',
    registryRoots: '{}', registryMinimumVersion: 6, network: WALLET_NETWORKS.mainnet, registryPublishedPath: root,
    runner: async () => { throw new Error('ozpb tool failed'); } });
  assert.deepEqual({ ...(await toolchain.registryMonitor({ wasmHashes: [ACCOUNT_WASM] })) }, expected, 'a timeout');
  assert.notEqual(MONITOR_UNAVAILABLE.status, REGISTRY_MONITOR[1].status);
});

test('without a published registry log configured, the registry part says so', async (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'wallet-registry-monitor-none-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const toolchain = new WalletToolchain({ executable: '/fixed/ozpb', workRoot: root, rpcUrl: 'https://rpc.example/', registrySnapshot: '{}',
    registryRoots: '{}', registryMinimumVersion: 6, network: WALLET_NETWORKS.testnet, runner: async () => assert.fail('nothing runs') });
  assert.deepEqual(await toolchain.registryMonitor({ wasmHashes: [ACCOUNT_WASM] }), { status: 'not_configured' });
});

test('the installed-grant monitor reports the registry alongside the grant', async () => {
  const { readFileSync: read } = await import('node:fs');
  const source = read(new URL('../server/monitor.mjs', import.meta.url), 'utf8');
  assert.match(source, /toolchain\.registryMonitor\(\{ wasmHashes: \[ACCOUNT_WASM, WEBAUTHN_WASM\] \}\)/);
  assert.doesNotMatch(source, /catch \{ registry = \{ status: 'log_unverifiable' \}/, 'a monitor that threw is unavailable, not an incident');
});

// Opt-in, against the real CLI (`OZPB_BIN`): the development registry on testnet, its committed
// signed head as the published log, and the checkpoint `ozpb registry verify` prints for it.
test('the real `ozpb registry monitor`: the committed head is read, and the revoked 0.7.2 account is reported revoked',
  { skip: !process.env.OZPB_BIN }, async (t) => {
    const { execFileSync } = await import('node:child_process');
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'wallet-registry-real-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const examples = new URL('../../docs/examples/', import.meta.url);
    const rootsFile = new URL('registry-roots.json', examples).pathname;
    const head = new URL('registry.signed.json', examples).pathname;
    const checkpoint = JSON.parse(execFileSync(process.env.OZPB_BIN, ['registry', 'verify', '--signed', head, '--registry-roots', rootsFile,
      '--network', WALLET_NETWORKS.testnet.passphrase]));
    const roots = JSON.stringify({ ...JSON.parse(readFileSync(rootsFile, 'utf8')), checkpoint });
    const workRoot = join(root, 'work');
    mkdirSync(workRoot, { mode: 0o700 });
    const toolchain = new WalletToolchain({ executable: process.env.OZPB_BIN, workRoot, rpcUrl: 'https://rpc.example/',
      registrySnapshot: readFileSync(head, 'utf8'), registryRoots: roots, registryMinimumVersion: 6, network: WALLET_NETWORKS.testnet,
      registryPublishedPath: head });
    const current = await toolchain.registryMonitor({ wasmHashes: [ACCOUNT_WASM, WEBAUTHN_WASM] });
    assert.ok(['current', 'expires_soon', 'expired'].includes(current.status), JSON.stringify(current));
    assert.equal(current.headVersion, checkpoint.version);
    const revokedAccount = Object.keys(checkpoint.revocations).find((key) => key.startsWith('account/')).slice('account/'.length);
    const revoked = await toolchain.registryMonitor({ wasmHashes: [revokedAccount] });
    assert.equal(revoked.status, 'revoked', JSON.stringify(revoked));
    assert.equal(revoked.exit, 6);
    assert.deepEqual(revoked.revoked.map((r) => r.wasm_hash), [revokedAccount]);
  });
