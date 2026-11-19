// Registry trust on mainnet: only the operator's production trust files (a signed snapshot, a root
// policy that does not name the development root, and its persisted checkpoint) configure a mainnet
// session, and the CLI's own refusal of a root policy (E_REGISTRY_ROOT_POLICY) reaches the page as one
// closed reason. Testnet keeps the development registry.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { Keypair } from '@stellar/stellar-sdk';
import { DEVELOPMENT_REGISTRY_ROOT, loadWalletConfig } from '../server/config.mjs';
import { REGISTRY_ROOT_POLICY, WalletToolchain } from '../server/toolchain.mjs';
import { REFUSAL_REASONS } from '../server/http.mjs';
import { REFUSAL_REASONS as CLIENT_REASONS } from '../overlay/files/src/policy-builder/client/client.mjs';
import { StrKey } from '@stellar/stellar-sdk';
import { WALLET_NETWORKS } from '../shared/networks.mjs';

/** A persisted checkpoint as the CLI writes it: u64 fields as decimal strings, the root as hex. */
const CHECKPOINT = (version) => ({ version: String(version), log_index: String(version), root: 'ef'.repeat(32), revocations: {} });
const EXAMPLE_ROOTS = readFileSync(new URL('../../docs/examples/registry-roots.json', import.meta.url), 'utf8');

function operator(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'wallet-registry-trust-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const workRoot = join(root, 'work');
  mkdirSync(workRoot, { mode: 0o700 });
  const executable = join(root, 'ozpb');
  writeFileSync(executable, '#!/bin/sh\nexit 99\n', { mode: 0o700 });
  writeFileSync(join(root, 'registry.json'), '{}', { mode: 0o600 });
  const keyPath = join(root, 'payer.key');
  writeFileSync(keyPath, `${Keypair.random().secret()}\n`, { mode: 0o600 });
  const path = join(root, 'operator.json');
  return (roots, extra = {}, snapshot = '{}') => {
    writeFileSync(join(root, 'registry.json'), snapshot, { mode: 0o600 });
    writeFileSync(join(root, `roots.json`), typeof roots === 'string' ? roots : JSON.stringify(roots), { mode: 0o600 });
    writeFileSync(path, JSON.stringify({ executable, workRoot, rpcUrl: 'https://rpc.example/', registrySnapshotPath: join(root, 'registry.json'),
      registryRootsPath: join(root, 'roots.json'), registryMinimumVersion: 6, network: 'mainnet', feePayerKeyPath: keyPath, ...extra }),
    { mode: 0o600 });
    return () => loadWalletConfig(path);
  };
}

test('the development registry root is the one the committed example roots name', () => {
  assert.deepEqual(Object.values(JSON.parse(EXAMPLE_ROOTS).keys), [DEVELOPMENT_REGISTRY_ROOT]);
});

test('a mainnet session refuses the development registry root, at startup and with the reason', (t) => {
  const save = operator(t);
  const withCheckpoint = { ...JSON.parse(EXAMPLE_ROOTS), checkpoint: CHECKPOINT(6) };
  assert.throws(save(withCheckpoint), (error) => /development registry root is refused/.test(error.startup));
  // Named among production keys, or in another case, it is refused all the same.
  const mixed = { threshold: 2, keys: { operator: 'ab'.repeat(32), dev: DEVELOPMENT_REGISTRY_ROOT.toUpperCase() }, checkpoint: CHECKPOINT(6) };
  assert.throws(save(mixed), (error) => /development registry root is refused/.test(error.startup));
  // Testnet keeps the development registry and needs no checkpoint.
  assert.doesNotThrow(save(EXAMPLE_ROOTS, { network: 'testnet', feePayerKeyPath: undefined }));
});

test('a mainnet session needs the persisted checkpoint, at or above the configured floor', (t) => {
  const save = operator(t);
  const production = { threshold: 1, keys: { operator: 'cd'.repeat(32) } };
  assert.throws(save(production), (error) => /persisted checkpoint/.test(error.startup));
  assert.throws(save({ ...production, checkpoint: CHECKPOINT(5) }), (error) => /older than the configured minimum/.test(error.startup));
  assert.throws(save({ ...production, checkpoint: [] }), (error) => /persisted checkpoint/.test(error.startup));
  assert.throws(save({ keys: production.keys, checkpoint: CHECKPOINT(6) }), (error) => /threshold/.test(error.startup));
  assert.throws(save({ threshold: 1, keys: {}, checkpoint: CHECKPOINT(6) }), (error) => /at least one key/.test(error.startup));
  const config = save({ ...production, checkpoint: CHECKPOINT(7) })();
  assert.equal(config.network.name, 'mainnet');
  assert.equal(config.registryRoots, JSON.stringify({ ...production, checkpoint: CHECKPOINT(7) }), 'the exact bytes reach the CLI');
  // The u64 fields are decimal strings (or, in older files, JSON integers); log_index and root are required.
  assert.doesNotThrow(save({ ...production, checkpoint: { ...CHECKPOINT(7), version: 7, log_index: 7 } }));
  assert.doesNotThrow(save({ ...production, checkpoint: { ...CHECKPOINT(7), version: '18446744073709551615' } }));
  for (const [name, checkpoint] of [
    ['a version below the floor, as a string', { ...CHECKPOINT(7), version: '5' }],
    ['a non-canonical version', { ...CHECKPOINT(7), version: '07' }],
    ['a version past u64', { ...CHECKPOINT(7), version: '18446744073709551616' }],
    ['a negative version', { ...CHECKPOINT(7), version: '-7' }],
    ['no log index', { version: '7', root: 'ef'.repeat(32), revocations: {} }],
    ['a fractional log index', { ...CHECKPOINT(7), log_index: 1.5 }],
    ['no root', { version: '7', log_index: '7', revocations: {} }],
    ['a short root', { ...CHECKPOINT(7), root: 'ef' }],
  ]) assert.throws(save({ ...production, checkpoint }), (error) => typeof error.startup === 'string', name);
});

// The mainnet registry is its own chain from version 1 (registry/mainnet/v0001.draft.json). The
// fixture is that draft, its pending review reference replaced, signed by two throwaway custodian
// keys (`ozpb registry keygen`, `sign`, `combine`; the keys were discarded), with the checkpoint
// `ozpb registry verify` printed for it.
const MAINNET_V1 = new URL('fixtures/mainnet-registry-v1/', import.meta.url);
const MAINNET_V1_SIGNED = readFileSync(new URL('registry.signed.json', MAINNET_V1), 'utf8');
const MAINNET_V1_ROOTS = readFileSync(new URL('registry-roots.json', MAINNET_V1), 'utf8');

test('a mainnet session starts on the mainnet registry\'s signed genesis, version 1, and still refuses a rollback', (t) => {
  const save = operator(t);
  const roots = JSON.parse(MAINNET_V1_ROOTS);
  const genesis = JSON.parse(MAINNET_V1_SIGNED).snapshot;
  assert.deepEqual([String(genesis.version), String(genesis.log_index), genesis.network_id],
    ['1', '1', WALLET_NETWORKS.mainnet.networkId]);
  assert.deepEqual([roots.checkpoint.version, roots.checkpoint.log_index], ['1', '1']);
  const config = save(MAINNET_V1_ROOTS, { registryMinimumVersion: 1 }, MAINNET_V1_SIGNED)();
  assert.equal(config.network.name, 'mainnet');
  assert.equal(config.registryMinimumVersion, 1);
  assert.equal(config.registrySnapshot, MAINNET_V1_SIGNED);
  // The floor is the operator's own registry's: a floor above the persisted checkpoint is a rollback, refused.
  assert.throws(save(MAINNET_V1_ROOTS, { registryMinimumVersion: 2 }, MAINNET_V1_SIGNED),
    (error) => /older than the configured minimum/.test(error.startup));
  // And there is no version 0.
  assert.throws(save(MAINNET_V1_ROOTS, { registryMinimumVersion: 0 }, MAINNET_V1_SIGNED), /configuration/);
});

// Opt-in, against the real CLI (`OZPB_BIN`): under the root policy alone, as at the ceremony, the
// fixture verifies on mainnet and prints exactly the committed checkpoint, and a floor above it is
// refused as a rollback.
test('the real `ozpb registry verify` accepts the mainnet genesis fixture at floor 1 and refuses it at floor 2',
  { skip: !process.env.OZPB_BIN }, async (t) => {
    const { execFileSync, spawnSync } = await import('node:child_process');
    const dir = realpathSync(mkdtempSync(join(tmpdir(), 'wallet-registry-genesis-')));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const { checkpoint: _persisted, ...policy } = JSON.parse(MAINNET_V1_ROOTS);
    const roots = join(dir, 'roots.json');
    writeFileSync(roots, JSON.stringify(policy), { mode: 0o600 });
    const signed = new URL('registry.signed.json', MAINNET_V1).pathname;
    const verify = (floor) => ['registry', 'verify', '--signed', signed, '--registry-roots', roots, '--network',
      'Public Global Stellar Network ; September 2015', '--at', '1798761700', '--min-version', String(floor)];
    assert.deepEqual(JSON.parse(execFileSync(process.env.OZPB_BIN, verify(1))), JSON.parse(MAINNET_V1_ROOTS).checkpoint);
    const refused = spawnSync(process.env.OZPB_BIN, verify(2), { encoding: 'utf8' });
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /^Error: E_REGISTRY_ROLLBACK: /);
  });

test('the CLI\'s E_REGISTRY_ROOT_POLICY reaches the page as registry_root_refused, from every registry-reading call', async (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'wallet-registry-cli-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const seen = [];
  const runner = async (_executable, args, options) => {
    seen.push({ command: args[0], codes: options.codes });
    if (args[0] === 'record') {
      const account = StrKey.encodeContract(Buffer.alloc(32, 3));
      return JSON.stringify({ trust: 'rpc_reported', recording_hash: '1'.repeat(64), bundle: { network_id: 'cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472',
        execution: 'executed_success', ledger: 10, contract_executables: { [account]: { observed_ledger: 10,
          executable: { wasm: { code_hash: '203e2970d9fed24fb5fca2e0aeebb3c1e4648b76dd6601567178e6474c9fec6f' } } } },
        authorizations: [{ authorizer: account }] } });
    }
    // The CLI reports the refusal as `Error: E_REGISTRY_ROOT_POLICY: …`; the runner hands back the code alone.
    throw Object.assign(new Error('wallet tool failed; no confidential diagnostics returned'), { code: REGISTRY_ROOT_POLICY });
  };
  const toolchain = new WalletToolchain({ executable: '/fixed/ozpb', workRoot: root, rpcUrl: 'https://rpc.example/',
    registrySnapshot: '{}', registryRoots: '{}', registryMinimumVersion: 6, runner,
    network: (await import('../shared/networks.mjs')).WALLET_NETWORKS.testnet });
  const account = StrKey.encodeContract(Buffer.alloc(32, 3));
  const record = await toolchain.record({ transactionHash: '2'.repeat(64), accountAddress: account });
  const refused = (error) => error.code === REGISTRY_ROOT_POLICY && error.reason === 'registry_root_refused';
  await assert.rejects(() => toolchain.generate({ recordId: record.recordId, delegateAddress: Keypair.random().publicKey(),
    validUntilLedger: 100, maxCalls: 1, grantName: 'grant', currentLedger: 50 }), refused);
  await assert.rejects(() => toolchain.authority('prepare-install-intent', { spec: {} }), refused);
  assert.ok(seen.every((call) => call.codes.includes(REGISTRY_ROOT_POLICY)), 'every CLI call may surface it');
  assert.ok(REFUSAL_REASONS.has('registry_root_refused') && CLIENT_REASONS.has('registry_root_refused'));
});

test('the integrated CLI\'s own stderr line, through the real tool runner, becomes registry_root_refused', async (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'wallet-registry-stderr-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  // Exactly what `ozpb` prints for the development root off testnet (crates/cli/tests/development_root_cli.rs):
  // its error, led by the code, on standard error, and a failing status.
  const executable = join(root, 'ozpb');
  writeFileSync(executable, '#!/bin/sh\nprintf \'Error: E_REGISTRY_ROOT_POLICY: the public development registry root is accepted only on testnet\\n\' >&2\nexit 1\n',
    { mode: 0o700 });
  const workRoot = join(root, 'work');
  mkdirSync(workRoot, { mode: 0o700 });
  const toolchain = new WalletToolchain({ executable, workRoot, rpcUrl: 'https://rpc.example/', registrySnapshot: '{}',
    registryRoots: '{}', registryMinimumVersion: 6, network: (await import('../shared/networks.mjs')).WALLET_NETWORKS.mainnet });
  const refused = (error) => error.code === REGISTRY_ROOT_POLICY && error.reason === 'registry_root_refused'
    && !String(error.message).includes('development registry root');
  for (const command of ['prepare-install-intent', 'check-policy-call-surface', 'assemble-install-transaction', 'check-installed-grant']) {
    await assert.rejects(() => toolchain.authority(command, { spec: {} }), refused, command);
  }
  // Any other code, or the same text not at the start of the line, says nothing.
  writeFileSync(executable, '#!/bin/sh\nprintf \'warning\\nError: E_REGISTRY_ROOT_POLICY: x\\n\' >&2\nexit 1\n', { mode: 0o700 });
  await assert.rejects(() => toolchain.authority('prepare-install-intent', { spec: {} }), (error) => error.reason === undefined);
});
