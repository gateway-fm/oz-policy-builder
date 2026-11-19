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
  return (roots, extra = {}) => {
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
  const withCheckpoint = { ...JSON.parse(EXAMPLE_ROOTS), checkpoint: { version: 6 } };
  assert.throws(save(withCheckpoint), (error) => /development registry root is refused/.test(error.startup));
  // Named among production keys, or in another case, it is refused all the same.
  const mixed = { threshold: 2, keys: { operator: 'ab'.repeat(32), dev: DEVELOPMENT_REGISTRY_ROOT.toUpperCase() }, checkpoint: { version: 6 } };
  assert.throws(save(mixed), (error) => /development registry root is refused/.test(error.startup));
  // Testnet keeps the development registry and needs no checkpoint.
  assert.doesNotThrow(save(EXAMPLE_ROOTS, { network: 'testnet', feePayerKeyPath: undefined }));
});

test('a mainnet session needs the persisted checkpoint, at or above the configured floor', (t) => {
  const save = operator(t);
  const production = { threshold: 1, keys: { operator: 'cd'.repeat(32) } };
  assert.throws(save(production), (error) => /persisted checkpoint/.test(error.startup));
  assert.throws(save({ ...production, checkpoint: { version: 5 } }), (error) => /older than the configured minimum/.test(error.startup));
  assert.throws(save({ ...production, checkpoint: [] }), (error) => /persisted checkpoint/.test(error.startup));
  assert.throws(save({ keys: production.keys, checkpoint: { version: 6 } }), (error) => /threshold/.test(error.startup));
  assert.throws(save({ threshold: 1, keys: {}, checkpoint: { version: 6 } }), (error) => /at least one key/.test(error.startup));
  const config = save({ ...production, checkpoint: { version: 7 } })();
  assert.equal(config.network.name, 'mainnet');
  assert.equal(config.registryRoots, JSON.stringify({ ...production, checkpoint: { version: 7 } }), 'the exact bytes reach the CLI');
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
    registrySnapshot: '{}', registryRoots: '{}', registryMinimumVersion: 6, runner });
  const account = StrKey.encodeContract(Buffer.alloc(32, 3));
  const record = await toolchain.record({ transactionHash: '2'.repeat(64), accountAddress: account });
  const refused = (error) => error.code === REGISTRY_ROOT_POLICY && error.reason === 'registry_root_refused';
  await assert.rejects(() => toolchain.generate({ recordId: record.recordId, delegateAddress: Keypair.random().publicKey(),
    validUntilLedger: 100, maxCalls: 1, grantName: 'grant', currentLedger: 50 }), refused);
  await assert.rejects(() => toolchain.authority('prepare-install-intent', { spec: {} }), refused);
  assert.ok(seen.every((call) => call.codes.includes(REGISTRY_ROOT_POLICY)), 'every CLI call may surface it');
  assert.ok(REFUSAL_REASONS.has('registry_root_refused') && CLIENT_REASONS.has('registry_root_refused'));
});
