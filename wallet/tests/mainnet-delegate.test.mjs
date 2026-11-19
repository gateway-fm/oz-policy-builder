// On mainnet the grant's delegate is the agent's own key, named by its proposal: the wallet generates
// no delegate key there. An optional operator delegate key file (0600) gives the wallet one key it may
// sign with as that delegate, for the checks that need its signatures and the one use of the grant;
// without it those steps say so instead of running. Keys here are throwaways generated at run time.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect } from 'node:util';
import test from 'node:test';
import { Keypair } from '@stellar/stellar-sdk';
import { WALLET_NETWORKS } from '../shared/networks.mjs';
import { MAINNET_FEE_DEFAULTS, loadWalletConfig } from '../server/config.mjs';
import { DelegateCapabilities } from '../server/native-execution.mjs';
import { setup } from './actions-fixture.mjs';

const MAINNET = WALLET_NETWORKS.mainnet;

function operatorFiles(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'wallet-mainnet-delegate-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const workRoot = join(root, 'work');
  mkdirSync(workRoot, { mode: 0o700 });
  writeFileSync(join(root, 'ozpb'), '#!/bin/sh\nexit 99\n', { mode: 0o700 });
  writeFileSync(join(root, 'registry.json'), '{}', { mode: 0o600 });
  writeFileSync(join(root, 'roots.json'), JSON.stringify({ threshold: 1, keys: { operator: 'ab'.repeat(32) },
    checkpoint: { version: '6', log_index: '6', root: 'ef'.repeat(32), revocations: {} } }), { mode: 0o600 });
  const key = (name, secret, mode = 0o600) => { const path = join(root, name); writeFileSync(path, `${secret}\n`, { mode }); return path; };
  const payer = Keypair.random().secret();
  const path = join(root, 'operator.json');
  const save = (extra) => {
    writeFileSync(path, JSON.stringify({ executable: join(root, 'ozpb'), workRoot, rpcUrl: 'https://rpc.example/', network: 'mainnet',
      registrySnapshotPath: join(root, 'registry.json'), registryRootsPath: join(root, 'roots.json'), registryMinimumVersion: 6,
      feePayerKeyPath: key('payer.key', payer), ...extra }), { mode: 0o600 });
    return () => loadWalletConfig(path);
  };
  return { key, save, payer };
}

test('the operator delegate key file is optional, mainnet only, 0600, never shown, and not the fee payer\'s key', (t) => {
  const { key, save, payer } = operatorFiles(t);
  assert.equal(save({})().delegateKey, null, 'no file: the wallet holds no delegate key');
  const secret = Keypair.random().secret();
  const config = save({ delegateKeyPath: key('delegate.key', secret) })();
  assert.equal(config.delegateKey.address, Keypair.fromSecret(secret).publicKey());
  for (const shown of [JSON.stringify(config), inspect(config), JSON.stringify(config.delegateKey)]) assert.equal(shown.includes(secret), false);
  assert.throws(save({ delegateKeyPath: key('open.key', secret, 0o644) }), (error) => /mode 0600/.test(error.startup));
  assert.throws(save({ delegateKeyPath: key('same.key', payer) }), (error) => /must not be the fee payer/.test(error.startup));
});

test('mainnet without the key file: no delegate key exists; with it, exactly that one', () => {
  const none = new DelegateCapabilities(MAINNET, { random: false });
  assert.equal(none.available, false);
  assert.throws(() => none.create(), /refused/);
  const key = Keypair.random();
  const fixed = new DelegateCapabilities(MAINNET, { random: false, key });
  const created = fixed.create();
  assert.equal(created.address, key.publicKey());
  assert.deepEqual(fixed.create(), created, 'the same capability again, never a new key');
  assert.equal(fixed.holds(key.publicKey()), true);
  assert.equal(fixed.holds(Keypair.random().publicKey()), false);
  // Testnet keeps generating its disposable automation keys.
  const testnet = new DelegateCapabilities(WALLET_NETWORKS.testnet);
  assert.notEqual(testnet.create().address, testnet.create().address);
});

test('mainnet actions: without the key file the delegate step and the use step say why they do not run', async () => {
  const mainnet = (delegates) => setup({ native: {}, delegates, network: { profile: MAINNET, fees: MAINNET_FEE_DEFAULTS, spentStroops: '0',
    classicAccount: async () => ({ exists: true, balanceStroops: '20000000', minimumStroops: '10000000', spendableStroops: '10000000', ledger: 9 }) } });
  const without = mainnet(new DelegateCapabilities(MAINNET, { random: false }));
  await assert.rejects(() => without.actions['create-delegate']({}), (error) => error.reason === 'delegate_key_unavailable');
  const status = await without.actions.status({});
  assert.equal(status.capabilities.delegateKey, false);
  const key = Keypair.random();
  const withKey = mainnet(new DelegateCapabilities(MAINNET, { random: false, key }));
  const created = await withKey.actions['create-delegate']({});
  assert.equal(created.address, key.publicKey());
  assert.deepEqual(created.account, { exists: true, minimumStroops: '10000000' });
  assert.equal((await withKey.actions.status({})).capabilities.delegateKey, true);
});
