// In an operator-funded session (always on mainnet; on testnet when the operator configures its own
// fee payer key, the rehearsal of the mainnet install) the grant's delegate is the agent's own key,
// named by its proposal: the wallet generates no delegate key. An optional operator delegate key file
// (0600) gives the wallet one key it may sign with as that delegate, for the checks that need its
// signatures and the one use of the grant; without it those steps say so instead of running. Keys here
// are throwaways generated at run time.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect } from 'node:util';
import test from 'node:test';
import { Account, Keypair, Operation, TransactionBuilder } from '@stellar/stellar-sdk';
import { WALLET_NETWORKS } from '../shared/networks.mjs';
import { MAINNET_FEE_DEFAULTS, loadWalletConfig } from '../server/config.mjs';
import { createWalletRuntime } from '../server/main.mjs';
import { DelegateCapabilities } from '../server/native-execution.mjs';
import { setup } from './actions-fixture.mjs';

const { mainnet: MAINNET, testnet: TESTNET } = WALLET_NETWORKS;

/** An operator-funded configuration on `network` (mainnet unless named): `save(extra)` writes it and returns its loader. */
function operatorFiles(t, network = 'mainnet') {
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
    writeFileSync(path, JSON.stringify({ executable: join(root, 'ozpb'), workRoot, rpcUrl: 'https://rpc.example/', network,
      registrySnapshotPath: join(root, 'registry.json'), registryRootsPath: join(root, 'roots.json'), registryMinimumVersion: 6,
      feePayerKeyPath: key('payer.key', payer), ...extra }), { mode: 0o600 });
    return () => loadWalletConfig(path);
  };
  return { key, save, payer, path, workRoot };
}

for (const network of ['mainnet', 'testnet']) {
  test(`${network}: the operator delegate key file is optional, taken only with the operator's fee payer, 0600, never shown, and not the fee payer's key`, (t) => {
    const { key, save, payer } = operatorFiles(t, network);
    assert.equal(save({})().delegateKey, null, 'no file: the wallet holds no delegate key');
    const secret = Keypair.random().secret();
    const config = save({ delegateKeyPath: key('delegate.key', secret) })();
    assert.equal(config.delegateKey.address, Keypair.fromSecret(secret).publicKey());
    for (const shown of [JSON.stringify(config), inspect(config), JSON.stringify(config.delegateKey)]) assert.equal(shown.includes(secret), false);
    assert.throws(save({ delegateKeyPath: key('open.key', secret, 0o644) }), (error) => /mode 0600/.test(error.startup));
    assert.throws(save({ delegateKeyPath: key('same.key', payer) }), (error) => /must not be the fee payer/.test(error.startup));
  });

  test(`${network}: an operator-funded runtime starts from its work root's journaled spend and holds only the operator's delegate key`, async (t) => {
    const { key, save, path, workRoot } = operatorFiles(t, network);
    const profile = WALLET_NETWORKS[network];
    // An earlier session in this (network-bound) work root sent one transaction whose fee could be 0.42 XLM.
    writeFileSync(join(workRoot, 'ozpb-wallet-network.json'), JSON.stringify({ network, networkId: profile.networkId }), { mode: 0o600 });
    mkdirSync(join(workRoot, 'wallet-session-earlier', 'journal'), { recursive: true, mode: 0o700 });
    const tx = new TransactionBuilder(new Account(Keypair.random().publicKey(), '7'), { fee: '4200000', networkPassphrase: profile.passphrase })
      .addOperation(Operation.bumpSequence({ bumpTo: '9' })).setTimeout(60).build();
    writeFileSync(join(workRoot, 'wallet-session-earlier', 'journal', '0001.intended.json'), JSON.stringify({ stage: 'deploy-policy',
      hash: 'a'.repeat(64), networkId: profile.networkId, envelopeXdr: tx.toEnvelope().toXDR('base64'), status: 'submission_unknown' }), { mode: 0o600 });
    const runtime = async () => {
      let captured;
      const started = await createWalletRuntime(path, { actionsFactory: (parts) => { captured = parts; return {}; } });
      assert.match(started.launchUrl, new RegExp(`&network=${network}$`));
      return captured;
    };
    save({});
    const without = await runtime();
    assert.equal(without.network.operatorFunded, true);
    assert.equal(without.network.spentStroops, '4200000', 'restarting the backend gives no budget back');
    assert.equal(without.delegates.available, false, 'no disposable automation key in an operator-funded session');
    const secret = Keypair.random().secret();
    save({ delegateKeyPath: key('delegate.key', secret) });
    const withKey = await runtime();
    assert.equal(withKey.delegates.create().address, Keypair.fromSecret(secret).publicKey());
    assert.deepEqual(withKey.delegates.create(), withKey.delegates.create(), 'that key only, never a new one');
  });
}

test('a testnet session with the wallet\'s own disposable fee payer keeps disposable delegates and no carried spend', async (t) => {
  const { save, path, workRoot } = operatorFiles(t, 'testnet');
  save({});
  // The same configuration without the operator's fee payer key.
  const { readFileSync } = await import('node:fs');
  const value = JSON.parse(readFileSync(path, 'utf8'));
  delete value.feePayerKeyPath;
  writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
  mkdirSync(join(workRoot, 'wallet-session-earlier', 'journal'), { recursive: true, mode: 0o700 });
  let captured;
  await createWalletRuntime(path, { actionsFactory: (parts) => { captured = parts; return {}; } });
  assert.equal(captured.network.operatorFunded, false);
  assert.equal(captured.network.spentStroops, '0');
  assert.notEqual(captured.delegates.create().address, captured.delegates.create().address);
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
  const mainnet = (delegates) => setup({ native: {}, delegates, network: { profile: MAINNET, fees: MAINNET_FEE_DEFAULTS, spentStroops: '0', operatorFunded: true,
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

test('operator-funded testnet actions: the same delegate steps, the delegate\'s account created through testnet\'s Friendbot', async () => {
  const testnet = (delegates) => {
    const created = [];
    const fixture = setup({ native: {}, delegates, network: { profile: TESTNET, fees: MAINNET_FEE_DEFAULTS, spentStroops: '0', operatorFunded: true,
      ensureDelegateAccount: async (address) => { created.push(address); return { ledger: 9, createdNow: true }; } } });
    return { ...fixture, created };
  };
  const without = testnet(new DelegateCapabilities(TESTNET, { random: false }));
  await assert.rejects(() => without.actions['create-delegate']({}), (error) => error.reason === 'delegate_key_unavailable');
  assert.equal((await without.actions.status({})).capabilities.delegateKey, false);
  assert.equal((await without.actions.status({})).feePayer.ownerFunded, true);
  const key = Keypair.random();
  const withKey = testnet(new DelegateCapabilities(TESTNET, { random: false, key }));
  const created = await withKey.actions['create-delegate']({});
  assert.equal(created.address, key.publicKey());
  // Friendbot is testnet's, for every account but the fee payer's: it creates the delegate's account, at no one's cost.
  assert.deepEqual(withKey.created, [key.publicKey()]);
  assert.equal((await withKey.actions.status({})).capabilities.delegateKey, true);
});
