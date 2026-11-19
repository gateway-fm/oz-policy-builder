// The network is chosen once, by the operator configuration, and everything is bound to it: the
// endpoint must serve it at protocol 30, the journal records it first, the work root belongs to it,
// and a proposal, approval, assembly, capability or page from the other network is refused.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { Keypair, Networks } from '@stellar/stellar-sdk';
import { WALLET_NETWORKS, networkById, walletNetwork } from '../shared/networks.mjs';
import { WalletNetwork } from '../server/network.mjs';
import { networkPreflight } from '../server/main.mjs';
import { MAINNET_FEE_DEFAULTS, loadWalletConfig } from '../server/config.mjs';
import { FeePayer } from '../server/fee-payer.mjs';
import { bindWorkRoot } from '../server/toolchain.mjs';
import { REFUSAL_REASONS } from '../server/http.mjs';
import { AgentHandoff } from '../server/agent-handoff.mjs';
import { DelegateCapabilities } from '../server/native-execution.mjs';
import { reviewIntent } from '../shared/approval.mjs';
import { validateAssembly } from '../shared/assembly.mjs';
import { parseGrantProposal } from '../shared/proposal.mjs';
import { reviewSample, validateSampleAssembly } from '../shared/sample.mjs';
import { reviewRemoval } from '../shared/revoke.mjs';
import { liveGrant } from '../shared/live-consent.mjs';
import { takeSession } from '../overlay/files/src/policy-builder/client/client.mjs';
import { REFUSAL_REASONS as CLIENT_REASONS } from '../overlay/files/src/policy-builder/client/client.mjs';
import { WalletController } from '../overlay/files/src/policy-builder/client/controller.mjs';
import { fixture } from './approval-fixture.mjs';
import { sample } from './assembly-fixture.mjs';
import { proposalFixture } from './proposal-fixture.mjs';
import { sampleTransfer } from './sample-fixture.mjs';

const { testnet: TESTNET, mainnet: MAINNET } = WALLET_NETWORKS;
const scratch = (t, prefix) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
};
/** A WalletNetwork for `network` against an endpoint reporting `reported`; every request and fetch is counted. */
function session(t, network, reported = { passphrase: network.passphrase, protocolVersion: 30 }, methods = {}) {
  const root = scratch(t, 'wallet-network-selection-');
  const requests = [];
  const server = new Proxy({ getNetwork: async () => { requests.push('getNetwork'); return reported; }, ...methods }, {
    get: (target, key) => target[key] ?? (async () => { requests.push(String(key)); throw new Error('unexpected read'); }),
  });
  // Mainnet has no disposable key: the operator's own key (a throwaway here) and its caps.
  const funding = network.friendbot ? {} : { feePayer: new FeePayer(Keypair.random(), true), fees: MAINNET_FEE_DEFAULTS };
  const wallet = new WalletNetwork({ network, rpcUrl: 'https://rpc.example/', journalRoot: root, server, ...funding,
    fetchImpl: async (url) => { requests.push(`fetch ${url}`); return new Response('{}'); }, pause: async () => {} });
  return { wallet, root, requests };
}

test('the two networks are derived from their passphrases and nothing else is a network', () => {
  assert.equal(TESTNET.passphrase, Networks.TESTNET);
  assert.equal(TESTNET.networkId, 'cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472');
  assert.equal(MAINNET.passphrase, Networks.PUBLIC);
  assert.equal(MAINNET.networkId, '7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979');
  assert.equal(MAINNET.nativeAsset, 'CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA');
  assert.equal(MAINNET.friendbot, null, 'no Friendbot on mainnet');
  assert.ok(Object.isFrozen(WALLET_NETWORKS) && Object.isFrozen(TESTNET) && Object.isFrozen(MAINNET));
  for (const name of ['pubnet', 'public', 'MAINNET', 'futurenet', '', undefined, 'constructor', '__proto__']) {
    assert.throws(() => walletNetwork(name), /testnet or mainnet only/, String(name));
  }
  assert.equal(networkById(MAINNET.networkId), MAINNET);
  assert.throws(() => networkById('a3a1c6a78286713e29be0e9785670fa838d13917cd8eaeb4a3579ff1debc7fd5'), /refused/, 'futurenet');
});

test('the operator chooses the network once, in the configuration: testnet by default, mainnet only by name', (t) => {
  const root = scratch(t, 'wallet-network-config-');
  const executable = join(root, 'ozpb');
  const workRoot = join(root, 'work');
  mkdirSync(workRoot, { mode: 0o700 });
  writeFileSync(executable, '#!/bin/sh\nexit 99\n', { mode: 0o700 });
  writeFileSync(join(root, 'registry.json'), '{}', { mode: 0o600 });
  // A production-shaped root policy with its persisted checkpoint: mainnet refuses the development root.
  writeFileSync(join(root, 'roots.json'), JSON.stringify({ threshold: 1, keys: { operator: 'ab'.repeat(32) }, checkpoint: { version: '6', log_index: '6', root: 'ef'.repeat(32), revocations: {} } }),
    { mode: 0o600 });
  const path = join(root, 'operator.json');
  const save = (extra) => writeFileSync(path, JSON.stringify({ executable, workRoot, rpcUrl: 'https://rpc.example/',
    registrySnapshotPath: join(root, 'registry.json'), registryRootsPath: join(root, 'roots.json'), registryMinimumVersion: 6, ...extra }),
  { mode: 0o600 });
  save({});
  assert.equal(loadWalletConfig(path).network, TESTNET);
  // A throwaway key generated here, never committed: mainnet takes only the operator's own key file.
  const keyPath = join(root, 'fee-payer.key');
  writeFileSync(keyPath, `${Keypair.random().secret()}\n`, { mode: 0o600 });
  save({ network: 'mainnet', feePayerKeyPath: keyPath });
  assert.equal(loadWalletConfig(path).network, MAINNET);
  for (const network of ['pubnet', 'Mainnet', null, 1, { name: 'mainnet' }]) {
    save({ network });
    assert.throws(() => loadWalletConfig(path), /invalid wallet operator configuration/, JSON.stringify(network));
  }
});

test('every read checks the endpoint serves the session network: another network is refused as network_mismatch', async (t) => {
  for (const [network, other] of [[MAINNET, TESTNET], [TESTNET, MAINNET]]) {
    const { wallet, requests } = session(t, network, { passphrase: other.passphrase, protocolVersion: 30 });
    await assert.rejects(() => wallet.assertNetwork(), (error) => error.reason === 'network_mismatch');
    await assert.rejects(() => wallet.latestLedger(), (error) => error.reason === 'network_mismatch');
    await assert.rejects(() => wallet.ledgerClock(), /refused/);
    assert.deepEqual(requests.filter((r) => r !== 'getNetwork'), [], `${network.name}: nothing past getNetwork was read`);
  }
  assert.ok(REFUSAL_REASONS.has('network_mismatch') && CLIENT_REASONS.has('network_mismatch'));
});

test('protocol 30 only: a mainnet endpoint still on protocol 29 is refused as protocol_unsupported, with a clear reason', async (t) => {
  const { wallet, requests } = session(t, MAINNET, { passphrase: Networks.PUBLIC, protocolVersion: 29 });
  await assert.rejects(() => wallet.assertNetwork(), (error) => error.reason === 'protocol_unsupported' && error.protocolVersion === 29);
  await assert.rejects(() => wallet.contractLiveness(MAINNET.nativeAsset), (error) => error.reason === 'protocol_unsupported');
  const message = await networkPreflight(wallet);
  assert.match(message, /reports protocol 29 for mainnet/);
  assert.match(message, /protocol 30 only/);
  assert.deepEqual(requests, ['getNetwork', 'getNetwork', 'getNetwork'], 'only getNetwork: nothing else is read');
  for (const [network, protocolVersion] of [[TESTNET, 29], [TESTNET, 31], [MAINNET, 31], [MAINNET, '30']]) {
    const other = session(t, network, { passphrase: network.passphrase, protocolVersion });
    await assert.rejects(() => other.wallet.assertNetwork(), (error) => error.reason === 'protocol_unsupported', `${network.name} ${protocolVersion}`);
  }
  assert.equal(await networkPreflight(session(t, MAINNET).wallet), null, 'a mainnet endpoint at protocol 30 passes');
  assert.match(await networkPreflight(session(t, MAINNET, { passphrase: Networks.TESTNET, protocolVersion: 30 }).wallet),
    /does not serve mainnet/);
  assert.ok(REFUSAL_REASONS.has('protocol_unsupported') && CLIENT_REASONS.has('protocol_unsupported'));
});

test('the session journal records the network first, before any obligation or submission', (t) => {
  const { wallet, root } = session(t, MAINNET);
  assert.equal(wallet.profile, MAINNET);
  assert.deepEqual(readdirSync(root), ['0000.session.json']);
  assert.deepEqual(JSON.parse(readFileSync(join(root, '0000.session.json'), 'utf8')),
    { network: 'mainnet', networkId: MAINNET.networkId, protocolVersion: 30 });
  assert.throws(() => new WalletNetwork({ rpcUrl: 'https://rpc.example/', journalRoot: root }), /refused/, 'no network, no session');
  assert.throws(() => new WalletNetwork({ network: { ...MAINNET }, rpcUrl: 'https://rpc.example/', journalRoot: root }), /refused/);
});

test('mainnet has no Friendbot: neither the fee payer nor a delegate is ever funded by the wallet', async (t) => {
  const { wallet, requests } = session(t, MAINNET, undefined, { getLedgerEntries: async () => ({ latestLedger: 100, entries: [] }) });
  await assert.rejects(() => wallet.fundPayer(), /refused/);
  await assert.rejects(() => wallet.ensureDelegateAccount(Keypair.random().publicKey()), /refused/, 'a missing delegate is not created');
  assert.equal(requests.some((r) => r.startsWith('fetch')), false, 'no Friendbot request');
  assert.equal(wallet.canSubmit, false);
});

test('a work root belongs to one network: the other network\'s retained sessions are refused at startup', (t) => {
  const testnetRoot = scratch(t, 'wallet-work-testnet-');
  bindWorkRoot(testnetRoot, TESTNET);
  bindWorkRoot(testnetRoot, TESTNET);
  assert.throws(() => bindWorkRoot(testnetRoot, MAINNET), (error) => /work root of its own/.test(error.startup));
  const mainnetRoot = scratch(t, 'wallet-work-mainnet-');
  bindWorkRoot(mainnetRoot, MAINNET);
  assert.throws(() => bindWorkRoot(mainnetRoot, TESTNET), (error) => /work root of its own/.test(error.startup));
  // Sessions retained before the marker existed were testnet sessions.
  const legacy = scratch(t, 'wallet-work-legacy-');
  mkdirSync(join(legacy, 'wallet-session-abc123'), { mode: 0o700 });
  assert.throws(() => bindWorkRoot(legacy, MAINNET), (error) => /work root of its own/.test(error.startup));
  bindWorkRoot(legacy, TESTNET);
  assert.deepEqual(JSON.parse(readFileSync(join(legacy, 'ozpb-wallet-network.json'), 'utf8')),
    { network: 'testnet', networkId: TESTNET.networkId });
});

test('cross-network proposals are refused in either direction, before any RPC or build', async () => {
  const f = proposalFixture();
  const text = JSON.stringify(f.proposal);
  assert.equal(parseGrantProposal(text, f.wallet.contractId, TESTNET.networkId).network_id, TESTNET.networkId);
  assert.throws(() => parseGrantProposal(text, f.wallet.contractId, MAINNET.networkId), /proposal refused/, 'testnet proposal, mainnet session');
  // The same grant on mainnet: its native asset is mainnet's, and a testnet session refuses it.
  const onMainnet = structuredClone(f.proposal);
  onMainnet.network_id = MAINNET.networkId;
  onMainnet.expected_grant.rules[0].context.contract = MAINNET.nativeAsset;
  assert.equal(parseGrantProposal(JSON.stringify(onMainnet), f.wallet.contractId, MAINNET.networkId).network_id, MAINNET.networkId);
  assert.throws(() => parseGrantProposal(JSON.stringify(onMainnet), f.wallet.contractId, TESTNET.networkId), /proposal refused/);
  // A mainnet proposal naming testnet's native asset is refused too.
  const mixed = structuredClone(onMainnet);
  mixed.expected_grant.rules[0].context.contract = TESTNET.nativeAsset;
  assert.throws(() => parseGrantProposal(JSON.stringify(mixed), f.wallet.contractId, MAINNET.networkId), /proposal refused/);
  assert.throws(() => parseGrantProposal(text, f.wallet.contractId), /proposal refused/, 'no session network');
  // The agent handoff of a mainnet session refuses a testnet draft on delivery.
  const handoff = new AgentHandoff({ network: MAINNET });
  const { pairingCode } = handoff.pair({ wallet: f.wallet, delegate: { address: f.proposal.decisions.delegate, capabilityId: 'a'.repeat(64) } });
  const { capability, connection } = handoff.connect(pairingCode);
  assert.equal(connection.networkId, MAINNET.networkId);
  assert.throws(() => handoff.deliver(capability, { deliveryId: 'd'.repeat(64), proposal: text }), (error) => error.reason === 'proposal_invalid');
});

test('a testnet approval is refused in a mainnet session and vice versa', () => {
  const input = fixture();
  // The CLI's verdict names testnet; a mainnet session expects mainnet.
  assert.equal(reviewIntent(input).networkId, TESTNET.networkId);
  assert.throws(() => reviewIntent({ ...input, expected: { ...input.expected, networkId: MAINNET.networkId } }), /refused/);
  assert.throws(() => reviewIntent({ ...input, expected: { ...input.expected, networkId: 'ab'.repeat(32) } }), /refused/);
  // An assembly for the other network, or an approval relabelled to it, is refused.
  const value = sample();
  assert.doesNotThrow(() => validateAssembly(value));
  assert.throws(() => validateAssembly({ ...value, assembly: { ...value.assembly, network_id: MAINNET.networkId } }), /refused/);
  assert.throws(() => validateAssembly({ ...value, approval: { ...value.approval, networkId: MAINNET.networkId } }), /refused/);
  // The sample transfer: a mainnet review commits to mainnet, and a testnet assembly does not validate under it.
  const s = sampleTransfer();
  const onTestnet = reviewSample({ ...s, networkId: TESTNET.networkId });
  const onMainnet = reviewSample({ ...s, networkId: MAINNET.networkId });
  assert.notEqual(onMainnet.commitment, onTestnet.commitment);
  assert.doesNotThrow(() => validateSampleAssembly({ ...s, approval: onTestnet }));
  assert.throws(() => validateSampleAssembly({ ...s, approval: onMainnet }), /refused/);
  assert.throws(() => reviewSample(s), /refused/, 'no session network');
  // A removal approval commits to its network too.
  const removal = { wallet: input.wallet, ownerRuleId: 7, ownerRuleXdr: input.ownerRuleXdr,
    installation: { account: input.wallet.contractId, ruleId: 1, transactionHash: 'e'.repeat(64) } };
  assert.notEqual(reviewRemoval({ ...removal, networkId: MAINNET.networkId }).commitment,
    reviewRemoval({ ...removal, networkId: TESTNET.networkId }).commitment);
  assert.throws(() => reviewRemoval(removal), /refused/, 'no session network');
});

test('a grant generated for one network is not the live check\'s shape on the other', () => {
  const f = proposalFixture();
  const spec = structuredClone(f.spec);
  spec.rules[0].allowed_calls[0].args[2].c.eq_i128.value = '1000000';
  assert.equal(liveGrant(spec, TESTNET.networkId).supported, true);
  assert.equal(liveGrant(spec, MAINNET.networkId).supported, false);
  assert.match(liveGrant(spec, MAINNET.networkId).reason, /not for mainnet/);
});

test('the delegate\'s live and use capabilities sign only for the session network', () => {
  const capabilities = new DelegateCapabilities(MAINNET);
  const { capabilityId, address } = capabilities.create();
  const account = 'CAWGOGD3YYSPUR6CPT6PE33DCUIGFNBVZVA5WEDGK2YM34FRLIUQBT5A';
  const recipient = Keypair.random().publicKey();
  const use = (networkId) => ({ network_id: networkId, account, recipient, expected_rule_id: 1, amount: '1000000',
    signature_expiration_ledger: 1030, read_ledger: 1010 });
  assert.throws(() => capabilities.use(capabilityId, address, use(TESTNET.networkId)), /refused/, 'a testnet use in a mainnet session');
  const capability = capabilities.use(capabilityId, address, use(MAINNET.networkId));
  assert.throws(() => capability.authorizeTransfer({ network_id: MAINNET.networkId, account, asset: TESTNET.nativeAsset, recipient,
    amount: '1000000', expected_rule_id: 1, nonce: '5', signature_expiration_ledger: 1030 }), /refused/, 'testnet\'s asset');
  const signed = capability.authorizeTransfer({ network_id: MAINNET.networkId, account, asset: MAINNET.nativeAsset, recipient,
    amount: '1000000', expected_rule_id: 1, nonce: '5', signature_expiration_ledger: 1030 });
  assert.ok(signed.transferEntryXdr && signed.delegateEntryXdr);
  // Without a session network no live or use capability is minted at all.
  const unbound = new DelegateCapabilities();
  const key = unbound.create();
  assert.throws(() => unbound.use(key.capabilityId, key.address, use(TESTNET.networkId)), /refused/);
});

test('the page holds the network its launch URL names, and refuses a backend on another', async () => {
  const history = { replaceState: () => {} };
  const launch = (hash) => takeSession({ href: `http://localhost:3000/policy-builder${hash}` }, history);
  const secret = 'ab'.repeat(32);
  assert.deepEqual({ ...launch(`#session=${secret}&network=mainnet`) }, { token: secret, network: 'mainnet' });
  assert.deepEqual({ ...launch(`#session=${secret}`) }, { token: secret, network: 'testnet' });
  for (const hash of [`#session=${secret}&network=pubnet`, `#session=${secret}&network=mainnet&x=1`, `#network=mainnet&session=${secret}`]) {
    assert.throws(() => launch(hash), /session unavailable/, hash);
  }
  const pins = { network: 'mainnet', networkId: MAINNET.networkId, accountWasm: 'a'.repeat(64), verifierWasm: 'b'.repeat(64) };
  const controller = (status) => new WalletController({ pins, validators: {}, sign: async () => [], origin: 'http://localhost:3000',
    request: async () => status, pause: async () => {} });
  await assert.rejects(() => controller({ ...pins, network: 'testnet', networkId: TESTNET.networkId, capabilities: {} }).connect(), /refused/);
  await assert.doesNotReject(() => controller({ ...pins, capabilities: {} }).connect());
  assert.throws(() => new WalletController({ pins: { ...pins, network: 'pubnet' }, validators: {}, request: async () => ({}) }), /refused/);
});

test('no network, no default: the toolchain, the agent handoff and the envelope check take the session\'s explicitly', async () => {
  const { WalletToolchain } = await import('../server/toolchain.mjs');
  const { checkPreparedEnvelope } = await import('../server/network.mjs');
  assert.throws(() => new AgentHandoff(), /refused/);
  assert.throws(() => new AgentHandoff({ network: { ...MAINNET } }), /refused/);
  assert.throws(() => new WalletToolchain({ executable: '/fixed/ozpb', workRoot: tmpdir(), rpcUrl: 'https://rpc.example/',
    registrySnapshot: '{}', registryRoots: '{}', registryMinimumVersion: 6 }), /refused/);
  assert.throws(() => checkPreparedEnvelope({}, Buffer.alloc(0), Networks.TESTNET), /refused/);
});
