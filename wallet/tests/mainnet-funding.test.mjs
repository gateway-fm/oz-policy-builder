// Mainnet's funding model: the fee payer is the operator's own key from a 0600 file, never printed,
// returned or journaled, and never a signer on an account; every transaction is held to a
// per-transaction fee cap and a session spend cap before it is signed; the wallet funds and creates
// nothing (no Friendbot, no sample funding, no delegate account), and pinned code missing on the
// network is refused with its upload command instead of being uploaded. Every key here is a throwaway
// generated at run time.
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect, isDeepStrictEqual } from 'node:util';
import test from 'node:test';
import { Account, Address, Keypair, Networks, Operation, SorobanDataBuilder, TransactionBuilder, hash, xdr } from '@stellar/stellar-sdk';
import { WALLET_NETWORKS } from '../shared/networks.mjs';
import { ACCOUNT_WASM, WEBAUTHN_WASM } from '../shared/approval.mjs';
import { FeePayer, loadFeePayerKey } from '../server/fee-payer.mjs';
import { MAINNET_FEE_DEFAULTS, loadWalletConfig } from '../server/config.mjs';
import { WalletNetwork } from '../server/network.mjs';
import { readPinnedWasm, uploadInstruction } from '../server/pinned-code.mjs';
import { setup, deploymentFixture } from './actions-fixture.mjs';

const MAINNET = WALLET_NETWORKS.mainnet;
const scratch = (t, prefix = 'wallet-mainnet-funding-') => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
};
const keyFile = (root, secret, mode = 0o600, name = 'payer.key') => {
  const path = join(root, name);
  writeFileSync(path, `${secret}\n`, { mode });
  chmodSync(path, mode);
  return path;
};

// --- the operator's key --------------------------------------------------------------------------------

test('the fee payer key is read only from a 0600 file owned by this user, and never shown', (t) => {
  const root = scratch(t);
  const secret = Keypair.random().secret();
  const payer = loadFeePayerKey(keyFile(root, secret));
  assert.equal(payer.address, Keypair.fromSecret(secret).publicKey());
  assert.equal(payer.operator, true);
  for (const shown of [JSON.stringify(payer), inspect(payer), String(Object.keys(payer)), JSON.stringify({ ...payer })]) {
    assert.equal(shown.includes(secret), false, shown);
  }
  for (const [mode, reason] of [[0o640, /mode 0600/], [0o644, /mode 0600/], [0o604, /mode 0600/]]) {
    assert.throws(() => loadFeePayerKey(keyFile(root, secret, mode, `k${mode}`)), (error) => reason.test(error.startup)
      && !error.startup.includes(secret) && !error.message.includes(secret));
  }
  const link = join(root, 'link.key');
  symlinkSync(keyFile(root, secret, 0o600, 'target.key'), link);
  assert.throws(() => loadFeePayerKey(link), (error) => /not a symlink/.test(error.startup));
  for (const content of [Keypair.random().publicKey(), `${secret} `, `${secret}\n${secret}`, 'not a key', '']) {
    const path = join(root, `c${Math.random()}`);
    writeFileSync(path, content, { mode: 0o600 });
    assert.throws(() => loadFeePayerKey(path), (error) => /secret seed/.test(error.startup) && !error.startup.includes(secret));
  }
  assert.throws(() => loadFeePayerKey('relative/payer.key'), (error) => /absolute/.test(error.startup));
  assert.throws(() => loadFeePayerKey(join(root, 'missing.key')), (error) => /does not exist/.test(error.startup));
});

test('mainnet configuration: the operator key is required, caps default conservatively and stay under their ceilings', (t) => {
  const root = scratch(t);
  const workRoot = join(root, 'work');
  mkdirSync(workRoot, { mode: 0o700 });
  const executable = join(root, 'ozpb');
  writeFileSync(executable, '#!/bin/sh\nexit 99\n', { mode: 0o700 });
  writeFileSync(join(root, 'registry.json'), '{}', { mode: 0o600 });
  // A production-shaped root policy with its persisted checkpoint: mainnet refuses the development root.
  writeFileSync(join(root, 'roots.json'), JSON.stringify({ threshold: 1, keys: { operator: 'ab'.repeat(32) }, checkpoint: { version: '6', log_index: '6', root: 'ef'.repeat(32), revocations: {} } }),
    { mode: 0o600 });
  const path = join(root, 'operator.json');
  const keyPath = keyFile(root, Keypair.random().secret());
  const base = { executable, workRoot, rpcUrl: 'https://rpc.example/', registrySnapshotPath: join(root, 'registry.json'),
    registryRootsPath: join(root, 'roots.json'), registryMinimumVersion: 6 };
  const save = (value) => writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
  save({ ...base, network: 'mainnet', feePayerKeyPath: keyPath });
  const config = loadWalletConfig(path);
  assert.deepEqual({ ...config.fees }, MAINNET_FEE_DEFAULTS);
  assert.deepEqual(MAINNET_FEE_DEFAULTS, { maxFeeStroops: 10_000_000, maxUploadFeeStroops: 120_000_000, sessionSpendCapStroops: 150_000_000 });
  assert.equal(config.feePayer.operator, true);
  assert.equal(JSON.stringify(config).includes(readFileSync(keyPath, 'utf8').trim()), false, 'the configuration never shows the key');
  save({ ...base, network: 'mainnet', feePayerKeyPath: keyPath, maxFeeStroops: 2_000_000, sessionSpendCapStroops: 130_000_000 });
  assert.deepEqual({ ...loadWalletConfig(path).fees }, { maxFeeStroops: 2_000_000, maxUploadFeeStroops: 120_000_000, sessionSpendCapStroops: 130_000_000 });
  // The upload and session caps are the operator's settings, raised from the simulated costs when an upload needs it.
  save({ ...base, network: 'mainnet', feePayerKeyPath: keyPath, maxUploadFeeStroops: 200_000_000, sessionSpendCapStroops: 300_000_000 });
  assert.deepEqual({ ...loadWalletConfig(path).fees }, { maxFeeStroops: 10_000_000, maxUploadFeeStroops: 200_000_000, sessionSpendCapStroops: 300_000_000 });
  for (const [name, value] of [
    ['no operator key', { ...base, network: 'mainnet' }],
    ['a per-transaction cap above 1 XLM', { ...base, network: 'mainnet', feePayerKeyPath: keyPath, maxFeeStroops: 10_000_001 }],
    ['an upload cap above 50 XLM', { ...base, network: 'mainnet', feePayerKeyPath: keyPath, maxUploadFeeStroops: 500_000_001, sessionSpendCapStroops: 500_000_000 }],
    ['a session cap above 50 XLM', { ...base, network: 'mainnet', feePayerKeyPath: keyPath, sessionSpendCapStroops: 500_000_001 }],
    ['an upload cap above the session cap', { ...base, network: 'mainnet', feePayerKeyPath: keyPath, maxUploadFeeStroops: 200_000_000 }],
    ['a session cap below the upload cap', { ...base, network: 'mainnet', feePayerKeyPath: keyPath, sessionSpendCapStroops: 100_000_000 }],
    ['a fractional cap', { ...base, network: 'mainnet', feePayerKeyPath: keyPath, maxFeeStroops: 1.5 }],
    ['no registry floor (versions start at 1)', { ...base, network: 'mainnet', feePayerKeyPath: keyPath, registryMinimumVersion: 0 }],
    ['a registry floor above the persisted checkpoint (a rollback)', { ...base, network: 'mainnet', feePayerKeyPath: keyPath, registryMinimumVersion: 7 }],
    ['an operator key on testnet', { ...base, feePayerKeyPath: keyPath }],
    ['caps on testnet', { ...base, maxFeeStroops: 1_000_000 }],
  ]) {
    save(value);
    assert.throws(() => loadWalletConfig(path), /configuration|refused/, name);
  }
  // Testnet keeps its disposable key and its fixed ceilings, with no session cap.
  save(base);
  const testnet = loadWalletConfig(path);
  assert.equal(testnet.feePayer.operator, false);
  assert.deepEqual({ ...testnet.fees }, { maxFeeStroops: 10_000_000, maxUploadFeeStroops: 150_000_000, sessionSpendCapStroops: null });
});

// --- the network layer -------------------------------------------------------------------------------------

/** A mainnet WalletNetwork over a fake endpoint; `fee` is what enforce-mode assembly charges. */
function mainnet(t, { payerFunded = true, fee = 2000, fees = MAINNET_FEE_DEFAULTS, change = () => {}, spent = '0', balance = 1_000_000_000n } = {}) {
  const root = scratch(t);
  const key = Keypair.random();
  const feePayer = new FeePayer(key, true);
  const calls = [];
  let sent;
  const header = new xdr.LedgerHeader({ ledgerVersion: 30, previousLedgerHash: Buffer.alloc(32),
    scpValue: new xdr.StellarValue({ txSetHash: Buffer.alloc(32), closeTime: 1n, upgrades: [], ext: xdr.StellarValueExt.stellarValueBasic() }),
    txSetResultHash: Buffer.alloc(32), bucketListHash: Buffer.alloc(32), ledgerSeq: 100, totalCoins: 0n, feePool: 0n, inflationSeq: 0,
    idPool: 0n, baseFee: 100, baseReserve: 5_000_000, maxTxSetSize: 100, skipList: [Buffer.alloc(32), Buffer.alloc(32), Buffer.alloc(32), Buffer.alloc(32)],
    ext: xdr.LedgerHeaderExt.v0() });
  const accountEntry = (g, balance) => ({ key: xdr.LedgerKey.account(new xdr.LedgerKeyAccount({ accountId: Keypair.fromPublicKey(g).xdrAccountId() })),
    val: xdr.LedgerEntryData.account(new xdr.AccountEntry({ accountId: Keypair.fromPublicKey(g).xdrAccountId(), balance, seqNum: 7n,
      numSubEntries: 0, inflationDest: null, flags: 0, homeDomain: '', thresholds: Buffer.from([1, 0, 0, 0]), signers: [],
      ext: xdr.AccountEntryExt.v0() })), lastModifiedLedgerSeq: 90, liveUntilLedgerSeq: undefined });
  const server = {
    getNetwork: async () => ({ passphrase: Networks.PUBLIC, protocolVersion: 30 }),
    getLatestLedger: async () => ({ sequence: 100, id: Buffer.from(hash(header.toXDR())).toString('hex'), headerXdr: header, protocolVersion: 30 }),
    getLedgerEntries: async (key) => ({ latestLedger: 100,
      entries: payerFunded ? [accountEntry(feePayer.address, balance)].filter((e) => same(e.key, key)) : [] }),
    getAccount: async (address) => new Account(address, '7'),
    simulateTransaction: async (tx, _resources, mode) => { calls.push({ mode }); return { latestLedger: 100, result: { auth: [], retval: xdr.ScVal.scvVoid() } }; },
    sendTransaction: async (tx) => { calls.push({ sent: true }); sent = tx; return { status: 'PENDING', hash: Buffer.from(tx.hash()).toString('hex') }; },
    getTransaction: async () => ({
      status: 'SUCCESS', ledger: 101, latestLedger: 101, envelopeXdr: sent.toEnvelope(),
      resultXdr: new xdr.TransactionResult({ feeCharged: 1500n, ext: xdr.TransactionResultExt.v0(),
        result: xdr.TransactionResultResult.txSuccess([xdr.OperationResult.opInner(xdr.OperationResultTr.invokeHostFunction(
          xdr.InvokeHostFunctionResult.invokeHostFunctionSuccess(Buffer.from(hash(
            new xdr.InvokeHostFunctionSuccessPreImage({ returnValue: xdr.ScVal.scvVoid(), events: [] }).toXDR())))))]) }),
      resultMetaXdr: xdr.TransactionMeta.v3(new xdr.TransactionMetaV3({ ext: xdr.ExtensionPoint.v0(), txChangesBefore: [],
        operations: [new xdr.OperationMeta({ changes: [] })], txChangesAfter: [],
        sorobanMeta: new xdr.SorobanTransactionMeta({ ext: xdr.SorobanTransactionMetaExt.v0(), events: [], returnValue: xdr.ScVal.scvVoid(),
          diagnosticEvents: [] }) })),
    }),
  };
  change(server, feePayer);
  const assemble = (tx) => ({ build: () => {
    const envelope = xdr.TransactionEnvelope.fromXDR(tx.toEnvelope().toXDR());
    envelope.v1.tx.fee = fee;
    envelope.v1.tx.ext = xdr.TransactionExt.sorobanData(new SorobanDataBuilder().setResourceFee(fee - 1000 > 0 ? fee - 1000 : 0).build());
    return TransactionBuilder.fromXDR(envelope.toXDR('base64'), Networks.PUBLIC);
  } });
  const network = new WalletNetwork({ network: MAINNET, rpcUrl: 'https://rpc.example/', journalRoot: root, server, feePayer, fees, spentStroops: spent,
    fetchImpl: async (url) => { calls.push({ fetched: url }); return new Response('{}'); }, assemble, pause: async () => {} });
  return { network, calls, root, key, feePayer };
}
const same = (a, b) => Buffer.from(a.toXDR()).equals(Buffer.from(b.toXDR()));
/** The account every contract call here is made on: `contractCall` is its `remove_context_rule(1)`, authorized by it. */
const REMOVAL_ACCOUNT = 'CAWGOGD3YYSPUR6CPT6PE33DCUIGFNBVZVA5WEDGK2YM34FRLIUQBT5A';
const REMOVAL = { account: REMOVAL_ACCOUNT };
const contractCall = (payer, signature = xdr.ScVal.scvVoid(), { target = REMOVAL_ACCOUNT, functionName = 'remove_context_rule',
  authorizer = target } = {}) => {
  const call = new xdr.InvokeContractArgs({ contractAddress: new Address(target).toScAddress(), functionName,
    args: [xdr.ScVal.scvU32(1)] });
  const entry = new xdr.SorobanAuthorizationEntry({ credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
    new xdr.SorobanAddressCredentials({ address: new Address(authorizer).toScAddress(), nonce: 5n, signatureExpirationLedger: 150, signature })),
  rootInvocation: new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call), subInvocations: [] }) });
  return new TransactionBuilder(new Account(payer, '7'), { fee: '1000', networkPassphrase: Networks.PUBLIC })
    .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(call), auth: [entry] }))
    .setTimeout(60).build().toEnvelope().toXDR('base64');
};

test('mainnet: the wallet never funds its fee payer; an unfunded operator account refuses as payer_unfunded', async (t) => {
  const unfunded = mainnet(t, { payerFunded: false });
  await assert.rejects(() => unfunded.network.fundPayer(), (error) => error.reason === 'payer_unfunded');
  assert.equal(unfunded.calls.some((call) => call.fetched), false, 'no Friendbot request');
  assert.equal(unfunded.network.canSubmit, false);
  const funded = mainnet(t);
  await funded.network.fundPayer();
  assert.equal(funded.network.canSubmit, true);
  const account = await funded.network.payerAccount();
  assert.deepEqual(account, { exists: true, balanceStroops: '1000000000', minimumStroops: '10000000', spendableStroops: '990000000', ledger: 100 });
});

test('mainnet: after a restart a removal needs only its own fee from the operator account, read through the real network', async (t) => {
  const account = 'CAWGOGD3YYSPUR6CPT6PE33DCUIGFNBVZVA5WEDGK2YM34FRLIUQBT5A';
  // The record-mode draft of `remove_context_rule(1)`: the account's own authorization of exactly that call.
  const recordRemoval = (server) => {
    const simulate = server.simulateTransaction;
    server.simulateTransaction = async (tx, resources, mode) => {
      if (mode !== 'record') return simulate(tx, resources, mode);
      const call = tx.toEnvelope().v1.tx.operations[0].body.invokeHostFunctionOp.hostFunction.invokeContract;
      const entry = new xdr.SorobanAuthorizationEntry({ credentials: xdr.SorobanCredentials.sorobanCredentialsAddressV2(
        new xdr.SorobanAddressCredentials({ address: new Address(account).toScAddress(), nonce: 5n, signatureExpirationLedger: 0,
          signature: xdr.ScVal.scvVoid() })), rootInvocation: new xdr.SorobanAuthorizedInvocation({
        function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call), subInvocations: [] }) });
      return { latestLedger: 100, result: { auth: [entry], retval: xdr.ScVal.scvVoid() } };
    };
  };
  const draft = (network) => network.prepareRemoval({ wallet: { contractId: account }, ruleId: 1, ownerReadLedger: 100 });
  // Spendable 200,000 stroops (two base reserves held back): below the 1 XLM per-transaction cap, above the removal's 2,000.
  const f = mainnet(t, { balance: 10_200_000n, change: recordRemoval });
  assert.equal(f.network.canSubmitRemoval, false, 'a restarted backend has checked nothing yet');
  await assert.rejects(() => f.network.fundPayer(), (error) => error.reason === 'payer_unfunded', 'too little for every other step');
  await f.network.fundRemoval();
  assert.equal(f.network.canSubmitRemoval, true);
  assert.equal(f.network.canSubmit, false, 'checking for a removal opens no other write');
  assert.equal((await draft(f.network)).assembly.fee_stroops, 2000);
  const removed = await f.network.submitEnvelope(contractCall(f.network.payerAddress), 'revoke-policy', REMOVAL);
  assert.match(removed.hash, /^[0-9a-f]{64}$/);
  await assert.rejects(() => f.network.submitEnvelope(contractCall(f.network.payerAddress), 'install-policy'), /refused/);
  assert.equal(f.calls.filter((call) => call.sent).length, 1);
  // An account that cannot pay even the removal's fee is refused with the reason, before drafting and before signing.
  const poor = mainnet(t, { balance: 10_001_000n, change: recordRemoval });
  await poor.network.fundRemoval();
  await assert.rejects(() => draft(poor.network), (error) => error.reason === 'payer_unfunded');
  await assert.rejects(() => poor.network.submitEnvelope(contractCall(poor.network.payerAddress), 'revoke-policy', REMOVAL),
    (error) => error.reason === 'payer_unfunded');
  assert.equal(poor.calls.some((call) => call.sent), false);
  assert.deepEqual(readdirSync(poor.root), ['0000.session.json'], 'nothing journaled: nothing was signed');
  // No account at all.
  await assert.rejects(() => mainnet(t, { payerFunded: false }).network.fundRemoval(), (error) => error.reason === 'payer_unfunded');
});

test('mainnet: a transaction above the per-transaction cap or the session cap is refused before it is signed', async (t) => {
  const over = mainnet(t, { fee: 10_000_001 });
  await over.network.fundPayer();
  await assert.rejects(() => over.network.submitEnvelope(contractCall(over.network.payerAddress), 'revoke-policy', REMOVAL),
    (error) => error.reason === 'fee_cap');
  assert.equal(over.calls.some((call) => call.sent), false);
  assert.deepEqual(readdirSync(over.root), ['0000.session.json'], 'nothing journaled: nothing was signed');
  // An installation keeps room for one removal (4500) under the cap.
  const tight = { maxFeeStroops: 4_500, maxUploadFeeStroops: 4_500, sessionSpendCapStroops: 11_500 };
  const session = mainnet(t, { fee: 4_000, fees: tight });
  await session.network.fundPayer();
  const first = await session.network.submitEnvelope(contractCall(session.network.payerAddress), 'install-policy');
  // The receipt says 1500 was charged; the cap still counts the 4000 the transaction could be charged,
  // so an RPC reporting a low fee cannot give back budget.
  assert.equal(first.feeChargedStroops, '1500');
  assert.equal(session.network.spentStroops, '4000');
  await assert.rejects(() => session.network.submitEnvelope(contractCall(session.network.payerAddress), 'install-policy'),
    (error) => error.reason === 'spend_cap', '4000 counted plus 4000 more plus the removal reserve passes the 11500 cap');
  assert.equal(session.calls.filter((call) => call.sent).length, 1, 'the second was never sent');
});

test('mainnet: the fee payer is never a signer: an envelope naming it as a signer is refused before signing', async (t) => {
  const f = mainnet(t);
  await f.network.fundPayer();
  const delegated = xdr.ScVal.scvMap([
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('context_rule_ids'), val: xdr.ScVal.scvVec([xdr.ScVal.scvU32(1)]) }),
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('signers'), val: xdr.ScVal.scvMap([new xdr.ScMapEntry({
      key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Delegated'), new Address(f.network.payerAddress).toScVal()]),
      val: xdr.ScVal.scvBytes(Buffer.alloc(0)) })]) }),
  ]);
  await assert.rejects(() => f.network.submitEnvelope(contractCall(f.network.payerAddress, delegated), 'revoke-policy', REMOVAL), /refused/);
  // Its own transfer, authorized by the source account's signature, is refused on mainnet: the operator's key moves no XLM.
  const asset = MAINNET.nativeAsset;
  const transfer = Operation.invokeContractFunction({ contract: asset, function: 'transfer', args: [new Address(f.network.payerAddress).toScVal(),
    new Address('CAWGOGD3YYSPUR6CPT6PE33DCUIGFNBVZVA5WEDGK2YM34FRLIUQBT5A').toScVal(), xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: 1n }))] });
  await assert.rejects(() => f.network.submitOperation(transfer, 'fund-account'), /refused/);
  assert.equal(f.calls.some((call) => call.sent), false);
  assert.deepEqual(readdirSync(f.root), ['0000.session.json']);
});

test('mainnet: a confirmed submission journals no part of the operator key', async (t) => {
  const f = mainnet(t);
  await f.network.fundPayer();
  await f.network.submitEnvelope(contractCall(f.network.payerAddress), 'revoke-policy', REMOVAL);
  const journal = readdirSync(f.root).map((name) => readFileSync(join(f.root, name), 'utf8')).join('\n');
  assert.ok(journal.includes('"stage":"revoke-policy"'), 'the submission is journaled');
  assert.equal(journal.includes(f.key.secret()), false);
  assert.equal(journal.includes(Buffer.from(f.key.rawSecretKey()).toString('base64')), false);
  assert.equal(journal.includes(Buffer.from(f.key.rawSecretKey()).toString('hex')), false);
});

test('mainnet: a missing delegate account is never created; it refuses as delegate_unfunded', async (t) => {
  const f = mainnet(t);
  const delegate = Keypair.random().publicKey();
  await assert.rejects(() => f.network.ensureDelegateAccount(delegate), (error) => error.reason === 'delegate_unfunded');
  assert.deepEqual(await f.network.classicAccount(delegate), { exists: false, minimumStroops: '10000000', ledger: 100 });
  assert.equal(f.calls.some((call) => call.fetched), false, 'no Friendbot request');
});

// --- the actions ---------------------------------------------------------------------------------------------

const mainnetActions = (overrides = {}, options = {}) => setup({ ...options, network: { profile: MAINNET,
  fees: MAINNET_FEE_DEFAULTS, spentStroops: '0', ...overrides } });

test('mainnet account preview: the owner funds the account; the caps are shown before anything is signed', async () => {
  const { actions, calls, f } = mainnetActions();
  const preview = await actions['prepare-account']({ credentialId: f.wallet.credentialId, publicKey: f.wallet.publicKey });
  assert.deepEqual(calls, []);
  assert.equal(preview.summary.sampleFundingStroops, '0');
  assert.equal(preview.summary.ownerFunds, true);
  assert.equal(preview.summary.maxFeeStroops, 10_000_000);
  assert.equal(preview.summary.sessionSpendCapStroops, 150_000_000);
  const status = await actions.status({});
  assert.equal(status.network, 'mainnet');
  assert.deepEqual(status.fees, { maxFeeStroops: 10_000_000, maxUploadFeeStroops: 120_000_000, sessionSpendCapStroops: 150_000_000, spentStroops: '0' });
  assert.equal(status.feePayer.ownerFunded, true);
  // Confirmation deploys the verifier and the account and moves no XLM from the fee payer.
  const result = await actions['confirm-account']({ id: preview.action.id });
  assert.deepEqual(result.wallet, f.wallet);
  assert.equal(result.receipts.length, 2);
  assert.equal(calls.includes('fund-account'), false);
  assert.deepEqual(calls.filter((call) => Array.isArray(call) && call[0] === 'code').map((call) => call[1]), [ACCOUNT_WASM, WEBAUTHN_WASM]);
});

test('mainnet: pinned account or verifier code missing on the network is refused, never uploaded', async () => {
  for (const missing of [ACCOUNT_WASM, WEBAUTHN_WASM]) {
    const { actions, calls, f } = mainnetActions({ codePresent: async (hash) => ({ present: hash !== missing, ledger: 100 }) });
    const preview = await actions['prepare-account']({ credentialId: f.wallet.credentialId, publicKey: f.wallet.publicKey });
    await assert.rejects(() => actions['confirm-account']({ id: preview.action.id }), (error) => error.reason === 'pinned_code_missing');
    assert.equal(calls.some((call) => ['deploy-verifier', 'deploy-account', 'fund', 'upload-policy'].includes(call)), false);
  }
});

test('mainnet readiness names each missing pinned Wasm with its upload command and, given the Wasm, its simulated cost', async (t) => {
  const dir = scratch(t);
  const uploads = [];
  const { actions } = mainnetActions({
    codePresent: async (hash) => ({ present: hash === WEBAUTHN_WASM, ledger: 100 }),
    payerAccount: async () => ({ exists: true, balanceStroops: '200000000', minimumStroops: '10000000', spendableStroops: '190000000', ledger: 100 }),
    uploadCost: async (wasm) => { uploads.push(wasm); return { resourceFeeStroops: '5000', feeStroops: '5100', ledger: 100 }; },
    diagnosticEvents: async () => ({ returned: true, ledger: 100 }),
  }, { pinnedWasmDir: dir });
  const ready = await actions.readiness({});
  assert.equal(ready.network, 'mainnet');
  assert.deepEqual(ready.pinned.find((p) => p.name === 'verifier'), { name: 'verifier', hash: WEBAUTHN_WASM, present: true });
  const account = ready.pinned.find((p) => p.name === 'account');
  assert.equal(account.present, false);
  assert.equal(account.upload.command, `stellar contract upload --wasm ${dir}/${ACCOUNT_WASM}.wasm --network mainnet --source <your funded mainnet key>`);
  assert.equal(account.upload.simulatedFeeStroops, null, 'no reproduced Wasm in the directory: no cost yet');
  assert.equal(uploads.length, 0);
  assert.equal(ready.helper.configured, false);
  assert.match(ready.helper.instruction, /stellar contract deploy --wasm ozpb_atomic_live_helper\.wasm --network mainnet/);
  assert.equal(ready.helper.uploadSimulatedFeeStroops, null, 'no reproduced helper Wasm in the directory: no cost yet');
  assert.deepEqual(ready.fees, { ...MAINNET_FEE_DEFAULTS, spentStroops: '0' });
  // The reproduced Wasm is read only when its SHA-256 is the pinned hash.
  const wasm = Buffer.from('0061736d01000000', 'hex');
  const wasmHash = Buffer.from(hash(wasm)).toString('hex');
  writeFileSync(join(dir, `${wasmHash}.wasm`), wasm);
  assert.deepEqual(readPinnedWasm(dir, wasmHash), wasm);
  writeFileSync(join(dir, `${'a'.repeat(64)}.wasm`), wasm);
  assert.equal(readPinnedWasm(dir, 'a'.repeat(64)), null, 'a file whose bytes are not the pinned hash');
  symlinkSync(join(dir, `${wasmHash}.wasm`), join(dir, `${'b'.repeat(64)}.wasm`));
  assert.equal(readPinnedWasm(dir, 'b'.repeat(64)), null, 'a symlink');
  assert.deepEqual({ ...uploadInstruction(MAINNET, null, wasmHash) }, { wasmPath: `<pinnedWasmDir>/${wasmHash}.wasm`,
    command: `stellar contract upload --wasm <pinnedWasmDir>/${wasmHash}.wasm --network mainnet --source <your funded mainnet key>` });
});

test('mainnet: a delegate is a key in memory whose account the owner funds; the wallet creates none', async () => {
  const reads = [];
  const { actions } = mainnetActions({
    classicAccount: async (address) => { reads.push(address); return { exists: false, minimumStroops: '10000000', ledger: 100 }; },
    ensureDelegateAccount: async () => assert.fail('nothing creates the account on mainnet'),
  }, { native: {} });
  const created = await actions['create-delegate']({});
  assert.match(created.address, /^G[A-Z2-7]{55}$/);
  assert.deepEqual(created.account, { exists: false, minimumStroops: '10000000' });
  assert.deepEqual(reads, [created.address]);
});

test('mainnet: the sample transfer waits for the owner to fund the account', async () => {
  const { actions, f } = mainnetActions({ transferReadiness: async () => ({ ledger: 100, recipientExists: true, covered: false }) });
  const preview = await actions['prepare-account']({ credentialId: f.wallet.credentialId, publicKey: f.wallet.publicKey });
  const created = await actions['confirm-account']({ id: preview.action.id });
  await assert.rejects(() => actions['prepare-sample']({ wallet: created.wallet }), (error) => error.reason === 'account_unfunded');
});

test('the fee payer is never the grant\'s delegate nor a signer in the reviewed authority', async () => {
  const payer = Keypair.random().publicKey();
  const { actions } = mainnetActions({ payerAddress: payer });
  await assert.rejects(() => actions.generate({ recordId: '4'.repeat(64), delegateAddress: payer, grantName: 'test', maxCalls: 1,
    validUntilLedger: 150 }), /refused/);
  // A testnet review whose authority list names the fee payer as a signer on any rule is refused.
  const f = deploymentFixture();
  const preview = await f.actions['prepare-deploy']({ artifactId: f.artifactId });
  const deployed = await f.actions['confirm-deploy']({ id: preview.action.id });
  const verdict = f.f.intent.authority.verdict;
  verdict.authority_list = [...verdict.authority_list, { ...structuredClone(verdict.authority_list[0]), rule_id: 9,
    requirement: { kind: 'all_of', signers: [{ kind: 'delegated', address: f.network.payerAddress }] } }];
  await assert.rejects(() => f.actions.review({ deploymentId: deployed.deploymentId, wallet: f.f.wallet }), /refused/);
});

test('mainnet deployment shows the policy upload\'s simulated cost first and refuses one above either cap', async () => {
  for (const [cost, spent, reason] of [['5100', '0', null], ['120000001', '0', 'fee_cap'], ['100000000', '45000000', 'spend_cap']]) {
    const f = deploymentFixture(() => {}, { network: { profile: MAINNET, fees: MAINNET_FEE_DEFAULTS, spentStroops: spent,
      uploadCost: async () => ({ resourceFeeStroops: cost, feeStroops: cost, ledger: 100 }) } });
    const prepared = f.actions['prepare-deploy']({ artifactId: f.artifactId });
    if (reason) await assert.rejects(() => prepared, (error) => error.reason === reason, `${cost} after ${spent}`);
    else assert.equal((await prepared).summary.uploadSimulatedFeeStroops, cost);
  }
});

test('mainnet: an upload above the upload cap is refused naming the setting and the simulated cost; raised, it proceeds', async () => {
  const cost = '190000000';
  const deploy = (fees) => {
    const f = deploymentFixture(() => {}, { network: { profile: MAINNET, fees, spentStroops: '0',
      uploadCost: async () => ({ resourceFeeStroops: '189000000', feeStroops: cost, ledger: 100 }) } });
    return f.actions['prepare-deploy']({ artifactId: f.artifactId });
  };
  await assert.rejects(() => deploy(MAINNET_FEE_DEFAULTS), (error) => error.reason === 'fee_cap'
    && isDeepStrictEqual(error.limit, { setting: 'maxUploadFeeStroops', simulatedFeeStroops: cost, neededStroops: cost }));
  // The session cap is named the same way, with the least that holds the upload, the policy's creation,
  // an installation and a removal.
  const raised = { ...MAINNET_FEE_DEFAULTS, maxUploadFeeStroops: 200_000_000, sessionSpendCapStroops: 219_999_999 };
  await assert.rejects(() => deploy(raised), (error) => error.reason === 'spend_cap'
    && isDeepStrictEqual(error.limit, { setting: 'sessionSpendCapStroops', simulatedFeeStroops: cost, neededStroops: '220000000' }));
  assert.equal((await deploy({ ...raised, sessionSpendCapStroops: 220_000_000 })).summary.uploadSimulatedFeeStroops, cost);
});

test('mainnet: the fee payer named as an authorizing address is refused before signing', async (t) => {
  const f = mainnet(t);
  await f.network.fundPayer();
  // An entry whose credentials name the payer itself: the payer's envelope signature would authorize it.
  const call = new xdr.InvokeContractArgs({ contractAddress: new Address(MAINNET.nativeAsset).toScAddress(), functionName: 'transfer',
    args: [new Address(f.network.payerAddress).toScVal(), new Address('CAWGOGD3YYSPUR6CPT6PE33DCUIGFNBVZVA5WEDGK2YM34FRLIUQBT5A').toScVal(),
      xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: 1n }))] });
  const entry = new xdr.SorobanAuthorizationEntry({ credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
    new xdr.SorobanAddressCredentials({ address: new Address(f.network.payerAddress).toScAddress(), nonce: 5n, signatureExpirationLedger: 150,
      signature: xdr.ScVal.scvVoid() })),
  rootInvocation: new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call), subInvocations: [] }) });
  const envelope = new TransactionBuilder(new Account(f.network.payerAddress, '7'), { fee: '1000', networkPassphrase: Networks.PUBLIC })
    .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(call), auth: [entry] }))
    .setTimeout(60).build().toEnvelope().toXDR('base64');
  await assert.rejects(() => f.network.submitEnvelope(envelope, 'use-grant'), /refused/);
  assert.equal(f.calls.some((c) => c.sent), false);
  assert.deepEqual(readdirSync(f.root), ['0000.session.json']);
});

test('mainnet: a Wasm upload is held to its own cap, every other transaction to the per-transaction cap', async (t) => {
  const fees = { maxFeeStroops: 3_000, maxUploadFeeStroops: 50_000, sessionSpendCapStroops: 1_000_000 };
  const upload = mainnet(t, { fee: 40_000, fees });
  await upload.network.fundPayer();
  // The upload's receipt fails the stored-hash check, but only after the fee checks let it through to be sent.
  await assert.rejects(() => upload.network.upload(Buffer.from('0061736d01000000', 'hex'), Buffer.from(hash(Buffer.from('0061736d01000000', 'hex'))).toString('hex')));
  assert.equal(upload.calls.filter((c) => c.sent).length, 1, '40000 is within the upload cap');
  const call = mainnet(t, { fee: 40_000, fees });
  await call.network.fundPayer();
  await assert.rejects(() => call.network.submitEnvelope(contractCall(call.network.payerAddress), 'revoke-policy', REMOVAL),
    (error) => error.reason === 'fee_cap', 'the same 40000 is above the per-transaction cap');
  const over = mainnet(t, { fee: 50_001, fees });
  await over.network.fundPayer();
  await assert.rejects(() => over.network.upload(Buffer.from('0061736d01000000', 'hex'), Buffer.from(hash(Buffer.from('0061736d01000000', 'hex'))).toString('hex')),
    (error) => error.reason === 'fee_cap');
});

test('mainnet: after an uncertain submission its whole fee stays counted and nothing else is sent', async (t) => {
  const f = mainnet(t, { fee: 4_000, fees: { maxFeeStroops: 4_500, maxUploadFeeStroops: 4_500, sessionSpendCapStroops: 100_000 },
    change: (server) => { server.sendTransaction = async () => { throw new Error('lost response'); }; } });
  await f.network.fundPayer();
  await assert.rejects(() => f.network.submitEnvelope(contractCall(f.network.payerAddress), 'revoke-policy', REMOVAL), /refused/);
  assert.equal(f.network.spentStroops, '4000');
  assert.equal(f.network.canSubmit, false);
  await assert.rejects(() => f.network.submitEnvelope(contractCall(f.network.payerAddress), 'revoke-policy', REMOVAL), /refused/);
  assert.equal(f.network.spentStroops, '4000', 'a refused second attempt adds nothing');
});

test('a refusal from the fee payer keeps its reason through the use and removal actions', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../server/actions.mjs', import.meta.url), 'utf8');
  for (const stage of ['use-grant', 'revoke-policy']) {
    // The removal also names the account it removes from (`{ account }`).
    const at = source.search(new RegExp(`'${stage}'(, \\{ account[^}]*\\})?\\); \\} catch`));
    assert.ok(at > 0, stage);
    assert.match(source.slice(at, at + 260), /refuse\(error\)|throw because\(error\.reason\)|rethrow\(error\)/, `${stage} keeps the reason`);
  }
});

test('the fee payer is found by its raw key too, as an External signer would carry it', async () => {
  const { payerMentioned } = await import('../server/actions.mjs');
  const payer = Keypair.random();
  const hex = Buffer.from(payer.rawPublicKey()).toString('hex');
  assert.equal(payerMentioned({ signers: [{ kind: 'delegated', address: payer.publicKey() }] }, payer.publicKey()), true);
  assert.equal(payerMentioned({ signers: [{ kind: 'external', public_key: hex }] }, payer.publicKey()), true);
  assert.equal(payerMentioned({ signers: [{ kind: 'external', key_hex: `${hex.toUpperCase()}01` }] }, payer.publicKey()), true);
  assert.equal(payerMentioned({ signers: [{ kind: 'external', public_key: Buffer.from(Keypair.random().rawPublicKey()).toString('hex') }] },
    payer.publicKey()), false);
});

test('mainnet: the spend cap counts every fee sent from this work root, not only this session\'s', async (t) => {
  const { journaledSpend } = await import('../server/network.mjs');
  const { mkdirSync } = await import('node:fs');
  const workRoot = scratch(t, 'wallet-work-spend-');
  const intended = (dir, serial, fee, networkId = MAINNET.networkId) => {
    const tx = new TransactionBuilder(new Account(Keypair.random().publicKey(), '7'), { fee: String(fee), networkPassphrase: Networks.PUBLIC })
      .addOperation(Operation.bumpSequence({ bumpTo: '9' })).setTimeout(60).build();
    mkdirSync(join(workRoot, dir, 'journal'), { recursive: true, mode: 0o700 });
    writeFileSync(join(workRoot, dir, 'journal', `${serial}.intended.json`), JSON.stringify({ stage: 'revoke-policy', hash: 'a'.repeat(64),
      networkId, envelopeXdr: tx.toEnvelope().toXDR('base64'), status: 'submission_unknown' }), { mode: 0o600 });
  };
  intended('wallet-session-earlier', '0001', 1_200_000);
  intended('wallet-session-earlier', '0002', 3_400_000);
  intended('wallet-session-other', '0001', 500_000);
  writeFileSync(join(workRoot, 'wallet-session-earlier', 'journal', '0003.confirmed.json'), '{}', { mode: 0o600 });
  assert.equal(journaledSpend(workRoot, MAINNET), '5100000');
  // A session started with it carries it against the cap.
  const f = mainnet(t, { fee: 4_000, fees: { maxFeeStroops: 4_500, maxUploadFeeStroops: 4_500, sessionSpendCapStroops: 5_102_000 },
    spent: journaledSpend(workRoot, MAINNET) });
  assert.equal(f.network.spentStroops, '5100000');
  await f.network.fundPayer();
  await assert.rejects(() => f.network.submitEnvelope(contractCall(f.network.payerAddress), 'install-policy'), (error) => error.reason === 'spend_cap');
  // Past serial 9999 the names grow a digit; those entries count too.
  intended('wallet-session-other', '10000', 700_000);
  assert.equal(journaledSpend(workRoot, MAINNET), '5800000');
  // An entry from another network, or one that does not decode, refuses: the work root cannot be accounted.
  intended('wallet-session-wrong', '0001', 100, WALLET_NETWORKS.testnet.networkId);
  assert.throws(() => journaledSpend(workRoot, MAINNET), (error) => /journal/.test(error.startup));
});

test('mainnet: a final journal entry a crash left truncated is counted at the largest cap, never as nothing', async (t) => {
  const { journaledSpend } = await import('../server/network.mjs');
  const workRoot = scratch(t, 'wallet-work-truncated-');
  const journal = join(workRoot, 'wallet-session-crashed', 'journal');
  mkdirSync(journal, { recursive: true, mode: 0o700 });
  const tx = new TransactionBuilder(new Account(Keypair.random().publicKey(), '7'), { fee: '1200000', networkPassphrase: Networks.PUBLIC })
    .addOperation(Operation.bumpSequence({ bumpTo: '9' })).setTimeout(60).build();
  const whole = JSON.stringify({ stage: 'deploy-policy', hash: 'a'.repeat(64), networkId: MAINNET.networkId,
    envelopeXdr: tx.toEnvelope().toXDR('base64'), status: 'submission_unknown' });
  writeFileSync(join(journal, '0001.intended.json'), whole, { mode: 0o600 });
  writeFileSync(join(journal, '0001.confirmed.json'), '{}', { mode: 0o600 });
  // The process stopped while writing the next intended entry: whether that transaction left is unknown.
  writeFileSync(join(journal, '0002.intended.json'), whole.slice(0, 40), { mode: 0o600 });
  const caps = { maxFeeStroops: 10_000_000, maxUploadFeeStroops: 200_000_000 };
  assert.equal(journaledSpend(workRoot, MAINNET, caps), String(1_200_000 + 200_000_000));
  // An empty final entry is the same case.
  writeFileSync(join(journal, '0002.intended.json'), '', { mode: 0o600, flag: 'w' });
  assert.equal(journaledSpend(workRoot, MAINNET, caps), String(1_200_000 + 200_000_000));
  // Anything after it means it was not the last write: an unreadable entry in the middle still refuses.
  writeFileSync(join(journal, '0003.intended.json'), whole, { mode: 0o600 });
  assert.throws(() => journaledSpend(workRoot, MAINNET, caps), (error) => /journal/.test(error.startup));
  rmSync(join(journal, '0003.intended.json'));
  writeFileSync(join(journal, '0002.submitted.json'), '{}', { mode: 0o600 });
  assert.throws(() => journaledSpend(workRoot, MAINNET, caps), (error) => /journal/.test(error.startup), 'a later phase of the same entry');
});

test('readiness probes whether the endpoint returns diagnostic events, which the live check and removal need', async () => {
  for (const events of [true, false]) {
    const { actions } = mainnetActions({
      codePresent: async () => ({ present: true, ledger: 100 }),
      payerAccount: async () => ({ exists: true, balanceStroops: '200000000', minimumStroops: '10000000', spendableStroops: '190000000', ledger: 100 }),
      diagnosticEvents: async () => ({ returned: events, ledger: 100 }),
    });
    const ready = await actions.readiness({});
    assert.deepEqual(ready.diagnosticEvents, { returned: events, ledger: 100 });
  }
});

test('a simulation answer without diagnostic events is its own reason, from the network layer too', async (t) => {
  const { ruleReadbackResult } = await import('../server/install.mjs');
  assert.throws(() => ruleReadbackResult({ latestLedger: 100, error: 'HostError: Error(Contract, #3000)', events: [] },
    { account: 'CAWGOGD3YYSPUR6CPT6PE33DCUIGFNBVZVA5WEDGK2YM34FRLIUQBT5A' }), (error) => error.reason === 'no_diagnostic_events');
  const { NETWORK_REASONS } = await import('../server/network.mjs');
  const { REFUSAL_REASONS } = await import('../server/http.mjs');
  assert.ok(NETWORK_REASONS.includes('no_diagnostic_events') && REFUSAL_REASONS.has('no_diagnostic_events'));
});

test('mainnet: once this session has installed a grant, using it keeps room only for its removal', async (t) => {
  const fees = { maxFeeStroops: 4_500, maxUploadFeeStroops: 4_500, sessionSpendCapStroops: 14_000 };
  // No installation yet: a step keeps room for one and for its removal (4000 + 4000 + 2 × 4500 > 14000).
  const before = mainnet(t, { fee: 4_000, fees, spent: '4000' });
  await before.network.fundPayer();
  await assert.rejects(() => before.network.submitEnvelope(contractCall(before.network.payerAddress), 'use-grant'),
    (error) => error.reason === 'spend_cap');
  // Installed in this session: the use needs room only for the removal (4000 + 4000 + 4500 = 12500).
  const after = mainnet(t, { fee: 4_000, fees });
  await after.network.fundPayer();
  await after.network.submitEnvelope(contractCall(after.network.payerAddress), 'install-policy');
  await after.network.submitEnvelope(contractCall(after.network.payerAddress), 'use-grant');
  assert.equal(after.network.spentStroops, '8000');
});

test('the removal stage\'s exemptions go only to a removal: remove_context_rule on the named account, authorized by it', async (t) => {
  const fees = { maxFeeStroops: 4_500, maxUploadFeeStroops: 4_500, sessionSpendCapStroops: 14_000 };
  const other = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC';
  for (const [label, envelope, options] of [
    ['another function', (payer) => contractCall(payer, undefined, { functionName: 'transfer' }), REMOVAL],
    ['another contract', (payer) => contractCall(payer, undefined, { target: other, authorizer: other }), REMOVAL],
    ['authorized by another address', (payer) => contractCall(payer, undefined, { authorizer: other }), REMOVAL],
    ['no account named', (payer) => contractCall(payer), undefined],
    ['another account named', (payer) => contractCall(payer), { account: other }],
  ]) {
    // Spent past the cap and funded for removals only: a real removal would still go, so only its shape can refuse it.
    const f = mainnet(t, { fee: 4_000, fees, spent: '14000', balance: 10_200_000n });
    await f.network.fundRemoval();
    await assert.rejects(() => f.network.submitEnvelope(envelope(f.network.payerAddress), 'revoke-policy', options), /refused/, label);
    assert.equal(f.calls.some((call) => call.sent), false, label);
  }
  const real = mainnet(t, { fee: 4_000, fees, spent: '14000', balance: 10_200_000n });
  await real.network.fundRemoval();
  await real.network.submitEnvelope(contractCall(real.network.payerAddress), 'revoke-policy', REMOVAL);
  assert.equal(real.calls.filter((call) => call.sent).length, 1);
});

test('mainnet: removal is never blocked by the session cap, and every other step leaves room for an installation and a removal', async (t) => {
  const fees = { maxFeeStroops: 4_500, maxUploadFeeStroops: 4_500, sessionSpendCapStroops: 14_000 };
  // 0 spent: an ordinary step needs room for itself plus an installation and a removal (4000 + 2 × 4500 = 13000).
  const ok = mainnet(t, { fee: 4_000, fees });
  await ok.network.fundPayer();
  await ok.network.submitEnvelope(contractCall(ok.network.payerAddress), 'deploy-policy');
  assert.equal(ok.network.spentStroops, '4000');
  // 4000 spent: another ordinary step would leave 14000 - 8000 = 6000, less than both reserves.
  await assert.rejects(() => ok.network.submitEnvelope(contractCall(ok.network.payerAddress), 'deploy-policy'),
    (error) => error.reason === 'spend_cap');
  // The installation only needs room for the removal after it (4000 + 4000 + 4500 = 12500).
  await ok.network.submitEnvelope(contractCall(ok.network.payerAddress), 'install-policy');
  assert.equal(ok.network.spentStroops, '8000');
  // 8000 spent: an installation now would leave no room for its removal; a removal always goes.
  await assert.rejects(() => ok.network.submitEnvelope(contractCall(ok.network.payerAddress), 'install-policy'),
    (error) => error.reason === 'spend_cap');
  const spentOut = mainnet(t, { fee: 4_000, fees, spent: '14000' });
  await spentOut.network.fundPayer();
  await spentOut.network.submitEnvelope(contractCall(spentOut.network.payerAddress), 'revoke-policy', REMOVAL);
  assert.equal(spentOut.network.spentStroops, '18000', 'counted, past the cap: removal is exempt from it');
  // The per-transaction cap still holds for a removal.
  const over = mainnet(t, { fee: 4_501, fees, spent: '14000' });
  await over.network.fundPayer();
  await assert.rejects(() => over.network.submitEnvelope(contractCall(over.network.payerAddress), 'revoke-policy', REMOVAL),
    (error) => error.reason === 'fee_cap');
});
