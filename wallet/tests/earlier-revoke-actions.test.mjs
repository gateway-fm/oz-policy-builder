// Removal of a grant an earlier backend session installed. A restarted backend holds no record of
// it, but removal must always be possible: the wallet lists the account's rules as stored now, the
// owner picks one, and the passkey signs `remove_context_rule` for exactly the bytes shown.
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Address, Keypair, Networks, SorobanDataBuilder, TransactionBuilder, hash, xdr } from '@stellar/stellar-sdk';
import { RULE_ID, installable, removedEvent } from './install-fixture.mjs';
import { WalletNetwork } from '../server/network.mjs';
import { WALLET_NETWORKS } from '../shared/networks.mjs';

/** A recovery or admin rule: any call (`Default` context), one signer, no policy limiting it. */
const RECOVERY_ID = RULE_ID + 1;
const recoveryRuleXdr = ({ id = RECOVERY_ID, context = xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Default')]), policies = [] } = {}) => {
  const fields = { context_type: context, id: xdr.ScVal.scvU32(id),
    name: xdr.ScVal.scvString('recovery'), policies: xdr.ScVal.scvVec(policies.map((p) => new Address(p).toScVal())),
    policy_ids: xdr.ScVal.scvVec(policies.map((_, i) => xdr.ScVal.scvU32(i))),
    signer_ids: xdr.ScVal.scvVec([xdr.ScVal.scvU32(2)]), signers: xdr.ScVal.scvVec([xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Delegated'),
      new Address(Keypair.fromRawEd25519Seed(Buffer.alloc(32, 8)).publicKey()).toScVal()])]), valid_until: xdr.ScVal.scvVoid() };
  return xdr.ScVal.scvMap(Object.keys(fields).sort().map((key) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val: fields[key] })))
    .toXDR('base64');
};

async function earlierSession({ recovery = false, extra = () => [] } = {}) {
  const f = await installable();
  // Installed by an earlier session: on the account, with no record in this backend.
  f.state.installed = true;
  const ruleXdr = f.rule.toXDR('base64');
  f.network.accountRules = async (account) => {
    assert.equal(account, f.f.wallet.contractId);
    return { ledger: f.state.ledger, rules: [{ id: 7, xdr: f.f.ownerRuleXdr }, ...(f.state.installed ? [{ id: RULE_ID, xdr: ruleXdr }] : []),
      ...(recovery ? [{ id: RECOVERY_ID, xdr: recoveryRuleXdr() }] : []), ...extra(f)] };
  };
  return { f, ruleXdr };
}
const ownerEntryOf = (prepared) => xdr.TransactionEnvelope.fromXDR(prepared.assembly.envelope_xdr_base64, 'base64')
  .v1.tx.operations[0].body.invokeHostFunctionOp.auth[0].toXDR('base64');

test('a rule an earlier session installed is listed, removed with the passkey and verified', async () => {
  const { f, ruleXdr } = await earlierSession();
  const listed = await f.actions['account-rules']({ wallet: f.f.wallet });
  assert.deepEqual(listed.rules.map((r) => [r.id, r.owner, r.grant]), [[7, true, false], [RULE_ID, false, true]]);
  assert.equal(listed.rules[1].xdr, ruleXdr);
  const prepared = await f.actions['prepare-earlier-revoke']({ wallet: f.f.wallet, ruleId: RULE_ID });
  assert.equal(prepared.display.installation.from_earlier_session, true);
  assert.equal(prepared.display.installation.transaction, null);
  assert.equal(prepared.ruleXdr, ruleXdr);
  assert.equal(f.submissions.length, 0, 'nothing sent before the passkey');
  const signed = await f.signEntry(ownerEntryOf(prepared));
  const result = await f.actions['confirm-earlier-revoke']({ id: prepared.action.id, signedAuthEntriesXdr: signed });
  assert.equal(result.removal.status, 'removed');
  assert.equal(result.removal.ruleReadback, 'absent');
  assert.deepEqual(f.submissions.map((s) => s.stage), ['revoke-policy']);
  const status = await f.actions.status({});
  assert.deepEqual(status.earlierRemovals.map((r) => [r.ruleId, r.status]), [[RULE_ID, 'removed']]);
  // Never twice.
  await assert.rejects(() => f.actions['confirm-earlier-revoke']({ id: prepared.action.id, signedAuthEntriesXdr: signed }), /unavailable|refused/);
  await assert.rejects(() => f.actions['prepare-earlier-revoke']({ wallet: f.f.wallet, ruleId: RULE_ID }), /refused/);
});

test('an earlier session\'s removal refuses the owner rule, a missing rule and changed bytes', async () => {
  const { f } = await earlierSession();
  await assert.rejects(() => f.actions['prepare-earlier-revoke']({ wallet: f.f.wallet, ruleId: 7 }), /refused/, 'the owner rule');
  await assert.rejects(() => f.actions['prepare-earlier-revoke']({ wallet: f.f.wallet, ruleId: RULE_ID + 5 }), /refused/, 'no such rule');
  const prepared = await f.actions['prepare-earlier-revoke']({ wallet: f.f.wallet, ruleId: RULE_ID });
  const signed = await f.signEntry(ownerEntryOf(prepared));
  // The rule changed between preparation and the passkey: the bytes shown are no longer what would be removed.
  const original = f.readback;
  f.readback = () => ({ ...original(), xdr: f.rule.toXDR('base64').replace(/.$/, 'A') });
  await assert.rejects(() => f.actions['confirm-earlier-revoke']({ id: prepared.action.id, signedAuthEntriesXdr: signed }), /refused/);
  assert.equal(f.submissions.length, 0);
});

test('an earlier session\'s removal offers only grant-shaped rules, never a recovery or admin rule', async () => {
  const { f } = await earlierSession({ recovery: true });
  const listed = await f.actions['account-rules']({ wallet: f.f.wallet });
  assert.deepEqual(listed.rules.map((r) => [r.id, r.owner, r.grant]), [[7, true, false], [RULE_ID, false, true], [RECOVERY_ID, false, false]]);
  await assert.rejects(() => f.actions['prepare-earlier-revoke']({ wallet: f.f.wallet, ruleId: RECOVERY_ID }), /refused/);
  assert.equal(f.submissions.length, 0);
  // The grant beside it can still be removed.
  assert.equal((await f.actions['prepare-earlier-revoke']({ wallet: f.f.wallet, ruleId: RULE_ID })).ruleXdr, f.rule.toXDR('base64'));
});

/**
 * A restarted backend: a fresh WalletNetwork over a stub endpoint, its fee payer never funded by an
 * account or deployment step. Funding, the removal's draft, the fee payer's sequence and submission go
 * through it; the account reads stay the fixture's.
 */
function restartedNetwork(t, f) {
  const root = mkdtempSync(join(tmpdir(), 'wallet-earlier-restart-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const account = f.f.wallet.contractId;
  const calls = [];
  let sent;
  const server = {
    getNetwork: async () => ({ passphrase: Networks.TESTNET, protocolVersion: 30 }),
    getLatestLedger: async () => ({ sequence: f.state.ledger }),
    getAccount: async (address) => { calls.push('getAccount'); return { accountId: () => address, sequenceNumber: () => '4242' }; },
    getLedgerEntries: async (key) => ({ latestLedger: f.state.ledger, entries: [{ key, lastModifiedLedgerSeq: f.state.ledger - 1,
      val: xdr.LedgerEntryData.account(new xdr.AccountEntry({ accountId: key.account.accountId, balance: 100_000_000n, seqNum: 4242n,
        numSubEntries: 0, inflationDest: null, flags: 0, homeDomain: '', thresholds: Buffer.from([1, 0, 0, 0]), signers: [],
        ext: xdr.AccountEntryExt.v0() })) }] }),
    simulateTransaction: async (tx, _resources, mode) => {
      calls.push(mode);
      const op = tx.toEnvelope().v1.tx.operations[0].body.invokeHostFunctionOp;
      if (mode === 'record') {
        const entry = new xdr.SorobanAuthorizationEntry({ credentials: xdr.SorobanCredentials.sorobanCredentialsAddressV2(
          new xdr.SorobanAddressCredentials({ address: new Address(account).toScAddress(), nonce: 77n, signatureExpirationLedger: 0,
            signature: xdr.ScVal.scvVoid() })), rootInvocation: new xdr.SorobanAuthorizedInvocation({
          function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(op.hostFunction.invokeContract), subInvocations: [] }) });
        return { latestLedger: f.state.ledger, result: { auth: [entry], retval: xdr.ScVal.scvVoid() } };
      }
      return { latestLedger: f.state.ledger, result: { auth: op.auth, retval: xdr.ScVal.scvVoid() } };
    },
    sendTransaction: async (tx) => {
      calls.push('send');
      sent = tx;
      f.state.ledger += 1;
      Object.assign(f.state, { installed: false });
      return { status: 'PENDING', hash: Buffer.from(tx.hash()).toString('hex') };
    },
    getTransaction: async () => {
      const events = [removedEvent(account)];
      const preimage = new xdr.InvokeHostFunctionSuccessPreImage({ returnValue: xdr.ScVal.scvVoid(), events });
      return { status: 'SUCCESS', ledger: f.state.ledger, latestLedger: f.state.ledger, envelopeXdr: sent.toEnvelope(),
        resultXdr: new xdr.TransactionResult({ feeCharged: 2000n, ext: xdr.TransactionResultExt.v0(),
          result: xdr.TransactionResultResult.txSuccess([xdr.OperationResult.opInner(xdr.OperationResultTr.invokeHostFunction(
            xdr.InvokeHostFunctionResult.invokeHostFunctionSuccess(Buffer.from(hash(preimage.toXDR())))))]) }),
        resultMetaXdr: xdr.TransactionMeta.v3(new xdr.TransactionMetaV3({ ext: xdr.ExtensionPoint.v0(), txChangesBefore: [],
          operations: [new xdr.OperationMeta({ changes: [] })], txChangesAfter: [],
          sorobanMeta: new xdr.SorobanTransactionMeta({ ext: xdr.SorobanTransactionMetaExt.v0(), events,
            returnValue: xdr.ScVal.scvVoid(), diagnosticEvents: [] }) })) };
    },
  };
  // Enforce-mode assembly: the resources and fee only, as the RPC's preparation would set them.
  const assemble = (tx) => ({ build: () => {
    const envelope = xdr.TransactionEnvelope.fromXDR(tx.toEnvelope().toXDR());
    envelope.v1.tx.fee = 2000;
    envelope.v1.tx.ext = xdr.TransactionExt.sorobanData(new SorobanDataBuilder().setResourceFee(1000).build());
    return TransactionBuilder.fromXDR(envelope.toXDR('base64'), Networks.TESTNET);
  } });
  const network = new WalletNetwork({ network: WALLET_NETWORKS.testnet, rpcUrl: 'https://rpc.example/testnet', journalRoot: root, server,
    assemble, pause: async () => {}, fetchImpl: async (url) => { calls.push(`friendbot ${new URL(url).origin}`); return new Response('{}'); } });
  const n = f.network;
  n.payerAddress = network.payerAddress;
  n.fundPayer = () => network.fundPayer();
  n.fundRemoval = () => network.fundRemoval();
  Object.defineProperty(n, 'canSubmit', { get: () => network.canSubmit, configurable: true });
  Object.defineProperty(n, 'canSubmitRemoval', { get: () => network.canSubmitRemoval, configurable: true });
  n.prepareRemoval = (request) => network.prepareRemoval(request);
  n.sourceCapture = () => network.sourceCapture();
  n.submitEnvelope = (envelopeXdr, stage, options) => {
    f.submissions.push({ envelopeXdr, stage }); return network.submitEnvelope(envelopeXdr, stage, options);
  };
  return { network, calls };
}

test('a rule on the account\'s own calls, or on a policy the account has bound, is not a grant this wallet installs', async () => {
  const callContract = (address) => xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('CallContract'), new Address(address).toScVal()]);
  const policyOf = (f) => scValPolicies(f.rule)[0];
  const { f } = await earlierSession({ extra: (fx) => [
    // A guardian or recovery rule over the account's own functions, limited by some policy.
    { id: RULE_ID + 2, xdr: recoveryRuleXdr({ id: RULE_ID + 2, context: callContract(fx.f.wallet.contractId), policies: [policyOf(fx)] }) },
    // A rule whose target is the grant's own policy contract, bound in another rule.
    { id: RULE_ID + 3, xdr: recoveryRuleXdr({ id: RULE_ID + 3, context: callContract(policyOf(fx)), policies: [policyOf(fx)] }) },
  ] });
  const listed = await f.actions['account-rules']({ wallet: f.f.wallet });
  assert.deepEqual(listed.rules.map((r) => [r.id, r.grant]), [[7, false], [RULE_ID, true], [RULE_ID + 2, false], [RULE_ID + 3, false]]);
  for (const ruleId of [RULE_ID + 2, RULE_ID + 3]) {
    await assert.rejects(() => f.actions['prepare-earlier-revoke']({ wallet: f.f.wallet, ruleId }), /refused/, String(ruleId));
  }
  assert.equal(f.submissions.length, 0);
});
const scValPolicies = (rule) => rule.map.find((e) => e.key.sym.toString() === 'policies').val.vec.map((v) => Address.fromScVal(v).toString());

test('after a restart, with no account or deployment step, an earlier session\'s grant is still removed', async (t) => {
  const { f } = await earlierSession();
  const { network, calls } = restartedNetwork(t, f);
  assert.equal(network.canSubmitRemoval, false, 'a restarted backend has not funded its fee payer yet');
  const prepared = await f.actions['prepare-earlier-revoke']({ wallet: f.f.wallet, ruleId: RULE_ID });
  assert.match(prepared.action.id, /^[0-9a-f]{64}$/);
  assert.equal(prepared.limits.feePayer, network.payerAddress);
  const signed = await f.signEntry(ownerEntryOf(prepared));
  const result = await f.actions['confirm-earlier-revoke']({ id: prepared.action.id, signedAuthEntriesXdr: signed });
  assert.equal(result.removal.status, 'removed');
  assert.deepEqual(f.submissions.map((s) => s.stage), ['revoke-policy']);
  assert.equal(calls.filter((c) => c === 'send').length, 1);
  assert.ok(calls.includes('friendbot https://friendbot.stellar.org'), 'the testnet payer was funded for the removal itself');
});

test('the in-session and the earlier-session removal actions do not consume each other', async () => {
  const { f } = await earlierSession();
  const prepared = await f.actions['prepare-earlier-revoke']({ wallet: f.f.wallet, ruleId: RULE_ID });
  const signed = await f.signEntry(ownerEntryOf(prepared));
  await assert.rejects(() => f.actions['confirm-revoke']({ id: prepared.action.id, signedAuthEntriesXdr: signed }), /refused/);
  assert.equal(f.submissions.length, 0);
});

test('the page lists the rules, shows the removal it derived itself and collects the passkey signature', async () => {
  const { WalletController } = await import('../overlay/files/src/policy-builder/client/controller.mjs');
  const { reviewRemoval, revokeConsent, validateRemovalAssembly } = await import('../shared/revoke.mjs');
  const { validateSignedAuthorization } = await import('../shared/signature.mjs');
  const { WALLET_NETWORKS } = await import('../shared/networks.mjs');
  const { ACCOUNT_WASM, WEBAUTHN_WASM } = await import('../shared/approval.mjs');
  const { f } = await earlierSession({ recovery: true });
  const signedBy = [];
  const controller = new WalletController({
    pins: { network: 'testnet', networkId: WALLET_NETWORKS.testnet.networkId, accountWasm: ACCOUNT_WASM, verifierWasm: WEBAUTHN_WASM },
    validators: { reviewRemoval, revokeConsent, validateRemovalAssembly, validateSignedAuthorization },
    origin: 'http://localhost:3000', request: async (name, body) => f.actions[name](body),
    sign: async ({ approval, checked }) => { signedBy.push(approval.installation.ruleXdr); return f.signEntry(checked.authEntriesXdr[0]); } });
  await controller.connect();
  // An attached wallet: the earlier session's account, by its public locator.
  controller.attachWallet(f.f.wallet);
  assert.ok(controller.state.wallet, 'the wallet is attached');
  await controller.listRules();
  assert.deepEqual(controller.state.accountRules.rules.map((r) => [r.id, r.owner, r.grant]),
    [[7, true, false], [RULE_ID, false, true], [RECOVERY_ID, false, false]]);
  // The page refuses a rule that is not a grant before asking the backend.
  const asked = [];
  const request = f.actions['prepare-earlier-revoke'];
  f.actions['prepare-earlier-revoke'] = async (body) => { asked.push(body.ruleId); return request(body); };
  await assert.rejects(() => controller.prepareEarlierRevoke(RECOVERY_ID), /refused/);
  assert.deepEqual(asked, []);
  // A fee payer that cannot pay (mainnet: the operator has not funded it) refuses with a reason the page explains.
  const fund = f.network.fundRemoval;
  f.network.fundRemoval = async () => { throw Object.assign(new Error('wallet network operation refused'), { reason: 'payer_unfunded' }); };
  await assert.rejects(() => controller.prepareEarlierRevoke(RULE_ID), (error) => error.reason === 'payer_unfunded');
  assert.equal(controller.state.earlierRevokePreview, null);
  f.network.fundRemoval = fund;
  await controller.prepareEarlierRevoke(RULE_ID);
  assert.equal(controller.state.earlierRevokePreview.display.installation.from_earlier_session, true);
  await controller.revokeEarlier();
  assert.equal(controller.state.earlierRemoval.status, 'removed');
  assert.deepEqual(signedBy, [f.rule.toXDR('base64')], 'the passkey was asked once, for exactly the listed bytes');
});
