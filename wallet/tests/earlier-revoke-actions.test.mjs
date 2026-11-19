// Removal of a grant an earlier backend session installed. A restarted backend holds no record of
// it, but removal must always be possible: the wallet lists the account's rules as stored now, the
// owner picks one, and the passkey signs `remove_context_rule` for exactly the bytes shown.
import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, Keypair, xdr } from '@stellar/stellar-sdk';
import { RULE_ID, installable } from './install-fixture.mjs';

/** A recovery or admin rule: any call (`Default` context), one signer, no policy limiting it. */
const RECOVERY_ID = RULE_ID + 1;
const recoveryRuleXdr = () => {
  const fields = { context_type: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Default')]), id: xdr.ScVal.scvU32(RECOVERY_ID),
    name: xdr.ScVal.scvString('recovery'), policies: xdr.ScVal.scvVec([]), policy_ids: xdr.ScVal.scvVec([]),
    signer_ids: xdr.ScVal.scvVec([xdr.ScVal.scvU32(2)]), signers: xdr.ScVal.scvVec([xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Delegated'),
      new Address(Keypair.fromRawEd25519Seed(Buffer.alloc(32, 8)).publicKey()).toScVal()])]), valid_until: xdr.ScVal.scvVoid() };
  return xdr.ScVal.scvMap(Object.keys(fields).sort().map((key) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val: fields[key] })))
    .toXDR('base64');
};

async function earlierSession({ recovery = false } = {}) {
  const f = await installable();
  // Installed by an earlier session: on the account, with no record in this backend.
  f.state.installed = true;
  const ruleXdr = f.rule.toXDR('base64');
  f.network.accountRules = async (account) => {
    assert.equal(account, f.f.wallet.contractId);
    return { ledger: f.state.ledger, rules: [{ id: 7, xdr: f.f.ownerRuleXdr }, ...(f.state.installed ? [{ id: RULE_ID, xdr: ruleXdr }] : []),
      ...(recovery ? [{ id: RECOVERY_ID, xdr: recoveryRuleXdr() }] : [])] };
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
  await controller.prepareEarlierRevoke(RULE_ID);
  assert.equal(controller.state.earlierRevokePreview.display.installation.from_earlier_session, true);
  await controller.revokeEarlier();
  assert.equal(controller.state.earlierRemoval.status, 'removed');
  assert.deepEqual(signedBy, [f.rule.toXDR('base64')], 'the passkey was asked once, for exactly the listed bytes');
});
