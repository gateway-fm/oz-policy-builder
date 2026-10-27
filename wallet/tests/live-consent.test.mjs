import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, Asset, Keypair, Networks, StrKey, xdr } from '@stellar/stellar-sdk';
import { installCall } from '../shared/assembly.mjs';
import { LIVE_SIGNATURE_LEDGERS, checkLiveOwnerEntry, consentDisplay, liveCases, liveGrant, liveShape } from '../shared/live-consent.mjs';

const SAC = Asset.native().contractId(Networks.TESTNET);
const ACCOUNT = StrKey.encodeContract(Buffer.alloc(32, 41));
const POLICY = StrKey.encodeContract(Buffer.alloc(32, 42));
const HELPER = StrKey.encodeContract(Buffer.alloc(32, 43));
const VERIFIER = StrKey.encodeContract(Buffer.alloc(32, 44));
const DELEGATE = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 45)).publicKey();
const RECIPIENT = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 46)).publicKey();
const N = 1030;

function spec({ amount = '1000000', state = [{ call_count_per_installation: { max_calls: 1 } }] } = {}) {
  return { smart_account: { address: ACCOUNT }, rules: [{ context: { contract: SAC }, state,
    authorization: { signers: [{ delegated: { address: DELEGATE } }] },
    allowed_calls: [{ fn: 'transfer', args: [{ i: 0, c: { eq_address: { value: 'SELF' } } },
      { i: 1, c: { eq_address: { value: RECIPIENT } } }, { i: 2, c: { eq_i128: { value: amount } } }] }] }] };
}
function approval(change = (intent) => intent) {
  const intent = change({ operation: 'add_context_rule', account_contract: ACCOUNT, context_contract: SAC, rule_name: 'live-check',
    valid_until_ledger: 5000, delegate_signers: [{ kind: 'delegated', address: DELEGATE }],
    policies: [{ policy_index: 0, address: POLICY, install_params: { kind: 'generated' } }] });
  return { intent, ownerRuleId: 0, commitment: 'c'.repeat(64),
    wallet: { contractId: ACCOUNT, verifier: VERIFIER, publicKey: `04${'11'.repeat(64)}`, credentialId: 'AQ' } };
}
const cases = (a = approval(), expiry = N) => liveCases({ approval: a, spec: spec(), helper: HELPER, policyCodeHash: 'b'.repeat(64),
  expectedRuleId: 1, signatureExpirationLedger: expiry });
function ownerEntry(change = () => {}) {
  const a = approval();
  const credentials = new xdr.SorobanAddressCredentials({ address: new Address(ACCOUNT).toScAddress(), nonce: 7n,
    signatureExpirationLedger: N, signature: xdr.ScVal.scvVoid() });
  const parts = { credentials, kind: 'sorobanCredentialsAddressV2', call: installCall(a.intent), subInvocations: [] };
  change(parts);
  return new xdr.SorobanAuthorizationEntry({ credentials: xdr.SorobanCredentials[parts.kind](parts.credentials),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({ function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(parts.call),
      subInvocations: parts.subInvocations }) }).toXDR('base64');
}

test('the owner entry the passkey may sign is exactly the reviewed installation, address-bound, for this account, expiring at N', () => {
  const a = approval();
  const checked = checkLiveOwnerEntry({ approval: a, cases: cases(), ownerEntryXdr: ownerEntry() });
  assert.deepEqual({ ...checked, authEntriesXdr: undefined }, { authEntriesXdr: undefined, ownerRuleId: 0, expirationLedger: N,
    authorityCommitment: 'c'.repeat(64) });
  const other = approval((intent) => ({ ...intent, rule_name: 'other-rule' }));
  for (const [label, change] of [
    ['expiry beyond N', (p) => { p.credentials.signatureExpirationLedger = N + 1; }],
    ['expiry before N', (p) => { p.credentials.signatureExpirationLedger = N - 1; }],
    ['another account', (p) => { p.credentials.address = new Address(StrKey.encodeContract(Buffer.alloc(32, 47))).toScAddress(); }],
    ['classic credentials', (p) => { p.kind = 'sorobanCredentialsAddress'; }],
    ['already signed', (p) => { p.credentials.signature = xdr.ScVal.scvVec([]); }],
    ['another installation', (p) => { p.call = installCall(other.intent); }],
    ['a sub-invocation', (p) => { p.subInvocations = [new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(installCall(a.intent)), subInvocations: [] })]; }],
  ]) {
    assert.throws(() => checkLiveOwnerEntry({ approval: a, cases: cases(), ownerEntryXdr: ownerEntry(change) }), /refused/, label);
  }
  assert.throws(() => checkLiveOwnerEntry({ approval: { ...a, ownerRuleId: 3 }, cases: cases(), ownerEntryXdr: ownerEntry() }), /refused/,
    'another owner rule than the cases were built for');
  assert.throws(() => checkLiveOwnerEntry({ approval: a, cases: cases(), ownerEntryXdr: `${ownerEntry()}\n` }), /refused/);
});

test('the consent statement allows an expiry at most 30 ledgers after the ledger it was prepared at', () => {
  const display = consentDisplay(cases(), { currentLedger: N - LIVE_SIGNATURE_LEDGERS });
  assert.equal(display.signature_expiration_ledger, N);
  for (const currentLedger of [N - LIVE_SIGNATURE_LEDGERS - 1, N - 1, N, N + 5]) {
    assert.throws(() => consentDisplay(cases(), { currentLedger }), /refused/, String(currentLedger));
  }
  const [permit, denial] = cases();
  assert.throws(() => consentDisplay([permit, { ...denial, amount: '1000002' }], { currentLedger: N - 10 }), /refused/);
  assert.throws(() => consentDisplay([permit, { ...denial, signature_expiration_ledger: N + 1 }], { currentLedger: N - 10 }), /refused/);
});

test('the shape is one exact native transfer of at most 1,000,000 stroops, with a call cap, installing exactly the reviewed grant', () => {
  assert.equal(liveGrant(spec()).supported, true);
  assert.equal(liveGrant(spec({ amount: '1000001' })).supported, false, 'the adjacent denial would exceed the helper bound');
  assert.equal(liveGrant(spec({ state: [] })).supported, false);
  const wallet = approval().wallet;
  for (const change of [
    (i) => ({ ...i, rule_name: 'a-rule-name-of-21-byt' }), (i) => ({ ...i, valid_until_ledger: null }),
    (i) => ({ ...i, delegate_signers: [{ kind: 'delegated', address: RECIPIENT }] }),
    (i) => ({ ...i, policies: [{ policy_index: 0, address: POLICY, install_params: { kind: 'spending_limit', spending_limit: '5', period_ledgers: 9 } }] }),
    (i) => ({ ...i, context_contract: POLICY }), (i) => ({ ...i, account_contract: POLICY }),
  ]) {
    const a = approval(change);
    assert.equal(liveShape({ spec: spec(), intent: a.intent, wallet }).supported, false);
    assert.throws(() => cases(a), /refused/);
  }
  const [permit, denial] = cases();
  assert.deepEqual([permit.amount, denial.amount], ['1000000', '1000001']);
});
