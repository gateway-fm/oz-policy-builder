import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { Address, StrKey, xdr } from '@stellar/stellar-sdk';
import * as F from './live-enforcement-fixture.mjs';
import {
  HELPER_ERROR_CODES, POLICY_NO_TUPLE_MATCHED, helperCall, liveCase, transferCall, validateLiveCase,
} from '../shared/live-enforcement.mjs';

const { PROBE } = F;
const EMPTY = Buffer.alloc(0);
const refused = (input, reason, name = '') => {
  const verdict = validateLiveCase(input);
  assert.equal(verdict.outcome, 'failed', `${name} ${JSON.stringify(verdict)}`);
  assert.equal(verdict.reason, reason, `${name} ${JSON.stringify(verdict)}`);
  assert.equal(typeof verdict.detail, 'string');
  return verdict;
};
const OTHER = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 77));
const sha256hex = (base64) => createHash('sha256').update(Buffer.from(base64, 'base64')).digest('hex');

/** Owner installation entry and its proof, then the given transfer entry with the delegate's proof. */
function withTransfer(transfer, ruleIds, { amount = PROBE.permitAmount, proofs = [PROBE.delegate] } = {}) {
  const [install, ownerProof] = F.caseEntries({ amount });
  return [install, ownerProof, transfer, ...proofs.map((signer) => F.signerEntry(signer, F.authDigest(transfer, ruleIds)))];
}
const delegateOnly = [[F.delegated(PROBE.delegate), EMPTY]];
const sample = (entries, { amount = PROBE.permitAmount, changes, simulation } = {}) => ({
  intent: F.intent({ amount: amount.toString() }),
  envelopeXdr: F.envelopeXdr(entries, { amount }),
  simulation: simulation ?? F.permitSimulation(changes ?? F.permitChanges(entries, { amount }), { entries, amount }),
});

// --- what counts -------------------------------------------------------------------------------------

test('the probed permit is evidence: exact transfer under the candidate rule, balances and counter drop', () => {
  const input = F.permitSample();
  const verdict = validateLiveCase(input);
  assert.deepEqual(verdict, {
    outcome: 'permit', reason: 'candidate_permitted', enforcer: PROBE.policy, returned_rule_id: 1,
    balance_changes: { account: '-1000000', recipient: '1000000' },
    candidate_counter: { rule_id: 1, used_before: 0, used_after: 1, installed_in_simulation: true },
    amount: '1000000', envelope_xdr_sha256: sha256hex(input.envelopeXdr),
    simulation_ledger: PROBE.simulationLedger, signature_expiration_ledger: PROBE.expiry,
  });
  assert.ok(Object.isFrozen(verdict) && Object.isFrozen(verdict.balance_changes));
});

test('the probed denial is evidence: NoTupleMatched raised by the candidate policy inside the account authentication', () => {
  assert.equal(POLICY_NO_TUPLE_MATCHED, 6);
  const input = F.denialSample();
  assert.deepEqual(validateLiveCase(input), {
    outcome: 'deny', reason: 'policy_denied', enforcer: PROBE.policy, code: 6,
    host: 'HostError: Error(Auth, InvalidAction)', amount: '1000001', envelope_xdr_sha256: sha256hex(input.envelopeXdr),
    simulation_ledger: PROBE.simulationLedger, signature_expiration_ledger: PROBE.expiry,
  });
});

test('a passkey owner signs the installation in the account entry, with no owner entry of its own', () => {
  const entries = F.passkeyEntries({ ownerRule: 4 });
  const input = { ...sample(entries), intent: F.intent({ owner_rule_id: 4,
    owner_signer: { kind: 'external', verifier: F.PASSKEY.verifier, key_hex: F.PASSKEY.keyHex } }) };
  assert.equal(validateLiveCase(input).outcome, 'permit');
  // The passkey must actually be the owner's: a different key in the entry is refused.
  input.intent.owner_signer = { kind: 'external', verifier: F.PASSKEY.verifier, key_hex: `04${'33'.repeat(64)}` };
  refused(input, 'unexpected_signer');
});

test('a delegate already registered on the account is reused: its signer count rises and no lookup is written', () => {
  const entries = F.caseEntries();
  const changes = F.permitChanges(entries);
  const signerKey = F.keyed('SignerData', xdr.ScVal.scvU32(1));
  const signer = (count) => F.dataEntry(PROBE.account, signerKey, F.struct({ count: xdr.ScVal.scvU32(count), signer: F.delegated(PROBE.delegate) }));
  changes.signer = F.change(F.dataKey(PROBE.account, signerKey), signer(1), signer(2));
  delete changes.signerLookup;
  const instanceKey = xdr.ScVal.scvLedgerKeyContractInstance();
  changes.instance = F.change(F.dataKey(PROBE.account, instanceKey),
    F.dataEntry(PROBE.account, instanceKey, F.instance({ Count: 1, NextId: 1, NextSignerId: 2 })),
    F.dataEntry(PROBE.account, instanceKey, F.instance({ Count: 2, NextId: 2, NextPolicyId: 1, NextSignerId: 2 })));
  assert.equal(validateLiveCase(sample(entries, { changes })).outcome, 'permit');
});

// --- the transfer authorization -----------------------------------------------------------------------

test('refuses transfer entry with an unexecuted sub-invocation', () => {
  // The host test's shape: the executed adjacent transfer as root under rule 0, a never-executed
  // permit-amount transfer as its sub-invocation under the candidate rule, signed by owner and
  // delegate. The helper reports success because the candidate counted the unexecuted context.
  const amount = PROBE.denialAmount;
  const ruleIds = [0, PROBE.ruleId];
  const transfer = F.accountEntry(F.transferRoot(amount, [F.transferRoot(PROBE.permitAmount)]), ruleIds,
    [[F.delegated(PROBE.owner), EMPTY], [F.delegated(PROBE.delegate), EMPTY]]);
  const entries = withTransfer(transfer, ruleIds, { amount, proofs: [PROBE.owner, PROBE.delegate] });
  refused(sample(entries, { amount }), 'sub_invocations');
  // Alone, with every other part of the entry exact, a sub-invocation is still refused.
  const exact = F.accountEntry(F.transferRoot(PROBE.permitAmount, [F.transferRoot(PROBE.permitAmount)]), [PROBE.ruleId], delegateOnly);
  refused(sample(withTransfer(exact, [PROBE.ruleId])), 'sub_invocations');
  // And on the owner's installation entry.
  const [, , okTransfer, delegateProof] = F.caseEntries();
  const nested = F.installRoot();
  nested.subInvocations = [F.transferRoot()];
  const install = F.accountEntry(nested, [0], [[F.delegated(PROBE.owner), EMPTY]]);
  refused(sample([install, F.signerEntry(PROBE.owner, F.authDigest(install, [0])), okTransfer, delegateProof]), 'sub_invocations');
});

test('refuses context_rule_ids [0, candidate]', () => {
  for (const ruleIds of [[0, PROBE.ruleId], [PROBE.ruleId, 0], [0], [], [PROBE.ruleId, PROBE.ruleId], [2]]) {
    const transfer = F.accountEntry(F.transferRoot(), ruleIds, delegateOnly);
    refused(sample(withTransfer(transfer, ruleIds)), 'transfer_rule_ids');
  }
});

test('refuses owner entry rooted at the transfer', () => {
  const [install, ownerProof, transfer, delegateProof] = F.caseEntries();
  const ownerTransfer = F.accountEntry(F.transferRoot(), [0], [[F.delegated(PROBE.owner), EMPTY]]);
  const ownerTransferProof = F.signerEntry(PROBE.owner, F.authDigest(ownerTransfer, [0]));
  // In place of the installation, and beside it.
  refused(sample([ownerTransfer, ownerTransferProof, transfer, delegateProof]), 'owner_entry_scope');
  refused(sample([install, ownerProof, ownerTransfer, ownerTransferProof, transfer, delegateProof]), 'owner_entry_scope');
  // The owner's installation must be the approved one, argument for argument.
  const renamed = F.accountEntry(F.installRoot(F.delegated(PROBE.delegate), 'other-name'), [0], [[F.delegated(PROBE.owner), EMPTY]]);
  refused(sample([renamed, F.signerEntry(PROBE.owner, F.authDigest(renamed, [0])), transfer, delegateProof]), 'owner_entry_scope');
  // Under its own rule only.
  const otherRule = F.accountEntry(F.installRoot(), [0, 3], [[F.delegated(PROBE.owner), EMPTY]]);
  refused(sample([otherRule, F.signerEntry(PROBE.owner, F.authDigest(otherRule, [0, 3])), transfer, delegateProof]), 'owner_rule_ids');
});

test('refuses an extra signer', () => {
  const signers = [[F.delegated(PROBE.delegate), EMPTY], [F.delegated(OTHER), EMPTY]];
  const transfer = F.accountEntry(F.transferRoot(), [PROBE.ruleId], signers);
  refused(sample(withTransfer(transfer, [PROBE.ruleId], { proofs: [PROBE.delegate, OTHER] })), 'transfer_signers');
  // The delegate's proof bytes must be empty: its proof is its own entry.
  const proofBytes = F.accountEntry(F.transferRoot(), [PROBE.ruleId], [[F.delegated(PROBE.delegate), Buffer.from([1])]]);
  refused(sample(withTransfer(proofBytes, [PROBE.ruleId])), 'transfer_signers');
  // A transfer entry signed by someone other than the delegate.
  const stranger = F.accountEntry(F.transferRoot(), [PROBE.ruleId], [[F.delegated(OTHER), EMPTY]]);
  refused(sample(withTransfer(stranger, [PROBE.ruleId], { proofs: [OTHER] })), 'unexpected_signer');
  // The owner's installation with a second signer.
  const [, , transfer2, delegateProof] = F.caseEntries();
  const install = F.accountEntry(F.installRoot(), [0], [[F.delegated(PROBE.owner), EMPTY], [F.delegated(OTHER), EMPTY]]);
  const proofs = [PROBE.owner, OTHER].map((s) => F.signerEntry(s, F.authDigest(install, [0])));
  refused(sample([install, ...proofs, transfer2, delegateProof]), 'owner_signers');
});

test('refuses a transfer entry for another call, amount or recipient', () => {
  for (const root of [F.transferRoot(PROBE.permitAmount + 1n), F.transferRoot(PROBE.permitAmount - 1n),
    F.transferRoot(PROBE.permitAmount, [], OTHER), F.transferRoot(PROBE.permitAmount, [], PROBE.recipient, 'burn')]) {
    const transfer = F.accountEntry(root, [PROBE.ruleId], delegateOnly);
    refused(sample(withTransfer(transfer, [PROBE.ruleId])), 'transfer_root');
  }
});

test('refuses missing, duplicated and unbound entries', () => {
  const [install, ownerProof, transfer, delegateProof] = F.caseEntries();
  refused(sample([install, ownerProof]), 'transfer_entry_count');
  refused(sample([transfer, delegateProof]), 'owner_entry_count');
  const second = F.accountEntry(F.transferRoot(), [PROBE.ruleId], delegateOnly);
  refused(sample([install, ownerProof, transfer, delegateProof, second, F.signerEntry(PROBE.delegate, F.authDigest(second, [PROBE.ruleId]))]),
    'transfer_entry_count');
  // The delegate's own entry must authorize exactly this transfer entry's digest.
  refused(sample([install, ownerProof, transfer, F.signerEntry(PROBE.delegate, Buffer.alloc(32, 9))]), 'signer_entry');
  refused(sample([install, ownerProof, transfer]), 'signer_entry');
  refused(sample([install, ownerProof, transfer, delegateProof, delegateProof]), 'signer_entry');
  // Nothing else may be authorized: an entry for another address, or another root.
  refused(sample([install, ownerProof, transfer, delegateProof, F.signerEntry(OTHER, Buffer.alloc(32, 1))]), 'signer_entry');
});

test('refuses recording-shaped, foreign-network and differently expiring authorizations', () => {
  const [install, ownerProof, transfer, delegateProof] = F.caseEntries();
  const unsigned = xdr.SorobanAuthorizationEntry.fromXDR(transfer.toXDR());
  unsigned.credentials.addressV2.signature = xdr.ScVal.scvVoid();
  refused(sample([install, ownerProof, unsigned, delegateProof]), 'auth_payload');
  const late = F.accountEntry(F.transferRoot(), [PROBE.ruleId], delegateOnly, { expiry: PROBE.expiry + 1 });
  refused(sample([install, ownerProof, late, F.signerEntry(PROBE.delegate, F.authDigest(late, [PROBE.ruleId]))]), 'expiry');
  const source = new xdr.SorobanAuthorizationEntry({ credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(), rootInvocation: F.transferRoot() });
  refused(sample([install, ownerProof, transfer, delegateProof, source]), 'credentials');
  refused({ ...F.permitSample(), intent: F.intent({ network_id: 'ab'.repeat(32) }) }, 'intent');
});

// --- the simulated call -------------------------------------------------------------------------------

test('refuses a simulation of anything but the helper call for the approved case', () => {
  const entries = F.caseEntries();
  const base = sample(entries);
  refused({ ...base, envelopeXdr: F.envelopeXdr(entries, { contract: PROBE.policy }) }, 'not_the_helper_call');
  refused({ ...base, envelopeXdr: F.envelopeXdr(entries, { fn: 'transfer' }) }, 'not_the_helper_call');
  refused({ ...base, envelopeXdr: F.envelopeXdr(entries, { amount: PROBE.denialAmount }) }, 'not_the_helper_call');
  refused({ ...base, envelopeXdr: 'not xdr' }, 'not_the_helper_call');
});

test('refuses a simulation that needs restoration or that is later than the signatures', () => {
  const base = F.permitSample();
  refused({ ...base, simulation: { ...base.simulation, restorePreamble: { minResourceFee: '1' } } }, 'simulation');
  refused({ ...base, simulation: { ...base.simulation, latestLedger: PROBE.expiry + 1 } }, 'simulation');
  // Protocol 23 restores archived entries inside the invocation and reports them as created.
  const entries = F.caseEntries();
  refused(sample(entries, { simulation: F.permitSimulation(F.permitChanges(entries), { entries, archived: [0] }) }), 'simulation');
});

test('takes the raw RPC result only, as canonical base64 XDR', () => {
  const base = F.permitSample();
  refused({ ...base, simulation: { ...base.simulation, _parsed: true } }, 'simulation');
  const [first, ...rest] = base.simulation.stateChanges;
  refused({ ...base, simulation: { ...base.simulation, stateChanges: [{ ...first, key: `${first.key}\n` }, ...rest] } }, 'simulation');
  // Base64 that decodes to the same bytes but is not their encoding is refused, as everywhere in the wallet.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const malleable = (text) => {
    const i = text.length - text.match(/=*$/)[0].length - 1;
    const twisted = text.slice(0, i) + alphabet[alphabet.indexOf(text[i]) + 1] + text.slice(i + 1);
    assert.deepEqual(Buffer.from(twisted, 'base64'), Buffer.from(text, 'base64'));
    return twisted;
  };
  const padded = base.simulation.stateChanges.findIndex((c) => c.key.endsWith('='));
  assert.ok(padded >= 0);
  const twisted = base.simulation.stateChanges.map((c, i) => (i === padded ? { ...c, key: malleable(c.key) } : c));
  refused({ ...base, simulation: { ...base.simulation, stateChanges: twisted } }, 'simulation');
  refused({ ...base, simulation: { ...base.simulation, stateChanges: [{ ...first, after: xdr.LedgerKey.fromXDR(first.key, 'base64') }, ...rest] } }, 'simulation');
  refused({ ...base, simulation: { ...base.simulation, results: [] } }, 'returned_rule');
  refused({ ...base, simulation: { ...base.simulation, transactionData: undefined } }, 'simulation');
  const denial = F.denialSample();
  refused({ ...denial, simulation: { ...denial.simulation, results: base.simulation.results } }, 'simulation');
});

test('every authorization\'s nonce is consumed in the reported changes, and only once', () => {
  const entries = F.caseEntries();
  for (let i = 0; i < entries.length; i++) {
    const changes = F.permitChanges(entries);
    delete changes[`nonce${i}`];
    refused(sample(entries, { changes }), 'nonces', `entry ${i}`);
  }
  const changes = F.permitChanges(entries);
  changes.nonce2 = F.change(changes.nonce2.key, changes.nonce2.after, changes.nonce2.after);
  refused(sample(entries, { changes }), 'nonces');
});

test('the digests follow each entry\'s credential type: classic account entries are accepted too', () => {
  const entries = F.caseEntries({ v1: true });
  assert.equal(validateLiveCase(sample(entries)).outcome, 'permit');
  // A delegate proof over the address-bound preimage does not authorize a classic entry.
  const [install, ownerProof, transfer] = entries;
  const v2 = xdr.SorobanAuthorizationEntry.fromXDR(transfer.toXDR());
  v2.credentials = xdr.SorobanCredentials.sorobanCredentialsAddressV2(transfer.credentials.address);
  refused(sample([install, ownerProof, transfer, F.signerEntry(PROBE.delegate, F.authDigest(v2, [PROBE.ruleId]))]), 'signer_entry');
});

// --- ledger changes -----------------------------------------------------------------------------------

test('refuses unexpected ledger change', () => {
  const entries = F.caseEntries();
  const u32 = xdr.ScVal.scvU32;
  const extras = {
    'another rule stored': F.change(F.dataKey(PROBE.account, F.keyed('ContextRuleData', u32(2))), null,
      F.dataEntry(PROBE.account, F.keyed('ContextRuleData', u32(2)), u32(0))),
    'a write to the helper': F.change(F.dataKey(PROBE.helper, F.keyed('Seen')), null, F.dataEntry(PROBE.helper, F.keyed('Seen'), u32(1))),
    'another account balance': F.change(F.accountKey(PROBE.delegate), F.accountEntryOf(PROBE.delegate, 5n), F.accountEntryOf(PROBE.delegate, 4n)),
    'another asset balance': F.change(F.dataKey(PROBE.policy, F.keyed('Balance', F.delegated(PROBE.account))), null,
      F.dataEntry(PROBE.policy, F.keyed('Balance', F.delegated(PROBE.account)), u32(1))),
    'a nonce of no entry': F.change(F.dataKey(PROBE.account, xdr.ScVal.scvLedgerKeyNonce(new xdr.ScNonceKey({ nonce: 1n })), xdr.ContractDataDurability.temporary),
      null, F.dataEntry(PROBE.account, xdr.ScVal.scvLedgerKeyNonce(new xdr.ScNonceKey({ nonce: 1n })), xdr.ScVal.scvVoid(), xdr.ContractDataDurability.temporary)),
  };
  for (const [name, extra] of Object.entries(extras)) {
    const changes = { ...F.permitChanges(entries), extra };
    refused(sample(entries, { changes }), 'unexpected_ledger_change', name);
  }
  // The same entry reported twice.
  const changes = F.permitChanges(entries);
  refused(sample(entries, { changes: { ...changes, again: changes.counter } }), 'ledger_changes');
  // Account bookkeeping beyond the installation: NextId jumping, a foreign instance key, a recipient
  // account changing more than its balance.
  const instanceKey = xdr.ScVal.scvLedgerKeyContractInstance();
  for (const after of [{ Count: 2, NextId: 3, NextPolicyId: 1, NextSignerId: 2 }, { Count: 2, NextId: 2, NextPolicyId: 1, NextSignerId: 2, Paused: 1 }]) {
    const bad = F.permitChanges(entries);
    bad.instance = F.change(F.dataKey(PROBE.account, instanceKey), bad.instance.before, F.dataEntry(PROBE.account, instanceKey, F.instance(after)));
    refused(sample(entries, { changes: bad }), 'account_bookkeeping');
  }
  const seq = F.permitChanges(entries);
  seq.recipient = F.change(F.accountKey(PROBE.recipient), seq.recipient.before,
    F.accountEntryOf(PROBE.recipient, seq.recipient.before.data.account.balance + PROBE.permitAmount, 1n));
  refused(sample(entries, { changes: seq }), 'balance_delta');
});

test('permit requires exact delta and counter drop', () => {
  const entries = F.caseEntries();
  const drop = (name) => { const c = F.permitChanges(entries); delete c[name]; return c; };
  const cases = [
    ['one stroop more leaving the account', F.permitChanges(entries, { amount: PROBE.permitAmount + 1n, received: PROBE.permitAmount }), 'balance_delta'],
    ['one stroop less reaching the recipient', F.permitChanges(entries, { received: PROBE.permitAmount - 1n }), 'balance_delta'],
    ['no balance moved', drop('sender'), 'balance_delta'],
    ['the counter untouched', drop('counter'), 'counter_not_dropped'],
    ['the counter used twice', F.permitChanges(entries, { used: 2 }), 'counter_not_dropped'],
    ['no installation marker', drop('installed'), 'install_marker'],
    ['no rule stored', drop('rule'), 'rule_not_stored'],
    ['no account bookkeeping', drop('instance'), 'account_bookkeeping'],
  ];
  const existing = F.permitChanges(entries);
  existing.counter = F.change(existing.counter.key, existing.counter.after, existing.counter.after);
  cases.push(['a counter that existed before', existing, 'counter_not_dropped']);
  for (const [name, changes, reason] of cases) refused(sample(entries, { changes }), reason, name);
  // The helper must return the candidate rule, as approved.
  const changes = F.permitChanges(entries);
  refused(sample(entries, { simulation: F.permitSimulation(changes, { entries, retval: F.returnedRule({ id: 2 }) }) }), 'returned_rule');
  refused(sample(entries, { simulation: F.permitSimulation(changes, { entries, retval: F.returnedRule({ name: 'other' }) }) }), 'returned_rule');
  refused(sample(entries, { simulation: F.permitSimulation([], { entries }) }), 'balance_delta');
});

// --- failures -----------------------------------------------------------------------------------------

test('denial requires code 6 from the policy contract id', () => {
  const base = F.denialSample();
  const failedWith = (text) => ({ ...base, simulation: { ...base.simulation, error: text } });
  // The same number raised by another contract (the asset's #6 is AccountMissingError) is not the policy.
  refused(failedWith(F.denialText({ raisedBy: PROBE.asset })), 'not_a_policy_denial');
  // A policy error with no failed authentication of this account is no decision on it.
  refused(failedWith(F.denialText({ account: PROBE.helper })), 'not_a_policy_denial');
  // Another policy code is a decision, but not this case's denial.
  refused(failedWith(F.denialText({ code: 7 })), 'policy_code');
  // Text without the event log, or no failure at all.
  refused(failedWith('HostError: Error(Auth, InvalidAction)'), 'not_a_policy_denial');
  refused(failedWith(42), 'simulation');
  // The asset's failed authentication of the account is what places the denial in the transfer.
  refused(failedWith(F.denialText({ failedAuthBy: PROBE.helper })), 'not_a_policy_denial');
  // The account's failure code and the policy's raised code must be one and the same.
  refused(failedWith(F.denialText().replace(`${PROBE.account}, Error(Contract, #6)]`, `${PROBE.account}, Error(Contract, #7)]`)), 'not_a_policy_denial');
  refused(failedWith(F.denialText().replace('"failing with contract error", 6]', '"failing with contract error", 7]')), 'not_a_policy_denial');
  // A failed simulation carries no ledger changes.
  refused({ ...base, simulation: F.failedSimulation(F.denialText(), { stateChanges: [F.rawChange(F.permitChanges([]).counter)] }) }, 'simulation');
  // Structure is checked for a denial too: an unexecuted context could otherwise be what the policy refused.
  const ruleIds = [0, PROBE.ruleId];
  const transfer = F.accountEntry(F.transferRoot(PROBE.denialAmount), ruleIds, delegateOnly);
  const entries = withTransfer(transfer, ruleIds, { amount: PROBE.denialAmount });
  refused({ ...sample(entries, { amount: PROBE.denialAmount, simulation: base.simulation }) }, 'transfer_rule_ids');
});

test('helper 7001-7009 is failed not denial', () => {
  assert.deepEqual(HELPER_ERROR_CODES, [7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009]);
  const base = F.denialSample();
  for (const code of HELPER_ERROR_CODES) {
    const verdict = refused({ ...base, simulation: F.failedSimulation(F.helperRefusalText(code)) }, 'helper_refusal');
    assert.equal(verdict.code, code);
    // Even beside an otherwise complete policy denial, a helper refusal settles nothing about the policy.
    const both = `${F.denialText()}\n${F.helperRefusalText(code).split('\n')[3]}`;
    refused({ ...base, simulation: F.failedSimulation(both) }, 'helper_refusal');
  }
});

test('an account error is failed, never a policy denial', () => {
  const base = F.denialSample();
  for (const code of [3002, 3005, 3016]) {
    const text = ['HostError: Error(Auth, InvalidAction)', '', 'Event log (newest first):',
      `   0: [Diagnostic Event] contract:${PROBE.asset}, topics:[error, Error(Auth, InvalidAction)], data:["failed account authentication with error", ${PROBE.account}, Error(Contract, #${code})]`,
      `   1: [Failed Diagnostic Event (not emitted)] contract:${PROBE.account}, topics:[error, Error(Contract, #${code})], data:["failing with contract error", ${code}]`].join('\n');
    refused({ ...base, simulation: F.failedSimulation(text) }, 'not_a_policy_denial');
  }
});

// --- the approved case --------------------------------------------------------------------------------

test('the approved case is checked before anything is compared with it', () => {
  assert.equal(liveCase(F.intent()).asset, PROBE.asset, 'the asset is the testnet native asset, derived, not supplied');
  assert.ok(Object.isFrozen(liveCase(F.intent())));
  for (const [name, change] of [
    ['mainnet', { network_id: '7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979' }],
    ['delegate is a contract', { delegate: PROBE.account }],
    ['delegate is the recipient', { delegate: PROBE.recipient }],
    ['policy is the helper', { policy: PROBE.helper }],
    ['zero amount', { amount: '0' }],
    ['non-canonical amount', { amount: '01000000' }],
    ['same rule for owner and candidate', { owner_rule_id: PROBE.ruleId }],
    ['owner signer is the delegate', { owner_signer: { kind: 'delegated', address: PROBE.delegate } }],
    ['no expiry', { signature_expiration_ledger: undefined }],
    ['rule name longer than the account accepts', { rule_name: 'n'.repeat(21) }],
    ['multi-byte rule name over the bound', { rule_name: '\u00e9'.repeat(11) }],
    ['open-ended grant', { valid_until_ledger: null }],
    ['contract owner signer', { owner_signer: { kind: 'delegated', address: PROBE.helper } }],
    ['short code hash', { policy_code_hash: 'ab' }],
  ]) assert.throws(() => liveCase(F.intent(change)), /live case refused/, name);
});

test('the helper call is the helper\'s own Candidate struct, and the transfer is on the derived native asset', () => {
  const rust = readFileSync(new URL('../../contracts/atomic-live-helper/src/lib.rs', import.meta.url), 'utf8');
  const declared = [.../pub (\w+): ([\w<>0-9]+),/g[Symbol.matchAll](/pub struct Candidate \{([^}]*)\}/.exec(rust)[1])];
  const scType = { Address: 'scvAddress', i128: 'scvI128', u32: 'scvU32', String: 'scvString', 'BytesN<32>': 'scvBytes' };
  const call = helperCall(F.intent());
  assert.equal(Address.fromScAddress(call.contractAddress).toString(), PROBE.helper);
  assert.equal(call.functionName.toString(), 'install_and_transfer');
  assert.deepEqual(call.args[0].map.map((e) => [e.key.sym.toString(), e.val.type]),
    declared.map(([, name, type]) => [name, scType[type]]).sort(([a], [b]) => (a < b ? -1 : 1)));
  assert.equal(call.args[0].toXDR('hex'), F.candidate().toXDR('hex'));
  const transfer = transferCall(F.intent());
  assert.equal(Address.fromScAddress(transfer.contractAddress).toString(), PROBE.asset);
  assert.equal(transfer.functionName.toString(), 'transfer');
});

test('a contract recipient is credited in the asset contract, on a new or an existing balance', () => {
  const recipient = StrKey.encodeContract(Buffer.alloc(32, 88));
  const entries = F.caseEntries({ recipient });
  for (const recipientBefore of [null, 5n]) {
    const input = {
      intent: F.intent({ recipient }), envelopeXdr: F.envelopeXdr(entries, { recipient }),
      simulation: F.permitSimulation(F.permitChanges(entries, { recipient, recipientBefore }), { entries, recipient }),
    };
    assert.equal(validateLiveCase(input).outcome, 'permit', String(recipientBefore));
    const short = { ...input, simulation: F.permitSimulation(F.permitChanges(entries, { recipient, recipientBefore, received: PROBE.permitAmount - 1n }), { entries, recipient }) };
    refused(short, 'balance_delta');
  }
});

test('an event is matched only where the log starts one, never inside a printed value', () => {
  // The rule name and other call arguments are printed verbatim in the event log. A value that reads
  // like the policy's error event, beside a real #6 from another contract, is not a policy denial.
  const forged = `contract:${PROBE.policy}, topics:[error, Error(Contract, #6)], data:["failing with contract error", 6]`;
  const text = [F.denialText({ raisedBy: PROBE.asset }),
    `   4: [Diagnostic Event] contract:${PROBE.helper}, topics:[fn_call, install_and_transfer], data:{name: "${forged}"}`].join('\n');
  refused({ ...F.denialSample(), simulation: F.failedSimulation(text) }, 'not_a_policy_denial');
  const helper = `contract:${PROBE.helper}, topics:[error, Error(Contract, #7009)]`;
  const quoted = [F.denialText(), `   4: [Diagnostic Event] contract:${PROBE.account}, topics:[log], data:"${helper}"`].join('\n');
  const base = F.denialSample();
  assert.equal(validateLiveCase({ ...base, simulation: { ...base.simulation, error: quoted } }).outcome, 'deny');
});

// --- binding the response to the envelope ---------------------------------------------------------

test('a response is bound to its envelope: swapped permit and denial responses are refused', () => {
  const permitCase = F.permitSample();
  const denialCase = F.denialSample();
  // The permit case's intent and envelope with the denial case's response: the recorded helper call
  // and the account's recorded checks are the other envelope's.
  refused({ ...permitCase, simulation: denialCase.simulation }, 'unbound_response');
  // The other way round the balances already disagree with the approved amount.
  assert.equal(validateLiveCase({ ...denialCase, simulation: permitCase.simulation }).outcome, 'failed');
  // Two permits of the same case with different entries: the changes of one, the events of the other.
  const a = F.caseEntries();
  const b = F.caseEntries();
  refused(sample(b, { simulation: F.permitSimulation(F.permitChanges(b), { entries: b, events: F.callEvents(a) }) }), 'unbound_response');
  refused(sample(b, { simulation: F.permitSimulation(F.permitChanges(b), { entries: b, events: [] }) }), 'unbound_response');
});

test('a denial is evidence only with its own events: the helper call and the account checks of this envelope', () => {
  const { entries, ...base } = F.denialSample();
  const withEvents = (events) => ({ ...base, simulation: { ...base.simulation, events } });
  refused(withEvents([]), 'unbound_response');
  refused(withEvents(undefined), 'unbound_response');
  // Its own events, rebuilt for another envelope of the same amount.
  refused(withEvents(F.callEvents(F.caseEntries({ amount: PROBE.denialAmount }), { amount: PROBE.denialAmount, denial: {} })), 'unbound_response');
  const own = F.callEvents(entries, { amount: PROBE.denialAmount, denial: {} });
  // The helper call recorded twice, or not at all.
  refused(withEvents([own[0], ...own]), 'unbound_response');
  refused(withEvents(own.slice(1)), 'unbound_response');
  // Each account entry's check must be recorded: the installation's, and the transfer's.
  const isCheck = (text) => {
    const data = xdr.DiagnosticEvent.fromXDR(text, 'base64').event.body.v0.data;
    return data.type === 'scvVec' && data.vec?.length === 3 && data.vec[0].type === 'scvBytes';
  };
  const checks = own.filter(isCheck);
  assert.equal(checks.length, 2);
  for (const missing of checks) refused(withEvents(own.filter((text) => text !== missing)), 'unbound_response');
  // An authorization check of something the envelope does not carry.
  const stranger = F.accountEntry(F.transferRoot(PROBE.denialAmount), [PROBE.ruleId], [[F.delegated(PROBE.delegate), EMPTY]]);
  refused(withEvents([...own, F.checkAuthCall(PROBE.asset, stranger)]), 'unbound_response');
  // A check of the transfer entry with other contexts, as for an entry with a sub-invocation.
  const nested = own.map((text) => {
    const event = xdr.DiagnosticEvent.fromXDR(text, 'base64');
    const data = event.event.body.v0.data;
    if (data.type === 'scvVec' && data.vec.length === 3 && data.vec[2].type === 'scvVec') {
      data.vec[2] = xdr.ScVal.scvVec([...data.vec[2].vec, ...data.vec[2].vec]);
    }
    return event.toXDR('base64');
  });
  refused(withEvents(nested), 'unbound_response');
  // Events that are not canonical XDR.
  refused(withEvents([`${own[0]}\n`, ...own.slice(1)]), 'simulation');
});

test('the denial must be in the structured events too, not only in the printed log', () => {
  const { entries, ...base } = F.denialSample();
  const withEvents = (denial) => ({ ...base, simulation: { ...base.simulation, events: F.callEvents(entries, { amount: PROBE.denialAmount, denial }) } });
  assert.equal(validateLiveCase(withEvents({})).outcome, 'deny');
  refused(withEvents({ raisedBy: PROBE.asset }), 'not_a_policy_denial');
  refused(withEvents({ code: 7 }), 'not_a_policy_denial');
  refused(withEvents({ account: PROBE.helper }), 'not_a_policy_denial');
  refused(withEvents({ failedAuthBy: PROBE.account }), 'not_a_policy_denial');
  // A helper refusal is found in the structured events even when the printed log lacks it.
  const refusal = { ...base.simulation, events: [...base.simulation.events,
    F.errorEvent(PROBE.helper, xdr.ScError.sceContract(7009), xdr.ScVal.scvVoid())] };
  assert.equal(refused({ ...base, simulation: refusal }, 'helper_refusal').code, 7009);
});

test('the result\'s authorization entries are absent or exactly the envelope\'s', () => {
  const entries = F.caseEntries();
  const own = entries.map((e) => e.toXDR('base64'));
  const at = (auth) => sample(entries, { simulation: F.permitSimulation(F.permitChanges(entries), { entries, auth }) });
  assert.equal(validateLiveCase(at([])).outcome, 'permit');
  assert.equal(validateLiveCase(at(own)).outcome, 'permit');
  const noAuth = at([]);
  delete noAuth.simulation.results[0].auth;
  assert.equal(validateLiveCase(noAuth).outcome, 'permit');
  refused(at([...own].reverse()), 'unbound_response');
  refused(at(own.slice(1)), 'unbound_response');
  refused(at(F.caseEntries().map((e) => e.toXDR('base64'))), 'unbound_response');
  refused(at('none'), 'unbound_response');
});

test('the validator answers with a verdict whatever it is given', () => {
  for (const input of [null, undefined, {}, 42, { intent: null }]) {
    const verdict = validateLiveCase(input);
    assert.equal(verdict.outcome, 'failed');
    assert.equal(verdict.reason, 'intent');
  }
  assert.equal(validateLiveCase().reason, 'intent');
});

// --- every guard, one negative test each --------------------------------------------------------------

test('the account registry entries must be exactly the delegate\'s and the policy\'s', () => {
  const entries = F.caseEntries();
  const u32 = xdr.ScVal.scvU32;
  const variant = (name, value) => {
    const changes = F.permitChanges(entries);
    changes[name] = F.change(changes[name].key, changes[name].before, F.dataEntry(PROBE.account, changes[name].after.data.contractData.key, value));
    return changes;
  };
  for (const [name, changes] of [
    ['another signer', variant('signer', F.struct({ count: u32(1), signer: F.delegated(OTHER) }))],
    ['a signer counted twice', variant('signer', F.struct({ count: u32(2), signer: F.delegated(PROBE.delegate) }))],
    ['a signer lookup to another id', variant('signerLookup', u32(0))],
    ['another policy', variant('policyData', F.struct({ count: u32(1), policy: F.delegated(PROBE.helper).vec[1] }))],
    ['a policy lookup to another id', variant('policyLookup', u32(3))],
  ]) refused(sample(entries, { changes }), 'account_bookkeeping', name);
  // An existing registration must be counted exactly once more.
  const signerKey = F.keyed('SignerData', u32(1));
  const signer = (count) => F.dataEntry(PROBE.account, signerKey, F.struct({ count: u32(count), signer: F.delegated(PROBE.delegate) }));
  const changes = F.permitChanges(entries);
  changes.signer = F.change(F.dataKey(PROBE.account, signerKey), signer(1), signer(3));
  delete changes.signerLookup;
  const instanceKey = xdr.ScVal.scvLedgerKeyContractInstance();
  changes.instance = F.change(F.dataKey(PROBE.account, instanceKey),
    F.dataEntry(PROBE.account, instanceKey, F.instance({ Count: 1, NextId: 1, NextSignerId: 2 })),
    F.dataEntry(PROBE.account, instanceKey, F.instance({ Count: 2, NextId: 2, NextPolicyId: 1, NextSignerId: 2 })));
  refused(sample(entries, { changes }), 'account_bookkeeping');
  changes.signer = F.change(F.dataKey(PROBE.account, signerKey), signer(1), signer(2));
  assert.equal(validateLiveCase(sample(entries, { changes })).outcome, 'permit');
});

test('a balance changes by its amount alone, and every change is reported under its own key', () => {
  const entries = F.caseEntries();
  const key = F.keyed('Balance', F.delegated(PROBE.account).vec[1]);
  const flipped = F.permitChanges(entries);
  flipped.sender = F.change(flipped.sender.key, flipped.sender.before,
    F.dataEntry(PROBE.asset, key, F.sacBalance(PROBE.accountBalance - PROBE.permitAmount, { authorized: false })));
  refused(sample(entries, { changes: flipped }), 'balance_delta');
  const mislabeled = F.permitChanges(entries);
  mislabeled.installed = F.change(mislabeled.installed.key, null, mislabeled.counter.after);
  refused(sample(entries, { changes: mislabeled }), 'ledger_changes');
});

test('the installation is fresh: new rule, new marker set to true, unchanged account code', () => {
  const entries = F.caseEntries();
  const instanceKey = xdr.ScVal.scvLedgerKeyContractInstance();
  const upgraded = F.permitChanges(entries);
  upgraded.instance = F.change(upgraded.instance.key, upgraded.instance.before,
    F.dataEntry(PROBE.account, instanceKey, F.instance({ Count: 2, NextId: 2, NextPolicyId: 1, NextSignerId: 2 }, 'ee'.repeat(32))));
  refused(sample(entries, { changes: upgraded }), 'account_bookkeeping');
  const existingRule = F.permitChanges(entries);
  existingRule.rule = F.change(existingRule.rule.key, existingRule.rule.after, existingRule.rule.after);
  refused(sample(entries, { changes: existingRule }), 'rule_not_stored');
  const existingMarker = F.permitChanges(entries);
  existingMarker.installed = F.change(existingMarker.installed.key, existingMarker.installed.after, existingMarker.installed.after);
  refused(sample(entries, { changes: existingMarker }), 'install_marker');
  const falseMarker = F.permitChanges(entries);
  falseMarker.installed = F.change(falseMarker.installed.key, null,
    F.dataEntry(PROBE.policy, falseMarker.installed.after.data.contractData.key, xdr.ScVal.scvBool(false)));
  refused(sample(entries, { changes: falseMarker }), 'install_marker');
});

test('owner proofs have the owner\'s shape, and there is one owner entry', () => {
  const [, , transfer, delegateProof] = F.caseEntries();
  const install = F.accountEntry(F.installRoot(), [0], [[F.delegated(PROBE.owner), Buffer.from([1])]]);
  refused(sample([install, F.signerEntry(PROBE.owner, F.authDigest(install, [0])), transfer, delegateProof]), 'owner_signers');
  const passkey = { owner_rule_id: 4, owner_signer: { kind: 'external', verifier: F.PASSKEY.verifier, key_hex: F.PASSKEY.keyHex } };
  const unproven = F.accountEntry(F.installRoot(), [4], [[F.external(F.PASSKEY.verifier, F.PASSKEY.keyHex), EMPTY]]);
  refused({ ...sample([unproven, transfer, delegateProof]), intent: F.intent(passkey) }, 'owner_signers');
  const [first, ...rest] = F.passkeyEntries({ ownerRule: 4 });
  const second = F.accountEntry(F.installRoot(), [4], [[F.external(F.PASSKEY.verifier, F.PASSKEY.keyHex), Buffer.alloc(96, 3)]]);
  refused({ ...sample([first, second, ...rest]), intent: F.intent(passkey) }, 'owner_entry_count');
});

test('signer entries are signed, flat and for the account\'s digest', () => {
  const [install, ownerProof, transfer, delegateProof] = F.caseEntries();
  const unsigned = xdr.SorobanAuthorizationEntry.fromXDR(delegateProof.toXDR());
  unsigned.credentials.address.signature = xdr.ScVal.scvVoid();
  refused(sample([install, ownerProof, transfer, unsigned]), 'signer_entry');
  const nested = xdr.SorobanAuthorizationEntry.fromXDR(delegateProof.toXDR());
  nested.rootInvocation.subInvocations = [F.transferRoot()];
  refused(sample([install, ownerProof, transfer, nested]), 'signer_entry');
});

test('an account entry\'s signature is exactly an AuthPayload', () => {
  const [install, ownerProof, transfer, delegateProof] = F.caseEntries();
  const sym = xdr.ScVal.scvSymbol;
  const ids = xdr.ScVal.scvVec([xdr.ScVal.scvU32(PROBE.ruleId)]);
  const signers = xdr.ScVal.scvMap([new xdr.ScMapEntry({ key: F.delegated(PROBE.delegate), val: xdr.ScVal.scvBytes(EMPTY) })]);
  const map = (entries) => xdr.ScVal.scvMap(entries.map(([key, val]) => new xdr.ScMapEntry({ key: sym(key), val })));
  for (const [name, signature] of [
    ['a third field', map([['context_rule_ids', ids], ['extra', ids], ['signers', signers]])],
    ['fields swapped', map([['signers', signers], ['context_rule_ids', ids]])],
    ['a misnamed field', map([['context_rule_id', ids], ['signers', signers]])],
    ['rule ids not a vector', map([['context_rule_ids', xdr.ScVal.scvU32(1)], ['signers', signers]])],
    ['a rule id not a u32', map([['context_rule_ids', xdr.ScVal.scvVec([xdr.ScVal.scvU64(xdr.Uint64.fromString('1'))])], ['signers', signers]])],
    ['signers not a map', map([['context_rule_ids', ids], ['signers', ids]])],
    ['no signers', map([['context_rule_ids', ids], ['signers', xdr.ScVal.scvMap([])]])],
    ['a proof not bytes', map([['context_rule_ids', ids], ['signers',
      xdr.ScVal.scvMap([new xdr.ScMapEntry({ key: F.delegated(PROBE.delegate), val: xdr.ScVal.scvVoid() })])]])],
  ]) {
    const bad = xdr.SorobanAuthorizationEntry.fromXDR(transfer.toXDR());
    bad.credentials.addressV2.signature = signature;
    refused(sample([install, ownerProof, bad, delegateProof]), 'auth_payload', name);
  }
});

// --- real testnet responses ---------------------------------------------------------------------------

// Raw enforce-mode responses from a testnet probe of the deployed helper on 21 October 2026, with the
// two classic signer entries' Ed25519 signatures zeroed (see the fixture's provenance). These pin the
// shapes above to what the RPC actually returns.
const REAL = JSON.parse(readFileSync(new URL('./live-enforcement-testnet.json', import.meta.url), 'utf8'));
const realCase = (name, simulation = REAL[name].simulation) => ({ intent: REAL[name].intent, envelopeXdr: REAL[name].envelopeXdr, simulation });
const clone = (value) => JSON.parse(JSON.stringify(value));

test('real testnet responses: the probed permit is a permit and the adjacent amount a policy denial', () => {
  const { provenance } = REAL;
  assert.deepEqual([provenance.harness_outcomes.permit.result, provenance.harness_outcomes.denial.result], ['permit', 'deny']);
  const permit = validateLiveCase(realCase('permit'));
  assert.equal(permit.outcome, 'permit', JSON.stringify(permit));
  assert.deepEqual([permit.enforcer, permit.returned_rule_id, permit.balance_changes, permit.amount],
    [provenance.candidate_policy, 1, { account: '-1000000', recipient: '1000000' }, '1000000']);
  const denial = validateLiveCase(realCase('denial'));
  assert.equal(denial.outcome, 'deny', JSON.stringify(denial));
  assert.deepEqual([denial.enforcer, denial.code, denial.amount, denial.host],
    [provenance.candidate_policy, 6, '1000001', 'HostError: Error(Auth, InvalidAction)']);
  assert.equal(provenance.post_expiry_readback.installed, false);
  assert.equal(provenance.post_expiry_readback.balance_after, provenance.post_expiry_readback.balance_before);
});

test('real testnet responses swapped between the two cases are refused', () => {
  refused(realCase('permit', REAL.denial.simulation), 'unbound_response');
  refused(realCase('denial', REAL.permit.simulation), 'balance_delta');
});

test('real responses carry the shapes the validator reads', () => {
  const permit = REAL.permit.simulation;
  const denial = REAL.denial.simulation;
  // Enforcing mode echoes the supplied entries; a failed simulation reports neither results nor changes.
  const envelopeAuth = (name) => xdr.TransactionEnvelope.fromXDR(REAL[name].envelopeXdr, 'base64')
    .v1.tx.operations[0].body.invokeHostFunctionOp.auth.map((e) => e.toXDR('base64'));
  assert.deepEqual(permit.results[0].auth, envelopeAuth('permit'));
  assert.equal(denial.results, undefined);
  assert.equal(denial.stateChanges, undefined);
  // Fourteen changes on a fresh account, four of them the entries' nonces.
  assert.equal(permit.stateChanges.length, 14);
  const nonces = permit.stateChanges.filter((c) => xdr.LedgerKey.fromXDR(c.key, 'base64').contractData?.key.type === 'scvLedgerKeyNonce');
  assert.equal(nonces.length, 4);
  // Both responses record the helper call and the account's two authorization checks; the denial's
  // events, all from failed calls, include the policy's own NoTupleMatched.
  const events = (simulation) => simulation.events.map((text) => xdr.DiagnosticEvent.fromXDR(text, 'base64'));
  const fnCalls = (simulation, fn) => events(simulation).filter((e) => e.event.body.v0.topics[0]?.sym?.toString() === 'fn_call'
    && e.event.body.v0.topics[2]?.sym?.toString() === fn);
  for (const simulation of [permit, denial]) {
    assert.equal(fnCalls(simulation, 'install_and_transfer').length, 1);
    assert.equal(fnCalls(simulation, '__check_auth').length, 2);
  }
  assert.ok(events(denial).every((e) => e.inSuccessfulContractCall === false));
  const policyId = Buffer.from(StrKey.decodeContract(REAL.provenance.candidate_policy)).toString('hex');
  assert.ok(events(denial).some((e) => e.event.contractId && Buffer.from(e.event.contractId.toXDR()).toString('hex') === policyId
    && e.event.body.v0.topics[1]?.error?.contractCode === 6));
});

test('real responses with one part removed or reordered are refused', () => {
  const withoutTransferCheck = clone(REAL.denial.simulation);
  const checks = withoutTransferCheck.events.filter((text) => {
    const topics = xdr.DiagnosticEvent.fromXDR(text, 'base64').event.body.v0.topics;
    return topics[2]?.sym?.toString() === '__check_auth';
  });
  withoutTransferCheck.events = withoutTransferCheck.events.filter((text) => text !== checks[1]);
  refused(realCase('denial', withoutTransferCheck), 'unbound_response');
  const reordered = clone(REAL.permit.simulation);
  reordered.results[0].auth.reverse();
  refused(realCase('permit', reordered), 'unbound_response');
  const nonceless = clone(REAL.permit.simulation);
  nonceless.stateChanges = nonceless.stateChanges.filter((c) => xdr.LedgerKey.fromXDR(c.key, 'base64').contractData?.key.type !== 'scvLedgerKeyNonce');
  refused(realCase('permit', nonceless), 'nonces');
  refused(realCase('permit', { ...REAL.permit.simulation, events: [] }), 'unbound_response');
  refused(realCase('denial', { ...REAL.denial.simulation, events: undefined }), 'unbound_response');
});
