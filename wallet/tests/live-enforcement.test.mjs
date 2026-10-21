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
  simulation: simulation ?? F.permitSimulation(changes ?? F.permitChanges(entries, { amount })),
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
  refused(sample(entries, { simulation: F.permitSimulation(F.permitChanges(entries), { archived: [0] }) }), 'simulation');
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
  refused({ ...F.denialSample(), simulation: F.failedSimulation(F.denialText(), { results: base.simulation.results }) }, 'simulation');
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
  refused(sample(entries, { simulation: F.permitSimulation(changes, { retval: F.returnedRule({ id: 2 }) }) }), 'returned_rule');
  refused(sample(entries, { simulation: F.permitSimulation(changes, { retval: F.returnedRule({ name: 'other' }) }) }), 'returned_rule');
  refused(sample(entries, { simulation: F.permitSimulation([]) }), 'balance_delta');
});

// --- failures -----------------------------------------------------------------------------------------

test('denial requires code 6 from the policy contract id', () => {
  const base = F.denialSample();
  const failedWith = (text) => ({ ...base, simulation: F.failedSimulation(text) });
  // The same number raised by another contract (the asset's #6 is AccountMissingError) is not the policy.
  refused(failedWith(F.denialText({ raisedBy: PROBE.asset })), 'not_a_policy_denial');
  // A policy error with no failed authentication of this account is no decision on it.
  refused(failedWith(F.denialText({ account: PROBE.helper })), 'not_a_policy_denial');
  // Another policy code is a decision, but not this case's denial.
  refused(failedWith(F.denialText({ code: 7 })), 'policy_code');
  // Text without the event log, or no failure at all.
  refused(failedWith('HostError: Error(Auth, InvalidAction)'), 'not_a_policy_denial');
  refused(failedWith(42), 'simulation');
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
      simulation: F.permitSimulation(F.permitChanges(entries, { recipient, recipientBefore })),
    };
    assert.equal(validateLiveCase(input).outcome, 'permit', String(recipientBefore));
    const short = { ...input, simulation: F.permitSimulation(F.permitChanges(entries, { recipient, recipientBefore, received: PROBE.permitAmount - 1n })) };
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
  assert.equal(validateLiveCase({ ...F.denialSample(), simulation: F.failedSimulation(quoted) }).outcome, 'deny');
});
