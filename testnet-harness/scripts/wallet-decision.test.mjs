// The wallet decision on the authority check's output, offline. The fixture is hand-written from
// the check's output types and contract document (`check_policy_call_surface` /
// `prepare_install_intent`), not captured from the tool, and filled with valid addresses and
// keys; each test changes one thing about it.
//
// Some of the check's regression cases are refusals the tool raises: a signerless permissive
// policy on the target, the agent added as a classic signer, a missing or zero-weight classic
// account. At this layer each is "refused → not accepted", which the refusal tests below cover.
// An owner-only rule scoped to the bound policy is not refused: the check lists it
// (`reach: policy`) for the wallet to match, and the tests below cover both outcomes.
//
//   node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { StrKey } from '@stellar/stellar-sdk';

import {
  TRUST_OPERATOR, TRUST_OWN, checkRequest, confirmationScreen, decide, identityKey, intentMismatches, recheck,
  walletTrust,
} from './wallet-decision.mjs';

const FIXTURE = JSON.parse(readFileSync(new URL('./fixtures/authority/intent-passkey-owner.json', import.meta.url), 'utf8'));
const intent = () => structuredClone(FIXTURE);
const check = () => intent().authority;

const PASSKEY = FIXTURE.authority.verdict.authority_list[0].requirement.signers[0].public_key;
const DELEGATE = 'GDKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNINJE';
const DELEGATE_HEX = 'd4'.repeat(32);
const GUARDIAN = 'GDS6LZPF4XS6LZPF4XS6LZPF4XS6LZPF4XS6LZPF4XS6LZPF4XS6LGS2';
const GUARDIAN_HEX = 'e5'.repeat(32);
const OTHER_VERIFIER = 'CCZ3HM5TWOZ3HM5TWOZ3HM5TWOZ3HM5TWOZ3HM5TWOZ3HM5TWOZ3HODI';
const EXPECT = {
  account: FIXTURE.account_contract,
  networkId: FIXTURE.authority.verdict.network_id,
  target: FIXTURE.context_contract,
  boundPolicies: [FIXTURE.policies[0].address],
  ruleIndex: 0,
  specHash: FIXTURE.authority.spec_hash,
  registrySnapshotRoot: FIXTURE.authority.registry_snapshot_root,
};
const ownPasskey = () => walletTrust({ own: [{ scheme: 'webauthn_p256', public_key: PASSKEY }] });

const classic = (address, hex, aliases = false) => ({
  kind: 'classic_account', address, ed25519_public_key: hex, aliases_restricted_key: aliases,
});
const external = (scheme, publicKey, aliases = false, verifier = FIXTURE.authority.verdict.authority_list[0].requirement.signers[0].verifier) => ({
  kind: 'external', verifier, verifier_code_hash: 'e6'.repeat(32), scheme, public_key: publicKey, aliases_restricted_key: aliases,
});
const managementRule = (ruleId, signers) => ({
  rule_id: ruleId, reach: { kind: 'any_call' }, valid_until: null, requirement: { kind: 'all_of', signers },
});
const finding = (code) => ({ code, rule_id: 3, reason: 'r', remediation: 'f' });

// --- identities --------------------------------------------------------------------------------

test('identities are compared by scheme and canonical key, never by verifier address', () => {
  assert.equal(identityKey(external('webauthn_p256', PASSKEY)), `webauthn_p256:${PASSKEY}`);
  assert.equal(identityKey(external('webauthn_p256', PASSKEY, false, OTHER_VERIFIER)), `webauthn_p256:${PASSKEY}`);
  // An ed25519 key behind a verifier is the same identity as the classic account with that key.
  assert.equal(identityKey(external('ed25519', GUARDIAN_HEX)), identityKey(classic(GUARDIAN, GUARDIAN_HEX)));
  // Hex case does not make a different key.
  assert.equal(identityKey(external('webauthn_p256', PASSKEY.toUpperCase())), `webauthn_p256:${PASSKEY}`);
});

test('a malformed identity is refused, not guessed at', () => {
  assert.throws(() => identityKey(external('webauthn_p256', PASSKEY.slice(0, 128))), /65-byte/);
  assert.throws(() => identityKey(external('webauthn_p256', `02${PASSKEY.slice(2)}`)), /uncompressed/);
  assert.throws(() => identityKey(external('ed25519', 'ab'.repeat(31))), /32-byte/);
  assert.throws(() => identityKey(external('secp256k1', PASSKEY)), /scheme/);
  // A classic account whose stated key is not its address's key is malformed output.
  assert.throws(() => identityKey(classic(GUARDIAN, DELEGATE_HEX)), /does not match/);
  assert.throws(() => identityKey({ kind: 'contract', address: EXPECT.account }), /kind/);
});

// --- the decision ------------------------------------------------------------------------------

test('accepts when the only owner rule needs the wallet\'s own passkey', () => {
  const d = decide(check(), { trust: ownPasskey(), expect: EXPECT });
  assert.equal(d.accept, true, d.reasons.join('; '));
  assert.deepEqual(d.reasons, []);
  assert.equal(d.commitment, FIXTURE.authority.verdict.authority_commitment);
  assert.equal(d.entries[0].signers[0].trusted_by, TRUST_OWN);
});

test('an independent owner is refused until the operator trusts it, and that trust is labelled', () => {
  const c = check();
  c.verdict.authority_list.push(managementRule(3, [classic(GUARDIAN, GUARDIAN_HEX)]));
  const untrusted = decide(c, { trust: ownPasskey(), expect: EXPECT });
  assert.equal(untrusted.accept, false);
  assert.match(untrusted.reasons.join('\n'), /rule 3/);

  const trust = walletTrust({ own: [{ scheme: 'webauthn_p256', public_key: PASSKEY }], operator: [{ classic_account: GUARDIAN }] });
  const trusted = decide(c, { trust, expect: EXPECT });
  assert.equal(trusted.accept, true, trusted.reasons.join('; '));
  assert.equal(trusted.entries[1].signers[0].trusted_by, TRUST_OPERATOR);
  assert.equal(TRUST_OPERATOR, 'operator-supplied test configuration');
});

test('one trusted member is enough for an all_of rule (the owner co-signs)', () => {
  const c = check();
  c.verdict.authority_list[0].requirement.signers.push(classic(GUARDIAN, GUARDIAN_HEX));
  assert.equal(decide(c, { trust: ownPasskey(), expect: EXPECT }).accept, true);
});

for (const [field, code] of [['refusals', 'E_DELEGATE_HAS_AUTHORITY'], ['unresolved', 'E_INCOMPLETE_ACCOUNT_STATE']]) {
  test(`trust never overrides ${field}`, () => {
    const c = check();
    c.verdict[field].push(finding(code));
    const d = decide(c, { trust: ownPasskey(), expect: EXPECT });
    assert.equal(d.accept, false);
    assert.match(d.reasons.join('\n'), new RegExp(code));
  });
}

test('an identity aliasing the restricted key never counts, even when trusted', () => {
  const c = check();
  c.verdict.authority_list = [managementRule(0, [classic(GUARDIAN, GUARDIAN_HEX, true)])];
  const trust = walletTrust({ operator: [{ classic_account: GUARDIAN }] });
  const d = decide(c, { trust, expect: EXPECT });
  assert.equal(d.accept, false);
  assert.match(d.entries[0].signers[0].excluded, /restricted key/);
});

test('the grant\'s own signer is removed from trust even if the tool did not flag it', () => {
  // Operator trust that names the agent's key, and a rule the agent can satisfy: refused.
  const c = check();
  c.verdict.authority_list = [managementRule(0, [classic(DELEGATE, DELEGATE_HEX)])];
  const trust = walletTrust({ operator: [{ classic_account: DELEGATE }] });
  assert.equal(decide(c, { trust, expect: EXPECT }).accept, false);
  // The same key behind an ed25519 verifier is the same agent.
  c.verdict.authority_list = [managementRule(0, [external('ed25519', DELEGATE_HEX)])];
  assert.equal(decide(c, { trust, expect: EXPECT }).accept, false);
});

test('the same passkey behind another verifier copy still matches', () => {
  const c = check();
  c.verdict.authority_list[0].requirement.signers[0].verifier = OTHER_VERIFIER;
  assert.equal(decide(c, { trust: ownPasskey(), expect: EXPECT }).accept, true);
});

test('an ed25519 owner key matches a classic owner account with that key', () => {
  const c = check();
  c.verdict.authority_list = [managementRule(0, [classic(GUARDIAN, GUARDIAN_HEX)])];
  const trust = walletTrust({ own: [{ scheme: 'ed25519', public_key: GUARDIAN_HEX }] });
  assert.equal(decide(c, { trust, expect: EXPECT }).accept, true);
});

test('fails closed on an authority entry it cannot evaluate, and on an empty list', () => {
  const c = check();
  c.verdict.authority_list[0].requirement = { kind: 'any_of', signers: [external('webauthn_p256', PASSKEY)], policies: [] };
  assert.equal(decide(c, { trust: ownPasskey(), expect: EXPECT }).accept, false);
  const empty = check();
  empty.verdict.authority_list = [];
  const d = decide(empty, { trust: ownPasskey(), expect: EXPECT });
  assert.equal(d.accept, false);
  assert.match(d.reasons.join('\n'), /no rule/i);
  const malformed = check();
  malformed.verdict.authority_list[0].requirement.signers[0].public_key = 'zz';
  assert.equal(decide(malformed, { trust: ownPasskey(), expect: EXPECT }).accept, false);
});

test('an answer about another account, network, target or policy is refused', () => {
  const cases = [
    (v) => { v.account_address = OTHER_VERIFIER; },
    (v) => { v.network_id = '00'.repeat(32); },
    (v) => { v.grant.target = OTHER_VERIFIER; },
    (v) => { v.bound_policy_addresses = [OTHER_VERIFIER]; },
    (v) => { v.authority_commitment = 'not-a-hash'; },
    (v) => { v.scope.targets = [OTHER_VERIFIER]; },
    (v) => { delete v.scope; },
    (v) => { v.spec_hash = '00'.repeat(32); },
  ];
  for (const change of cases) {
    const c = check();
    change(c.verdict);
    assert.equal(decide(c, { trust: ownPasskey(), expect: EXPECT }).accept, false, change.toString());
  }
});

test('an owner-only rule scoped to the bound policy is accepted when the wallet trusts its owner', () => {
  const c = check();
  c.verdict.authority_list.push({ ...managementRule(4, [classic(GUARDIAN, GUARDIAN_HEX)]), reach: { kind: 'policy', address: EXPECT.boundPolicies[0] } });
  const trust = walletTrust({ own: [{ scheme: 'webauthn_p256', public_key: PASSKEY }], operator: [{ classic_account: GUARDIAN }] });
  const d = decide(c, { trust, expect: EXPECT });
  assert.equal(d.accept, true, d.reasons.join('; '));
  assert.match(d.entries[1].reach, /calls to policy/);
});

test('every rule must be satisfied: one trusted rule does not carry an untrusted one', () => {
  const c = check();
  c.verdict.authority_list.push({ ...managementRule(4, [classic(GUARDIAN, GUARDIAN_HEX)]), reach: { kind: 'policy', address: EXPECT.boundPolicies[0] } });
  const d = decide(c, { trust: ownPasskey(), expect: EXPECT });
  assert.equal(d.accept, false);
  assert.match(d.reasons.join('\n'), /rule 4 \(calls to policy/);
  assert.doesNotMatch(d.reasons.join('\n'), /rule 0/);
});

test('a key the check marks as the agent\'s is excluded in every rule, not only where it is marked', () => {
  const c = check();
  c.verdict.authority_list = [
    managementRule(0, [classic(GUARDIAN, GUARDIAN_HEX, true)]),
    managementRule(1, [external('ed25519', GUARDIAN_HEX, false)]),
  ];
  const trust = walletTrust({ operator: [{ classic_account: GUARDIAN }] });
  const d = decide(c, { trust, expect: EXPECT });
  assert.equal(d.accept, false);
  assert.match(d.entries[1].signers[0].excluded, /restricted key/);
});

test('a key sharing its first 32 bytes with the agent\'s counts as the agent, as the check treats it', () => {
  // The check over-approximates aliasing (same bytes, or the same first 32 bytes); the wallet
  // does the same with the grant's signers, so it cannot trust what the check would call the agent.
  const c = check();
  const agentLike = StrKey.encodeEd25519PublicKey(Buffer.from(PASSKEY.slice(0, 64), 'hex'));
  c.verdict.grant.signers = [{ kind: 'delegated', address: agentLike }];
  const d = decide(c, { trust: ownPasskey(), expect: EXPECT });
  assert.equal(d.accept, false);
  assert.match(d.entries[0].signers[0].excluded, /grant/);
});

test('an expired grant is refused at the ledger the answer was read', () => {
  const c = check();
  c.verdict.grant.valid_until = c.verdict.observed_ledger;
  const d = decide(c, { trust: ownPasskey(), expect: EXPECT });
  assert.equal(d.accept, false);
  assert.match(d.reasons.join('\n'), /expire/);
  const open = check();
  open.verdict.grant.valid_until = null;
  assert.equal(decide(open, { trust: ownPasskey(), expect: { ...EXPECT } }).accept, true);
});

test('a grant aimed at the account itself or at its own policy is refused by the wallet too', () => {
  // The intent refuses these before reading; the plain check only after it. The wallet does not
  // depend on either.
  for (const target of [EXPECT.account, EXPECT.boundPolicies[0]]) {
    const c = check();
    c.verdict.grant.target = target;
    const d = decide(c, { trust: ownPasskey(), expect: { ...EXPECT, target } });
    assert.equal(d.accept, false, target);
    assert.match(d.reasons.join('\n'), /targets/);
  }
});

test('an answer for another rule of the spec is refused', () => {
  const c = check();
  c.verdict.grant.rule_index = 1;
  assert.equal(decide(c, { trust: ownPasskey(), expect: EXPECT }).accept, false);
});

test('finding codes such as E_UNSAFE_MANAGEMENT_SURFACE are not mistaken for a "safe" claim', () => {
  const c = check();
  c.summary += 'E_UNSAFE_MANAGEMENT_SURFACE and E_UNSAFE_CALL_SURFACE were not raised.\n';
  assert.equal(decide(c, { trust: ownPasskey(), expect: EXPECT }).accept, true);
});

test('an answer for another spec or registry is refused', () => {
  for (const change of [(c) => { c.spec_hash = '00'.repeat(32); }, (c) => { c.registry_snapshot_root = '00'.repeat(32); }]) {
    const c = check();
    change(c);
    assert.equal(decide(c, { trust: ownPasskey(), expect: EXPECT }).accept, false);
  }
});

test('the screen still renders, and refuses, when the answer lacks parts', () => {
  const c = check();
  delete c.verdict.scope;
  delete c.verdict.grant.policies;
  const d = decide(c, { trust: ownPasskey(), expect: EXPECT });
  assert.equal(d.accept, false);
  assert.match(confirmationScreen({ check: c, decision: d }), /REFUSED/);
});

test('notes and coverage exclusions never block', () => {
  const c = check();
  c.verdict.coverage_exclusions.push({ rule_id: 5, context: { call_contract: { address: OTHER_VERIFIER } }, policy_addresses: [] });
  c.verdict.notes.expired_rules.push({ rule_id: 4, context: 'default', valid_until: 10 });
  assert.equal(decide(c, { trust: ownPasskey(), expect: EXPECT }).accept, true);
});

// --- the intent --------------------------------------------------------------------------------

test('the intent\'s arguments are exactly the checked grant', () => {
  assert.deepEqual(intentMismatches(intent()), []);
  // Key order is not a difference; a missing field is not a null one.
  const reordered = intent();
  reordered.policies[0] = { install_params: reordered.policies[0].install_params, address: reordered.policies[0].address, policy_index: 0 };
  assert.deepEqual(intentMismatches(reordered), []);
  const missing = intent();
  delete missing.valid_until_ledger;
  missing.authority.verdict.grant.valid_until = null;
  assert.notDeepEqual(intentMismatches(missing), []);
  const cases = {
    context_contract: (i) => { i.context_contract = OTHER_VERIFIER; },
    rule_name: (i) => { i.rule_name = 'other'; },
    valid_until_ledger: (i) => { i.valid_until_ledger = 140001; },
    'valid_until_ledger null': (i) => { i.valid_until_ledger = null; },
    delegate_signers: (i) => { i.delegate_signers = [{ kind: 'delegated', address: GUARDIAN }]; },
    'policies address': (i) => { i.policies[0].address = OTHER_VERIFIER; },
    'policies index': (i) => { i.policies[0].policy_index = 1; },
    'policies params': (i) => { i.policies[0].install_params = { kind: 'spending_limit', spending_limit: '1', period_ledgers: 1 }; },
    'extra policy': (i) => { i.policies.push({ ...i.policies[0], policy_index: 1 }); },
    account_contract: (i) => { i.account_contract = OTHER_VERIFIER; },
    operation: (i) => { i.operation = 'remove_context_rule'; },
  };
  for (const [name, change] of Object.entries(cases)) {
    const i = intent();
    change(i);
    assert.notDeepEqual(intentMismatches(i), [], name);
  }
});

// --- the pre-sign re-check ------------------------------------------------------------------------

test('a fresh read with the same commitment passes, even at a later ledger with new evidence', () => {
  const approved = decide(check(), { trust: ownPasskey(), expect: EXPECT });
  const fresh = check();
  fresh.verdict.observed_ledger += 50;
  fresh.verdict.evidence.attempts = 2;
  fresh.verdict.evidence.raw_ordered_entry_digest = '77'.repeat(32);
  fresh.summary = 'read again';
  assert.equal(recheck(approved, fresh, { trust: ownPasskey(), expect: EXPECT }).accept, true);
});

test('a changed commitment means asking again, and a fresh refusal still refuses', () => {
  const approved = decide(check(), { trust: ownPasskey(), expect: EXPECT });
  const changed = check();
  changed.verdict.authority_commitment = '88'.repeat(32);
  const r = recheck(approved, changed, { trust: ownPasskey(), expect: EXPECT });
  assert.equal(r.accept, false);
  assert.match(r.reasons.join('\n'), /changed since.*approved|ask again/i);

  const refused = check();
  refused.verdict.refusals.push(finding('E_UNSAFE_MANAGEMENT_SURFACE'));
  assert.equal(recheck(approved, refused, { trust: ownPasskey(), expect: EXPECT }).accept, false);
  // Nothing approved, nothing to re-check.
  const rejected = decide(refused, { trust: ownPasskey(), expect: EXPECT });
  assert.equal(recheck(rejected, check(), { trust: ownPasskey(), expect: EXPECT }).accept, false);
});

// --- the screen --------------------------------------------------------------------------------

test('the confirmation screen shows the summary, scope and trust labels, and never says "safe"', () => {
  const c = check();
  c.verdict.authority_list.push(managementRule(3, [classic(GUARDIAN, GUARDIAN_HEX)]));
  const trust = walletTrust({ own: [{ scheme: 'webauthn_p256', public_key: PASSKEY }], operator: [{ classic_account: GUARDIAN }] });
  const d = decide(c, { trust, expect: EXPECT });
  const screen = confirmationScreen({ check: c, decision: d });
  for (const want of [c.summary.trim().split('\n')[0], EXPECT.target, EXPECT.boundPolicies[0], 'rule 0', 'rule 3',
    TRUST_OWN, TRUST_OPERATOR, DELEGATE, 'not proof that a human approved']) {
    assert.ok(screen.includes(want), `screen lacks ${want}`);
  }
  assert.doesNotMatch(screen, /\bsafe/i);
  // A refused answer says so on the screen, with every finding.
  c.verdict.refusals.push(finding('E_DELEGATE_GRANT_OVERLAP'), finding('E_UNSAFE_MANAGEMENT_SURFACE'));
  const refused = confirmationScreen({ check: c, decision: decide(c, { trust, expect: EXPECT }) });
  assert.match(refused, /E_DELEGATE_GRANT_OVERLAP/);
  assert.match(refused, /E_UNSAFE_MANAGEMENT_SURFACE/);
  assert.match(refused, /REFUSED/);
  assert.doesNotMatch(refused, /\bsafe/i);
});

test('a tool summary that claims "safe" is treated as malformed output', () => {
  const c = check();
  c.summary = 'This install is safe.';
  assert.equal(decide(c, { trust: ownPasskey(), expect: EXPECT }).accept, false);
});

// --- the request -------------------------------------------------------------------------------

test('the check request binds the generated policy by its own build manifest', () => {
  const manifest = { spec_hash: '11'.repeat(32), wasm_hash: '99'.repeat(32), rule_index: 0, registry_snapshot: 'a0'.repeat(32) };
  const spec = { name: 'native-sub', network_id: EXPECT.networkId, registry_snapshot: 'a0'.repeat(32), smart_account: { address: EXPECT.account } };
  const req = checkRequest({
    spec, ruleIndex: 0, manifest, policyAddress: EXPECT.boundPolicies[0], resolutionReference: 'deploy tx ab12',
    signedRegistrySnapshot: { signed: true }, rpcSource: 'testnet',
  });
  assert.deepEqual(Object.keys(req).sort(),
    ['account_address', 'binding_set', 'network_id', 'rpc_source', 'rule_index', 'signed_registry_snapshot', 'spec']);
  assert.equal(req.network_id, EXPECT.networkId);
  assert.deepEqual(req.binding_set, {
    schema: 'policy-binding-set/v1', spec_hash: manifest.spec_hash, network_id: EXPECT.networkId,
    bindings: [{
      rule_index: 0, policy_index: 0, contract_address: EXPECT.boundPolicies[0], observed_wasm_hash: manifest.wasm_hash,
      recognition: { kind: 'verified_generated_manifest', build_manifest: manifest },
      resolution_reference: 'deploy tx ab12',
    }],
  });
  assert.equal(req.account_address, EXPECT.account);
  assert.equal(req.spec, spec, 'the spec goes as it is, unchanged after generate');
  assert.equal(req.binding_set.bindings[0].recognition.build_manifest, manifest, 'the manifest goes unmodified');
  const base = { spec, ruleIndex: 0, manifest, policyAddress: EXPECT.boundPolicies[0], resolutionReference: 'ref', signedRegistrySnapshot: {}, rpcSource: 'testnet' };
  assert.throws(() => checkRequest({ ...base, ruleIndex: 1 }), /rule/);
  assert.throws(() => checkRequest({ ...base, resolutionReference: '  ' }), /resolution reference/);
  // The tool refuses a zero registry root (E_POLICY_BINDING_INVALID); say so before asking it.
  assert.throws(() => checkRequest({ ...base, spec: { ...spec, registry_snapshot: '0'.repeat(64) }, manifest: { ...manifest, registry_snapshot: '0'.repeat(64) } }), /registry/);
  // The spec must be the one the manifest was generated from.
  assert.throws(() => checkRequest({ ...base, spec: { ...spec, registry_snapshot: 'b0'.repeat(32) } }), /manifest/);
  assert.throws(() => checkRequest({ ...base, manifest: { ...manifest, spec_hash: 'AB'.repeat(32) } }), /hash/);
  assert.throws(() => checkRequest({ ...base, policyAddress: EXPECT.account }), /account/);
});
