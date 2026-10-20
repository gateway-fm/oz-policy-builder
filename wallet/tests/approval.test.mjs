import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, xdr } from '@stellar/stellar-sdk';
import { fixture } from './approval-fixture.mjs';
import { reviewIntent } from '../shared/approval.mjs';


test('wallet chooses its exact passkey management rule and freezes displayed semantics', () => {
  const input = fixture();
  const approval = reviewIntent(input);
  assert.equal(approval.ownerRuleId, 7);
  assert.equal(approval.commitment, input.intent.authority.verdict.authority_commitment);
  assert.ok(Object.isFrozen(approval.intent.delegate_signers));
  input.intent.rule_name = 'replaced';
  assert.equal(approval.intent.rule_name, 'native-sub');
});

for (const mutation of ['account code', 'verifier code', 'foreign key', 'refusal', 'unresolved', 'intent', 'binding hash', 'expired owner', 'no owner']) {
  test(`wallet refuses ${mutation} before requesting a passkey signature`, () => {
    const input = fixture();
    const v = input.intent.authority.verdict;
    switch (mutation) {
      case 'account code': v.account_code_hash = '0'.repeat(64); break;
      case 'verifier code': v.authority_list[0].requirement.signers[0].verifier_code_hash = '0'.repeat(64); break;
      case 'foreign key': input.wallet.publicKey = '04' + '1'.repeat(128); break;
      case 'refusal': v.refusals.push({ code: 'E_DELEGATE_HAS_AUTHORITY', reason: 'refused' }); break;
      case 'unresolved': v.unresolved.push({ code: 'E_INCOMPLETE_ACCOUNT_STATE', reason: 'missing' }); break;
      case 'intent': input.intent.rule_name = 'another grant'; break;
      case 'binding hash': input.intent.authority.binding_set_hash = '0'.repeat(64); break;
      case 'expired owner': v.authority_list[0].valid_until = v.observed_ledger; break;
      case 'no owner': v.authority_list[0].reach = { kind: 'policy', address: v.bound_policy_addresses[0] }; break;
    }
    assert.throws(() => reviewIntent(input), /refused/);
  });
}

test('matching public key does not substitute for the exact stored credential or policy-free rule', () => {
  const input = fixture();
  for (const changes of [
    { id: xdr.ScVal.scvU32(0) },
    { policies: xdr.ScVal.scvVec([new Address(input.expected.boundPolicies[0]).toScVal()]) },
    { signers: xdr.ScVal.scvVec([]) },
    { context_type: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('CallContract'), new Address(input.expected.target).toScVal()]) },
    { valid_until: xdr.ScVal.scvU32(1) },
  ]) assert.throws(() => reviewIntent({ ...input, ownerRuleXdr: input.ruleXdr(changes) }), /refused/);
  input.wallet.credentialId = 'Ag';
  assert.throws(() => reviewIntent(input), /refused/);
});
