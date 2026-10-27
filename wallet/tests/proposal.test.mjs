import test from 'node:test';
import assert from 'node:assert/strict';
import { parseGrantProposal, checkProposalArtifact } from '../shared/proposal.mjs';
import { proposalFixture } from './proposal-fixture.mjs';

test('proposal binds the exact permission while displaying different acquisition hashes', () => {
  const f = proposalFixture();
  const parsed = parseGrantProposal(JSON.stringify(f.proposal), f.wallet.contractId);
  const receipt = checkProposalArtifact(parsed, f.artifact);
  assert.equal(receipt.agentSpecHash, f.proposal.spec_hash);
  assert.equal(receipt.walletSpecHash, f.artifact.specHash);
  assert.equal(receipt.hashesMatch, false);
  assert.equal(receipt.grantsMatch, true);
  assert.equal(Object.isFrozen(parsed.expected_grant.rules[0]), true);
  const reverse = (x) => Array.isArray(x) ? x.map(reverse) : x && typeof x === 'object'
    ? Object.fromEntries(Object.entries(x).reverse().map(([k, v]) => [k, reverse(v)])) : x;
  checkProposalArtifact(parseGrantProposal(JSON.stringify(reverse(f.proposal)), f.wallet.contractId), f.artifact);
});

const badProposals = {
  arraySpecHash: p => { p.spec_hash = [p.spec_hash]; },
  arrayTransactionHash: p => { p.transaction_hash = [p.transaction_hash]; },
  version: p => { p.schema = 'ozpb-grant-proposal/v2'; },
  network: p => { p.network_id = 'f'.repeat(64); },
  account: p => { p.expected_grant.account = p.expected_grant.rules[0].context.contract; },
  widening: p => { p.decisions.widenings = []; },
  spending: p => { p.decisions.spending_limit = null; },
  uncapped: p => { p.decisions.max_calls = null; p.decisions.unlimited_calls_acknowledged = true; },
  expiredShape: p => { p.decisions.valid_until_ledger = null; },
  cap: p => { p.decisions.max_calls = 10001; },
  duplicateRule: p => { p.expected_grant.rules.push(p.expected_grant.rules[0]); },
  otherFunction: p => { p.expected_grant.rules[0].calls[0].fn = 'approve'; },
  anyArgument: p => { p.expected_grant.rules[0].calls[0].args[2].c = 'any_value'; },
  sender: p => { p.expected_grant.rules[0].calls[0].args[0].c.eq_address.value = p.decisions.delegate; },
  overflow: p => { p.expected_grant.rules[0].calls[0].args[2].c.eq_i128.value = (2n ** 127n).toString(); },
  negative: p => { p.expected_grant.rules[0].calls[0].args[2].c.eq_i128.value = '-1'; },
  predicate: p => { p.expected_grant.rules[0].authorization.kind = 'all_of'; },
  nonStrict: p => { p.expected_grant.rules[0].authorization.strict_signer_set = false; },
  targetCode: p => { p.expected_grant.rules[0].context.target_code_hash = 'a'.repeat(64); },
  policy: p => { p.expected_grant.rules[0].policy_kinds = ['oz:spending_limit']; },
  expiryMismatch: p => { p.expected_grant.rules[0].valid_until_ledger++; },
  capMismatch: p => { p.expected_grant.rules[0].max_calls++; },
  delegateMismatch: p => { p.expected_grant.rules[0].authorization.signers[0].delegated.address = p.expected_grant.rules[0].calls[0].args[1].c.eq_address.value; },
};
for (const [name, change] of Object.entries(badProposals)) test(`proposal refuses ${name}`, () => {
  const f = proposalFixture(); change(f.proposal);
  assert.throws(() => parseGrantProposal(JSON.stringify(f.proposal), f.wallet.contractId), /proposal refused/);
});

test('artifact identifiers must be strings, without regex coercion', () => {
  for (const field of ['artifactId', 'specHash', 'wasmHash']) {
    const f = proposalFixture(); f.artifact[field] = [f.artifact[field]];
    assert.throws(() => checkProposalArtifact(parseGrantProposal(JSON.stringify(f.proposal), f.wallet.contractId), f.artifact), /proposal refused/);
  }
});

test('proposal JSON refuses duplicate and reserved keys, lossy numbers, oversized input and deep nesting', () => {
  const f = proposalFixture(), text = JSON.stringify(f.proposal);
  for (const raw of [text.replace('"max_calls":2', '"max_calls":1,"max_calls":2'),
    text.replace('"max_calls":2', '"max_calls":1,"max_\\u0063alls":2'),
    text.replace('"max_calls":2', '"max_calls":2.0000000000000001'),
    text.replace('"max_calls":2', '"max_calls":2e0'), text.replace('"max_calls":2', '"__proto__":{},"max_calls":2'),
    ' '.repeat(17000) + text, '{"x":'.repeat(40) + '0' + '}'.repeat(40), text + '{}']) {
    assert.throws(() => parseGrantProposal(raw, f.wallet.contractId), /proposal refused/);
  }
});

for (const [name, change] of Object.entries({
  name: s => { s.name = 'other'; }, network: s => { s.network_id = 'f'.repeat(64); },
  account: s => { s.smart_account.address = s.rules[0].context.contract; },
  target: s => { s.rules[0].context.contract = s.smart_account.address; },
  amount: s => { s.rules[0].allowed_calls[0].args[2].c.eq_i128.value = '2000000'; },
  recipient: s => { s.rules[0].allowed_calls[0].args[1].c.eq_address.value = s.rules[0].authorization.signers[0].delegated.address; },
  predicate: s => { s.rules[0].authorization.kind = 'all_of'; },
  strict: s => { s.rules[0].authorization.strict_signer_set = false; },
  cap: s => { s.rules[0].state[0].call_count_per_installation.max_calls++; },
  expiry: s => { s.rules[0].valid_until.ledger++; },
  policy: s => { s.rules[0].policies[0].generated.kind = 'gen:scope'; },
  code: s => { s.rules[0].context.target_code_hash = { hash: 'f'.repeat(64) }; },
})) test(`independent regeneration refuses changed ${name}`, () => {
  const f = proposalFixture(); change(f.spec);
  assert.throws(() => checkProposalArtifact(parseGrantProposal(JSON.stringify(f.proposal), f.wallet.contractId), f.artifact), /proposal refused/);
});
