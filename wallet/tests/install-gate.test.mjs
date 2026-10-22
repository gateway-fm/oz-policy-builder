// Each installation check on its own: a variant that changes only what one check guards must be
// refused, so removing any one check fails a test here.
import assert from 'node:assert/strict';
import test from 'node:test';
import { Keypair, StrKey, xdr } from '@stellar/stellar-sdk';
import { reviewIntent } from '../shared/approval.mjs';
import { validateAssembly } from '../shared/assembly.mjs';
import { installConsent } from '../shared/install.mjs';
import { INSTALL_EVIDENCE_MAX_AGE_LEDGERS, installGate, verifyInstallation, verifyRemoval } from '../server/install.mjs';
import { fixture } from './approval-fixture.mjs';
import { sample } from './assembly-fixture.mjs';
import { RULE_ID, addedEvent, contractEvent, installable, installedRule, removedEvent, verified } from './install-fixture.mjs';

const OTHER_CONTRACT = StrKey.encodeContract(Buffer.alloc(32, 0x5a));
const OTHER_G = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 0x5b)).publicKey();
const sym = (value) => xdr.ScVal.scvSymbol(value);
const u32 = (value) => xdr.ScVal.scvU32(value);

// --- installGate ----------------------------------------------------------------------------------

async function gateBase() {
  const f = await installable();
  const { live } = await verified(f);
  const layers = live.verification.layers;
  return { review: { verification: live.verification, nextRuleId: RULE_ID, approval: { wallet: f.f.wallet, intent: f.f.intent },
    accountLayer: layers[1], targetLayer: layers[2], liveLayer: layers[3] },
  deployment: { response: { policyAddress: f.policy, bindingSetHash: f.f.expected.bindingSetHash } },
  artifact: { specHash: f.artifact.specHash, wasmHash: f.artifact.wasmHash }, currentLedger: f.state.ledger };
}
const STORED = [null, 'accountLayer', 'targetLayer', 'liveLayer'];
/** Change layer `index` in the report and in the review's stored copy alike. */
const both = (index, change) => (input) => {
  change(input.review.verification.layers[index]);
  if (STORED[index]) change(input.review[STORED[index]]);
};
const captured = (input) => input.review.targetLayer.evidence.observedLedger;
const liveLedgers = (input) => input.review.liveLayer.evidence.cases.map((c) => c.simulationLedger);

const GATE = {
  'an incomplete report': (i) => { i.review.verification.complete = false; },
  'a failed reference layer': both(0, (l) => { l.status = 'failed'; }),
  'a failed account layer': both(1, (l) => { l.status = 'failed'; }),
  'a failed captured layer': both(2, (l) => { l.status = 'unavailable'; }),
  'a failed live layer': both(3, (l) => { l.status = 'unsupported'; }),
  'layers out of order': (i) => { const l = i.review.verification.layers; [l[1], l[2]] = [l[2], l[1]]; },
  'a reference layer under another name': both(0, (l) => { l.layer = 'static_source'; }),
  'another spec': (i) => { i.review.verification.specHash = 'f'.repeat(64); },
  'another code hash in the report': (i) => { i.review.verification.wasmHash = 'f'.repeat(64); },
  'another binding set': (i) => { i.review.verification.bindingSetHash = 'f'.repeat(64); },
  'an account layer not stored for this review': (i) => { i.review.accountLayer = { ...i.review.accountLayer, detail: 'copied' }; },
  'a captured layer not stored for this review': (i) => { i.review.targetLayer = { ...i.review.targetLayer, detail: 'copied' }; },
  'a live layer not stored for this review': (i) => { i.review.liveLayer = { ...i.review.liveLayer, detail: 'copied' }; },
  'account evidence for another rule': both(1, (l) => { l.evidence.candidateContextRuleId = 2; }),
  'account evidence for another policy': both(1, (l) => { l.evidence.policyAddress = OTHER_CONTRACT; }),
  'account evidence for other policy code': both(1, (l) => { l.evidence.policyCodeHash = 'f'.repeat(64); }),
  'account evidence for another delegate': both(1, (l) => { l.evidence.delegateAddress = OTHER_G; }),
  'captured evidence for another rule': both(2, (l) => { l.evidence.candidateContextRuleId = 2; }),
  'captured evidence for another policy': both(2, (l) => { l.evidence.policyAddress = OTHER_CONTRACT; }),
  'captured evidence for other policy code': both(2, (l) => { l.evidence.policyCodeHash = 'f'.repeat(64); }),
  'captured evidence for another delegate': both(2, (l) => { l.evidence.delegateAddress = OTHER_G; }),
  'captured evidence from another preparation': both(2, (l) => { l.evidence.runHash = 'f'.repeat(64); }),
  'live evidence for another account': both(3, (l) => { l.evidence.account = OTHER_CONTRACT; }),
  'live evidence for another policy': both(3, (l) => { l.evidence.policy = OTHER_CONTRACT; }),
  'live evidence for other policy code': both(3, (l) => { l.evidence.policyCodeHash = 'f'.repeat(64); }),
  'live evidence for another rule': both(3, (l) => { l.evidence.expectedRuleId = 2; }),
  'live evidence claiming human approval': both(3, (l) => { l.evidence.owner.human_approval_attested = true; }),
  'live evidence with one case': both(3, (l) => { l.evidence.cases = l.evidence.cases.slice(0, 1); }),
  'a review for another rule ID': (i) => { i.review.nextRuleId = RULE_ID + 1; },
  'a deployment of another policy': (i) => { i.deployment.response.policyAddress = OTHER_CONTRACT; },
  'artifact code differing from the report': (i) => { i.artifact.wasmHash = 'f'.repeat(64); },
  'captured evidence after the current ledger': (i) => { i.currentLedger = captured(i) - 1; },
  'captured evidence too old': (i) => { i.currentLedger = captured(i) + INSTALL_EVIDENCE_MAX_AGE_LEDGERS + 1; },
  'live evidence after the current ledger': both(3, (l) => { l.evidence.cases[1].simulationLedger = 10 ** 9; }),
  'live evidence too old': (i) => {
    i.currentLedger = Math.max(...liveLedgers(i)) + INSTALL_EVIDENCE_MAX_AGE_LEDGERS + 1;
    both(2, (l) => { l.evidence.observedLedger = i.currentLedger; })(i);
  },
  'no current ledger': (i) => { i.currentLedger = undefined; },
};

test('the installation gate accepts the review the four layers ran for', async () => {
  const base = await gateBase();
  const result = installGate(structuredClone(base));
  assert.equal(result.capturedLedger, captured(base));
  assert.deepEqual(result.liveLedgers, liveLedgers(base));
  // The age bound itself: exactly the bound is accepted.
  const edge = structuredClone(base);
  edge.currentLedger = Math.min(captured(edge), ...liveLedgers(edge)) + INSTALL_EVIDENCE_MAX_AGE_LEDGERS;
  assert.doesNotThrow(() => installGate(edge));
});
test('the installation gate refuses every changed identity, status or evidence ledger', async () => {
  const base = await gateBase();
  for (const [name, change] of Object.entries(GATE)) {
    const input = structuredClone(base);
    change(input);
    assert.throws(() => installGate(input), /refused/, name);
  }
});

// --- verifyInstallation and verifyRemoval ---------------------------------------------------------

const intent = fixture().intent;
const account = intent.account_contract;
function installation(change = () => {}) {
  const rule = installedRule(intent);
  const value = { hash: 'e'.repeat(64), ledger: 100, returnValue: rule, events: [
    contractEvent(account, [sym('signer_registered'), u32(1)], xdr.ScVal.scvMap([])), addedEvent(account, rule),
    contractEvent(intent.policies[0].address, [sym('generated_policy_installed'), xdr.ScVal.scvVoid()], xdr.ScVal.scvMap([]))] };
  change(value, rule);
  return value;
}
const field = (rule, name) => rule.map.find((e) => e.key.sym.toString() === name);
const ruleWith = (name, val) => {
  const rule = installedRule(intent);
  field(rule, name).val = val;
  return rule;
};
const dataWith = (name, val) => {
  const rule = installedRule(intent);
  const event = addedEvent(account, rule);
  event.body.v0.data.map.find((e) => e.key.sym.toString() === name).val = val;
  return event;
};
const withType = (event, type) => { event.type = xdr.ContractEventType[type]; return event; };

test('an installation is verified from the returned rule and exactly one context_rule_added of the account', () => {
  const result = verifyInstallation({ submitted: installation(), intent, ruleId: RULE_ID });
  assert.deepEqual([result.transactionHash, result.ledger, result.ruleId], ['e'.repeat(64), 100, RULE_ID]);
  assert.equal(result.ruleXdr, installedRule(intent).toXDR('base64'));
});
test('installation verification refuses each difference on its own', () => {
  const variants = {
    'no transaction hash': (v) => { v.hash = 'e'; },
    'no ledger': (v) => { v.ledger = 0; },
    'a returned rule with another ID': (v) => { v.returnValue = ruleWith('id', u32(2)); },
    'a returned rule for another target': (v) => { v.returnValue = ruleWith('context_type', xdr.ScVal.scvVec([sym('Default')])); },
    'a returned rule with another name': (v) => { v.returnValue = ruleWith('name', xdr.ScVal.scvString('other')); },
    'a returned rule with another expiry': (v) => { v.returnValue = ruleWith('valid_until', u32(1)); },
    'a returned rule with other signers': (v) => { v.returnValue = ruleWith('signers', xdr.ScVal.scvVec([])); },
    'a returned rule with other policies': (v) => { v.returnValue = ruleWith('policies', xdr.ScVal.scvVec([])); },
    'a returned rule with too few policy IDs': (v) => { v.returnValue = ruleWith('policy_ids', xdr.ScVal.scvVec([])); },
    'a returned rule with too few signer IDs': (v) => { v.returnValue = ruleWith('signer_ids', xdr.ScVal.scvVec([])); },
    'a returned rule with a missing field': (v) => { v.returnValue = xdr.ScVal.scvMap(installedRule(intent).map.slice(1)); },
    'no event': (v) => { v.events = v.events.filter((e) => e.body.v0.topics[0].sym.toString() !== 'context_rule_added'); },
    'two events': (v, rule) => { v.events.push(addedEvent(account, rule)); },
    'the event from another contract': (v, rule) => { v.events[1] = addedEvent(OTHER_CONTRACT, rule); },
    'a diagnostic event only': (v, rule) => { v.events[1] = withType(addedEvent(account, rule), 'diagnostic'); },
    'the event for another rule ID': (v, rule) => { v.events[1] = addedEvent(account, rule, 2); },
    'the event with another topic count': (v, rule) => { v.events[1].body.v0.topics.push(u32(1)); },
    'event data with another target': (v) => { v.events[1] = dataWith('context_type', xdr.ScVal.scvVec([sym('Default')])); },
    'event data with another name': (v) => { v.events[1] = dataWith('name', xdr.ScVal.scvString('other')); },
    'event data with other policy IDs': (v) => { v.events[1] = dataWith('policy_ids', xdr.ScVal.scvVec([u32(5)])); },
    'event data with other signer IDs': (v) => { v.events[1] = dataWith('signer_ids', xdr.ScVal.scvVec([u32(5)])); },
    'event data with another expiry': (v) => { v.events[1] = dataWith('valid_until', u32(1)); },
    'event data with a missing field': (v) => { v.events[1].body.v0.data = xdr.ScVal.scvMap(v.events[1].body.v0.data.map.slice(1)); },
    'no event list': (v) => { v.events = undefined; },
  };
  for (const [name, change] of Object.entries(variants)) {
    assert.throws(() => verifyInstallation({ submitted: installation(change), intent, ruleId: RULE_ID }), /refused/, name);
  }
  assert.throws(() => verifyInstallation({ submitted: installation(), intent, ruleId: RULE_ID + 1 }), /refused/, 'another expected rule ID');
});

function removal(change = () => {}) {
  const value = { hash: 'f'.repeat(64), ledger: 120, returnValue: xdr.ScVal.scvVoid(), events: [removedEvent(account)] };
  change(value);
  return value;
}
test('a removal is verified from exactly one context_rule_removed of the account', () => {
  assert.deepEqual(verifyRemoval({ submitted: removal(), account, ruleId: RULE_ID }),
    { transactionHash: 'f'.repeat(64), ledger: 120, ruleId: RULE_ID });
  const variants = {
    'no transaction hash': (v) => { v.hash = 'f'; },
    'a return value': (v) => { v.returnValue = u32(1); },
    'no event': (v) => { v.events = []; },
    'two events': (v) => { v.events.push(removedEvent(account)); },
    'the event from another contract': (v) => { v.events = [removedEvent(OTHER_CONTRACT)]; },
    'a diagnostic event only': (v) => { v.events = [withType(removedEvent(account), 'diagnostic')]; },
    'the event for another rule ID': (v) => { v.events = [removedEvent(account, 2)]; },
    'the event with another topic count': (v) => { v.events[0].body.v0.topics.push(u32(1)); },
    'event data that is not the empty map': (v) => { v.events[0].body.v0.data = xdr.ScVal.scvMap([
      new xdr.ScMapEntry({ key: sym('id'), val: u32(1) })]); },
  };
  for (const [name, change] of Object.entries(variants)) {
    assert.throws(() => verifyRemoval({ submitted: removal(change), account, ruleId: RULE_ID }), /refused/, name);
  }
  assert.throws(() => verifyRemoval({ submitted: removal(), account, ruleId: RULE_ID + 1 }), /refused/, 'another expected rule ID');
});

// --- installConsent ------------------------------------------------------------------------------

function consentBase() {
  const value = sample();
  const approval = value.approval;
  const checked = validateAssembly(value);
  const i = approval.intent;
  const spec = { smart_account: { address: i.account_contract }, rules: [{ context: { contract: i.context_contract },
    valid_until: { ledger: i.valid_until_ledger }, authorization: { signers: [{ delegated: { address: i.delegate_signers[0].address } }] },
    state: [{ call_count_per_installation: { max_calls: 1 } }], allowed_calls: [{ fn: 'transfer', args: [] }] }] };
  return { approval, checked: structuredClone(checked), spec, maxFeeStroops: 10_000_000, ruleId: RULE_ID };
}
test('the installation consent is derived only for the reviewed grant, rule and fee bound', () => {
  const display = installConsent(consentBase());
  assert.equal(display.grant.rule_id, RULE_ID);
  assert.equal(display.fee.max_fee_stroops, 10_000_000);
  assert.deepEqual(display.owner_signs.context_rule_ids, [7]);
  const variants = {
    'the owner rule as the new rule': (b) => { b.ruleId = 7; },
    'no rule ID': (b) => { b.ruleId = 0; },
    'another commitment': (b) => { b.checked.authorityCommitment = 'f'.repeat(64); },
    'another owner rule': (b) => { b.checked.ownerRuleId = 8; },
    'a fee above the bound': (b) => { b.checked.feeStroops = 10_000_001; },
    'no fee bound': (b) => { b.maxFeeStroops = 0; },
    'a spec for another delegate': (b) => { b.spec.rules[0].authorization.signers[0].delegated.address = OTHER_G; },
    'a spec for another target': (b) => { b.spec.rules[0].context.contract = OTHER_CONTRACT; },
    'a spec with another expiry': (b) => { b.spec.rules[0].valid_until.ledger += 1; },
    'a spec for another account': (b) => { b.spec.smart_account.address = OTHER_CONTRACT; },
    'a spec without a call cap': (b) => { b.spec.rules[0].state = []; },
    'a spec without allowed calls': (b) => { b.spec.rules[0].allowed_calls = []; },
    'a spec with two rules': (b) => { b.spec.rules.push(b.spec.rules[0]); },
  };
  for (const [name, change] of Object.entries(variants)) {
    const input = consentBase();
    change(input);
    assert.throws(() => installConsent(input), /refused/, name);
  }
  assert.ok(reviewIntent(fixture()));
});
