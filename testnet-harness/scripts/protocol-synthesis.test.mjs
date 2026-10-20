import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { protocolInputs, validateProtocolSynthesis } from './protocol-synthesis.mjs';
const capture = JSON.parse(readFileSync(new URL('./fixtures/protocol-swap-observation.json', import.meta.url)));
function fixture() {
  const f = structuredClone(capture);
  // This is a validation fixture, never evidence of an executed swap. The preserved capture
  // itself is an unsigned simulation; the execution rejection below tests that boundary.
  f.record.bundle.execution = 'executed_success';
  f.run = { network: 'Test SDF Network ; September 2015', account: f.plan.account,
    account_code_hash: f.synthesis.spec.smart_account.observed_code_hash,
    delegate: f.synthesis.spec.rules[0].authorization.signers[0].delegated.address, walkthrough: f.plan };
  return f;
}
for (const horizon of [180, 0, 1001, 1.5]) {
  test(`protocol grant horizon is explicit and bounded: ${horizon}`, () => {
    const f = fixture();
    f.run.walkthrough.grant_duration_ledgers = horizon;
    if (horizon === 180) assert.equal(protocolInputs(f.run, f.record).decisions.valid_until_ledger, f.record.bundle.ledger + 180);
    else assert.throws(() => protocolInputs(f.run, f.record), /horizon/);
  });
}
for (const mutation of ['matching', 'simulation only', 'extra auth', 'missing child', 'extra child', 'wrong child amount', 'wrong root code', 'wrong account code']) {
  test(`protocol recording keeps the complete selected authorization: ${mutation}`, () => {
    const f = fixture();
    const root = f.record.bundle.authorizations[0].root;
    if (mutation === 'simulation only') f.record.bundle.execution = 'simulated';
    if (mutation === 'extra auth') f.record.bundle.authorizations.push(f.record.bundle.authorizations[0]);
    if (mutation === 'missing child') root.sub_invocations = [];
    if (mutation === 'extra child') root.sub_invocations.push(root.sub_invocations[0]);
    if (mutation === 'wrong child amount') root.sub_invocations[0].call.contract.args[2].i128++;
    if (mutation === 'wrong root code') f.record.bundle.contract_executables[root.call.contract.contract].executable.wasm.code_hash = 'ab'.repeat(32);
    if (mutation === 'wrong account code') f.record.bundle.contract_executables[f.run.account].executable.wasm.code_hash = 'ab'.repeat(32);
    if (mutation === 'matching') {
      const inputs = protocolInputs(f.run, f.record);
      assert.equal(inputs.calls.length, 2);
      assert.equal(inputs.calls[1].path, 'recordings[0]/auth[0]/sub[0]');
      assert.equal(inputs.decisions.widenings.length, 3);
      validateProtocolSynthesis(f.synthesis, f.run, inputs, f.synthesis.spec.registry_snapshot);
    } else assert.throws(() => protocolInputs(f.run, f.record));
  });
}
for (const mutation of ['drop child rule', 'extra rule', 'reorder rules', 'floor removed', 'path broadened', 'deadline broadened',
  'child recipient', 'child cap', 'unbound target code', 'reviewed-policy invention', 'wrong manifest root']) {
  test(`protocol synthesis refuses altered independent capabilities: ${mutation}`, () => {
    const f = fixture(); const input = protocolInputs(f.run, f.record);
    const spec = f.synthesis.spec;
    if (mutation === 'drop child rule') spec.rules.pop();
    if (mutation === 'extra rule') spec.rules.push(spec.rules[1]);
    if (mutation === 'reorder rules') spec.rules.reverse();
    if (mutation === 'floor removed') spec.rules[0].allowed_calls[0].args[1].c = { any_value: null };
    if (mutation === 'path broadened') spec.rules[0].allowed_calls[0].args[2].c = { any_value: null };
    if (mutation === 'deadline broadened') spec.rules[0].allowed_calls[0].args[4].c = { any_value: null };
    if (mutation === 'child recipient') spec.rules[1].allowed_calls[0].args[1].c.eq_address.value = f.run.account;
    if (mutation === 'child cap') spec.rules[1].allowed_calls[0].args[2].c.le_i128.max = '1000001';
    if (mutation === 'unbound target code') spec.rules[0].context.target_code_hash = null;
    if (mutation === 'reviewed-policy invention') spec.rules[0].policies.push({ reviewed: {} });
    if (mutation === 'wrong manifest root') spec.registry_snapshot = 'ab'.repeat(32);
    assert.throws(() => validateProtocolSynthesis(f.synthesis, f.run, input, capture.synthesis.spec.registry_snapshot));
  });
}
